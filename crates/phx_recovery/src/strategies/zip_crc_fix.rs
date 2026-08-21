//! `ZipCrcFix` — repair a damaged CRC32 *field* in a ZIP, never a damaged payload.
//!
//! ZIP stores every CRC-32 twice: once in the local file header and once in the central
//! directory. That redundancy is the whole basis of this strategy. A stored checksum is
//! corrected **only** when a surviving independent copy proves the correct value:
//!
//! * payload agrees with the local header → the payload is proven intact, so a disagreeing
//!   central-directory copy is the damaged one and is synced from it;
//! * payload agrees with the central directory → the local-header field is the damaged one
//!   and is synced from the central directory;
//! * payload agrees with **neither** → the *payload* is what is damaged. The checksum is left
//!   exactly as found and the mismatch is annotated.
//!
//! The last case is why this strategy is called `CrcAnnotate`. Overwriting a checksum with one
//! recomputed from the bytes under suspicion would make the archive self-consistent while still
//! holding wrong data: the later CRC check would be verifying those bytes against a checksum
//! derived from them, which proves nothing (`CLAUDE.md`, tautology rule — a checksum the repair
//! targeted contributes zero evidence bits). It also destroys the only signal that the payload is
//! wrong, turning detectable corruption into silent corruption.

use std::collections::BTreeMap;
use std::io::Read;

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Corruption};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const CDFH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

pub struct ZipCrcFix;

/// One central-directory record's CRC-32: where the field lives, and what it says.
struct CdCrc {
    field_offset: usize,
    crc: u32,
}

impl RecoveryStrategy for ZipCrcFix {
    fn name(&self) -> &str {
        "zip-crc-fix"
    }

    fn technique(&self) -> &'static str {
        "CrcAnnotate"
    }

    fn risk(&self) -> RepairRisk {
        RepairRisk::Safe
    }

    fn handles(&self, c: &Corruption) -> bool {
        c.chain.primary.rule_id == "ZIP_CRC_001"
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "correct a CRC32 field that a surviving independent copy disproves; annotate (never \
         rewrite) a checksum the payload itself contradicts"
            .to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Zip)
            && result
                .corruptions
                .iter()
                .any(|c| c.chain.primary.rule_id == "ZIP_CRC_001")
    }

    fn priority(&self) -> u8 {
        75
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let mut data = read_all(source)?;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        // The second copy of every CRC-32. Without it there is no independent evidence and no
        // field may be rewritten.
        let cd_index = index_central_directory(&data);

        let mut lfh_fixed = 0usize;
        let mut cd_fixed = 0usize;
        // Entries whose payload contradicts every surviving checksum: annotated, never rewritten.
        let mut payload_damaged: Vec<String> = Vec::new();

        let len = data.len();
        let mut pos = 0usize;
        while pos + 30 <= len {
            if data[pos..pos + 4] != LFH_SIG {
                pos += 1;
                continue;
            }
            let flags = u16::from_le_bytes([data[pos + 6], data[pos + 7]]);
            let method = u16::from_le_bytes([data[pos + 8], data[pos + 9]]);
            let stored_crc = u32::from_le_bytes([
                data[pos + 14],
                data[pos + 15],
                data[pos + 16],
                data[pos + 17],
            ]);
            let compressed_size = u32::from_le_bytes([
                data[pos + 18],
                data[pos + 19],
                data[pos + 20],
                data[pos + 21],
            ]) as usize;
            let name_len = u16::from_le_bytes([data[pos + 26], data[pos + 27]]) as usize;
            let extra_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;
            let data_start = pos + 30 + name_len + extra_len;

            // Data descriptor flag: CRC/sizes come after the data, so the header field here is
            // not the authority and is left alone.
            let has_descriptor = flags & 0x0008 != 0;
            if has_descriptor {
                pos = data_start.saturating_add(compressed_size).min(len);
                continue;
            }
            if data_start + compressed_size > len {
                pos = data_start;
                continue;
            }

            let compressed = &data[data_start..data_start + compressed_size];
            let computed_crc = match method {
                0 => crc32_of(compressed),
                8 => {
                    let mut dec = flate2::read::DeflateDecoder::new(compressed);
                    let mut decompressed = Vec::new();
                    if dec.read_to_end(&mut decompressed).is_err() && decompressed.is_empty() {
                        pos = data_start + compressed_size;
                        continue;
                    }
                    crc32_of(&decompressed)
                }
                _ => {
                    pos = data_start + compressed_size;
                    continue;
                }
            };

            let entry_name = entry_name_at(&data, pos + 30, name_len);
            let cd = cd_index.get(&pos);

            if computed_crc == stored_crc {
                // Payload and local header agree: two sources, so the payload is proven intact.
                // A central-directory copy that disagrees is the damaged one.
                if let Some(cd) = cd {
                    if cd.crc != computed_crc {
                        write_crc(&mut data, cd.field_offset, computed_crc);
                        cd_fixed += 1;
                    }
                }
            } else if cd.map(|c| c.crc) == Some(computed_crc) {
                // Payload and central directory agree: the local-header field is the damaged one.
                write_crc(&mut data, pos + 14, computed_crc);
                lfh_fixed += 1;
            } else {
                // The payload contradicts every checksum that survived. The damage is in the
                // data, not in the header. Leave both copies untouched so the corruption stays
                // detectable, and record it.
                payload_damaged.push(entry_name);
            }

            pos = data_start + compressed_size;
        }

        let total_fixed = lfh_fixed + cd_fixed;

        if !payload_damaged.is_empty() {
            report.warnings.push(format!(
                "payload damage on {} entr(ies): {}. The stored CRC-32 contradicts the actual \
                 bytes and no surviving copy agrees with them, so the checksum was left intact \
                 and the entries stay detectably corrupt. Rewriting it would hide the damage, \
                 not repair it.",
                payload_damaged.len(),
                payload_damaged.join(", ")
            ));
        }

        if total_fixed == 0 {
            report.success = false;
            if payload_damaged.is_empty() {
                report
                    .warnings
                    .push("no correctable CRC32 fields found".to_string());
            }
            return Ok(report);
        }

        output.write(&data);
        report.bytes_recovered = data.len() as u64;
        report.success = true;
        report.warnings.push(format!(
            "corrected CRC32 against an independent surviving copy: {lfh_fixed} LFH + {cd_fixed} \
             CD entr(ies)"
        ));
        Ok(report)
    }
}

/// Index the central directory by the local-header offset each record points at.
fn index_central_directory(data: &[u8]) -> BTreeMap<usize, CdCrc> {
    let mut index = BTreeMap::new();
    let len = data.len();
    let Some(eocd_pos) = find_eocd(data) else {
        return index;
    };
    if eocd_pos + 22 > len {
        return index;
    }
    let cd_offset = u32::from_le_bytes([
        data[eocd_pos + 16],
        data[eocd_pos + 17],
        data[eocd_pos + 18],
        data[eocd_pos + 19],
    ]) as usize;
    if cd_offset >= len {
        return index;
    }

    let mut pos = cd_offset;
    while pos + 46 <= len {
        if data[pos..pos + 4] != CDFH_SIG {
            break;
        }
        // Central Directory File Header layout (offsets from CDFH start):
        //  16  4  crc-32
        //  42  4  relative offset of local header
        let lfh_offset = u32::from_le_bytes([
            data[pos + 42],
            data[pos + 43],
            data[pos + 44],
            data[pos + 45],
        ]) as usize;
        let crc = u32::from_le_bytes([
            data[pos + 16],
            data[pos + 17],
            data[pos + 18],
            data[pos + 19],
        ]);
        index.insert(
            lfh_offset,
            CdCrc {
                field_offset: pos + 16,
                crc,
            },
        );

        let name_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([data[pos + 30], data[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([data[pos + 32], data[pos + 33]]) as usize;
        pos += 46 + name_len + extra_len + comment_len;
    }
    index
}

fn write_crc(data: &mut [u8], field_offset: usize, crc: u32) {
    let b = crc.to_le_bytes();
    data[field_offset] = b[0];
    data[field_offset + 1] = b[1];
    data[field_offset + 2] = b[2];
    data[field_offset + 3] = b[3];
}

fn entry_name_at(data: &[u8], start: usize, name_len: usize) -> String {
    let end = start.saturating_add(name_len).min(data.len());
    if start >= end {
        return "<unnamed>".to_string();
    }
    String::from_utf8_lossy(&data[start..end]).into_owned()
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    // EOCD is at the end of the file; scan backwards from max comment length.
    let min_start = data.len().saturating_sub(65557); // 22 + 65535 max comment
    (min_start..data.len().saturating_sub(21))
        .rev()
        .find(|&i| data[i..i + 4] == EOCD_SIG)
}

fn crc32_of(data: &[u8]) -> u32 {
    phx_analyze_engine::integrity::crc32::crc32(data)
}
