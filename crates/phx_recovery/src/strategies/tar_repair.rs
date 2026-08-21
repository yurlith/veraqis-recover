//! TAR structural repair strategies (Phase 6, Step 6.2).
//!
//! Two techniques:
//! - `TarChecksumFix`      — recompute and overwrite UStar header checksums.
//! - `TarTerminatorAppend` — append missing end-of-archive two-block terminator.

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Corruption, CorruptionCategory};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

// ── TarChecksumFix ────────────────────────────────────────────────────────────

/// Recompute and overwrite the checksum field of every UStar header block whose
/// stored checksum doesn't match the computed one.
///
/// The UStar checksum is the sum of all header bytes treating the 8-byte
/// checksum field itself as spaces (0x20). It is stored as a 6-digit zero-
/// padded octal number followed by a space and a NUL.
pub struct TarChecksumFix;

impl RecoveryStrategy for TarChecksumFix {
    fn name(&self) -> &str {
        "tar-checksum-fix"
    }

    fn technique(&self) -> &'static str {
        "UstarChecksumFix"
    }

    fn risk(&self) -> RepairRisk {
        RepairRisk::Safe
    }

    fn handles(&self, c: &Corruption) -> bool {
        c.chain.primary.rule_id == "TAR_UST_001"
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "recompute and overwrite the UStar header checksum field".to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Tar)
            && result
                .corruptions
                .iter()
                .any(|c| c.chain.primary.rule_id == "TAR_UST_001")
    }

    fn priority(&self) -> u8 {
        85
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let mut data = read_all(source)?;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        let mut fixed = 0usize;
        let nblocks = data.len() / 512;
        let mut pos = 0usize;

        while pos < nblocks {
            let off = pos * 512;
            let block = &data[off..off + 512];

            // All-zero block = end-of-archive terminator; stop.
            if block.iter().all(|&b| b == 0) {
                break;
            }

            // Verify UStar magic before touching this block.
            if &block[257..262] != b"ustar" {
                // Not a recognized header — skip one block and continue.
                pos += 1;
                continue;
            }

            let stored = ustar_checksum_read(block);
            let computed = ustar_checksum_compute(block);

            if stored != computed {
                // Write corrected checksum: 6-digit octal, space, NUL.
                let cksum_str = format!("{computed:06o}\x20\x00");
                let cksum_bytes = cksum_str.as_bytes();
                data[off + 148..off + 156].copy_from_slice(&cksum_bytes[..8]);
                fixed += 1;
            }

            // Advance past this header block + data blocks.
            let size = octal_field(&data[off + 124..off + 136]).unwrap_or(0);
            let data_blocks = size.div_ceil(512) as usize;
            pos += 1 + data_blocks;
        }

        if fixed == 0 && data.iter().all(|&b| b == 0) {
            report.success = false;
            report
                .warnings
                .push("no valid UStar headers found".to_string());
            return Ok(report);
        }

        output.write(&data);
        report.bytes_recovered = data.len() as u64;
        report.success = true;
        report
            .warnings
            .push(format!("fixed checksum in {fixed} TAR header block(s)"));
        Ok(report)
    }
}

// ── TarTerminatorAppend ───────────────────────────────────────────────────────

/// Append the two 512-byte all-zero blocks that form the TAR end-of-archive
/// terminator when they are missing.
pub struct TarTerminatorAppend;

impl RecoveryStrategy for TarTerminatorAppend {
    fn name(&self) -> &str {
        "tar-terminator-append"
    }

    fn technique(&self) -> &'static str {
        "TerminatorAppend"
    }

    fn risk(&self) -> RepairRisk {
        RepairRisk::Safe
    }

    fn handles(&self, c: &Corruption) -> bool {
        c.chain.primary.rule_id == "TAR_TERM_001"
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "append two 512-byte zero blocks (end-of-archive terminator)".to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Tar)
            && result.corruptions.iter().any(|c| {
                c.chain.primary.rule_id == "TAR_TERM_001"
                    || c.category == CorruptionCategory::Truncation
            })
    }

    fn priority(&self) -> u8 {
        88
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let data = read_all(source)?;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        // Check if the archive already ends with a valid terminator.
        let already_terminated =
            data.len() >= 1024 && data[data.len() - 1024..].iter().all(|&b| b == 0);

        output.write(&data);

        if already_terminated {
            report.bytes_recovered = data.len() as u64;
            report.success = true;
            report
                .warnings
                .push("archive already has a terminator; copied verbatim".to_string());
        } else {
            output.write(&[0u8; 1024]);
            report.bytes_recovered = (data.len() + 1024) as u64;
            report.success = true;
            report
                .warnings
                .push("appended 2×512 end-of-archive terminator blocks".to_string());
        }

        Ok(report)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute the UStar checksum for a 512-byte block (checksum field treated as spaces).
fn ustar_checksum_compute(block: &[u8]) -> u32 {
    let mut sum = 0u32;
    for (i, &b) in block.iter().enumerate() {
        if (148..156).contains(&i) {
            sum += 0x20; // treat checksum field as spaces
        } else {
            sum += b as u32;
        }
    }
    sum
}

/// Read the stored checksum from a UStar header block (octal string at +148).
fn ustar_checksum_read(block: &[u8]) -> u32 {
    octal_field(&block[148..156]).unwrap_or(u64::MAX) as u32
}

/// Parse an octal ASCII field (null- or space-terminated).
fn octal_field(field: &[u8]) -> Option<u64> {
    let s = field.split(|&b| b == 0 || b == b' ').next()?;
    if s.is_empty() {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(s).ok()?, 8).ok()
}
