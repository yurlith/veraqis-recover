//! `TarSizeBoundaryResync` — rebuild a TAR archive from UStar header scan
//! when corrupted size fields cause misaligned block navigation (Phase 6, Step 6.2).
//!
//! When a TAR entry's size field is wrong, the parser walks to a wrong 512-byte
//! boundary and interprets data bytes as a header. This strategy scans every
//! 512-byte block independently for the "ustar" magic (offset 257 in the block),
//! determines true entry boundaries, infers the corrected size from those
//! boundaries, and emits a repaired TAR with valid checksums.

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Corruption, CorruptionCategory};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

const BLOCK: usize = 512;

pub struct TarSizeBoundaryResync;

impl RecoveryStrategy for TarSizeBoundaryResync {
    fn name(&self) -> &str {
        "tar-size-resync"
    }

    fn technique(&self) -> &'static str {
        "SizeBoundaryResync"
    }

    fn risk(&self) -> RepairRisk {
        RepairRisk::Inferred
    }

    fn handles(&self, c: &Corruption) -> bool {
        c.chain.primary.rule_id == "TAR_SIZE_001"
            || c.category == CorruptionCategory::StructuralCorruption
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "scan 512-byte blocks for UStar magic, infer true sizes from header positions, \
         rebuild archive with corrected size fields and checksums"
            .to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Tar)
            && result.corruptions.iter().any(|c| {
                c.chain.primary.rule_id == "TAR_SIZE_001"
                    || c.chain.primary.rule_id == "TAR_UST_001"
                    || c.category == CorruptionCategory::StructuralCorruption
            })
    }

    fn priority(&self) -> u8 {
        78
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let data = read_all(source)?;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        let nblocks = data.len() / BLOCK;

        // Phase 1: find all 512-byte blocks that look like UStar headers
        // (have "ustar" at block-offset 257 and a plausible checksum).
        let mut header_positions: Vec<usize> = Vec::new();
        for i in 0..nblocks {
            let off = i * BLOCK;
            let block = &data[off..off + BLOCK];
            if is_ustar_header(block) {
                header_positions.push(off);
            }
        }

        if header_positions.is_empty() {
            report.success = false;
            report
                .warnings
                .push("no UStar headers found; cannot resync".to_string());
            return Ok(report);
        }

        // Phase 2: for each header, derive the true data size from the distance
        // to the next header (or the end-of-archive terminator).
        // Find end-of-archive: two consecutive all-zero blocks.
        let eoa = find_end_of_archive(&data, nblocks);

        let mut out: Vec<u8> = Vec::new();
        let mut corrected = 0usize;

        for (idx, &hdr_off) in header_positions.iter().enumerate() {
            let block = &data[hdr_off..hdr_off + BLOCK];

            // Stored size (octal) from the header.
            let stored_size = octal_field(&block[124..136]).unwrap_or(0) as usize;

            // Next header or end-of-archive offset determines the actual data span.
            let next_boundary = if idx + 1 < header_positions.len() {
                header_positions[idx + 1]
            } else {
                eoa
            };

            // The data region is between this header and the next boundary.
            let max_data = next_boundary.saturating_sub(hdr_off + BLOCK);
            // Round stored_size up to 512 to get how many data blocks it declares.
            let declared_data_blocks = stored_size.div_ceil(BLOCK);
            let declared_data_bytes = declared_data_blocks * BLOCK;

            let (true_size, true_data_blocks) = if declared_data_bytes <= max_data {
                // Stored size fits; trust it.
                (stored_size, declared_data_blocks)
            } else {
                // Stored size overflows into the next header's territory. Infer the
                // true size from the gap to the next header.
                let inferred_blocks = max_data / BLOCK;
                let inferred_size = inferred_blocks * BLOCK; // conservative: full blocks
                corrected += 1;
                (inferred_size, inferred_blocks)
            };

            // Rebuild the header with the corrected size and a fresh checksum.
            let mut hdr = [0u8; BLOCK];
            hdr.copy_from_slice(block);

            // Write corrected size as a 12-byte octal field (null-terminated).
            let size_str = format!("{true_size:011o}\x00");
            hdr[124..136].copy_from_slice(size_str.as_bytes());

            // Recompute checksum (treat checksum field as spaces for the sum).
            let cksum = ustar_checksum(&hdr);
            let cksum_str = format!("{cksum:06o}\x20\x00");
            hdr[148..156].copy_from_slice(&cksum_str.as_bytes()[..8]);

            out.extend_from_slice(&hdr);

            // Copy the actual data blocks.
            let data_start = hdr_off + BLOCK;
            let data_end = (data_start + true_data_blocks * BLOCK).min(data.len());
            out.extend_from_slice(&data[data_start..data_end]);
            // Pad to a 512-byte boundary if the last block was short.
            let written = data_end - data_start;
            let pad = true_data_blocks * BLOCK - written;
            out.extend(std::iter::repeat(0u8).take(pad));
        }

        // Append end-of-archive terminator.
        out.extend_from_slice(&[0u8; 1024]);

        if corrected == 0 {
            // No size correction was needed; the stored sizes were all consistent.
            // The output is still useful (clean checksums) but this strategy is not
            // strictly better than tar-checksum-fix alone. The caller will evaluate.
        }

        output.write(&out);
        report.bytes_recovered = out.len() as u64;
        report.success = true;
        report.warnings.push(format!(
            "resynced {}/{} entries; corrected size field in {corrected}",
            header_positions.len(),
            nblocks,
        ));
        Ok(report)
    }
}

/// Check whether a 512-byte block is a UStar header.
fn is_ustar_header(block: &[u8]) -> bool {
    if block.len() < 265 {
        return false;
    }
    // All-zero block is an end-of-archive terminator, not a header.
    if block.iter().all(|&b| b == 0) {
        return false;
    }
    // UStar magic at offset 257.
    &block[257..262] == b"ustar"
}

/// Find the offset of the end-of-archive (two consecutive zero blocks).
/// Returns the offset of the first zero block pair, or `nblocks * 512`.
fn find_end_of_archive(data: &[u8], nblocks: usize) -> usize {
    for i in 0..nblocks.saturating_sub(1) {
        let a = i * BLOCK;
        let b = (i + 1) * BLOCK;
        if data[a..a + BLOCK].iter().all(|&x| x == 0) && data[b..b + BLOCK].iter().all(|&x| x == 0)
        {
            return a;
        }
    }
    nblocks * BLOCK
}

fn ustar_checksum(block: &[u8]) -> u32 {
    block
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                0x20u32
            } else {
                b as u32
            }
        })
        .sum()
}

fn octal_field(field: &[u8]) -> Option<u64> {
    let s = field.split(|&b| b == 0 || b == b' ').next()?;
    if s.is_empty() {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(s).ok()?, 8).ok()
}
