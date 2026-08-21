//! GZIP structural repair strategies (Phase 6, Step 6.2).
//!
//! Three techniques:
//! - `GzMagicRestore`     — overwrite corrupted magic bytes with `1F 8B`.
//! - `GzTrailerRecompute` — recompute and rewrite CRC32 + ISIZE trailer.
//! - `GzPartialInflate`   — decompress as far as possible, wrap result in
//!                          a new GZIP stream (partial content recovery).

use std::io::{Read, Write};

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Corruption, CorruptionCategory};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

// ── GzMagicRestore ────────────────────────────────────────────────────────────

/// Restore the two-byte GZIP magic `1F 8B` when corrupted.
///
/// The magic bytes are a known constant — this repair is deterministic and
/// carries no risk of data loss.
pub struct GzMagicRestore;

impl RecoveryStrategy for GzMagicRestore {
    fn name(&self) -> &str {
        "gz-magic-restore"
    }

    fn technique(&self) -> &'static str {
        "GzMagicRestore"
    }

    fn risk(&self) -> RepairRisk {
        RepairRisk::Safe
    }

    fn handles(&self, c: &Corruption) -> bool {
        c.chain.primary.rule_id == "GZ_MAGIC_001"
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "overwrite bytes 0–1 with the GZIP magic 1F 8B".to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Gzip)
            && result
                .corruptions
                .iter()
                .any(|c| c.chain.primary.rule_id == "GZ_MAGIC_001")
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

        if data.len() < 2 {
            report.success = false;
            report
                .warnings
                .push("file too short to contain GZIP magic".to_string());
            return Ok(report);
        }

        data[0] = 0x1F;
        data[1] = 0x8B;
        let total = data.len() as u64;
        output.write(&data);

        report.bytes_recovered = total;
        report.success = true;
        report
            .warnings
            .push("restored GZIP magic bytes 1F 8B at offset 0".to_string());
        Ok(report)
    }
}

// ── GzTrailerRecompute ────────────────────────────────────────────────────────

/// Recompute the GZIP trailer (CRC32 + ISIZE) from the actual decompressed
/// content when the stored values are wrong.
pub struct GzTrailerRecompute;

impl RecoveryStrategy for GzTrailerRecompute {
    fn name(&self) -> &str {
        "gz-trailer-recompute"
    }

    fn technique(&self) -> &'static str {
        "GzTrailerRecompute"
    }

    // A GZIP member carries ONE verifier (CRC32+ISIZE) over the whole payload.
    // A mismatch cannot be localized: the trailer fields may be damaged (this
    // strategy's legitimate case) or the payload itself may be corrupt — and a
    // recomputed trailer is a checksum fitted to the data, contributing zero
    // evidence bits (Evidence model, tautology rule). EXP-PCRB-PUBLIC run 1
    // measured the consequence: on payload-corrupt streams the rewrite blessed
    // 205,713 wrong bytes with a now-valid CRC. Inferred ⇒ the engine keeps
    // this output only when it byte-verifies against an external reference.
    fn risk(&self) -> RepairRisk {
        RepairRisk::Inferred
    }

    fn handles(&self, c: &Corruption) -> bool {
        matches!(
            c.chain.primary.rule_id.as_str(),
            "GZ_ICRC_001" | "GZ_ISIZE_001"
        )
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "decompress the stream, recompute CRC32 and ISIZE, rewrite the 8-byte trailer".to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Gzip)
            && result.corruptions.iter().any(|c| {
                matches!(
                    c.chain.primary.rule_id.as_str(),
                    "GZ_ICRC_001" | "GZ_ISIZE_001"
                )
            })
    }

    fn priority(&self) -> u8 {
        82
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let data = read_all(source)?;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        if data.len() < 18 {
            report.success = false;
            report.warnings.push("file too short for GZIP".to_string());
            return Ok(report);
        }

        // Use DeflateDecoder directly on the DEFLATE body (no trailer check).
        // MultiGzDecoder would fail at the trailer — exactly what this strategy
        // is supposed to fix.
        let body_start = gz_body_start(&data);
        let trailer_start = data.len().saturating_sub(8);
        if body_start >= trailer_start {
            report.success = false;
            report
                .warnings
                .push("GZIP body is empty or missing".to_string());
            return Ok(report);
        }

        let mut decoder = flate2::read::DeflateDecoder::new(&data[body_start..trailer_start]);
        let mut decompressed = Vec::new();
        if let Err(e) = decoder.read_to_end(&mut decompressed) {
            // The stream does not decompress to end-of-stream, so the file is
            // truncated or corrupt mid-body — the last 8 bytes are then part of
            // the compressed data, NOT a trailer. Rewriting them would destroy
            // payload bytes and stamp a fitted CRC onto an incomplete stream
            // (measured in EXP-PCRB-PUBLIC run 1: 180 false bytes + `lost=0B`
            // claimed on 40%-truncated files). Refuse; truncation belongs to
            // gz-partial-inflate / gz-member-salvage.
            report.success = false;
            report.warnings.push(format!(
                "stream does not reach end-of-stream ({} B decoded): {e}; \
                 refusing to rewrite the trailer of an incomplete stream",
                decompressed.len()
            ));
            return Ok(report);
        }

        let crc32 = {
            let mut h = flate2::Crc::new();
            h.update(&decompressed);
            h.sum()
        };
        let isize_val = decompressed.len() as u32;

        // Write header + DEFLATE body (unchanged) + correct trailer.
        output.write(&data[..trailer_start]);
        output.write(&crc32.to_le_bytes());
        output.write(&isize_val.to_le_bytes());

        report.bytes_recovered = data.len() as u64;
        report.success = true;
        report.warnings.push(format!(
            "recomputed GZIP trailer: CRC32=0x{crc32:08X} ISIZE={isize_val}"
        ));
        Ok(report)
    }
}

// ── GzPartialInflate ──────────────────────────────────────────────────────────

/// Salvage readable bytes from a truncated or internally-corrupted GZIP stream.
///
/// Decompresses as much as possible and wraps the recovered content in a fresh
/// GZIP envelope. The salvaged file is valid GZIP but shorter than the original
/// — member data past the corruption point is irrecoverably lost.
pub struct GzPartialInflate;

impl RecoveryStrategy for GzPartialInflate {
    fn name(&self) -> &str {
        "gz-partial-inflate"
    }

    fn technique(&self) -> &'static str {
        "GzPartialInflate"
    }

    fn risk(&self) -> RepairRisk {
        RepairRisk::Lossy
    }

    fn handles(&self, c: &Corruption) -> bool {
        matches!(
            c.chain.primary.rule_id.as_str(),
            "GZ_TRUNC_001" | "GZ_TRUNC_002"
        )
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "decompress readable bytes and wrap in a fresh GZIP stream; tail past corruption is lost"
            .to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Gzip)
            && result.corruptions.iter().any(|c| {
                c.category == CorruptionCategory::Truncation
                    || matches!(
                        c.chain.primary.rule_id.as_str(),
                        "GZ_TRUNC_001" | "GZ_TRUNC_002"
                    )
            })
    }

    fn priority(&self) -> u8 {
        40
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let data = read_all(source)?;
        let total = data.len() as u64;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        // Try decompression, collecting however many bytes decompress before error.
        let mut decoder = flate2::read::DeflateDecoder::new(deflate_body(&data));
        let mut decompressed = Vec::new();
        let decomp_result = decoder.read_to_end(&mut decompressed);
        let recovered_content = decompressed.len();

        if recovered_content == 0 {
            report.success = false;
            report
                .warnings
                .push("no bytes could be decompressed; stream may be fully corrupted".to_string());
            return Ok(report);
        }

        // Build a fresh GZIP wrapper around the partial content.
        let mut gz_out = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz_out, flate2::Compression::default());
            encoder
                .write_all(&decompressed)
                .map_err(|e| RecoveryError::Strategy {
                    strategy: self.name().to_string(),
                    reason: e.to_string(),
                })?;
            encoder.finish().map_err(|e| RecoveryError::Strategy {
                strategy: self.name().to_string(),
                reason: e.to_string(),
            })?;
        }

        output.write(&gz_out);
        report.bytes_recovered = recovered_content as u64;
        report.bytes_lost = total.saturating_sub(recovered_content as u64);
        report.success = true;

        let tail_note = if decomp_result.is_err() {
            format!("; {recovered_content} bytes recovered, tail lost at corruption boundary")
        } else {
            format!("; {recovered_content} bytes recovered")
        };
        report.warnings.push(format!("partial inflate{tail_note}"));
        Ok(report)
    }
}

/// Return the byte offset where the DEFLATE body starts (past the GZIP fixed
/// and optional header sections).
fn gz_body_start(data: &[u8]) -> usize {
    if data.len() < 10 {
        return data.len();
    }
    let flags = data[3];
    let mut pos = 10usize;

    if flags & 0x04 != 0 {
        if pos + 2 > data.len() {
            return data.len();
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
    }
    if flags & 0x08 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flags & 0x10 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flags & 0x02 != 0 {
        pos += 2;
    }
    pos.min(data.len())
}

/// Extract the raw DEFLATE body from a GZIP stream (skips the 10-byte fixed
/// header and optional variable-length sections; does not strip the 8-byte
/// trailer). `flate2::DeflateDecoder` handles the DEFLATE body directly.
fn deflate_body(data: &[u8]) -> &[u8] {
    let start = gz_body_start(data);
    if start >= data.len() {
        return &[];
    }
    // Strip the 8-byte trailer if present (DeflateDecoder doesn't need it).
    let body_end = if data.len() > start + 8 {
        data.len() - 8
    } else {
        data.len()
    };
    &data[start..body_end]
}
