//! `ForensicCarving` — scan raw bytes for known file signatures and carve out
//! the regions that look like recoverable files.
//!
//! Last-resort strategy for raw/unknown data with catastrophic damage. It
//! copies the carved regions verbatim; it does not attempt to repair them.

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Severity};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

/// A known magic signature used for carving.
struct Signature {
    label: &'static str,
    magic: &'static [u8],
}

const SIGNATURES: &[Signature] = &[
    Signature {
        label: "zip",
        magic: b"PK\x03\x04",
    },
    Signature {
        label: "png",
        magic: &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
    },
    Signature {
        label: "jpg",
        magic: &[0xFF, 0xD8, 0xFF],
    },
    Signature {
        label: "pdf",
        magic: b"%PDF-",
    },
    Signature {
        label: "gzip",
        magic: &[0x1F, 0x8B],
    },
    Signature {
        label: "elf",
        magic: &[0x7F, b'E', b'L', b'F'],
    },
];

/// Carve files from raw data by signature scanning.
pub struct ForensicCarving;

impl RecoveryStrategy for ForensicCarving {
    fn name(&self) -> &str {
        "forensic-carve"
    }

    fn technique(&self) -> &'static str {
        "ForensicCarve"
    }

    fn risk(&self) -> RepairRisk {
        // Carves regions by signature and copies them verbatim; surrounding
        // damaged bytes are dropped. A last-resort, lossy salvage.
        RepairRisk::Lossy
    }

    // `handles` keeps the default (false): carving is a whole-stream fallback,
    // not a per-rule repair, so it contributes no rule-keyed plan entries.

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        let raw_or_unknown = matches!(result.archive_format, Some(ArchiveFormat::Raw) | None);
        let catastrophic = result
            .corruptions
            .iter()
            .any(|c| c.severity == Severity::Catastrophic);
        raw_or_unknown && (catastrophic || result.corruptions.is_empty())
    }

    fn priority(&self) -> u8 {
        10
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let data = read_all(source)?;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        let hits = scan_signatures(&data);
        if hits.is_empty() {
            report
                .warnings
                .push("no known file signatures found to carve".to_string());
            report.success = false;
            return Ok(report);
        }

        // Carve each region from its signature to the next signature (or EOF).
        let mut carved = 0u64;
        for (i, (offset, label)) in hits.iter().enumerate() {
            let end = hits.get(i + 1).map(|(o, _)| *o).unwrap_or(data.len());
            output.write(&data[*offset..end]);
            carved += (end - offset) as u64;
            report
                .files_recovered
                .push(format!("carved-{i:04}.{label}").into());
        }

        report.bytes_recovered = carved;
        report.bytes_lost = source.len().saturating_sub(carved);
        report.success = carved > 0;
        report
            .warnings
            .push(format!("carved {} region(s) by signature", hits.len()));
        Ok(report)
    }
}

/// Find `(offset, label)` of every known signature in `data`.
fn scan_signatures(data: &[u8]) -> Vec<(usize, &'static str)> {
    let mut hits = Vec::new();
    for i in 0..data.len() {
        for sig in SIGNATURES {
            if data[i..].starts_with(sig.magic) {
                hits.push((i, sig.label));
            }
        }
    }
    hits.sort_by_key(|(o, _)| *o);
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carves_two_embedded_signatures() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(b"PK\x03\x04zipbody");
        data.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        data.extend_from_slice(b"pngbody");
        let src = DataSource::from_bytes("raw", data);
        let mut sink = DataSink::new();
        let report = ForensicCarving.apply(&src, &mut sink).unwrap();
        assert_eq!(report.files_recovered.len(), 2);
        assert!(report.success);
    }
}
