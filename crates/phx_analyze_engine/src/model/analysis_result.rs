//! Top-level analysis output types (Module 1).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::corruption::Corruption;
use super::health::HealthScore;
use super::integrity::IntegrityResult;
use super::recoverability::RecoverabilityScore;

/// Detected container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveFormat {
    Raw,
    Zip,
    Tar,
    Iso9660,
    Gzip,
    Sqlite,
    SevenZ,
    Rar,
    Pdf,
    Bzip2,
    Xz,
    Zstd,
    Lz4,
}

impl ArchiveFormat {
    /// Stable identifier for serialization / display.
    pub fn as_str(self) -> &'static str {
        match self {
            ArchiveFormat::Raw => "raw",
            ArchiveFormat::Zip => "zip",
            ArchiveFormat::Tar => "tar",
            ArchiveFormat::Iso9660 => "iso9660",
            ArchiveFormat::Gzip => "gzip",
            ArchiveFormat::Sqlite => "sqlite",
            ArchiveFormat::SevenZ => "7z",
            ArchiveFormat::Rar => "rar",
            ArchiveFormat::Pdf => "pdf",
            ArchiveFormat::Bzip2 => "bzip2",
            ArchiveFormat::Xz => "xz",
            ArchiveFormat::Zstd => "zstd",
            ArchiveFormat::Lz4 => "lz4",
        }
    }

    /// Whether the format is a multi-member archive (drives per-file analysis).
    pub fn is_archive(self) -> bool {
        !matches!(self, ArchiveFormat::Raw)
    }
}

/// Per-contained-file analysis result (archives only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileResult {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub integrity: Option<IntegrityResult>,
    pub corruptions: Vec<Corruption>,
    pub health_score: HealthScore,
    pub recoverability_score: RecoverabilityScore,
}

/// Complete result of analyzing one target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub target_path: PathBuf,
    pub total_size_bytes: u64,
    pub archive_format: Option<ArchiveFormat>,
    pub integrity_result: IntegrityResult,
    pub corruptions: Vec<Corruption>,
    pub health_score: HealthScore,
    pub recoverability_score: RecoverabilityScore,
    pub per_file_results: Vec<FileResult>,
    pub analysis_duration_ms: u64,
    pub warnings: Vec<String>,
}

impl AnalysisResult {
    /// `true` if no corruptions were recorded at the container level.
    pub fn is_clean(&self) -> bool {
        self.corruptions.is_empty()
    }

    /// Highest severity observed at the container level, if any.
    pub fn worst_severity(&self) -> Option<super::corruption::Severity> {
        self.corruptions.iter().map(|c| c.severity).max()
    }

    /// Classify the evidence backing this analysis into strength bands. This is
    /// **domain logic** (it interprets the evidence model), so it lives in the
    /// engine — callers (`phx_api`, the UI) only display the result.
    ///
    /// This is **analysis-time evidence strength**, a coarse detection-side
    /// signal. It is **not** PCC / `evidence_bits`-based proof-carrying recovery;
    /// it never claims a byte is recoverable. Per band:
    /// - **Strong** — a finding backed by an *independent* checksum/signature
    ///   verifier at high aggregate confidence (≥ 0.90): the detection-side
    ///   analogue of `evidence_bits ≥ 32`. Heuristic / low-confidence findings
    ///   never count as Strong; a checksum a solver was *fitted to* would
    ///   contribute nothing here (analysis evidence is independent of any repair,
    ///   so there is no `solved_against` to taint it — if such data is ever
    ///   threaded in, it must be excluded from Strong).
    /// - **Medium** — a valid finding below the strong bar (confidence ≥ 0.70).
    /// - **Weak** — a lower-confidence / heuristic finding.
    /// - **None** — a region with **no surviving verifier**: a catastrophic loss
    ///   in a provably-unrecoverable archive (the lost region cannot be verified
    ///   against anything), or a provably-unrecoverable archive with no specific
    ///   findings. Recoverability `None` *contributes* to this bucket but never
    ///   reclassifies a recoverable, non-catastrophic finding — real findings are
    ///   not hidden.
    pub fn evidence_breakdown(&self) -> EvidenceBreakdown {
        use super::corruption::Severity;
        use super::evidence::EvidenceType;
        use super::recoverability::RecoverabilityClass;

        let mut b = EvidenceBreakdown::default();
        let unrecoverable = self.recoverability_score.class() == RecoverabilityClass::None;

        for c in &self.corruptions {
            // A catastrophic loss in an unrecoverable archive has no verifier
            // surviving for its region → None (not an evidence band).
            if unrecoverable && c.severity == Severity::Catastrophic {
                b.none += 1;
                continue;
            }
            let verifier_backed = matches!(
                c.chain.primary.evidence_type,
                EvidenceType::ChecksumMismatch | EvidenceType::SignatureMismatch
            );
            let conf = c.chain.aggregate_confidence;
            if verifier_backed && conf >= 0.90 {
                b.strong += 1;
            } else if conf >= 0.70 {
                b.medium += 1;
            } else {
                b.weak += 1;
            }
        }

        // A provably-unrecoverable archive with no specific findings: nothing to
        // verify against at all.
        if unrecoverable && self.corruptions.is_empty() {
            b.none += 1;
        }
        b
    }
}

/// A breakdown of analysis evidence into strength bands (see
/// [`AnalysisResult::evidence_breakdown`]). Additive across archives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBreakdown {
    pub strong: u32,
    pub medium: u32,
    pub weak: u32,
    pub none: u32,
}

impl EvidenceBreakdown {
    /// Total evidence items across all bands.
    pub fn total(&self) -> u32 {
        self.strong + self.medium + self.weak + self.none
    }

    /// Fold another breakdown into this one (for fleet/history aggregation).
    pub fn merge(&mut self, other: &EvidenceBreakdown) {
        self.strong += other.strong;
        self.medium += other.medium;
        self.weak += other.weak;
        self.none += other.none;
    }
}

#[cfg(test)]
mod evidence_breakdown_tests {
    use super::super::corruption::{Corruption, CorruptionCategory, CorruptionLocation, Severity};
    use super::super::evidence::{ChainOfEvidence, Evidence, EvidenceType};
    use super::super::health::HealthScore;
    use super::super::integrity::{HashType, IntegrityResult};
    use super::super::recoverability::RecoverabilityScore;
    use super::*;

    fn corruption_sev(et: EvidenceType, conf: f64, sev: Severity) -> Corruption {
        let e = Evidence::new(0, None, Vec::new(), "f", "d", conf, "RULE_001", et);
        Corruption::from_chain(
            CorruptionLocation::stream(0, 0),
            CorruptionCategory::ChecksumMismatch,
            sev,
            ChainOfEvidence::single(e),
            None,
        )
    }

    fn corruption(et: EvidenceType, conf: f64) -> Corruption {
        corruption_sev(et, conf, Severity::Major)
    }

    fn result(corr: Vec<Corruption>, prob: f64) -> AnalysisResult {
        AnalysisResult {
            target_path: PathBuf::from("x"),
            total_size_bytes: 100,
            archive_format: None,
            integrity_result: IntegrityResult::without_manifest(HashType::Sha256, "h".into()),
            corruptions: corr,
            health_score: HealthScore::perfect(),
            recoverability_score: RecoverabilityScore::new(prob, 1.0, Vec::new()),
            per_file_results: Vec::new(),
            analysis_duration_ms: 1,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn bands_classify_by_verifier_and_confidence() {
        let r = result(
            vec![
                corruption(EvidenceType::ChecksumMismatch, 0.95), // strong
                corruption(EvidenceType::SignatureMismatch, 0.92), // strong
                corruption(EvidenceType::StructureMissing, 0.80), // medium (no verifier)
                corruption(EvidenceType::ChecksumMismatch, 0.60), // weak (low confidence)
            ],
            0.9, // High recoverability → no None bucket
        );
        let b = r.evidence_breakdown();
        assert_eq!((b.strong, b.medium, b.weak, b.none), (2, 1, 1, 0));
        assert_eq!(b.total(), 4);
    }

    #[test]
    fn none_bucket_counts_unrecoverable_with_no_findings() {
        let b = result(Vec::new(), 0.05).evidence_breakdown(); // class None, no findings
        assert_eq!(b.none, 1);
        assert_eq!(b.strong + b.medium + b.weak, 0);
    }

    #[test]
    fn unrecoverable_catastrophic_is_none_but_findings_not_hidden() {
        // An unrecoverable archive: the catastrophic loss has no verifier → None;
        // the non-catastrophic finding keeps its real evidence band (not hidden).
        let r = result(
            vec![
                corruption_sev(EvidenceType::ChecksumMismatch, 0.95, Severity::Catastrophic),
                corruption_sev(EvidenceType::StructureMissing, 0.80, Severity::Major),
            ],
            0.05, // class None
        );
        let b = r.evidence_breakdown();
        assert_eq!((b.strong, b.medium, b.weak, b.none), (0, 1, 0, 1));
    }

    #[test]
    fn add_folds_breakdowns() {
        let mut a = EvidenceBreakdown {
            strong: 1,
            medium: 2,
            weak: 0,
            none: 1,
        };
        a.merge(&EvidenceBreakdown {
            strong: 3,
            medium: 0,
            weak: 4,
            none: 0,
        });
        assert_eq!(
            a,
            EvidenceBreakdown {
                strong: 4,
                medium: 2,
                weak: 4,
                none: 1
            }
        );
    }
}
