//! `PartialExtraction` — copy whatever is currently readable into the output.
//!
//! Applicable to any archive with any damage. It never fabricates data: it
//! stages every byte it can read, so the output is at worst a faithful copy of
//! the readable portion of the source.

use phx_analyze_engine::model::{AnalysisResult, Corruption, CorruptionCategory};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

/// Extract all readable bytes (the universal fallback strategy).
pub struct PartialExtraction;

impl RecoveryStrategy for PartialExtraction {
    fn name(&self) -> &str {
        "partial-extract"
    }

    fn technique(&self) -> &'static str {
        "TruncationSalvage"
    }

    fn risk(&self) -> RepairRisk {
        // Copies the readable portion verbatim; the unreadable tail is lost.
        RepairRisk::Lossy
    }

    fn handles(&self, c: &Corruption) -> bool {
        c.category == CorruptionCategory::Truncation
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "salvage every readable byte up to the truncation; lost tail is reported".to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        // Truncation only — matching `handles()`. A verbatim copy is salvage
        // exactly when part of the source is gone and the readable prefix is
        // worth carrying out. For in-place corruption the copy reproduces the
        // damaged bytes one-for-one while claiming them recovered (`lost=0`),
        // which launders bytes the format's own verifier contradicts
        // (EXP-PCRB-PUBLIC run 1: a CRC-mismatching GZIP payload re-emitted as
        // a "recovery"). Emission on such damage belongs to strategies that
        // can verify what they emit — or to Tier-0 abstain.
        result
            .corruptions
            .iter()
            .any(|c| c.category == CorruptionCategory::Truncation)
    }

    fn priority(&self) -> u8 {
        30
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let bytes = read_all(source)?;
        let total = source.len();
        let recovered = bytes.len() as u64;
        output.write(&bytes);

        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());
        report.bytes_recovered = recovered;
        report.bytes_lost = total.saturating_sub(recovered);
        report.success = recovered > 0;
        if report.bytes_lost > 0 {
            report.warnings.push(format!(
                "{} of {} bytes were unreadable and omitted",
                report.bytes_lost, total
            ));
        }
        Ok(report)
    }
}
