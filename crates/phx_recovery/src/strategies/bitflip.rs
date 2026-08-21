//! `BitFlipCorrection` — repair flipped bits using a reference.
//!
//! Honest V1 scope: without a per-block reference manifest or ECC, flipped bits
//! cannot be located and corrected from the damaged copy alone. This strategy
//! stages the source verbatim and defers to post-recovery verification; when a
//! whole-file manifest is available the engine can confirm whether the data is
//! in fact intact. It never fabricates "corrected" bytes.

use phx_analyze_engine::model::{AnalysisResult, Corruption, CorruptionCategory};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

/// Correct flipped bits (requires a reference; otherwise a verified pass-through).
pub struct BitFlipCorrection;

impl RecoveryStrategy for BitFlipCorrection {
    fn name(&self) -> &str {
        "bitflip"
    }

    fn technique(&self) -> &'static str {
        "ReferenceVerify"
    }

    fn risk(&self) -> RepairRisk {
        // Without per-block ECC the flip cannot be located; the strategy stages
        // the source verbatim and lets verification confirm or deny — it never
        // fabricates "corrected" bytes.
        RepairRisk::Inferred
    }

    fn handles(&self, c: &Corruption) -> bool {
        c.category == CorruptionCategory::BitFlip
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "verify the flipped region against the manifest (no ECC ⇒ confirm, not correct)".to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.integrity_result.manifest_present
            && result
                .corruptions
                .iter()
                .any(|c| c.category == CorruptionCategory::BitFlip)
    }

    fn priority(&self) -> u8 {
        90
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let bytes = read_all(source)?;
        output.write(&bytes);

        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());
        report.bytes_recovered = bytes.len() as u64;
        report.warnings.push(
            "bitflip correction requires a per-block reference or ECC; \
             staged source verbatim for verification"
                .to_string(),
        );
        // Success is decided by the engine's post-recovery verification.
        report.success = false;
        Ok(report)
    }
}
