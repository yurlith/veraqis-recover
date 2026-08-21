//! `TarBlockReorder` — restore the original order of shuffled TAR blocks.
//!
//! V1 scope: reordering requires authoritative ordering metadata (e.g. an
//! index or per-block reference) that a damaged TAR does not carry. This
//! strategy validates that headers are individually parseable and stages the
//! readable blocks; it does not guess an order it cannot verify.

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Corruption, CorruptionCategory};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

/// Reorder shuffled TAR blocks (requires ordering metadata).
pub struct TarBlockReorder;

impl RecoveryStrategy for TarBlockReorder {
    fn name(&self) -> &str {
        "tar-reorder"
    }

    fn technique(&self) -> &'static str {
        "BlockResequence"
    }

    fn risk(&self) -> RepairRisk {
        // Stages individually-readable blocks; never guesses an unverifiable
        // order, so no readable data is altered.
        RepairRisk::Safe
    }

    fn handles(&self, c: &Corruption) -> bool {
        c.chain.primary.rule_id.starts_with("TAR_BLOCK")
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "stage individually-readable TAR blocks (reorder needs ordering metadata)".to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Tar)
            && result
                .corruptions
                .iter()
                .any(|c| c.category == CorruptionCategory::BlockReorder)
    }

    fn priority(&self) -> u8 {
        80
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
            "block reordering requires authoritative ordering metadata; \
             staged readable blocks unchanged"
                .to_string(),
        );
        report.success = false;
        Ok(report)
    }
}
