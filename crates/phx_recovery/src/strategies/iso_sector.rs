//! `IsoSectorReconstruction` — rebuild missing ISO sectors from ECC.
//!
//! V1 scope: plain ISO 9660 images carry no error-correcting code; ECC
//! reconstruction applies only to formats that embed it (e.g. raw 2352-byte
//! CD sectors). When no ECC is present this strategy stages the readable
//! sectors and reports that reconstruction was not possible.

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Corruption, CorruptionCategory};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

/// Reconstruct ISO sectors from ECC (when ECC is present).
pub struct IsoSectorReconstruction;

impl RecoveryStrategy for IsoSectorReconstruction {
    fn name(&self) -> &str {
        "iso-sector"
    }

    fn technique(&self) -> &'static str {
        "SectorExtract"
    }

    fn risk(&self) -> RepairRisk {
        // Plain ISO carries no ECC; readable sectors are staged and missing
        // ones dropped.
        RepairRisk::Lossy
    }

    fn handles(&self, c: &Corruption) -> bool {
        c.chain.primary.rule_id.starts_with("ISO_SECTOR")
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "extract readable sectors; missing sectors need ECC to reconstruct".to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Iso9660)
            && result
                .corruptions
                .iter()
                .any(|c| c.category == CorruptionCategory::MissingData)
    }

    fn priority(&self) -> u8 {
        70
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
            "no ECC sectors present; staged readable sectors without reconstruction".to_string(),
        );
        report.success = false;
        Ok(report)
    }
}
