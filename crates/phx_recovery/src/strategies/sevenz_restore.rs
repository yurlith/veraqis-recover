//! 7-Zip structural repair strategies (Phase 6 catalog).
//!
//! `SevenZSignatureRestore` — restore a corrupted 7z signature
//! (`37 7A BC AF 27 1C`), **gated by the Start-Header CRC**. The repair fires
//! only when [`crate::sevenz::repair_signature`] confirms the structure is
//! provably intact (the bytes written are the invariant spec constant). If the
//! CRC does not validate, it **abstains** — never writing onto unverified
//! structure. `false_recovered_bytes = 0`, cf. `GzMagicRestore`.

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Corruption};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

/// Restore the 7z signature when corrupted, behind the Start-Header CRC.
pub struct SevenZSignatureRestore;

impl RecoveryStrategy for SevenZSignatureRestore {
    fn name(&self) -> &str {
        "sevenz-signature-restore"
    }

    fn technique(&self) -> &'static str {
        "SevenZSignatureRestore"
    }

    fn risk(&self) -> RepairRisk {
        RepairRisk::Safe
    }

    fn handles(&self, c: &Corruption) -> bool {
        c.chain.primary.rule_id == "7Z_MAGIC_001"
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "restore the 7z signature 37 7A BC AF 27 1C (gated by the Start-Header CRC)".to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::SevenZ)
            && result
                .corruptions
                .iter()
                .any(|c| c.chain.primary.rule_id == "7Z_MAGIC_001")
    }

    fn priority(&self) -> u8 {
        85
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let data = read_all(source)?;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        match crate::sevenz::repair_signature(&data) {
            Some(rep) => {
                let total = rep.data.len() as u64;
                output.write(&rep.data);
                report.bytes_recovered = total;
                report.success = true;
                report.warnings.push(format!(
                    "restored 7z signature ({} byte(s) at offset 0); verified by {}",
                    rep.bytes_written, rep.verified_by
                ));
            }
            None => {
                // Start-Header CRC does not validate (or the signature is fine):
                // abstain — never write the constant onto unverified structure.
                report.success = false;
                report.warnings.push(
                    "7z Start-Header CRC does not validate — abstaining (structure not \
                     provably intact)"
                        .to_string(),
                );
            }
        }
        Ok(report)
    }
}
