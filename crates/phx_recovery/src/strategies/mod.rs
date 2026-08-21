//! Recovery strategies and the [`RecoveryStrategy`] trait.
//!
//! Selection (in [`crate::engine`]): every strategy whose `can_apply` returns
//! `true` is sorted by `priority()` (highest first) and applied in order until
//! post-recovery verification passes or all are exhausted.

pub mod bitflip;
pub mod forensic_carve;
pub mod gz_member_salvage;
pub mod gz_restore;
pub mod iso_sector;
pub mod partial_extract;
pub mod sevenz_restore;
pub mod tar_continuation_salvage;
pub mod tar_reorder;
pub mod tar_repair;
pub mod tar_size_resync;
pub mod zip_crc_fix;
pub mod zip_rebuild;

use phx_analyze_engine::model::{AnalysisResult, Corruption};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::{RepairPlan, RepairRisk};

pub use bitflip::BitFlipCorrection;
pub use forensic_carve::ForensicCarving;
pub use gz_member_salvage::GzMemberSalvage;
pub use gz_restore::{GzMagicRestore, GzPartialInflate, GzTrailerRecompute};
pub use iso_sector::IsoSectorReconstruction;
pub use partial_extract::PartialExtraction;
pub use sevenz_restore::SevenZSignatureRestore;
pub use tar_continuation_salvage::TarContinuationSalvage;
pub use tar_reorder::TarBlockReorder;
pub use tar_repair::{TarChecksumFix, TarTerminatorAppend};
pub use tar_size_resync::TarSizeBoundaryResync;
pub use zip_crc_fix::ZipCrcFix;
pub use zip_rebuild::ZipCentralDirectoryRebuild;

/// A single recovery technique.
pub trait RecoveryStrategy {
    /// Stable strategy identifier (matches `--strategy <name>`).
    fn name(&self) -> &str;

    /// Catalog technique name (Step 6.2), e.g. `"CentralDirRebuild"`.
    fn technique(&self) -> &'static str;

    /// Trust level of this technique's output (Step 6.1 risk taxonomy).
    fn risk(&self) -> RepairRisk;

    /// Whether this strategy addresses a *specific* corruption (rule-keyed).
    /// Drives [`plan`](RecoveryStrategy::plan); defaults to "never", so a
    /// strategy that only does whole-stream salvage need not implement it.
    fn handles(&self, _corruption: &Corruption) -> bool {
        false
    }

    /// Whether this strategy is relevant to the given analysis.
    fn can_apply(&self, result: &AnalysisResult) -> bool;

    /// Selection priority; `0` is lowest. Higher runs first.
    fn priority(&self) -> u8;

    /// Describe — read-only — what this strategy *would* repair for the given
    /// analysis. The default emits one [`RepairPlan`] per corruption the
    /// strategy [`handles`](RecoveryStrategy::handles).
    fn plan(&self, result: &AnalysisResult) -> Vec<RepairPlan> {
        result
            .corruptions
            .iter()
            .filter(|c| self.handles(c))
            .map(|c| {
                RepairPlan::new(
                    c.chain.primary.rule_id.clone(),
                    self.technique(),
                    c.byte_range,
                    self.predicted_outcome(c),
                    self.risk(),
                )
            })
            .collect()
    }

    /// Per-corruption predicted-outcome text for the plan. Defaults to a
    /// technique-and-rule description; strategies may override for specificity.
    fn predicted_outcome(&self, corruption: &Corruption) -> String {
        format!(
            "apply {} to {}",
            self.technique(),
            corruption.chain.primary.rule_id
        )
    }

    /// Apply the strategy, writing reconstructed data into `output`. Reads from
    /// `source` only — never modifies it.
    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError>;
}

/// All built-in strategies, unsorted.
pub fn all_strategies() -> Vec<Box<dyn RecoveryStrategy>> {
    vec![
        Box::new(BitFlipCorrection),
        Box::new(ZipCentralDirectoryRebuild),
        Box::new(ZipCrcFix),
        Box::new(TarChecksumFix),
        Box::new(TarTerminatorAppend),
        Box::new(TarSizeBoundaryResync),
        Box::new(TarBlockReorder),
        Box::new(GzMagicRestore),
        Box::new(GzTrailerRecompute),
        Box::new(GzMemberSalvage),
        Box::new(GzPartialInflate),
        Box::new(SevenZSignatureRestore),
        Box::new(TarContinuationSalvage),
        Box::new(IsoSectorReconstruction),
        Box::new(PartialExtraction),
        Box::new(ForensicCarving),
    ]
}

/// Look up a strategy by its `--strategy` name.
pub fn strategy_by_name(name: &str) -> Option<Box<dyn RecoveryStrategy>> {
    all_strategies().into_iter().find(|s| s.name() == name)
}

/// Read the entire source into memory. Shared by strategies that need random
/// access to the raw bytes.
pub(crate) fn read_all(source: &DataSource) -> Result<Vec<u8>, RecoveryError> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(source.len() as usize);
    source
        .stream()
        .map_err(|e| RecoveryError::io(source.path(), e))?
        .read_to_end(&mut buf)
        .map_err(|e| RecoveryError::io(source.path(), e))?;
    Ok(buf)
}
