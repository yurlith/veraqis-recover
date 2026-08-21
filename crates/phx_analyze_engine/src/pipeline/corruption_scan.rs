//! Stage 4 — Corruption scan. Thin wrapper over [`crate::corruption::scan`].

use crate::corruption::{self, ScanResult};
use crate::model::{AnalysisConfig, ArchiveFormat, IntegrityResult};
use crate::reader::DataSource;

/// Detect and classify corruptions for `source`.
pub fn run(
    source: &DataSource,
    format: ArchiveFormat,
    integrity: &IntegrityResult,
    config: &AnalysisConfig,
) -> ScanResult {
    corruption::scan(
        source,
        format,
        integrity,
        config.verify_embedded_checksums,
        config.max_corruptions_reported,
    )
}
