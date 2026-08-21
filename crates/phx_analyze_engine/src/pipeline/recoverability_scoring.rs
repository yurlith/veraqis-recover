//! Stage 6 — Recoverability scoring. Wraps [`crate::recoverability::estimate`]
//! and assembles its inputs from the rest of the pipeline.

use crate::model::{ArchiveFormat, Corruption, IntegrityResult, RecoverabilityScore};
use crate::reader::DataSource;
use crate::recoverability::{self, Inputs};

/// Estimate recoverability for the container.
#[allow(clippy::too_many_arguments)]
pub fn run(
    source: &DataSource,
    corruptions: &[Corruption],
    format: ArchiveFormat,
    integrity: &IntegrityResult,
    embedded_checksums_present: bool,
    scan_capped: bool,
    io_errors: bool,
    format_detection_failed: bool,
) -> RecoverabilityScore {
    let inputs = Inputs {
        corruptions,
        format: Some(format),
        manifest_present: integrity.manifest_present,
        embedded_checksums_present,
        total_size: source.len(),
        scan_capped,
        io_errors,
        format_detection_failed,
    };
    recoverability::estimate(&inputs)
}
