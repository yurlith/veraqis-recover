//! Module 1 — Corruption scan.
//!
//! [`detector`] locates raw defects; [`classifier`] assigns category/severity
//! and merges adjacent same-kind damage. [`scan`] is the stage entry point.

pub mod classifier;
pub mod confidence;
pub mod detector;
pub mod reference;
pub mod rules;

pub use classifier::{classify, merge_adjacent, DefectKind, Detected};
pub use rules::{rule, ClassifierRule, RULES};

/// Classify reference-diff findings (damaged `corrupted` vs known-good `clean`)
/// into corruptions. `format` is the short label derived from the extension.
pub fn scan_reference(corrupted: &[u8], clean: &[u8], format: &str) -> Vec<Corruption> {
    reference::diff(format, corrupted, clean)
        .into_iter()
        .filter_map(classify)
        .collect()
}

use crate::model::{ArchiveFormat, Corruption, IntegrityResult};
use crate::reader::DataSource;

/// Outcome of the corruption scan.
pub struct ScanResult {
    pub corruptions: Vec<Corruption>,
    /// `true` if detection stopped at `max_corruptions`.
    pub capped: bool,
    /// Count of findings dropped for confidence below the emit threshold.
    pub low_confidence_dropped: usize,
}

/// Detect, classify, and merge corruptions for `source`.
pub fn scan(
    source: &DataSource,
    format: ArchiveFormat,
    integrity: &IntegrityResult,
    verify_embedded_checksums: bool,
    max_corruptions: usize,
) -> ScanResult {
    let (detected, capped) = detector::detect(
        source,
        format,
        integrity,
        verify_embedded_checksums,
        max_corruptions,
    );
    let total = detected.len();
    let classified: Vec<Corruption> = detected.into_iter().filter_map(classify).collect();
    let low_confidence_dropped = total - classified.len();
    let corruptions = merge_adjacent(classified);
    ScanResult {
        corruptions,
        capped,
        low_confidence_dropped,
    }
}
