//! Stage 7 — Report assembly. For archives, derive a [`FileResult`] per
//! contained member by attributing container-level corruptions to members and
//! scoring each member independently.
//!
//! V1 does not decompress members, so per-member integrity is left `None`;
//! per-member health and recoverability are derived from attributed damage.

use crate::model::{ArchiveFormat, Corruption, FileResult, RecoverabilityScore};
use crate::reader::{reader_for, DataSource};
use crate::{health, recoverability};

/// Build per-file results for an archive. Returns empty for `Raw`.
pub fn run(
    source: &DataSource,
    format: ArchiveFormat,
    container_corruptions: &[Corruption],
) -> Vec<FileResult> {
    if !format.is_archive() {
        return Vec::new();
    }

    let entries = match reader_for(format).entries(source) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    entries
        .into_iter()
        .map(|entry| {
            // Attribute container corruptions whose path matches this member.
            let corruptions: Vec<Corruption> = container_corruptions
                .iter()
                .filter(|c| {
                    c.location
                        .file_path
                        .as_deref()
                        .map(|p| p == entry.path)
                        .unwrap_or(false)
                })
                .cloned()
                .collect();

            let health_score = health::score(&corruptions);
            let recoverability_score = member_recoverability(&corruptions, &entry);

            FileResult {
                path: entry.path,
                size_bytes: entry.size,
                integrity: None,
                corruptions,
                health_score,
                recoverability_score,
            }
        })
        .collect()
}

fn member_recoverability(
    corruptions: &[Corruption],
    entry: &crate::reader::ArchiveEntry,
) -> RecoverabilityScore {
    let inputs = recoverability::Inputs {
        corruptions,
        format: None,
        manifest_present: false,
        embedded_checksums_present: entry.stored_crc32.is_some(),
        total_size: entry.size.max(1),
        scan_capped: false,
        io_errors: false,
        format_detection_failed: false,
    };
    recoverability::estimate(&inputs)
}
