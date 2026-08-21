//! Module 3 — Integrity Verification.
//!
//! Produces an [`IntegrityResult`]: a global digest, optional per-block
//! digests, and a comparison against an external manifest when one is found.
//! This layer reports *match / mismatch* only — it never interprets what a
//! mismatch means (that is the corruption layer's job) and never repairs.

pub mod crc32;
pub mod hasher;
pub mod manifest;

use std::path::Path;

pub use crc32::{crc32, Crc32};
pub use hasher::{hash_source, to_hex, HashOutcome};
pub use manifest::{find_sidecar, Manifest};

use crate::error::EngineError;
use crate::model::{HashType, IntegrityResult};
use crate::reader::DataSource;

/// Default cap on `BlockVerification` entries (performance rule).
pub const MAX_BLOCKS: usize = 500_000;

/// Run the integrity scan against `source`.
///
/// `manifest_name` is the key used to look up the expected hash in the
/// manifest (typically the target's file name). When `None`, no manifest is
/// consulted.
pub fn run(
    source: &DataSource,
    hash_type: HashType,
    block_size_bytes: Option<u64>,
) -> Result<IntegrityResult, EngineError> {
    let outcome = hash_source(source, hash_type, block_size_bytes, MAX_BLOCKS)?;
    Ok(IntegrityResult {
        hash_type,
        expected_hash: None,
        actual_hash: outcome.actual_hash,
        matches: false,
        manifest_present: false,
        verified_blocks: outcome.blocks,
        signature_verification: None,
    })
}

/// Run the integrity scan and, if a sidecar manifest exists next to `target`,
/// compare against it. `lookup_name` is the entry name inside the manifest.
pub fn run_with_manifest(
    source: &DataSource,
    target: &Path,
    lookup_name: &str,
    hash_type: HashType,
    block_size_bytes: Option<u64>,
) -> Result<IntegrityResult, EngineError> {
    let mut result = run(source, hash_type, block_size_bytes)?;

    if let Some(manifest_path) = find_sidecar(target, hash_type) {
        let manifest = Manifest::load(&manifest_path)?;
        result.manifest_present = true;
        if let Some(expected) = manifest.lookup(lookup_name) {
            let expected = expected.to_ascii_lowercase();
            result.matches = expected == result.actual_hash;
            result.expected_hash = Some(expected);
        }
    }

    Ok(result)
}
