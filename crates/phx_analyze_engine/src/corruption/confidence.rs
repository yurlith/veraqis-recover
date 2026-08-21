//! Deterministic confidence computation (Phase 2, Step 2.4).
//!
//! Confidence is never a free-form float in classifier code — it is computed
//! here from the [`EvidenceType`] and the relevant context. All values are
//! named constants with the rationale from the spec table.

use crate::model::EvidenceType;

/// Signature bytes either match or they don't.
pub const SIGNATURE: f64 = 1.0;
/// CRC/hash computed over the full data.
pub const CHECKSUM_FULL: f64 = 1.0;
/// CRC/hash computed at block granularity.
pub const CHECKSUM_BLOCK: f64 = 0.95;
/// Pointer strictly beyond EOF.
pub const OFFSET_BEYOND_EOF: f64 = 1.0;
/// Pointer beyond 90% of the file (suspicious but in-bounds).
pub const OFFSET_NEAR_EOF: f64 = 0.9;
/// base + length exceeds the file.
pub const LENGTH_OVERFLOW: f64 = 1.0;
/// Length below the structural minimum.
pub const LENGTH_UNDERFLOW: f64 = 0.95;
/// A required structure is entirely absent (could rarely be embedded).
pub const STRUCTURE_MISSING: f64 = 0.98;
/// Numeric field outside the spec range (could be a tool extension).
pub const VALUE_OUT_OF_RANGE: f64 = 0.95;
/// Block reordering requires a manifest/sequence heuristic.
pub const BLOCK_REORDER: f64 = 0.8;
/// Non-zero padding may be valid in some format versions.
pub const PADDING_VIOLATION: f64 = 0.7;
/// EOF before a structure completes is unambiguous.
pub const TRUNCATION_MARKER: f64 = 0.99;
/// Bitflip via block-hash mismatch: base, plus a bonus per extra block.
pub const BITFLIP_BASE: f64 = 0.85;
pub const BITFLIP_PER_BLOCK: f64 = 0.05;

// ── Security evidence (Phase 0.5) ────────────────────────────────────────────
/// Overlapping local file headers (Fifield bomb signature): a strong but
/// structural heuristic, never quite certain (some packers legitimately share).
pub const OVERLAPPING_ENTRIES: f64 = 0.99;
/// A measured compression ratio / output cap was exceeded — the produced bytes
/// are counted, not declared, so the breach is real but a hair below certain.
pub const RATIO_EXCEEDED: f64 = 0.99;
/// Observed nesting strictly exceeded the depth limit — deterministic.
pub const DEPTH_EXCEEDED: f64 = 1.0;
/// A normalized path escapes the staging root — deterministic.
pub const PATH_ESCAPE: f64 = 1.0;
/// A nested container hash equals an ancestor's — deterministic cycle.
pub const CYCLE_DETECTED: f64 = 1.0;

/// Confidence for a [`EvidenceType::OffsetOutOfBounds`] given the pointer value
/// and the file size.
pub fn offset_out_of_bounds(offset: u64, file_size: u64) -> f64 {
    // Called only for offsets already deemed out-of-bounds/suspicious: strictly
    // beyond EOF is certain, otherwise (near-EOF) slightly less so.
    if offset > file_size {
        OFFSET_BEYOND_EOF
    } else {
        OFFSET_NEAR_EOF
    }
}

/// Confidence for a checksum mismatch (full-data vs block-level).
pub fn checksum(full_data: bool) -> f64 {
    if full_data {
        CHECKSUM_FULL
    } else {
        CHECKSUM_BLOCK
    }
}

/// Confidence for a bitflip confirmed by `confirming_blocks` block hashes.
pub fn bitflip(confirming_blocks: u32) -> f64 {
    (BITFLIP_BASE + BITFLIP_PER_BLOCK * confirming_blocks.saturating_sub(1) as f64).clamp(0.0, 1.0)
}

/// Baseline confidence for an evidence type that needs no extra context.
pub fn base(evidence_type: EvidenceType) -> f64 {
    match evidence_type {
        EvidenceType::SignatureMismatch => SIGNATURE,
        EvidenceType::ChecksumMismatch => CHECKSUM_FULL,
        EvidenceType::OffsetOutOfBounds => OFFSET_BEYOND_EOF,
        EvidenceType::LengthOverflow => LENGTH_OVERFLOW,
        EvidenceType::LengthUnderflow => LENGTH_UNDERFLOW,
        EvidenceType::StructureMissing => STRUCTURE_MISSING,
        EvidenceType::ValueOutOfRange => VALUE_OUT_OF_RANGE,
        EvidenceType::BlockReorder => BLOCK_REORDER,
        EvidenceType::PaddingViolation => PADDING_VIOLATION,
        EvidenceType::TruncationMarker => TRUNCATION_MARKER,
        EvidenceType::OverlappingEntries => OVERLAPPING_ENTRIES,
        EvidenceType::RatioExceeded => RATIO_EXCEEDED,
        EvidenceType::DepthExceeded => DEPTH_EXCEEDED,
        EvidenceType::PathEscape => PATH_ESCAPE,
        EvidenceType::CycleDetected => CYCLE_DETECTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_certain() {
        assert_eq!(base(EvidenceType::SignatureMismatch), 1.0);
    }

    #[test]
    fn offset_grades() {
        assert_eq!(offset_out_of_bounds(200, 100), 1.0);
        assert_eq!(offset_out_of_bounds(95, 100), 0.9);
    }

    #[test]
    fn bitflip_rises_with_blocks() {
        assert!((bitflip(1) - 0.85).abs() < 1e-9);
        assert!((bitflip(2) - 0.90).abs() < 1e-9);
        assert!(bitflip(100) <= 1.0);
    }

    #[test]
    fn checksum_full_vs_block() {
        assert_eq!(checksum(true), 1.0);
        assert_eq!(checksum(false), 0.95);
    }
}
