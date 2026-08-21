//! Corruption model types (Module 1 corruption-scan output).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Half-open-ish byte range describing an affected region.
///
/// Invariant: `end >= start`. Both bounds are absolute byte offsets into the
/// stream being analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    /// Create a range, panicking in debug builds if `end < start`.
    pub fn new(start: u64, end: u64) -> Self {
        debug_assert!(end >= start, "ByteRange end {end} < start {start}");
        ByteRange { start, end }
    }

    /// Number of bytes covered.
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the range covers zero bytes.
    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }

    /// Whether two ranges touch or overlap (used to merge adjacent damage).
    pub fn adjacent_or_overlapping(&self, other: &ByteRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

/// Where a corruption was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorruptionLocation {
    /// Set for archive members; `None` for the container/stream itself.
    pub file_path: Option<std::path::PathBuf>,
    pub offset_start: u64,
    pub offset_end: u64,
}

impl CorruptionLocation {
    /// Construct a stream-level location (no contained file).
    ///
    /// Invariant: `offset_end >= offset_start`.
    pub fn stream(offset_start: u64, offset_end: u64) -> Self {
        debug_assert!(offset_end >= offset_start);
        CorruptionLocation {
            file_path: None,
            offset_start,
            offset_end,
        }
    }
}

/// Classification of a detected defect. Classification only — interpretation
/// of *how bad* it is lives in [`Severity`], and routing to health subscores
/// lives in [`crate::health`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CorruptionCategory {
    /// Bytes that should exist are absent.
    MissingData,
    /// One or more flipped bits (typically detected via checksum/manifest).
    BitFlip,
    /// Blocks present but out of order.
    BlockReorder,
    /// Stream cut short before its declared end.
    Truncation,
    /// Padding region does not match expected fill.
    PaddingMismatch,
    /// An embedded checksum (e.g. ZIP CRC-32) did not verify.
    ChecksumMismatch,
    /// Structural metadata (headers, directories, descriptors) is damaged.
    StructuralCorruption,
    /// A sandbox policy violation: zip bomb, quine, path traversal, or other
    /// hostile-input signature detected during bounded traversal (Phase 0.5).
    /// Findings in this category are "unrecoverable by policy".
    SecurityThreat,
}

impl CorruptionCategory {
    /// Stable lowercase identifier for serialization / CLI display.
    pub fn as_str(self) -> &'static str {
        match self {
            CorruptionCategory::MissingData => "missing_data",
            CorruptionCategory::BitFlip => "bit_flip",
            CorruptionCategory::BlockReorder => "block_reorder",
            CorruptionCategory::Truncation => "truncation",
            CorruptionCategory::PaddingMismatch => "padding_mismatch",
            CorruptionCategory::ChecksumMismatch => "checksum_mismatch",
            CorruptionCategory::StructuralCorruption => "structural_corruption",
            CorruptionCategory::SecurityThreat => "security_threat",
        }
    }
}

/// How critical a corruption is. Penalty mapping lives in [`crate::health`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Benign,
    Minor,
    Major,
    Catastrophic,
}

impl Severity {
    /// Health penalty points for this severity (see Module 2 table).
    pub fn penalty(self) -> u8 {
        match self {
            Severity::Benign => 0,
            Severity::Minor => 10,
            Severity::Major => 25,
            Severity::Catastrophic => 50,
        }
    }

    /// Stable lowercase identifier for serialization / CLI display.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Benign => "benign",
            Severity::Minor => "minor",
            Severity::Major => "major",
            Severity::Catastrophic => "catastrophic",
        }
    }
}

/// A single detected defect.
/// A single detected defect.
///
/// `description` is **always auto-generated** from the [`ChainOfEvidence`]
/// (Phase 2, Step 2.1) — manually setting it is forbidden in new code. Equality
/// is `PartialEq` only because the chain carries floating-point confidences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Corruption {
    pub id: Uuid,
    pub location: CorruptionLocation,
    pub category: CorruptionCategory,
    pub severity: Severity,
    /// Auto-generated from `chain`; see [`Corruption::refresh_description`].
    pub description: String,
    pub byte_range: Option<ByteRange>,
    pub chain: super::evidence::ChainOfEvidence,
}

impl Corruption {
    /// Build a corruption from its evidence chain, auto-generating the
    /// description.
    pub fn from_chain(
        location: CorruptionLocation,
        category: CorruptionCategory,
        severity: Severity,
        chain: super::evidence::ChainOfEvidence,
        byte_range: Option<ByteRange>,
    ) -> Self {
        let mut c = Corruption {
            id: Uuid::new_v4(),
            location,
            category,
            severity,
            description: String::new(),
            byte_range,
            chain,
        };
        c.refresh_description();
        c
    }

    /// Regenerate `description` from the current chain (Step 2.1 format).
    pub fn refresh_description(&mut self) {
        let p = &self.chain.primary;
        self.description = format!(
            "{}: {} at offset 0x{:X} (confidence {:.0}%)",
            p.rule_id,
            p.field_name,
            p.offset,
            self.chain.aggregate_confidence * 100.0
        );
    }

    /// Test/utility constructor: build a corruption with a minimal synthetic
    /// chain for the given rule id. Used where full evidence is not the point
    /// (unit tests, internal fixtures).
    pub fn synthetic(
        location: CorruptionLocation,
        category: CorruptionCategory,
        severity: Severity,
        rule_id: &str,
        byte_range: Option<ByteRange>,
    ) -> Self {
        let primary = super::evidence::Evidence::new(
            location.offset_start,
            None,
            Vec::new(),
            "synthetic",
            "synthetic evidence",
            1.0,
            rule_id,
            super::evidence::EvidenceType::StructureMissing,
        );
        Corruption::from_chain(
            location,
            category,
            severity,
            super::evidence::ChainOfEvidence::single(primary),
            byte_range,
        )
    }
}
