//! Forensic evidence model (Phase 2, Step 2.1).
//!
//! A [`Corruption`](super::corruption::Corruption) now carries a
//! [`ChainOfEvidence`]: one required `primary` [`Evidence`] plus optional
//! `supporting` evidence, with an aggregate confidence combining them.

use serde::{Deserialize, Serialize};

/// Maximum number of `actual_bytes` captured for a single piece of evidence.
pub const MAX_EVIDENCE_BYTES: usize = 64;

/// Minimum aggregate confidence required to emit a `Corruption`. Below this a
/// finding is recorded as a warning only (Step 2.4).
pub const MIN_EMIT_CONFIDENCE: f64 = 0.50;

/// The kind of signal that produced a piece of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Magic/signature bytes wrong.
    SignatureMismatch,
    /// Hash or CRC computed vs stored.
    ChecksumMismatch,
    /// Pointer field value exceeds file size.
    OffsetOutOfBounds,
    /// Length field + base > file size.
    LengthOverflow,
    /// Length field smaller than the minimum valid value.
    LengthUnderflow,
    /// A required structure is entirely absent.
    StructureMissing,
    /// Numeric field outside its valid spec range.
    ValueOutOfRange,
    /// Block sequence number or position wrong.
    BlockReorder,
    /// Non-zero bytes in a required-zero region.
    PaddingViolation,
    /// EOF reached before a structure completed.
    TruncationMarker,
    // ── Security (Phase 0.5) ────────────────────────────────────────────
    /// Two local file headers reference overlapping data ranges (Fifield
    /// non-recursive overlap-bomb signature).
    OverlappingEntries,
    /// A per-entry or aggregate compression ratio / output cap was exceeded.
    RatioExceeded,
    /// Container nesting exceeded the configured depth limit.
    DepthExceeded,
    /// An entry path escapes the staging root after normalization
    /// (Zip-Slip / traversal / drive-relative / UNC / reserved name).
    PathEscape,
    /// A nested container's content hash equals an ancestor's (quine cycle).
    CycleDetected,
}

impl EvidenceType {
    /// Stable lowercase identifier for serialization / display.
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceType::SignatureMismatch => "signature_mismatch",
            EvidenceType::ChecksumMismatch => "checksum_mismatch",
            EvidenceType::OffsetOutOfBounds => "offset_out_of_bounds",
            EvidenceType::LengthOverflow => "length_overflow",
            EvidenceType::LengthUnderflow => "length_underflow",
            EvidenceType::StructureMissing => "structure_missing",
            EvidenceType::ValueOutOfRange => "value_out_of_range",
            EvidenceType::BlockReorder => "block_reorder",
            EvidenceType::PaddingViolation => "padding_violation",
            EvidenceType::TruncationMarker => "truncation_marker",
            EvidenceType::OverlappingEntries => "overlapping_entries",
            EvidenceType::RatioExceeded => "ratio_exceeded",
            EvidenceType::DepthExceeded => "depth_exceeded",
            EvidenceType::PathEscape => "path_escape",
            EvidenceType::CycleDetected => "cycle_detected",
        }
    }
}

/// A single piece of forensic evidence for a corruption finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub offset: u64,
    /// Expected value, when one is known (signature/checksum); `None` otherwise.
    pub expected_bytes: Option<Vec<u8>>,
    /// Bytes actually observed (capped at [`MAX_EVIDENCE_BYTES`]).
    pub actual_bytes: Vec<u8>,
    /// Field identifier, e.g. `"EOCD.signature"`.
    pub field_name: String,
    /// Human description, e.g. `"End of Central Directory signature"`.
    pub field_description: String,
    /// Confidence in `0.0..=1.0`.
    pub confidence: f64,
    /// Classifier rule id, e.g. `"ZIP_EOCD_001"`.
    pub rule_id: String,
    pub evidence_type: EvidenceType,
}

impl Evidence {
    /// Build a piece of evidence, truncating `actual_bytes` to the cap and
    /// clamping confidence into range.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        offset: u64,
        expected_bytes: Option<Vec<u8>>,
        mut actual_bytes: Vec<u8>,
        field_name: impl Into<String>,
        field_description: impl Into<String>,
        confidence: f64,
        rule_id: impl Into<String>,
        evidence_type: EvidenceType,
    ) -> Self {
        actual_bytes.truncate(MAX_EVIDENCE_BYTES);
        Evidence {
            offset,
            expected_bytes: expected_bytes.map(|mut e| {
                e.truncate(MAX_EVIDENCE_BYTES);
                e
            }),
            actual_bytes,
            field_name: field_name.into(),
            field_description: field_description.into(),
            confidence: confidence.clamp(0.0, 1.0),
            rule_id: rule_id.into(),
            evidence_type,
        }
    }
}

/// One or more pieces of evidence supporting a single corruption finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainOfEvidence {
    pub primary: Evidence,
    pub supporting: Vec<Evidence>,
    pub aggregate_confidence: f64,
}

impl ChainOfEvidence {
    /// Build a chain from a primary piece of evidence (no supporting yet) and
    /// compute the aggregate.
    pub fn single(primary: Evidence) -> Self {
        let mut chain = ChainOfEvidence {
            primary,
            supporting: Vec::new(),
            aggregate_confidence: 0.0,
        };
        chain.compute_aggregate();
        chain
    }

    /// Add a supporting piece of evidence and recompute the aggregate.
    pub fn add_supporting(&mut self, evidence: Evidence) {
        self.supporting.push(evidence);
        self.compute_aggregate();
    }

    /// Combine primary + supporting confidences into the aggregate.
    ///
    /// Independent confirming signals are combined with the standard noisy-OR
    /// rule: `aggregate = 1 − (1 − primary) · ∏(1 − sᵢ)`. With no supporting
    /// evidence this reduces to `primary.confidence` — matching the Step 2.5
    /// example (`primary 1.0`, `supporting []` → `aggregate 1.0`). (The Step
    /// 2.1 prose `primary · (1 − ∏(1 − sᵢ))` yields 0 for the empty case and
    /// contradicts that example, so the example is taken as authoritative.)
    pub fn compute_aggregate(&mut self) {
        let mut inverse = 1.0 - self.primary.confidence;
        for s in &self.supporting {
            inverse *= 1.0 - s.confidence;
        }
        self.aggregate_confidence = (1.0 - inverse).clamp(0.0, 1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(confidence: f64) -> Evidence {
        Evidence::new(
            0,
            Some(vec![0x50, 0x4B, 0x05, 0x06]),
            vec![0, 0, 0, 0],
            "EOCD.signature",
            "End of Central Directory signature",
            confidence,
            "ZIP_EOCD_001",
            EvidenceType::SignatureMismatch,
        )
    }

    #[test]
    fn primary_only_aggregate_equals_primary() {
        let c = ChainOfEvidence::single(ev(1.0));
        assert_eq!(c.aggregate_confidence, 1.0);
    }

    #[test]
    fn primary_only_partial() {
        let c = ChainOfEvidence::single(ev(0.85));
        assert!((c.aggregate_confidence - 0.85).abs() < 1e-9);
    }

    #[test]
    fn primary_zero_is_zero() {
        let c = ChainOfEvidence::single(ev(0.0));
        assert_eq!(c.aggregate_confidence, 0.0);
    }

    #[test]
    fn supporting_raises_confidence() {
        let mut c = ChainOfEvidence::single(ev(0.85));
        c.add_supporting(ev(0.85));
        // 1 - 0.15*0.15 = 0.9775
        assert!((c.aggregate_confidence - 0.9775).abs() < 1e-9);
    }

    #[test]
    fn two_supporting_raise_further() {
        let mut c = ChainOfEvidence::single(ev(0.5));
        c.add_supporting(ev(0.5));
        c.add_supporting(ev(0.5));
        // 1 - 0.5^3 = 0.875
        assert!((c.aggregate_confidence - 0.875).abs() < 1e-9);
    }

    #[test]
    fn deterministic_primary_stays_one() {
        let mut c = ChainOfEvidence::single(ev(1.0));
        c.add_supporting(ev(0.3));
        assert_eq!(c.aggregate_confidence, 1.0);
    }

    #[test]
    fn aggregate_never_exceeds_one() {
        let mut c = ChainOfEvidence::single(ev(0.99));
        for _ in 0..10 {
            c.add_supporting(ev(0.99));
        }
        assert!(c.aggregate_confidence <= 1.0);
    }

    #[test]
    fn aggregate_never_below_zero() {
        let c = ChainOfEvidence::single(ev(0.0));
        assert!(c.aggregate_confidence >= 0.0);
    }

    #[test]
    fn actual_bytes_capped_at_64() {
        let e = Evidence::new(
            0,
            None,
            vec![0xAB; 200],
            "f",
            "d",
            0.9,
            "R",
            EvidenceType::ChecksumMismatch,
        );
        assert_eq!(e.actual_bytes.len(), MAX_EVIDENCE_BYTES);
    }

    #[test]
    fn confidence_clamped() {
        let e = ev(5.0);
        assert_eq!(e.confidence, 1.0);
        let e = ev(-1.0);
        assert_eq!(e.confidence, 0.0);
    }

    #[test]
    fn supporting_order_independent() {
        let mut a = ChainOfEvidence::single(ev(0.6));
        a.add_supporting(ev(0.7));
        a.add_supporting(ev(0.8));
        let mut b = ChainOfEvidence::single(ev(0.6));
        b.add_supporting(ev(0.8));
        b.add_supporting(ev(0.7));
        assert!((a.aggregate_confidence - b.aggregate_confidence).abs() < 1e-12);
    }
}
