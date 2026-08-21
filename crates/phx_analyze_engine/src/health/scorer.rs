//! Module 2 — Health scoring (Phase 3 calibrated).
//!
//! Consumes classified [`Corruption`]s and produces a [`HealthScore`]. Each
//! corruption deducts its **per-rule** penalty (from [`super::weights`]) from
//! the subscores that rule routes to. Subscores are clamped to `0..=100` and
//! the overall is the frozen weighted sum
//! `structural*0.4 + data*0.4 + metadata*0.2`. There are no magic numbers
//! here — every penalty and routing decision comes from `weights`.

use crate::model::{Corruption, HealthScore};

use super::weights;

/// Compute the health score from a slice of corruptions.
pub fn score(corruptions: &[Corruption]) -> HealthScore {
    let mut structural: i32 = 100;
    let mut data: i32 = 100;
    let mut metadata: i32 = 100;

    for c in corruptions {
        let p = weights::penalty_for(&c.chain.primary.rule_id, c.severity, c.category);
        let points = p.points as i32;
        if p.structural {
            structural -= points;
        }
        if p.data {
            data -= points;
        }
        if p.metadata {
            metadata -= points;
        }
    }

    HealthScore::from_subscores(
        structural.clamp(0, 100) as u8,
        data.clamp(0, 100) as u8,
        metadata.clamp(0, 100) as u8,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ByteRange, CorruptionCategory, CorruptionLocation, Severity};

    // An id deliberately absent from the penalty table, so the scorer exercises
    // the severity/category fallback rather than a calibrated table entry.
    fn corruption(cat: CorruptionCategory, sev: Severity) -> Corruption {
        Corruption::synthetic(
            CorruptionLocation::stream(0, 1),
            cat,
            sev,
            "TEST_UNLISTED_RULE",
            Some(ByteRange::new(0, 1)),
        )
    }

    #[test]
    fn clean_input_is_perfect() {
        assert_eq!(score(&[]), HealthScore::perfect());
    }

    #[test]
    fn two_major_data_corruptions_give_data_health_50() {
        let cs = vec![
            corruption(CorruptionCategory::ChecksumMismatch, Severity::Major),
            corruption(CorruptionCategory::BitFlip, Severity::Major),
        ];
        let h = score(&cs);
        assert_eq!(h.data_health, 50);
        assert_eq!(h.structural_health, 100);
        assert_eq!(h.metadata_health, 100);
    }

    #[test]
    fn catastrophic_hits_all_three() {
        let cs = vec![corruption(
            CorruptionCategory::StructuralCorruption,
            Severity::Catastrophic,
        )];
        let h = score(&cs);
        assert_eq!(h.structural_health, 50);
        assert_eq!(h.data_health, 50);
        assert_eq!(h.metadata_health, 50);
        assert_eq!(h.overall, 50);
    }

    #[test]
    fn truncation_hits_structural_and_data() {
        let cs = vec![corruption(CorruptionCategory::Truncation, Severity::Major)];
        let h = score(&cs);
        assert_eq!(h.structural_health, 75);
        assert_eq!(h.data_health, 75);
        assert_eq!(h.metadata_health, 100);
    }
}
