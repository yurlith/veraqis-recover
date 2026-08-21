//! Recoverability-score model types (Module 5 heuristic, computed by Analysis).

use serde::{Deserialize, Serialize};

/// A single factor that pushed the recovery probability up or down.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryFactor {
    pub name: String,
    /// `true` if this raised the probability, `false` if it lowered it.
    pub positive: bool,
    /// Signed weight as applied (positive factors > 0, negative factors < 0).
    pub weight: f64,
}

impl RecoveryFactor {
    pub fn new(name: impl Into<String>, weight: f64) -> Self {
        RecoveryFactor {
            name: name.into(),
            positive: weight >= 0.0,
            weight,
        }
    }
}

/// Coarse recoverability bucket derived from the probability (Step 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoverabilityClass {
    /// probability ≥ 0.75 — standard tools can recover.
    High,
    /// probability 0.40–0.74 — specialized tools, partial recovery.
    Medium,
    /// probability 0.15–0.39 — forensic only, significant data loss expected.
    Low,
    /// probability < 0.15 — unrecoverable with current technology.
    None,
}

impl RecoverabilityClass {
    /// Parse the corpus `expected_recoverability` string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "High" => Some(Self::High),
            "Medium" => Some(Self::Medium),
            "Low" => Some(Self::Low),
            "None" => Some(Self::None),
            _ => None,
        }
    }

    /// Stable label (matches the corpus vocabulary).
    pub fn label(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::None => "None",
        }
    }

    /// Ordinal for "within one class" comparisons (None=0 … High=3).
    pub fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
        }
    }

    /// Absolute class distance (0 = exact, 1 = adjacent, …).
    pub fn distance(self, other: Self) -> u8 {
        self.rank().abs_diff(other.rank())
    }
}

/// Heuristic estimate of how likely recovery is to succeed.
///
/// Invariants: `probability` and `confidence` both lie in `0.0..=1.0`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoverabilityScore {
    pub probability: f64,
    pub confidence: f64,
    pub factors: Vec<RecoveryFactor>,
}

impl RecoverabilityScore {
    /// Construct, clamping both scores into the valid range defensively.
    pub fn new(probability: f64, confidence: f64, factors: Vec<RecoveryFactor>) -> Self {
        RecoverabilityScore {
            probability: probability.clamp(0.0, 1.0),
            confidence: confidence.clamp(0.0, 1.0),
            factors,
        }
    }

    /// Perfect, fully-confident recoverability (used for undamaged input).
    pub fn certain() -> Self {
        RecoverabilityScore {
            probability: 1.0,
            confidence: 1.0,
            factors: Vec::new(),
        }
    }

    /// Bucket the probability into a [`RecoverabilityClass`] (Step 4.1 bands).
    pub fn class(&self) -> RecoverabilityClass {
        if self.probability >= 0.75 {
            RecoverabilityClass::High
        } else if self.probability >= 0.40 {
            RecoverabilityClass::Medium
        } else if self.probability >= 0.15 {
            RecoverabilityClass::Low
        } else {
            RecoverabilityClass::None
        }
    }

    /// Human-readable verdict for CLI display.
    pub fn verdict(&self) -> &'static str {
        match self.class() {
            RecoverabilityClass::High => "HIGH — standard recovery tools likely succeed",
            RecoverabilityClass::Medium => {
                "MEDIUM — specialized tools required, partial loss expected"
            }
            RecoverabilityClass::Low => "LOW — forensic recovery only, significant data loss",
            RecoverabilityClass::None => "NONE — unrecoverable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(p: f64) -> RecoverabilityScore {
        RecoverabilityScore::new(p, 1.0, Vec::new())
    }

    #[test]
    fn class_bands_match_spec() {
        assert_eq!(score(0.90).class(), RecoverabilityClass::High);
        assert_eq!(score(0.75).class(), RecoverabilityClass::High);
        assert_eq!(score(0.74).class(), RecoverabilityClass::Medium);
        assert_eq!(score(0.40).class(), RecoverabilityClass::Medium);
        assert_eq!(score(0.39).class(), RecoverabilityClass::Low);
        assert_eq!(score(0.15).class(), RecoverabilityClass::Low);
        assert_eq!(score(0.14).class(), RecoverabilityClass::None);
        assert_eq!(score(0.0).class(), RecoverabilityClass::None);
    }

    #[test]
    fn certain_is_high() {
        assert_eq!(
            RecoverabilityScore::certain().class(),
            RecoverabilityClass::High
        );
    }

    #[test]
    fn parse_roundtrips_label() {
        for s in ["High", "Medium", "Low", "None"] {
            assert_eq!(RecoverabilityClass::parse(s).unwrap().label(), s);
        }
        assert!(RecoverabilityClass::parse("bogus").is_none());
    }

    #[test]
    fn distance_is_symmetric_class_gap() {
        assert_eq!(
            RecoverabilityClass::High.distance(RecoverabilityClass::None),
            3
        );
        assert_eq!(
            RecoverabilityClass::Medium.distance(RecoverabilityClass::Low),
            1
        );
        assert_eq!(
            RecoverabilityClass::Low.distance(RecoverabilityClass::Low),
            0
        );
    }
}
