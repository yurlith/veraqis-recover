//! Evidence model (`PROOF_CARRYING_RECOVERY.md` §1 / CLAUDE.md "Evidence model
//! (governing law)") — the spine every recovery emission passes through.
//!
//! Two **orthogonal** axes, never collapsed into one ranked enum:
//! - **Axis P** — probabilistic, quantified in bits:
//!   `evidence_bits = Σ wᵢ` over verifiers that are mutually independent **and**
//!   independent of the candidate generator. Special deterministic sub-class:
//!   **Exact-Erasure** (we know *which* bytes are gone + a trusted covering
//!   target with full rank → the unique original).
//! - **Axis L** — logical / structural. "Unique under the stated constraints";
//!   failure mode is *model incompleteness*, not collision, so it carries **no**
//!   `evidence_bits` and is validated empirically (`false_* = 0`).
//! - **Axis S** — suggestion. Never `Verified`, never raises Health.
//!
//! **The tautology rule (critical, §1.1 / VR-5):** a checksum the solver
//! *targeted* (listed in [`SolvedAgainst`]) contributes **0 bits** — a full-rank
//! solve satisfies it by construction. Only verifiers the candidate was **not**
//! fitted to count. A result with `evidence_bits = 0` and no exact-erasure basis
//! **may not be emitted**.
//!
//! **The Health gate (§1.5, binding):** Health may rise **only** from
//! exact-erasure (corroborated trusted target), an Axis-P result with
//! `evidence_bits ≥ 32` and ≥ 1 independent verifier, or an Axis-L
//! `structural_unique` that passed its unique-gate with a clean differential
//! record. Never from `0` bits, `structural_heuristic`, or `suggested`.

use serde::{Deserialize, Serialize};

/// Health may rise from an Axis-P result only at or above this many bits (§1.5).
pub const HEALTH_MIN_BITS: u32 = 32;

/// The two orthogonal evidence axes plus the suggestion axis (§1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Axis {
    /// Probabilistic — quantified in `evidence_bits`.
    #[serde(rename = "P")]
    Probabilistic,
    /// Logical / structural — empirically validated, no bits.
    #[serde(rename = "L")]
    Logical,
    /// Suggestion — never proof.
    #[serde(rename = "S")]
    Suggestion,
}

/// Evidence class (§1.7). Determines emission/Health semantics together with the
/// axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    /// Deterministic erasure solve under a trusted target (Axis P).
    ExactErasure,
    /// Candidate confirmed by an independent verifier the solver was not fitted
    /// to (Axis P).
    AlgebraicIndependent,
    /// Bytes copied from a verified duplicate, placement independently verified
    /// (Axis P).
    ExactCopy,
    /// Provably one candidate under the full modelled constraint set (Axis L).
    StructuralUnique,
    /// Best candidate, not unique — never raises Health (Axis L).
    StructuralHeuristic,
    /// Synthesized content that may aid opening — never verified (Axis S).
    Suggested,
}

/// An independent verifier (§1.1) — something that was **checked**, not solved-to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verifier {
    /// e.g. `"CRC-32/ISO-HDLC"`, `"Adler-32"`, `"SHA-256"`, `"length"`.
    pub kind: String,
    /// Bits of false-accept protection this verifier contributes.
    pub width: u32,
    /// File region the verifier covers `[start, end)`.
    pub region: (u64, u64),
}

/// A target the candidate was **solved/fitted to** (§1.7) — contributes 0 bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvedAgainst {
    pub kind: String,
    pub region: (u64, u64),
}

/// Why a record could not be constructed/emitted honestly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// An Axis-P, non-erasure result with no independent verifier (only the
    /// solved-against target) — would be a tautology (§1.1).
    NoIndependentVerifier,
    /// A verifier coincides with a checksum the candidate was solved-to (same
    /// kind + overlapping region) — the tautology (§1.1 / VR-5).
    TautologicalVerifier { kind: String },
    /// Exact-erasure asserted without a corroborated trusted target (VR-2).
    UntrustedErasureTarget,
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceError::NoIndependentVerifier => {
                write!(
                    f,
                    "Axis-P result has 0 evidence_bits and no exact-erasure basis"
                )
            }
            EvidenceError::TautologicalVerifier { kind } => {
                write!(
                    f,
                    "verifier '{kind}' was solved-against (tautology, 0 bits)"
                )
            }
            EvidenceError::UntrustedErasureTarget => {
                write!(
                    f,
                    "exact-erasure asserted without a corroborated trusted target"
                )
            }
        }
    }
}
impl std::error::Error for EvidenceError {}

/// One evidence record (§1.7 manifest schema). Construct via the typed
/// constructors so the axis/class invariants hold by design; finish with
/// [`EvidenceRecord::finish`] to run the tautology + emission guards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub axis: Axis,
    pub class: EvidenceClass,
    pub independent_verifiers: Vec<Verifier>,
    pub solved_against: Vec<SolvedAgainst>,
    pub logical_constraints_used: Vec<String>,
    /// Corroboration source for an exact-erasure target (VR-2), e.g.
    /// `"zip-local==central"`.
    pub target_trust: Option<String>,
    /// Axis-L `structural_unique`: the unique-gate passed.
    pub unique_gate_passed: bool,
    /// Axis-L `structural_unique`: a clean differential record (`false_* = 0`).
    pub clean_differential: bool,
}

impl EvidenceRecord {
    fn base(axis: Axis, class: EvidenceClass) -> Self {
        EvidenceRecord {
            axis,
            class,
            independent_verifiers: Vec::new(),
            solved_against: Vec::new(),
            logical_constraints_used: Vec::new(),
            target_trust: None,
            unique_gate_passed: false,
            clean_differential: false,
        }
    }

    /// Axis-P deterministic erasure solve. `target_trust` is the corroboration
    /// source (VR-2); without it the record cannot be emitted.
    pub fn exact_erasure(target_trust: impl Into<String>) -> Self {
        let mut r = Self::base(Axis::Probabilistic, EvidenceClass::ExactErasure);
        r.target_trust = Some(target_trust.into());
        r
    }

    /// Axis-P candidate to be confirmed by independent verifier(s).
    pub fn algebraic_independent() -> Self {
        Self::base(Axis::Probabilistic, EvidenceClass::AlgebraicIndependent)
    }

    /// Axis-P exact copy (placement independently verified).
    pub fn exact_copy() -> Self {
        Self::base(Axis::Probabilistic, EvidenceClass::ExactCopy)
    }

    /// Axis-L `structural_unique`. Raises Health only if both gates hold.
    pub fn structural_unique(unique_gate_passed: bool, clean_differential: bool) -> Self {
        let mut r = Self::base(Axis::Logical, EvidenceClass::StructuralUnique);
        r.unique_gate_passed = unique_gate_passed;
        r.clean_differential = clean_differential;
        r
    }

    /// Axis-L `structural_heuristic` — best candidate, never raises Health.
    pub fn structural_heuristic() -> Self {
        Self::base(Axis::Logical, EvidenceClass::StructuralHeuristic)
    }

    /// Axis-S suggestion — never verified, never Health.
    pub fn suggested() -> Self {
        Self::base(Axis::Suggestion, EvidenceClass::Suggested)
    }

    /// Record a target the candidate was solved/fitted to (0 bits).
    pub fn solved_against(mut self, kind: impl Into<String>, region: (u64, u64)) -> Self {
        self.solved_against.push(SolvedAgainst {
            kind: kind.into(),
            region,
        });
        self
    }

    /// Add an independent verifier (the only thing that earns bits).
    pub fn verified_by(mut self, kind: impl Into<String>, width: u32, region: (u64, u64)) -> Self {
        self.independent_verifiers.push(Verifier {
            kind: kind.into(),
            width,
            region,
        });
        self
    }

    /// Record a logical constraint used (Axis L provenance).
    pub fn with_constraint(mut self, c: impl Into<String>) -> Self {
        self.logical_constraints_used.push(c.into());
        self
    }

    /// `evidence_bits = Σ wᵢ` over independent verifiers — Axis P only; Axis L/S
    /// are not bit-quantified (§1.3/§1.4). The tautology rule is structural: a
    /// solved-against target is in a *separate* list and never summed.
    pub fn evidence_bits(&self) -> u32 {
        match self.axis {
            Axis::Probabilistic => self
                .independent_verifiers
                .iter()
                .map(|v| v.width)
                .fold(0u32, |a, w| a.saturating_add(w)),
            Axis::Logical | Axis::Suggestion => 0,
        }
    }

    /// Run the §1.1 / VR-2 guards. Returns the record if it is honestly
    /// constructible, else the reason it is not.
    pub fn finish(self) -> Result<Self, EvidenceError> {
        // Tautology: a verifier may not coincide with a solved-against target.
        for v in &self.independent_verifiers {
            if self
                .solved_against
                .iter()
                .any(|s| s.kind == v.kind && overlaps(s.region, v.region))
            {
                return Err(EvidenceError::TautologicalVerifier {
                    kind: v.kind.clone(),
                });
            }
        }
        match (self.axis, self.class) {
            (Axis::Probabilistic, EvidenceClass::ExactErasure) => {
                if self.target_trust.is_none() {
                    return Err(EvidenceError::UntrustedErasureTarget);
                }
            }
            (Axis::Probabilistic, _) => {
                // Non-erasure Axis-P needs ≥ 1 independent verifier (else 0 bits).
                if self.evidence_bits() == 0 {
                    return Err(EvidenceError::NoIndependentVerifier);
                }
            }
            _ => {}
        }
        Ok(self)
    }

    /// May this record be emitted at all? (§1.1: an Axis-P, non-erasure result
    /// with `0` bits may not be emitted; Axis-L is validated empirically and is
    /// emittable; Axis-S is emittable only as `suggested`.)
    pub fn can_emit(&self) -> bool {
        match self.axis {
            Axis::Probabilistic => match self.class {
                EvidenceClass::ExactErasure => self.target_trust.is_some(),
                _ => self.evidence_bits() > 0,
            },
            Axis::Logical | Axis::Suggestion => true,
        }
    }

    /// Does this record raise Health? (§1.5 — binding.)
    pub fn raises_health(&self) -> bool {
        match (self.axis, self.class) {
            (Axis::Probabilistic, EvidenceClass::ExactErasure) => self.target_trust.is_some(),
            (Axis::Probabilistic, _) => {
                self.evidence_bits() >= HEALTH_MIN_BITS && !self.independent_verifiers.is_empty()
            }
            (Axis::Logical, EvidenceClass::StructuralUnique) => {
                self.unique_gate_passed && self.clean_differential
            }
            _ => false,
        }
    }

    /// `false_accept_bound` field (§1.7).
    pub fn false_accept_bound(&self) -> String {
        match self.axis {
            Axis::Probabilistic => match self.class {
                EvidenceClass::ExactErasure => {
                    "deterministic (exact erasure under trusted target)".to_string()
                }
                _ => format!("2^-{}", self.evidence_bits()),
            },
            Axis::Logical => "model-incompleteness (empirical: 0 on corpus)".to_string(),
            Axis::Suggestion => "suggestion — not a correctness claim".to_string(),
        }
    }
}

#[inline]
fn overlaps(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_independent_crc_is_32_bits_and_raises_health() {
        let r = EvidenceRecord::algebraic_independent()
            .verified_by("CRC-32/ISO-HDLC", 32, (0, 100))
            .finish()
            .unwrap();
        assert_eq!(r.evidence_bits(), 32);
        assert!(r.can_emit());
        assert!(r.raises_health());
        assert_eq!(r.false_accept_bound(), "2^-32");
    }

    #[test]
    fn two_independent_crcs_sum_to_64_bits() {
        let r = EvidenceRecord::algebraic_independent()
            .verified_by("CRC-32/ISO-HDLC", 32, (0, 100))
            .verified_by("Adler-32", 32, (0, 100))
            .finish()
            .unwrap();
        assert_eq!(r.evidence_bits(), 64);
        assert!(r.raises_health());
    }

    #[test]
    fn solved_against_alone_is_a_tautology_and_cannot_emit() {
        // Only the target we solved-to, no independent verifier → 0 bits.
        let built = EvidenceRecord::algebraic_independent()
            .solved_against("CRC-32/ISO-HDLC", (0, 100))
            .finish();
        assert_eq!(built.unwrap_err(), EvidenceError::NoIndependentVerifier);
    }

    #[test]
    fn listing_the_solved_against_crc_as_verifier_is_rejected() {
        // The classic tautology: "re-verify" against the very CRC we solved to.
        let built = EvidenceRecord::algebraic_independent()
            .solved_against("CRC-32/ISO-HDLC", (0, 100))
            .verified_by("CRC-32/ISO-HDLC", 32, (0, 100))
            .finish();
        assert!(matches!(
            built.unwrap_err(),
            EvidenceError::TautologicalVerifier { .. }
        ));
    }

    #[test]
    fn independent_second_crc_over_disjoint_region_is_not_tautological() {
        let r = EvidenceRecord::algebraic_independent()
            .solved_against("CRC-32/ISO-HDLC", (0, 100))
            .verified_by("CRC-32/ISO-HDLC", 32, (200, 300))
            .finish()
            .unwrap();
        assert_eq!(r.evidence_bits(), 32);
        assert!(r.raises_health());
    }

    #[test]
    fn exact_erasure_emits_and_raises_health_with_zero_prob_bits() {
        let r = EvidenceRecord::exact_erasure("zip-local==central")
            .solved_against("CRC-32/ISO-HDLC", (50, 54))
            .finish()
            .unwrap();
        assert_eq!(r.evidence_bits(), 0); // no *independent* verifier
        assert!(r.can_emit()); // deterministic erasure basis
        assert!(r.raises_health());
        assert!(r.false_accept_bound().contains("deterministic"));
    }

    #[test]
    fn exact_erasure_without_trusted_target_cannot_be_built() {
        let mut r = EvidenceRecord::exact_erasure("x");
        r.target_trust = None;
        assert_eq!(
            r.finish().unwrap_err(),
            EvidenceError::UntrustedErasureTarget
        );
    }

    #[test]
    fn structural_unique_raises_health_only_with_both_gates() {
        let ok = EvidenceRecord::structural_unique(true, true)
            .with_constraint("schema serial-types + rowid order")
            .finish()
            .unwrap();
        assert_eq!(ok.evidence_bits(), 0);
        assert!(ok.can_emit());
        assert!(ok.raises_health());

        let no_diff = EvidenceRecord::structural_unique(true, false)
            .finish()
            .unwrap();
        assert!(no_diff.can_emit());
        assert!(!no_diff.raises_health());
    }

    #[test]
    fn structural_heuristic_emits_but_never_raises_health() {
        let r = EvidenceRecord::structural_heuristic().finish().unwrap();
        assert!(r.can_emit());
        assert!(!r.raises_health());
        assert_eq!(r.evidence_bits(), 0);
    }

    #[test]
    fn suggested_is_axis_s_emittable_but_never_health() {
        let r = EvidenceRecord::suggested().finish().unwrap();
        assert_eq!(r.axis, Axis::Suggestion);
        assert!(r.can_emit());
        assert!(!r.raises_health());
    }

    #[test]
    fn sub_32_bit_verifier_does_not_raise_health() {
        let r = EvidenceRecord::algebraic_independent()
            .verified_by("length", 16, (0, 100))
            .finish()
            .unwrap();
        assert_eq!(r.evidence_bits(), 16);
        assert!(r.can_emit()); // emittable (some independent evidence)
        assert!(!r.raises_health()); // but < 32 bits → no Health
    }

    #[test]
    fn manifest_serializes_to_the_schema_field_names() {
        let r = EvidenceRecord::algebraic_independent()
            .verified_by("CRC-32/ISO-HDLC", 32, (0, 100))
            .finish()
            .unwrap();
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["axis"], "P");
        assert_eq!(j["class"], "algebraic_independent");
        assert_eq!(j["independent_verifiers"][0]["width"], 32);
    }

    #[test]
    fn exact_copy_needs_independent_placement_verification() {
        // A hash proves identity, not placement (§7 EXP-EC): without an
        // independent placement verifier the copy is not emittable.
        assert_eq!(
            EvidenceRecord::exact_copy().finish().unwrap_err(),
            EvidenceError::NoIndependentVerifier
        );
        let ok = EvidenceRecord::exact_copy()
            .verified_by("CRC-32/ISO-HDLC", 32, (0, 4096))
            .finish()
            .unwrap();
        assert_eq!(ok.evidence_bits(), 32);
        assert!(ok.can_emit());
        assert!(ok.raises_health());
    }

    #[test]
    fn false_accept_bound_for_logical_and_suggestion() {
        let l = EvidenceRecord::structural_unique(true, true)
            .finish()
            .unwrap();
        assert!(l.false_accept_bound().contains("model-incompleteness"));
        let s = EvidenceRecord::suggested().finish().unwrap();
        assert!(s.false_accept_bound().contains("suggestion"));
    }

    #[test]
    fn error_display_covers_all_variants() {
        for e in [
            EvidenceError::NoIndependentVerifier,
            EvidenceError::TautologicalVerifier {
                kind: "CRC-32/ISO-HDLC".into(),
            },
            EvidenceError::UntrustedErasureTarget,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
