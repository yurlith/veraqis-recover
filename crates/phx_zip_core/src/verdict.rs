//! Recovery verdicts — what a produced artifact is actually worth.
//!
//! A single boolean "recovered" is not honest enough to ship. It cannot distinguish bytes proven
//! identical to the original from bytes that merely survived a repair, and that gap is exactly
//! where a false recovery hides: the user is handed a file the report calls recovered, and only
//! discovers otherwise when they open it.
//!
//! Every verdict here answers one question — *what proves this?* — and only the two trusted
//! verdicts may be presented to a user as a recovered file (`VERAQIS_AGENT_ROADMAP.md` Phase 2.5A,
//! owner decision D-004).

use std::fmt;

/// Where the central directory being read actually came from (E1, DEC-016 §5).
///
/// A ZIP's central directory is normally an *independent* second witness: written by the producer,
/// separate from the local headers it describes. That independence is destroyed the moment PHX
/// rebuilds the directory from those same local headers — the copy is then derived from the thing
/// it would attest, and believing it is believing one witness twice.
///
/// This cannot be recorded inside the archive: a repaired ZIP must remain an ordinary ZIP, and a
/// private marker in it would be both non-standard and forgeable. Provenance therefore travels
/// with the recovery *operation*, alongside the bytes, and every caller must state it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CdProvenance {
    /// Read from a physically surviving directory in the artifact as received.
    OriginalSurviving,
    /// Built by PHX from local headers, a scan, or the repair pipeline. **Zero independent
    /// evidentiary weight** — it may still be a structurally valid directory for the output file.
    Reconstructed,
    /// Attested by a source outside this archive (Shield sidecar, prior manifest).
    ExternalAttested,
    /// Not established. Fails closed: never treated as surviving original.
    Unknown,
}

impl CdProvenance {
    /// May a directory record of this origin be counted as evidence that an entry existed?
    ///
    /// `Reconstructed` is false by construction — that is the whole point of E1 — and `Unknown`
    /// is false because a provenance nobody established must not become attestation by default.
    pub fn attests_existence(self) -> bool {
        matches!(
            self,
            CdProvenance::OriginalSurviving | CdProvenance::ExternalAttested
        )
    }

    /// Does this specific entry's central-directory record count as an independent witness that
    /// the entry existed? Folds the two conditions every caller must check together: the record
    /// must actually be a central-directory record for this entry (`from_central_dir`), and this
    /// directory's own provenance must be one that carries weight ([`Self::attests_existence`]).
    pub fn entry_is_attested(self, from_central_dir: bool) -> bool {
        from_central_dir && self.attests_existence()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CdProvenance::OriginalSurviving => "ORIGINAL_SURVIVING",
            CdProvenance::Reconstructed => "RECONSTRUCTED",
            CdProvenance::ExternalAttested => "EXTERNAL_ATTESTED",
            CdProvenance::Unknown => "UNKNOWN",
        }
    }
}

impl fmt::Display for CdProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a recovery produced for one entry, ordered by how much is proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryVerdict {
    /// The bytes are the original bytes, proven by a checksum **independent** of how they were
    /// produced. The only verdict that may be called an exact recovery.
    ExactRecoverable,
    /// The bytes are proven original, but some metadata around them (timestamp, attributes, a
    /// rebuilt directory record) was reconstructed rather than recovered. The content is exact;
    /// the envelope is not.
    RecoverableWithMetadataLoss,
    /// Bytes were obtained, but nothing independent proves they are the original bytes. They may
    /// be right. They may be silently wrong. Never an exact recovery, never counted in precision,
    /// never returned by the release surface as a successful recovery.
    SalvagedUnverified,
    /// Nothing could be produced for this entry, and PHX says so.
    Unrecoverable,
}

impl RecoveryVerdict {
    /// May this be presented to a user as a recovered file?
    ///
    /// The load-bearing predicate of Phase 2.5A. `SalvagedUnverified` is deliberately excluded:
    /// unverified bytes are a lead, not a result.
    pub fn is_trusted(self) -> bool {
        matches!(
            self,
            RecoveryVerdict::ExactRecoverable | RecoveryVerdict::RecoverableWithMetadataLoss
        )
    }

    /// May this count toward exact-recovery precision in a benchmark?
    ///
    /// Stricter than [`Self::is_trusted`]: metadata loss means the artifact is not byte-identical
    /// as a whole, so it is honest recovery but not an *exact* one.
    pub fn counts_as_exact(self) -> bool {
        self == RecoveryVerdict::ExactRecoverable
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RecoveryVerdict::ExactRecoverable => "EXACT_RECOVERABLE",
            RecoveryVerdict::RecoverableWithMetadataLoss => "RECOVERABLE_WITH_METADATA_LOSS",
            RecoveryVerdict::SalvagedUnverified => "SALVAGED_UNVERIFIED",
            RecoveryVerdict::Unrecoverable => "UNRECOVERABLE",
        }
    }
}

impl fmt::Display for RecoveryVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_proven_verdicts_are_trusted() {
        assert!(RecoveryVerdict::ExactRecoverable.is_trusted());
        assert!(RecoveryVerdict::RecoverableWithMetadataLoss.is_trusted());
        assert!(
            !RecoveryVerdict::SalvagedUnverified.is_trusted(),
            "unverified salvage must never be presentable as a recovered file"
        );
        assert!(!RecoveryVerdict::Unrecoverable.is_trusted());
    }

    #[test]
    fn only_exact_counts_toward_exact_precision() {
        assert!(RecoveryVerdict::ExactRecoverable.counts_as_exact());
        for v in [
            RecoveryVerdict::RecoverableWithMetadataLoss,
            RecoveryVerdict::SalvagedUnverified,
            RecoveryVerdict::Unrecoverable,
        ] {
            assert!(!v.counts_as_exact(), "{v} must not count as exact recovery");
        }
    }

    #[test]
    fn wire_names_match_the_roadmap() {
        assert_eq!(
            RecoveryVerdict::ExactRecoverable.as_str(),
            "EXACT_RECOVERABLE"
        );
        assert_eq!(
            RecoveryVerdict::RecoverableWithMetadataLoss.as_str(),
            "RECOVERABLE_WITH_METADATA_LOSS"
        );
        assert_eq!(
            RecoveryVerdict::SalvagedUnverified.as_str(),
            "SALVAGED_UNVERIFIED"
        );
        assert_eq!(RecoveryVerdict::Unrecoverable.as_str(), "UNRECOVERABLE");
    }
}

#[cfg(test)]
mod cd_provenance_tests {
    use super::*;

    #[test]
    fn reconstructed_cd_has_no_independent_evidence_weight() {
        assert!(
            !CdProvenance::Reconstructed.attests_existence(),
            "a directory PHX built from the headers it would attest is one witness counted twice"
        );
    }

    #[test]
    fn unknown_cd_provenance_fails_closed() {
        assert!(
            !CdProvenance::Unknown.attests_existence(),
            "unestablished provenance must never default into surviving-original evidence"
        );
    }

    #[test]
    fn original_surviving_cd_still_attests_when_valid() {
        assert!(CdProvenance::OriginalSurviving.attests_existence());
        assert!(CdProvenance::ExternalAttested.attests_existence());
    }

    #[test]
    fn reconstructed_cd_cannot_become_original_surviving() {
        // There is no conversion, promotion or `From` impl that could launder one into the other.
        assert_ne!(CdProvenance::Reconstructed, CdProvenance::OriginalSurviving);
        assert_eq!(CdProvenance::Reconstructed.as_str(), "RECONSTRUCTED");
    }
}

#[cfg(test)]
mod cd_provenance_matrix {
    use super::*;

    /// The full matrix, all four variants, exactly as DEC-016/DEC-017 specify it.
    #[test]
    fn attests_existence_matrix_is_exact() {
        let matrix = [
            (CdProvenance::OriginalSurviving, true),
            (CdProvenance::Reconstructed, false),
            (CdProvenance::ExternalAttested, true),
            (CdProvenance::Unknown, false),
        ];
        for (p, expected) in matrix {
            assert_eq!(
                p.attests_existence(),
                expected,
                "{p} must {} attest existence",
                if expected { "" } else { "NOT" }
            );
        }
    }

    /// Guards the enum against a new variant silently inheriting attestation: `attests_existence`
    /// uses an explicit alternation, and this exhaustive match (no wildcard) fails to compile if a
    /// variant is added without a deliberate decision here.
    #[test]
    fn every_variant_is_classified_without_a_wildcard() {
        fn classify(p: CdProvenance) -> bool {
            match p {
                CdProvenance::OriginalSurviving => true,
                CdProvenance::Reconstructed => false,
                CdProvenance::ExternalAttested => true,
                CdProvenance::Unknown => false,
            }
        }
        for p in [
            CdProvenance::OriginalSurviving,
            CdProvenance::Reconstructed,
            CdProvenance::ExternalAttested,
            CdProvenance::Unknown,
        ] {
            assert_eq!(
                classify(p),
                p.attests_existence(),
                "{p}: the exhaustive reference classification and the shipped predicate disagree"
            );
        }
    }

    /// There must be no `Default`, `From` or other conversion that could turn a non-attesting
    /// provenance into an attesting one. Asserted behaviourally: the only way to obtain
    /// `OriginalSurviving` is to name it.
    #[test]
    fn no_conversion_launders_a_non_attesting_provenance() {
        let derived = CdProvenance::Reconstructed;
        assert!(!derived.attests_existence());
        assert_ne!(derived, CdProvenance::OriginalSurviving);
        assert_ne!(CdProvenance::Unknown, CdProvenance::OriginalSurviving);
        assert_eq!(CdProvenance::Unknown.as_str(), "UNKNOWN");
        assert_eq!(CdProvenance::ExternalAttested.as_str(), "EXTERNAL_ATTESTED");
    }
}
