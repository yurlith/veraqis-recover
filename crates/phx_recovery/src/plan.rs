//! Repair planning model (Phase 6, Step 6.1).
//!
//! A [`RepairPlan`] is the **read-only** description of what a surgical repair
//! *would* change, produced from the analysis before any byte is written. It is
//! the data behind `phx recover --plan` ("what would change?") and the record
//! each executed repair is checked against. Plans are rule-keyed: every plan
//! names the diagnosis [`rule_id`](RepairPlan::rule_id) it addresses, joining
//! the repair back to the Phase 2 evidence model.

use phx_analyze_engine::model::ByteRange;
use serde::Serialize;

/// How much trust to place in a repair's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RepairRisk {
    /// Deterministic, byte-exact reconstruction from surviving redundant data
    /// (e.g. rebuild the central directory from intact local headers). No
    /// information is invented; member payloads are copied verbatim.
    Safe,
    /// The repair infers values that are very likely but not certain (e.g.
    /// recompute a size field or checksum from observed boundaries).
    Inferred,
    /// The repair discards or cannot recover some data (e.g. carve the readable
    /// members out of a head-truncated archive and drop the rest).
    Lossy,
}

impl RepairRisk {
    pub fn label(self) -> &'static str {
        match self {
            RepairRisk::Safe => "Safe",
            RepairRisk::Inferred => "Inferred",
            RepairRisk::Lossy => "Lossy",
        }
    }
}

/// A single planned repair: which technique, where, the predicted result, and
/// how risky it is. Produced by [`crate::strategies::RecoveryStrategy::plan`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RepairPlan {
    /// The diagnosis rule this repair addresses (join key to the evidence model).
    pub rule_id: String,
    /// Catalog technique name (Step 6.2), e.g. `"CentralDirRebuild"`.
    pub technique: &'static str,
    /// Byte range the repair targets, when the diagnosis located one.
    pub target_range: Option<ByteRange>,
    /// Human-readable description of the predicted result.
    pub predicted_outcome: String,
    /// Trust level of the output.
    pub risk: RepairRisk,
}

impl RepairPlan {
    pub fn new(
        rule_id: impl Into<String>,
        technique: &'static str,
        target_range: Option<ByteRange>,
        predicted_outcome: impl Into<String>,
        risk: RepairRisk,
    ) -> Self {
        RepairPlan {
            rule_id: rule_id.into(),
            technique,
            target_range,
            predicted_outcome: predicted_outcome.into(),
            risk,
        }
    }

    /// One-line preview used by `recover --plan`.
    pub fn summary(&self) -> String {
        let where_ = self
            .target_range
            .map(|r| format!(" @ {:#x}..{:#x}", r.start, r.end))
            .unwrap_or_default();
        format!(
            "[{}] {} via {}{} — {}",
            self.risk.label(),
            self.rule_id,
            self.technique,
            where_,
            self.predicted_outcome
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phx_analyze_engine::model::ByteRange;

    #[test]
    fn risk_labels_are_stable() {
        assert_eq!(RepairRisk::Safe.label(), "Safe");
        assert_eq!(RepairRisk::Inferred.label(), "Inferred");
        assert_eq!(RepairRisk::Lossy.label(), "Lossy");
    }

    #[test]
    fn summary_includes_rule_technique_and_range() {
        let p = RepairPlan::new(
            "ZIP_EOCD_001",
            "CentralDirRebuild",
            Some(ByteRange::new(0x10, 0x20)),
            "rebuild the directory",
            RepairRisk::Safe,
        );
        let s = p.summary();
        assert!(s.contains("ZIP_EOCD_001"));
        assert!(s.contains("CentralDirRebuild"));
        assert!(s.contains("Safe"));
        assert!(s.contains("0x10..0x20"));
    }
}
