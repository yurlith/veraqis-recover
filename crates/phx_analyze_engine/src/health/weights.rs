//! Per-rule health penalties (Phase 3, Step 3.2).
//!
//! The Module 2 formula weights (0.4 / 0.4 / 0.2) are frozen; only these
//! per-rule penalties are tuned during calibration. Every penalty is a named
//! entry here with its rationale — the scorer contains no magic numbers and
//! looks everything up through [`penalty_for`]. Calibration history and the
//! final values are documented in `CALIBRATION.md`.

use crate::model::{CorruptionCategory, Severity};

/// How a rule's penalty is applied: the point cost and which subscores it hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulePenalty {
    pub points: u8,
    pub structural: bool,
    pub data: bool,
    pub metadata: bool,
}

impl RulePenalty {
    const fn s(points: u8) -> Self {
        RulePenalty {
            points,
            structural: true,
            data: false,
            metadata: false,
        }
    }
    const fn d(points: u8) -> Self {
        RulePenalty {
            points,
            structural: false,
            data: true,
            metadata: false,
        }
    }
    const fn sd(points: u8) -> Self {
        RulePenalty {
            points,
            structural: true,
            data: true,
            metadata: false,
        }
    }
    const fn all(points: u8) -> Self {
        RulePenalty {
            points,
            structural: true,
            data: true,
            metadata: true,
        }
    }
}

// ── Default penalties by severity (fallback for rules not in the table) ──────

/// Benign defects cost nothing.
pub const DEFAULT_BENIGN: u8 = 0;
/// Minor defect default penalty.
pub const DEFAULT_MINOR: u8 = 10;
/// Major defect default penalty.
pub const DEFAULT_MAJOR: u8 = 25;
/// Catastrophic defect default penalty.
pub const DEFAULT_CATASTROPHIC: u8 = 50;

/// Penalty + routing for a rule. Uses the calibrated table when the rule is
/// listed; otherwise falls back to the severity default routed by category.
pub fn penalty_for(rule_id: &str, severity: Severity, category: CorruptionCategory) -> RulePenalty {
    if let Some(p) = RULE_PENALTIES.iter().find(|(id, _)| *id == rule_id) {
        return p.1;
    }
    let points = match severity {
        Severity::Benign => DEFAULT_BENIGN,
        Severity::Minor => DEFAULT_MINOR,
        Severity::Major => DEFAULT_MAJOR,
        Severity::Catastrophic => DEFAULT_CATASTROPHIC,
    };
    let routed = route(category, points);
    // Any catastrophic defect hits all three subscores (Module 2 rule).
    if severity == Severity::Catastrophic {
        RulePenalty::all(points)
    } else {
        routed
    }
}

/// Default category → subscore routing (Module 2 table).
fn route(category: CorruptionCategory, points: u8) -> RulePenalty {
    use CorruptionCategory::*;
    match category {
        StructuralCorruption | BlockReorder | PaddingMismatch => RulePenalty::s(points),
        BitFlip | ChecksumMismatch => RulePenalty::d(points),
        MissingData => RulePenalty::d(points),
        Truncation => RulePenalty::sd(points),
        // A security threat is a policy failure of the whole container: it
        // poisons every subscore (a bomb is never "partially healthy").
        SecurityThreat => RulePenalty::all(points),
    }
}

/// Calibrated per-rule penalties (Phase 3, final — calibration run 005).
///
/// Penalties are sized to the corpus `expected_health_range` of each rule under
/// the frozen formula. Because `overall = s*0.4 + d*0.4 + m*0.2`, a data-only
/// penalty cannot pull `overall` below 60, so corruptions whose expected band
/// is below 60 are routed to all three subscores (`all`). Targets:
/// `[80,100]→d~10`, `[70,95]→d~20`, `[50,79]→sd~44`, `[40,70]→sd~56`,
/// `[20,49]→all~65`, `[0,19]→all~85`. Full methodology, iteration history and
/// known limitations are in `CALIBRATION.md`.
pub static RULE_PENALTIES: &[(&str, RulePenalty)] = &[
    // ZIP — structural catastrophes ([0,19]) route to all three.
    ("ZIP_EOCD_001", RulePenalty::all(85)),
    ("ZIP_EOCD_002", RulePenalty::all(63)), // [20,50]
    ("ZIP_EOCD_003", RulePenalty::all(63)),
    ("ZIP_CD_001", RulePenalty::all(85)),
    ("ZIP_CD_002", RulePenalty::sd(44)), // [50,79]
    ("ZIP_CD_003", RulePenalty::sd(56)), // [40,70]
    ("ZIP_LFH_001", RulePenalty::sd(56)),
    ("ZIP_CRC_001", RulePenalty::d(10)), // [85,100] — extracts with a warning
    ("ZIP_CRC_002", RulePenalty::sd(44)),
    ("ZIP_SIZE_001", RulePenalty::sd(56)),
    ("ZIP_TRUNC_001", RulePenalty::sd(13)),  // [80,99]
    ("ZIP_TRUNC_002", RulePenalty::sd(44)),  // [50,79]
    ("ZIP_TRUNC_003", RulePenalty::all(68)), // [20,49]/[0,19]
    ("ZIP_TRUNC_004", RulePenalty::all(85)), // [0,19]
    ("ZIP_FLIP_001", RulePenalty::d(10)),    // [80,99]
    ("ZIP_FLIP_002", RulePenalty::sd(40)),   // [50,79]
    ("ZIP_FLIP_003", RulePenalty::sd(44)),
    ("ZIP_EXTRA_001", RulePenalty::sd(22)), // [70,95]
    ("ZIP_Z64_001", RulePenalty::sd(56)),   // [40,70]
    // TAR
    ("TAR_UST_001", RulePenalty::sd(25)), // [60,90] checksum, data readable
    ("TAR_TERM_001", RulePenalty::d(10)), // [85,100] benign
    ("TAR_SIZE_001", RulePenalty::sd(44)),
    // Reference-diff's "TAR data missing" rule covers two corpus populations
    // whose bands overlap only at 60: zeroed sector data ([30,60], opens=false)
    // and the corpus's checksum-on-data-block entries ([60,90], opens=true).
    // Target overall 60 to keep both in-range and out of the false_* buckets.
    ("TAR_SIZE_002", RulePenalty::all(40)),
    ("TAR_BLOCK_001", RulePenalty::sd(44)),
    ("TAR_GNU_001", RulePenalty::sd(56)),
    ("TAR_TRUNC_001", RulePenalty::sd(13)),
    ("TAR_TRUNC_002", RulePenalty::sd(44)),
    ("TAR_TRUNC_003", RulePenalty::all(85)),
    ("TAR_FLIP_001", RulePenalty::d(10)),
    ("TAR_FLIP_002", RulePenalty::sd(44)), // [50,75] header multi-flip
    // ISO
    ("ISO_PVD_001", RulePenalty::all(85)),
    ("ISO_PT_001", RulePenalty::all(63)),
    ("ISO_SVD_001", RulePenalty::sd(44)), // [50,80]
    ("ISO_DIR_001", RulePenalty::sd(44)),
    ("ISO_SECTOR_001", RulePenalty::d(10)), // [80,99]
    ("ISO_SECTOR_002", RulePenalty::sd(56)),
    ("ISO_TRUNC_001", RulePenalty::sd(44)),
    ("ISO_TRUNC_002", RulePenalty::all(68)),
    // GZIP
    ("GZ_MAGIC_001", RulePenalty::all(85)),
    ("GZ_ICRC_001", RulePenalty::sd(56)),
    ("GZ_ISIZE_001", RulePenalty::d(15)),
    ("GZ_FLIP_001", RulePenalty::sd(56)),
    // PDF
    ("PDF_HDR_001", RulePenalty::all(85)),
    ("PDF_XREF_001", RulePenalty::sd(44)),
    ("PDF_EOF_001", RulePenalty::sd(30)),
    // SQLite
    ("SQ_MAGIC_001", RulePenalty::all(85)),
    ("SQ_PGSIZE_001", RulePenalty::all(85)),
    ("SQ_PGSIZE_002", RulePenalty::sd(30)),
    ("SQ_FC_001", RulePenalty::s(10)),
    ("SQ_BTREE_001", RulePenalty::sd(44)),
    ("SQ_BTREE_002", RulePenalty::sd(30)),
    ("SQ_BTREE_003", RulePenalty::sd(20)),
    ("SQ_FREE_001", RulePenalty::d(15)),
    ("SQ_FREE_002", RulePenalty::sd(20)),
    ("SQ_WAL_001", RulePenalty::s(10)),
    ("SQ_WAL_002", RulePenalty::s(15)),
    ("SQ_TRUNC_001", RulePenalty::sd(44)),
    ("SQ_TRUNC_002", RulePenalty::all(75)),
    ("SQ_FLIP_001", RulePenalty::d(10)),
    ("SQ_FLIP_002", RulePenalty::sd(25)),
    ("SQ_COMP_001", RulePenalty::all(70)),
    // Generic / cross-format defaults used by reference-diff findings.
    ("GEN_TRUNC_001", RulePenalty::sd(44)),
    ("GEN_FLIP_001", RulePenalty::d(10)),
    ("GEN_MISSING_001", RulePenalty::sd(44)),
    ("GEN_STRUCT_001", RulePenalty::sd(44)),
    ("INTEGRITY_HASH_001", RulePenalty::d(20)),
    ("RAR_MAGIC_001", RulePenalty::all(85)),
    ("7Z_MAGIC_001", RulePenalty::all(85)),
    ("7Z_TRUNC_001", RulePenalty::sd(50)),
    ("BZ2_MAGIC_001", RulePenalty::all(85)),
    ("XZ_MAGIC_001", RulePenalty::all(85)),
    ("ZST_MAGIC_001", RulePenalty::all(85)),
    ("LZ4_MAGIC_001", RulePenalty::all(85)),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_lookup_used_for_listed_rule() {
        // Catastrophic structural rule routes to all three subscores ([0,19]).
        let p = penalty_for(
            "ZIP_EOCD_001",
            Severity::Catastrophic,
            CorruptionCategory::StructuralCorruption,
        );
        assert_eq!(p.points, 85);
        assert!(p.structural && p.data && p.metadata);
    }

    #[test]
    fn crc_is_minor_data_penalty() {
        let p = penalty_for(
            "ZIP_CRC_001",
            Severity::Minor,
            CorruptionCategory::ChecksumMismatch,
        );
        assert_eq!(p, RulePenalty::d(10));
    }

    #[test]
    fn unlisted_rule_falls_back_to_severity_default() {
        let p = penalty_for("ZZZ_UNLISTED", Severity::Minor, CorruptionCategory::BitFlip);
        assert_eq!(p.points, DEFAULT_MINOR);
        assert!(p.data && !p.structural);
    }

    #[test]
    fn unlisted_catastrophic_hits_all_three() {
        let p = penalty_for(
            "UNKNOWN",
            Severity::Catastrophic,
            CorruptionCategory::StructuralCorruption,
        );
        assert!(p.structural && p.data && p.metadata);
        assert_eq!(p.points, DEFAULT_CATASTROPHIC);
    }
}
