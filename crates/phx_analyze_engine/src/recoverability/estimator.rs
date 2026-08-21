//! Recoverability heuristic (Module 5 formula, calibrated in Phase 4).
//!
//! `probability = clamp(BASE + Σ factors, 0.0, 1.0)`, then bucketed into a
//! [`RecoverabilityClass`] by [`RecoverabilityScore::class`]. Every factor
//! weight is a named constant in [`super::weights`]; this file contains no
//! magic numbers. Confidence reflects how complete/clean the scan itself was.
//! This is a heuristic only — actual repair lives in `phx_recovery`.

use crate::model::{
    ArchiveFormat, Corruption, CorruptionCategory, RecoverabilityScore, RecoveryFactor, Severity,
};

use super::weights as w;

/// Inputs the estimator needs beyond the corruption list.
pub struct Inputs<'a> {
    pub corruptions: &'a [Corruption],
    pub format: Option<ArchiveFormat>,
    pub manifest_present: bool,
    /// Format-embedded checksums (e.g. ZIP CRC-32) are present.
    pub embedded_checksums_present: bool,
    pub total_size: u64,
    /// Corruption scan stopped at the configured cap.
    pub scan_capped: bool,
    /// I/O errors occurred during the scan.
    pub io_errors: bool,
    /// Format detection failed (fell back to Raw unexpectedly).
    pub format_detection_failed: bool,
}

/// Estimate recoverability.
pub fn estimate(inputs: &Inputs) -> RecoverabilityScore {
    // Undamaged input is fully recoverable with full confidence.
    if inputs.corruptions.is_empty() && !inputs.io_errors {
        return RecoverabilityScore::certain();
    }

    // A security threat (bomb, quine, traversal) is unrecoverable by policy —
    // the container's behaviour is hostile, not merely damaged. Skip the factor
    // accumulation entirely; the class is definitively None.
    if inputs
        .corruptions
        .iter()
        .any(|c| c.category == CorruptionCategory::SecurityThreat)
    {
        return RecoverabilityScore::new(
            0.0,
            1.0,
            vec![RecoveryFactor::new(
                "security threat detected — unrecoverable by policy",
                -1.0,
            )],
        );
    }

    let mut factors: Vec<RecoveryFactor> = Vec::new();
    let mut prob = w::BASE;
    let mut add = |name: &str, weight: f64| {
        prob += weight;
        factors.push(RecoveryFactor::new(name, weight));
    };

    let has_rule = |id: &str| -> bool {
        inputs
            .corruptions
            .iter()
            .any(|c| c.chain.primary.rule_id == id)
    };
    let has_rule_prefix = |prefix: &str| -> bool {
        inputs
            .corruptions
            .iter()
            .any(|c| c.chain.primary.rule_id.starts_with(prefix))
    };
    let has_rule_suffix = |suffix: &str| -> bool {
        inputs
            .corruptions
            .iter()
            .any(|c| c.chain.primary.rule_id.ends_with(suffix))
    };

    // ---- Positive factors (Step 4.3) ----
    let all_bitflip = !inputs.corruptions.is_empty()
        && inputs
            .corruptions
            .iter()
            .all(|c| c.category == CorruptionCategory::BitFlip);
    if all_bitflip {
        add("bitflip-only damage", w::BITFLIP_ONLY);
    }

    // TAR checksum-only damage: every finding is a UStar checksum defect.
    let tar_checksum_only = !inputs.corruptions.is_empty()
        && inputs
            .corruptions
            .iter()
            .all(|c| c.chain.primary.rule_id == "TAR_UST_001");
    if tar_checksum_only {
        add("TAR checksum only", w::TAR_CHECKSUM_ONLY);
    }

    // ZIP redundancy: the central directory and local headers back each other
    // up, so damage is recoverable unless the directory itself is gone.
    if inputs.format == Some(ArchiveFormat::Zip)
        && !has_rule("ZIP_CD_001")
        && !has_rule("ZIP_TRUNC_004")
    {
        add("ZIP central directory intact", w::ZIP_REDUNDANCY);
    }

    // Linearized PDF: when the header survives, the first-page object set is
    // typically recoverable. PDF is carried via rule ids (the engine detects it
    // as Raw), so key on a PDF finding whose header is intact.
    if has_rule_prefix("PDF_") && !has_rule("PDF_HDR_001") {
        add("PDF linearization hint", w::PDF_LINEARIZATION);
    }

    // SQLite WAL provides transaction recovery of the main database.
    if has_rule("SQ_WAL_001") {
        add("SQLite WAL recovery", w::SQLITE_WAL);
    }

    if inputs.manifest_present {
        add("external manifest available", w::EXTERNAL_MANIFEST);
    }

    if inputs.embedded_checksums_present {
        add("embedded checksums present", w::EMBEDDED_CHECKSUMS);
    }

    if let Some(frac) = damage_fraction(inputs) {
        if frac < 0.01 {
            add("small damage area <1%", w::SMALL_DAMAGE_AREA);
        }
    }

    // ---- Negative factors (Step 4.3) ----
    // A definitive unrecoverable signal: the format's entry signature is gone,
    // the header was truncated away, or the DB page size is unparseable. These
    // are the only conditions that justify a `None` verdict — anything else is
    // at worst forensic (Low). Each also contributes an explanatory factor.
    //
    // GZ_MAGIC_001 is excluded: the GZIP magic is a known 2-byte constant that
    // GzMagicRestore writes back deterministically. Treating it as unrecoverable
    // would contradict recovery success (GzMagicRestore restores health to 100).
    let signature_missing =
        (has_rule_suffix("_MAGIC_001") && !has_rule("GZ_MAGIC_001")) || has_rule("PDF_HDR_001");
    if signature_missing {
        add("format signature destroyed", w::SIGNATURE_MISSING);
    }
    if has_rule("SQ_PGSIZE_001") {
        add("SQLite page size invalid", w::DB_PAGE_SIZE_INVALID);
    }
    if truncation_at_header(inputs) || has_rule("ZIP_TRUNC_004") || has_rule("TAR_TRUNC_003") {
        add("truncation at header", w::TRUNCATED_AT_HEADER);
    }
    let unrecoverable = signature_missing
        || has_rule("SQ_PGSIZE_001")
        || has_rule("ZIP_TRUNC_004")
        || has_rule("TAR_TRUNC_003");

    let missing = inputs
        .corruptions
        .iter()
        .filter(|c| c.category == CorruptionCategory::MissingData)
        .count();
    if missing > 0 {
        add("missing data", w::MISSING_DATA * missing as f64);
    }

    // A catastrophic structural defect with no format redundancy to rebuild
    // from. ZIP directory/EOCD catastrophes are excluded: the redundancy factor
    // already credits their recoverability and `zip -FF` handles them.
    let zip_redundant_catastrophe = inputs.format == Some(ArchiveFormat::Zip)
        && (has_rule("ZIP_EOCD_001") || has_rule("ZIP_EOCD_002") || has_rule("ZIP_EOCD_003"))
        && !has_rule("ZIP_CD_001");
    if !zip_redundant_catastrophe
        && inputs.corruptions.iter().any(|c| {
            c.category == CorruptionCategory::StructuralCorruption
                && c.severity == Severity::Catastrophic
        })
    {
        add(
            "catastrophic structural corruption",
            w::CATASTROPHIC_STRUCTURAL,
        );
    }

    if !inputs.manifest_present && !inputs.embedded_checksums_present {
        add("no manifest and no checksums", w::NO_MANIFEST_NO_CHECKSUMS);
    }

    // Clamp to the class floor/ceiling: `None` is reserved for a definitive
    // unrecoverable signal; everything else is at worst Low.
    let probability = if unrecoverable {
        prob.min(w::NONE_CEILING)
    } else {
        prob.clamp(w::LOW_FLOOR, 1.0)
    };
    let confidence = confidence(inputs);
    RecoverabilityScore::new(probability, confidence, factors)
}

/// Fraction of the stream covered by located damage, if measurable.
fn damage_fraction(inputs: &Inputs) -> Option<f64> {
    if inputs.total_size == 0 {
        return None;
    }
    let damaged: u64 = inputs
        .corruptions
        .iter()
        .filter_map(|c| c.byte_range.map(|r| r.len()))
        .sum();
    if damaged == 0 {
        return None;
    }
    Some(damaged as f64 / inputs.total_size as f64)
}

fn truncation_at_header(inputs: &Inputs) -> bool {
    if inputs.total_size == 0 {
        return false;
    }
    let head = (inputs.total_size as f64 * 0.10) as u64;
    inputs.corruptions.iter().any(|c| {
        c.category == CorruptionCategory::Truncation
            && c.location.offset_end > 0
            && c.location.offset_end < head
    })
}

fn confidence(inputs: &Inputs) -> f64 {
    if inputs.format_detection_failed {
        0.3
    } else if inputs.io_errors {
        0.4
    } else if inputs.scan_capped {
        0.6
    } else {
        1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ByteRange, CorruptionLocation};

    fn corruption(cat: CorruptionCategory, sev: Severity, range: ByteRange) -> Corruption {
        Corruption::synthetic(
            CorruptionLocation {
                file_path: None,
                offset_start: range.start,
                offset_end: range.end,
            },
            cat,
            sev,
            "GEN_STRUCT_001",
            Some(range),
        )
    }

    fn base_inputs(corruptions: &[Corruption]) -> Inputs<'_> {
        Inputs {
            corruptions,
            format: Some(ArchiveFormat::Raw),
            manifest_present: false,
            embedded_checksums_present: false,
            total_size: 10_000,
            scan_capped: false,
            io_errors: false,
            format_detection_failed: false,
        }
    }

    #[test]
    fn clean_is_certain() {
        let s = estimate(&base_inputs(&[]));
        assert_eq!(s.probability, 1.0);
        assert_eq!(s.confidence, 1.0);
    }

    #[test]
    fn probability_always_in_range() {
        let cs = vec![
            corruption(
                CorruptionCategory::MissingData,
                Severity::Catastrophic,
                ByteRange::new(0, 5000),
            ),
            corruption(
                CorruptionCategory::MissingData,
                Severity::Catastrophic,
                ByteRange::new(5000, 9000),
            ),
            corruption(
                CorruptionCategory::StructuralCorruption,
                Severity::Catastrophic,
                ByteRange::new(0, 10),
            ),
        ];
        let s = estimate(&base_inputs(&cs));
        assert!((0.0..=1.0).contains(&s.probability));
    }

    #[test]
    fn manifest_and_bitflip_raise_probability() {
        let cs = vec![corruption(
            CorruptionCategory::BitFlip,
            Severity::Minor,
            ByteRange::new(0, 4),
        )];
        let mut inputs = base_inputs(&cs);
        inputs.manifest_present = true;
        let s = estimate(&inputs);
        // 0.5 + 0.10 (bitflip) + 0.15 (manifest) + 0.10 (small area) = 0.85
        assert!(s.probability > 0.8);
    }

    #[test]
    fn security_threat_forces_none() {
        let cs = vec![corruption(
            CorruptionCategory::SecurityThreat,
            Severity::Catastrophic,
            ByteRange::new(0, 100),
        )];
        let s = estimate(&base_inputs(&cs));
        assert_eq!(s.class(), crate::model::RecoverabilityClass::None);
        assert_eq!(s.probability, 0.0);
        assert!(s.factors.iter().any(|f| f.name.contains("security threat")));
    }

    #[test]
    fn capped_scan_lowers_confidence() {
        let cs = vec![corruption(
            CorruptionCategory::BitFlip,
            Severity::Minor,
            ByteRange::new(0, 4),
        )];
        let mut inputs = base_inputs(&cs);
        inputs.scan_capped = true;
        assert_eq!(estimate(&inputs).confidence, 0.6);
    }
}
