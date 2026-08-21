//! Classification: map a located raw defect to a typed [`Corruption`] with a
//! [`ChainOfEvidence`], and merge adjacent same-kind damage.
//!
//! Category/severity/evidence-type/affected-field all come from the rule
//! registry ([`super::rules`]); confidence comes from [`super::confidence`].
//! This module assigns no free-form descriptions — they are auto-generated.

use crate::model::{
    ByteRange, ChainOfEvidence, Corruption, CorruptionCategory, CorruptionLocation, Evidence,
    MIN_EMIT_CONFIDENCE,
};

use super::confidence;
use super::rules;

/// A defect located by the detector, before category/severity/evidence are
/// resolved from the rule registry.
#[derive(Debug, Clone)]
pub struct Detected {
    pub kind: DefectKind,
    pub location: CorruptionLocation,
    pub byte_range: Option<ByteRange>,
    /// Bytes observed at the defect (captured by the detector, ≤ 64).
    pub actual_bytes: Vec<u8>,
    /// Expected bytes, when known (signatures/checksums).
    pub expected_bytes: Option<Vec<u8>>,
    /// Confidence override; when `None` the rule/evidence-type default is used.
    pub confidence: Option<f64>,
    /// Explicit rule id (reference-diff findings compute it directly); when
    /// `None` the kind's default rule id is used.
    pub rule_id_override: Option<&'static str>,
    /// Extra human-readable context (not used for the auto description).
    pub detail: String,
}

impl Detected {
    pub fn new(kind: DefectKind, location: CorruptionLocation) -> Self {
        Detected {
            kind,
            location,
            byte_range: None,
            actual_bytes: Vec::new(),
            expected_bytes: None,
            confidence: None,
            rule_id_override: None,
            detail: String::new(),
        }
    }

    /// Build a reference-diff finding with an explicit rule id.
    pub fn with_rule(mut self, rule_id: &'static str) -> Self {
        self.rule_id_override = Some(rule_id);
        self
    }

    pub fn with_range(mut self, range: ByteRange) -> Self {
        self.byte_range = Some(range);
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn with_bytes(mut self, actual: Vec<u8>, expected: Option<Vec<u8>>) -> Self {
        self.actual_bytes = actual;
        self.expected_bytes = expected;
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = Some(confidence);
        self
    }
}

/// The kinds of defect the detector can locate. Each maps to a registry rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefectKind {
    ZipMissingEocd,
    ZipEocdCdOffsetOob,
    ZipCentralDirectoryMissing,
    ZipCentralDirectoryDamaged,
    ZipEntryCountMismatch,
    ZipLocalHeaderMissing,
    ZipCrcMismatch,
    /// LFH compressed_size differs from the CD compressed_size for the same entry.
    ZipSizeMismatch,
    TarHeaderChecksumBad,
    // ── SQLite ───────────────────────────────────────────────────────────────
    SqMagicBad,
    SqPageSizeBad,
    SqPageSizeMismatch,
    SqFileChangeCounter,
    SqBtreePageTypeBad,
    SqBtreeCellCountBad,
    SqBtreeCellPtrBad,
    SqFreelistTrunkBad,
    SqFreelistCountBad,
    SqTruncatedMidPage,
    SqTruncatedBeforePage2,
    SqWalMagicBad,
    SqWalSaltMismatch,
    TarMissingTerminator,
    TarTruncated,
    IsoMissingPvd,
    IsoPathTableOutOfBounds,
    /// GZIP magic bytes `1F 8B` are wrong or missing.
    GzMagicBad,
    /// GZIP compression method byte (byte 2) is not `08`.
    GzCompressionMethodBad,
    /// GZIP stream shorter than the minimum 18-byte header+trailer.
    GzTruncated,
    /// GZIP CRC32 in the trailer does not match the decompressed content.
    GzCrcBad,
    /// GZIP ISIZE field does not match the decompressed size.
    GzIsizeBad,
    /// 7-Zip signature (`37 7A BC AF 27 1C`) corrupted.
    SevenZMagicBad,
    /// 7-Zip Start Header CRC-32 does not match the start-header bytes.
    SevenZStartHeaderCrcBad,
    /// 7-Zip end header (CRC-proven `NextHeaderOffset`+`Size`) lies past EOF →
    /// the file was truncated (the only structure map is gone).
    SevenZEndHeaderOob,
    /// RAR signature (`Rar!\x1A\x07..`) corrupted.
    RarMagicBad,
    /// Whole-stream hash disagreed with the manifest.
    ManifestHashMismatch,
    /// A single flipped-bit region, located against a block reference.
    BitFlipRegion,
    /// A finding produced by reference-diff; carries an explicit rule id.
    ReferenceDiff,
}

impl DefectKind {
    /// Registry rule id for this defect kind.
    pub fn rule_id(self) -> &'static str {
        match self {
            DefectKind::ZipMissingEocd => "ZIP_EOCD_001",
            DefectKind::ZipEocdCdOffsetOob => "ZIP_EOCD_002",
            DefectKind::ZipCentralDirectoryMissing => "ZIP_CD_001",
            DefectKind::ZipCentralDirectoryDamaged => "ZIP_CD_002",
            DefectKind::ZipEntryCountMismatch => "ZIP_CD_003",
            DefectKind::ZipLocalHeaderMissing => "ZIP_LFH_001",
            DefectKind::ZipCrcMismatch => "ZIP_CRC_001",
            DefectKind::ZipSizeMismatch => "ZIP_SIZE_001",
            DefectKind::TarHeaderChecksumBad => "TAR_UST_001",
            // SQLite
            DefectKind::SqMagicBad => "SQ_MAGIC_001",
            DefectKind::SqPageSizeBad => "SQ_PGSIZE_001",
            DefectKind::SqPageSizeMismatch => "SQ_PGSIZE_002",
            DefectKind::SqFileChangeCounter => "SQ_FC_001",
            DefectKind::SqBtreePageTypeBad => "SQ_BTREE_001",
            DefectKind::SqBtreeCellCountBad => "SQ_BTREE_002",
            DefectKind::SqBtreeCellPtrBad => "SQ_BTREE_003",
            DefectKind::SqFreelistTrunkBad => "SQ_FREE_001",
            DefectKind::SqFreelistCountBad => "SQ_FREE_002",
            DefectKind::SqTruncatedMidPage => "SQ_TRUNC_001",
            DefectKind::SqTruncatedBeforePage2 => "SQ_TRUNC_002",
            DefectKind::SqWalMagicBad => "SQ_WAL_001",
            DefectKind::SqWalSaltMismatch => "SQ_WAL_002",
            DefectKind::TarMissingTerminator => "TAR_TERM_001",
            DefectKind::TarTruncated => "TAR_TRUNC_002",
            DefectKind::IsoMissingPvd => "ISO_PVD_001",
            DefectKind::IsoPathTableOutOfBounds => "ISO_PT_001",
            DefectKind::GzMagicBad => "GZ_MAGIC_001",
            DefectKind::GzCompressionMethodBad => "GZ_CM_001",
            DefectKind::GzTruncated => "GZ_TRUNC_001",
            DefectKind::GzCrcBad => "GZ_ICRC_001",
            DefectKind::GzIsizeBad => "GZ_ISIZE_001",
            DefectKind::SevenZMagicBad => "7Z_MAGIC_001",
            DefectKind::SevenZStartHeaderCrcBad => "7Z_CRC_001",
            DefectKind::SevenZEndHeaderOob => "7Z_TRUNC_001",
            DefectKind::RarMagicBad => "RAR_MAGIC_001",
            DefectKind::ManifestHashMismatch => "INTEGRITY_HASH_001",
            DefectKind::BitFlipRegion => "GEN_FLIP_001",
            DefectKind::ReferenceDiff => "GEN_STRUCT_001",
        }
    }
}

/// Turn a located defect into a typed [`Corruption`], or `None` if the
/// aggregate confidence falls below [`MIN_EMIT_CONFIDENCE`] (recorded as a
/// warning by the caller, never added to the corruptions vector).
pub fn classify(detected: Detected) -> Option<Corruption> {
    let rule_id = detected.rule_id_override.unwrap_or(detected.kind.rule_id());
    let rule = rules::rule(rule_id).expect("every rule id must be registered");

    let conf = match detected.confidence {
        Some(c) => c,
        None if rule.confidence_deterministic => 1.0,
        None => confidence::base(rule.evidence_type),
    };

    let evidence = Evidence::new(
        detected.location.offset_start,
        detected.expected_bytes,
        detected.actual_bytes,
        rule.affected_field,
        rule.description,
        conf,
        rule.id,
        rule.evidence_type,
    );
    let chain = ChainOfEvidence::single(evidence);

    if chain.aggregate_confidence < MIN_EMIT_CONFIDENCE {
        return None;
    }

    Some(Corruption::from_chain(
        detected.location,
        rule.category,
        rule.default_severity,
        chain,
        detected.byte_range,
    ))
}

/// Merge adjacent/overlapping `BitFlip` corruptions into single records.
///
/// Other categories pass through unchanged. A merged region spans the lowest
/// start to the highest end and takes the group's highest severity; its
/// description is regenerated from the (updated) primary evidence.
pub fn merge_adjacent(corruptions: Vec<Corruption>) -> Vec<Corruption> {
    let (mut bitflips, others): (Vec<_>, Vec<_>) = corruptions
        .into_iter()
        .partition(|c| c.category == CorruptionCategory::BitFlip && c.byte_range.is_some());

    bitflips.sort_by_key(|c| c.byte_range.unwrap().start);

    let mut merged: Vec<Corruption> = Vec::new();
    for c in bitflips {
        let range = c.byte_range.unwrap();
        match merged.last_mut() {
            Some(prev) if prev.byte_range.unwrap().adjacent_or_overlapping(&range) => {
                let prev_range = prev.byte_range.unwrap();
                let new_range = ByteRange::new(
                    prev_range.start.min(range.start),
                    prev_range.end.max(range.end),
                );
                prev.byte_range = Some(new_range);
                prev.location.offset_start = new_range.start;
                prev.location.offset_end = new_range.end;
                prev.severity = prev.severity.max(c.severity);
                prev.chain.primary.offset = new_range.start;
                prev.refresh_description();
            }
            _ => merged.push(c),
        }
    }

    merged.extend(others);
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn bitflip(start: u64, end: u64) -> Corruption {
        Corruption::synthetic(
            CorruptionLocation::stream(start, end),
            CorruptionCategory::BitFlip,
            Severity::Minor,
            "GEN_FLIP_001",
            Some(ByteRange::new(start, end)),
        )
    }

    #[test]
    fn classify_missing_eocd_is_catastrophic_structural() {
        let d = Detected::new(DefectKind::ZipMissingEocd, CorruptionLocation::stream(0, 0))
            .with_bytes(vec![0, 0, 0, 0], Some(vec![0x50, 0x4B, 0x05, 0x06]));
        let c = classify(d).unwrap();
        assert_eq!(c.category, CorruptionCategory::StructuralCorruption);
        assert_eq!(c.severity, Severity::Catastrophic);
        assert_eq!(c.chain.primary.rule_id, "ZIP_EOCD_001");
        assert_eq!(c.chain.aggregate_confidence, 1.0);
        assert!(c.description.contains("ZIP_EOCD_001"));
    }

    #[test]
    fn adjacent_bitflips_merge_into_one() {
        let input = vec![bitflip(0, 4), bitflip(4, 8), bitflip(20, 24)];
        let merged = merge_adjacent(input);
        let flips: Vec<_> = merged
            .iter()
            .filter(|c| c.category == CorruptionCategory::BitFlip)
            .collect();
        assert_eq!(flips.len(), 2);
        let first = flips
            .iter()
            .find(|c| c.byte_range.unwrap().start == 0)
            .unwrap();
        assert_eq!(first.byte_range.unwrap().end, 8);
    }

    #[test]
    fn non_bitflip_passes_through() {
        let s = Corruption::synthetic(
            CorruptionLocation::stream(0, 1),
            CorruptionCategory::StructuralCorruption,
            Severity::Major,
            "ZIP_CD_002",
            None,
        );
        let out = merge_adjacent(vec![s]);
        assert_eq!(out.len(), 1);
    }
}
