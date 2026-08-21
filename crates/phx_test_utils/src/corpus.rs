//! Phase 1 corpus data model and a deterministic PRNG.
//!
//! These serde types mirror the `metadata.json` schema in CLAUDE.md Step 1.4.
//! Every corruption entry records how it was generated (`generator_method` +
//! `generator_params`) so the entire corpus is reproducible from a fixed seed.

use serde::{Deserialize, Serialize};

/// One expected corruption finding for a corpus entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedCorruption {
    /// `CorruptionCategory` variant name, e.g. `"ChecksumMismatch"`.
    pub category: String,
    /// `Severity` variant name, e.g. `"Minor"`.
    pub severity: String,
    /// Classifier rule id, e.g. `"ZIP_CRC_001"`.
    pub rule_id: String,
    /// Structural field affected, e.g. `"LocalFileHeader.crc32"`.
    pub affected_field: String,
    /// Inclusive byte-offset range `[start, end]` the damage falls within.
    pub approximate_offset_range: [u64; 2],
}

/// External-tool ground truth for an entry. Commands are templates; the actual
/// exit codes are filled in once a tool has been run against the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GroundTruth {
    pub tool_verify_cmd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_verify_exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_recover_cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_recover_exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_recover_and_test_cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_recover_success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// A single corpus entry (one corrupted file + its ground truth).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub id: String,
    /// Path relative to the `testdata/` root, e.g. `"zip/bad_crc/zip_042.zip"`.
    pub file: String,
    pub format: String,
    /// `"single"` or `"compound"`.
    pub corruption_class: String,
    pub corruption_type: String,
    pub generator_method: String,
    pub generator_params: serde_json::Value,

    pub expected_corruptions: Vec<ExpectedCorruption>,
    pub expected_health_range: [u8; 2],
    /// `"High"`, `"Medium"`, `"Low"`, or `"None"`.
    pub expected_recoverability: String,
    pub expected_opens: bool,
    pub expected_extractable_pct: u8,

    pub ground_truth: GroundTruth,

    #[serde(default)]
    pub compound: bool,
    #[serde(default)]
    pub compound_ids: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl CorpusEntry {
    /// Validate the required fields per Step 1.4. Returns the list of problems
    /// (empty = valid).
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();
        let mut req = |cond: bool, msg: &str| {
            if !cond {
                errs.push(format!("{}: {msg}", self.id));
            }
        };
        req(!self.id.is_empty(), "id is empty");
        req(!self.file.is_empty(), "file is empty");
        req(!self.format.is_empty(), "format is empty");
        req(!self.corruption_type.is_empty(), "corruption_type is empty");
        req(
            !self.expected_corruptions.is_empty(),
            "expected_corruptions is empty",
        );
        req(
            self.expected_health_range[0] <= self.expected_health_range[1]
                && self.expected_health_range[1] <= 100,
            "expected_health_range invalid",
        );
        req(
            matches!(
                self.expected_recoverability.as_str(),
                "High" | "Medium" | "Low" | "None"
            ),
            "expected_recoverability not in {High,Medium,Low,None}",
        );
        req(
            !self.ground_truth.tool_verify_cmd.is_empty(),
            "ground_truth.tool_verify_cmd is empty",
        );
        for (i, c) in self.expected_corruptions.iter().enumerate() {
            req(
                !c.rule_id.is_empty(),
                &format!("expected_corruptions[{i}].rule_id empty"),
            );
            req(
                c.approximate_offset_range[0] <= c.approximate_offset_range[1],
                &format!("expected_corruptions[{i}].approximate_offset_range reversed"),
            );
        }
        errs
    }
}

/// Per-format `metadata.json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatMetadata {
    pub format: String,
    pub generated_with_seed: u64,
    pub entries: Vec<CorpusEntry>,
}

/// A clean reference file and its external-tool verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanFile {
    pub format: String,
    pub file: String,
    pub verify_cmd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Root `corpus_index.json` aggregating every format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusIndex {
    pub schema_version: String,
    pub generated_with_seed: u64,
    pub total_entries: usize,
    pub formats: Vec<FormatSummary>,
    #[serde(default)]
    pub clean_files: Vec<CleanFile>,
}

/// Summary of one format inside the corpus index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatSummary {
    pub format: String,
    pub entry_count: usize,
    pub metadata_path: String,
}

/// SplitMix64 — a tiny, deterministic, dependency-free PRNG. Same seed always
/// yields the same stream, which is what makes the corpus reproducible.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    /// Derive an independent stream keyed by a string (e.g. an entry id), so
    /// each corpus entry is reproducible regardless of generation order.
    pub fn keyed(seed: u64, key: &str) -> Self {
        let mut h: u64 = seed ^ 0x9E37_79B9_7F4A_7C15;
        for b in key.bytes() {
            h = (h ^ b as u64).wrapping_mul(0x0100_0000_01B3); // FNV-ish mix
        }
        SplitMix64::new(h)
    }

    /// Next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform value in `0..bound` (bound must be > 0).
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_is_deterministic_for_same_seed() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn keyed_streams_differ_by_key() {
        let mut a = SplitMix64::keyed(7, "ZIP_001");
        let mut b = SplitMix64::keyed(7, "ZIP_002");
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn entry_validation_catches_missing_fields() {
        let entry = CorpusEntry {
            id: String::new(),
            file: "x".into(),
            format: "ZIP".into(),
            corruption_class: "single".into(),
            corruption_type: "CRC_MISMATCH".into(),
            generator_method: "zip_corrupt_crc".into(),
            generator_params: serde_json::json!({}),
            expected_corruptions: vec![],
            expected_health_range: [80, 100],
            expected_recoverability: "High".into(),
            expected_opens: true,
            expected_extractable_pct: 100,
            ground_truth: GroundTruth::default(),
            compound: false,
            compound_ids: vec![],
            tags: vec![],
        };
        let errs = entry.validate();
        assert!(errs.iter().any(|e| e.contains("id is empty")));
        assert!(errs
            .iter()
            .any(|e| e.contains("expected_corruptions is empty")));
        assert!(errs.iter().any(|e| e.contains("tool_verify_cmd is empty")));
    }
}
