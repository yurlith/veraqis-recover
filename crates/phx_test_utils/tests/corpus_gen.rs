//! Phase 1: CorpusGenerator produces valid, analyzable corpus entries.

use phx_analyze_engine::model::{AnalysisConfig, CorruptionCategory};
use phx_analyze_engine::Engine;
use phx_test_utils::generators::{clean_zip, CorpusGenerator};
use phx_test_utils::TempDir;

const MEMBERS: &[(&str, &[u8])] = &[
    ("a.txt", b"first member content"),
    ("b.txt", b"second member content"),
    ("c.txt", b"third member content"),
];

#[test]
fn generated_crc_entry_is_valid_and_analyzable() {
    let dir = TempDir::new("corpus").unwrap();
    let clean = clean_zip(MEMBERS);
    let g = CorpusGenerator::new(dir.path(), "ZIP", "zip", "zip", clean, 12345);

    let entry = g.zip_corrupt_crc(0, "ZIP_TEST_0001").unwrap();

    // Metadata is schema-valid.
    assert!(entry.validate().is_empty(), "{:?}", entry.validate());
    assert_eq!(entry.expected_corruptions[0].rule_id, "ZIP_CRC_001");

    // The file was written where the metadata says.
    let path = dir.path().join(&entry.file);
    assert!(path.exists(), "missing {}", path.display());

    // The engine analyzes it without error and flags the CRC mismatch.
    let result = Engine::new()
        .analyze(&path, AnalysisConfig::default())
        .expect("analysis must not error");
    assert!(result
        .corruptions
        .iter()
        .any(|c| c.category == CorruptionCategory::ChecksumMismatch));
}

#[test]
fn clean_zip_is_perfectly_healthy() {
    let dir = TempDir::new("corpus-clean").unwrap();
    let clean = clean_zip(MEMBERS);
    let path = dir.write_file("clean.zip", &clean).unwrap();
    let result = Engine::new()
        .analyze(&path, AnalysisConfig::default())
        .unwrap();
    assert_eq!(result.health_score.overall, 100);
    assert!(result.is_clean());
}

#[test]
fn generator_is_reproducible() {
    // Same seed + id → identical bytes on disk.
    let d1 = TempDir::new("repro1").unwrap();
    let d2 = TempDir::new("repro2").unwrap();
    let clean = clean_zip(MEMBERS);
    let g1 = CorpusGenerator::new(d1.path(), "ZIP", "zip", "zip", clean.clone(), 999);
    let g2 = CorpusGenerator::new(d2.path(), "ZIP", "zip", "zip", clean, 999);

    let e1 = g1.random_bitflips_payload(5, "SAME_ID").unwrap();
    let e2 = g2.random_bitflips_payload(5, "SAME_ID").unwrap();

    let b1 = std::fs::read(d1.path().join(&e1.file)).unwrap();
    let b2 = std::fs::read(d2.path().join(&e2.file)).unwrap();
    assert_eq!(b1, b2, "same seed+id must produce identical bytes");
}
