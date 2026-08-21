//! Engine integration tests — the required Analysis cases from CLAUDE.md.

use phx_analyze_engine::model::{AnalysisConfig, ArchiveFormat, CorruptionCategory, Severity};
use phx_analyze_engine::{Engine, EngineError};
use phx_test_utils::{assertions, generators, TempDir};

fn analyze(bytes: &[u8], name: &str) -> phx_analyze_engine::AnalysisResult {
    let dir = TempDir::new("analysis").unwrap();
    let path = dir.write_file(name, bytes).unwrap();
    Engine::new()
        .analyze(&path, AnalysisConfig::default())
        .expect("analysis should not error")
}

#[test]
fn good_file_is_perfectly_healthy() {
    let result = analyze(b"clean and intact data", "good.bin");
    assert_eq!(result.health_score.overall, 100);
    assert_eq!(result.recoverability_score.probability, 1.0);
    assert!(result.is_clean());
    assert_eq!(result.archive_format, Some(ArchiveFormat::Raw));
    assertions::assert_result_invariants(&result);
}

#[test]
fn zip_missing_eocd_is_catastrophic_structural() {
    let result = analyze(&generators::zip_without_eocd(), "broken.zip");
    assert_eq!(result.archive_format, Some(ArchiveFormat::Zip));
    let c = result
        .corruptions
        .iter()
        .find(|c| c.category == CorruptionCategory::StructuralCorruption)
        .expect("expected a structural corruption");
    assert_eq!(c.severity, Severity::Catastrophic);
    assertions::assert_result_invariants(&result);
}

#[test]
fn encrypted_zip_errors_rather_than_panicking() {
    let dir = TempDir::new("enc").unwrap();
    let bytes = generators::encrypted_zip("secret.txt", b"hidden");
    let path = dir.write_file("enc.zip", &bytes).unwrap();
    let err = Engine::new()
        .analyze(&path, AnalysisConfig::default())
        .unwrap_err();
    assert!(matches!(err, EngineError::Encrypted(_)));
}

#[test]
fn no_manifest_is_not_an_error() {
    let result = analyze(b"no manifest here", "lonely.bin");
    assert!(!result.integrity_result.manifest_present);
    assert!(result.integrity_result.expected_hash.is_none());
}

#[test]
fn matching_manifest_verifies() {
    let dir = TempDir::new("manifest").unwrap();
    let data = b"data with a sidecar manifest";
    let path = dir.write_file("payload.bin", data).unwrap();
    dir.write_sha256_manifest(&path, data).unwrap();

    let result = Engine::new()
        .analyze(&path, AnalysisConfig::default())
        .unwrap();
    assert!(result.integrity_result.manifest_present);
    assert!(result.integrity_result.matches);
    assert!(result.is_clean());
}

#[test]
fn tampered_manifest_flags_checksum_mismatch() {
    let dir = TempDir::new("tamper").unwrap();
    let original = b"original content";
    let path = dir.write_file("p.bin", original).unwrap();
    // Manifest records the hash of *different* bytes.
    dir.write_sha256_manifest(&path, b"some other content")
        .unwrap();

    let result = Engine::new()
        .analyze(&path, AnalysisConfig::default())
        .unwrap();
    assert!(result.integrity_result.manifest_present);
    assert!(!result.integrity_result.matches);
    assert!(result
        .corruptions
        .iter()
        .any(|c| c.category == CorruptionCategory::ChecksumMismatch));
    assertions::assert_result_invariants(&result);
}

#[test]
fn probability_always_within_bounds() {
    for bytes in [
        b"abc".to_vec(),
        generators::zip_without_eocd(),
        generators::tar_with_file("x", b"data"),
        vec![0u8; 5000],
    ] {
        let result = analyze(&bytes, "case.bin");
        assertions::assert_recoverability_invariants(&result.recoverability_score);
        assertions::assert_health_invariants(&result.health_score);
    }
}
