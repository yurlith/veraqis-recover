//! Recovery integration tests.

use phx_analyze_engine::model::AnalysisConfig;
use phx_analyze_engine::reader::{ArchiveReader, DataSource, ZipReader};
use phx_analyze_engine::Engine;
use phx_recovery::{RecoveryEngine, RecoveryOptions};
use phx_test_utils::{generators, TempDir};

fn analyze(path: &std::path::Path) -> phx_analyze_engine::AnalysisResult {
    Engine::new()
        .analyze(path, AnalysisConfig::default())
        .unwrap()
}

#[test]
fn zip_rebuild_produces_navigable_archive() {
    let dir = TempDir::new("recover-zip").unwrap();
    let bytes = generators::zip_local_header_only("hello.txt", b"hello world");
    let src = dir.write_file("broken.zip", &bytes).unwrap();
    let analysis = analyze(&src);

    let out_dir = dir.path().join("out");
    let options = RecoveryOptions {
        output_dir: out_dir.clone(),
        forced_strategy: Some("zip-rebuild".to_string()),
        hash_type: analysis.integrity_result.hash_type,
        ..Default::default()
    };

    let report = RecoveryEngine::new()
        .recover(&src, &analysis, &options)
        .unwrap();
    assert!(report.success);
    assert!(report.output_path.exists());

    // The rebuilt archive now has a discoverable central directory.
    let recovered = std::fs::read(&report.output_path).unwrap();
    let ds = DataSource::from_bytes("rebuilt.zip", recovered);
    let entries = ZipReader.entries(&ds).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_string_lossy(), "hello.txt");
}

#[test]
fn output_path_differs_from_source() {
    let dir = TempDir::new("recover-out").unwrap();
    let bytes = generators::zip_local_header_only("a.txt", b"abc");
    let src = dir.write_file("in.zip", &bytes).unwrap();
    let analysis = analyze(&src);

    let options = RecoveryOptions {
        output_dir: dir.path().to_path_buf(),
        forced_strategy: Some("partial-extract".to_string()),
        ..Default::default()
    };
    let report = RecoveryEngine::new()
        .recover(&src, &analysis, &options)
        .unwrap();
    assert_ne!(report.output_path, src);
}

#[test]
fn recovery_records_health_and_never_regresses() {
    // Phase 6 rollback guarantee: the committed output's health is recorded and
    // is never worse than the source's (auto-rollback otherwise).
    let dir = TempDir::new("recover-health").unwrap();
    let bytes = generators::zip_local_header_only("hello.txt", b"hello world");
    let src = dir.write_file("broken.zip", &bytes).unwrap();
    let analysis = analyze(&src);

    let options = RecoveryOptions {
        output_dir: dir.path().join("out"),
        ..Default::default()
    };
    let report = RecoveryEngine::new()
        .recover(&src, &analysis, &options)
        .unwrap();

    let before = report.health_before.expect("health_before recorded");
    let after = report.health_after.expect("health_after recorded");
    assert!(
        after >= before,
        "recovery must not regress health ({before} -> {after})"
    );
    // Rebuilding the directory should strictly improve a header-only ZIP.
    assert!(
        after > before,
        "expected health improvement ({before} -> {after})"
    );

    // A signed repair manifest sidecar is written by default (Step 6.3).
    let manifest = report.manifest_path.expect("manifest written by default");
    assert!(manifest.exists(), "manifest sidecar must exist on disk");
    let json = std::fs::read_to_string(&manifest).unwrap();
    assert!(json.contains("\"signature\""), "manifest must be signed");
    assert!(
        json.contains("ZIP_EOCD_001"),
        "manifest records the repaired rule"
    );
}

#[test]
fn stream_recovery_rebuilds_in_memory_without_sidecar() {
    // Step 6.4: bytes-in/bytes-out recovery for --stdin/--stdout.
    let bytes = generators::zip_local_header_only("hi.txt", b"hi there");
    let label = std::path::Path::new("stream.zip");
    let (out, report) = RecoveryEngine::new()
        .recover_stream(&bytes, label, &RecoveryOptions::default())
        .unwrap();

    // The rebuilt stream is a navigable archive.
    let ds = DataSource::from_bytes("out.zip", out);
    let entries = ZipReader.entries(&ds).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path.to_string_lossy(), "hi.txt");
    // A pure stream writes no manifest sidecar.
    assert!(report.manifest_path.is_none());
}

#[test]
fn stream_passthrough_on_clean_input() {
    // A clean archive streams through unchanged (faithful passthrough).
    let bytes = generators::clean_tar(&[("a.txt", b"hello")]);
    let (out, _report) = RecoveryEngine::new()
        .recover_stream(
            &bytes,
            std::path::Path::new("stream.tar"),
            &RecoveryOptions::default(),
        )
        .unwrap();
    assert_eq!(out, bytes, "clean input must pass through byte-for-byte");
}

#[test]
fn dry_run_writes_no_output() {
    let dir = TempDir::new("recover-dry").unwrap();
    let bytes = generators::zip_local_header_only("a.txt", b"abc");
    let src = dir.write_file("in.zip", &bytes).unwrap();
    let analysis = analyze(&src);

    let options = RecoveryOptions {
        output_dir: dir.path().join("dry"),
        forced_strategy: Some("partial-extract".to_string()),
        dry_run: true,
        ..Default::default()
    };
    let report = RecoveryEngine::new()
        .recover(&src, &analysis, &options)
        .unwrap();
    assert!(!report.output_path.exists());
}
