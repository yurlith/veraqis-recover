//! Regression tests binding the three Evidence-model tautology fixes measured
//! by EXP-PCRB-PUBLIC run 1 (BENCHMARKS.md, Moat M2; fixed in the Phase-6
//! engine). Each test discriminates one corrected behavior: it fails against
//! the pre-fix engine and passes against the fixed one.

use phx_analyze_engine::model::AnalysisConfig;
use phx_analyze_engine::Engine;
use phx_recovery::{RecoveryEngine, RecoveryOptions};
use phx_test_utils::{generators, TempDir};

fn analyze(path: &std::path::Path) -> phx_analyze_engine::AnalysisResult {
    Engine::new()
        .analyze(path, AnalysisConfig::default())
        .unwrap()
}

/// A compressible payload large enough that truncation cuts mid-DEFLATE-body.
fn payload() -> Vec<u8> {
    b"verified recovery, not trust marketing. "
        .repeat(2048)
        .to_vec()
}

/// Fix 1 — `GzTrailerRecompute` must not self-validate a corrupt payload:
/// on a truncated stream (payload provably incomplete), recomputing CRC32 +
/// ISIZE over the partial decode and rewriting the last 8 bytes destroys
/// compressed data and stamps a fitted CRC onto bytes the format cannot
/// vouch for. Run 1 measured 180 false bytes + a false `lost=0B` claim from
/// exactly this path. The strategy must refuse (no output artifact).
#[test]
fn trailer_recompute_refuses_a_stream_that_does_not_reach_end_of_stream() {
    let dir = TempDir::new("tautology-trunc").unwrap();
    let gz = generators::clean_gzip(&payload());
    let truncated = &gz[..gz.len() * 6 / 10];
    let src = dir.write_file("truncated.gz", truncated).unwrap();
    let analysis = analyze(&src);

    let options = RecoveryOptions {
        output_dir: dir.path().join("out"),
        forced_strategy: Some("gz-trailer-recompute".to_string()),
        ..Default::default()
    };
    let report = RecoveryEngine::new()
        .recover(&src, &analysis, &options)
        .unwrap();

    assert!(
        !report.success,
        "trailer recompute must refuse an incomplete stream"
    );
    assert!(
        !report.output_path.exists(),
        "no artifact may be written for a refused trailer rewrite"
    );
}

/// Fix 2 — Inferred-risk output must not justify itself with health measured
/// on its own rewritten bytes. A GZIP with a corrupted CRC field decodes to
/// end-of-stream; the recomputed trailer makes the file re-analyze as
/// perfectly healthy — but that verifier was fitted to the data (zero
/// evidence bits, tautology rule), and trailer-damage cannot be distinguished
/// from payload-damage with one equation. The engine must stage it, see it is
/// not byte-verified, and roll it back: the recovery abstains.
#[test]
fn inferred_repair_is_rolled_back_without_external_byte_verification() {
    let dir = TempDir::new("tautology-inferred").unwrap();
    let mut gz = generators::clean_gzip(&payload());
    let crc_at = gz.len() - 8; // trailer: CRC32 (4) + ISIZE (4)
    gz[crc_at] ^= 0xFF;
    let src = dir.write_file("crc-corrupt.gz", &gz).unwrap();
    let analysis = analyze(&src);
    assert!(
        !analysis.corruptions.is_empty(),
        "fixture must present a detectable CRC mismatch"
    );

    let options = RecoveryOptions {
        output_dir: dir.path().join("out"),
        ..Default::default()
    };
    let report = RecoveryEngine::new()
        .recover(&src, &analysis, &options)
        .unwrap();

    assert!(
        report
            .rolled_back
            .iter()
            .any(|s| s == "gz-trailer-recompute"),
        "the inferred trailer rewrite must be staged and rolled back, got rolled_back={:?}",
        report.rolled_back
    );
    assert!(
        !report.output_path.exists(),
        "an unlocalizable single-verifier mismatch must abstain, not emit \
         (fitted health cannot keep an inferred repair)"
    );
}

/// Fix 3 — `PartialExtraction` (and the engine around it) must not label an
/// unchanged damaged input as recovered output. Tar carries no payload
/// checksums, so a flipped data byte analyzes as perfectly healthy; run 1
/// measured a verbatim copy emitted as `recovered=216,576B lost=0`. With
/// nothing detected there is nothing provable to repair: recover must
/// abstain — no pass-through artifact.
#[test]
fn undetectable_damage_is_not_relabelled_as_recovery() {
    let dir = TempDir::new("tautology-passthrough").unwrap();
    let big = payload();
    let mut tar = generators::clean_tar(&[("data.bin", big.as_slice())]);
    // Flip one byte inside the member's data region (well past the 512-byte
    // header) — invisible to ustar's header-only checksums.
    tar[512 + 1000] ^= 0xFF;
    let src = dir.write_file("silent-corrupt.tar", &tar).unwrap();
    let analysis = analyze(&src);
    assert!(
        analysis.corruptions.is_empty(),
        "fixture must be undetectable by design (tar has no payload checksums)"
    );

    let options = RecoveryOptions {
        output_dir: dir.path().join("out"),
        ..Default::default()
    };
    let report = RecoveryEngine::new()
        .recover(&src, &analysis, &options)
        .unwrap();

    assert!(
        !report.output_path.exists(),
        "healthy-scored input must produce no 'recovered' artifact"
    );
    assert!(
        report.strategies_applied.is_empty(),
        "no strategy may claim recovered bytes on a zero-corruption analysis, got {:?}",
        report.strategies_applied
    );
}
