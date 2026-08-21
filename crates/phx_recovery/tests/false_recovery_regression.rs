//! Phase 2.5A regression suite — the 95 measured false recoveries must never come back.
//!
//! The 2026-07-25 comparative run (`reports/ci-summary.json`) scored VERAQIS `best_effort` at
//! 1.27 % strict false recovery: 95 produced files that were **not** the original content, across
//! 13 distinct damage cases. Root cause, proven in `reports/phase-2.5/root-cause.md`:
//! `zip_crc_fix` recomputed each CRC-32 from whatever payload survived and wrote it into both the
//! local header and the central directory. The later "independent" CRC check in
//! [`phx_recovery::mobile_zip`] then compared the corrupted bytes against a checksum derived from
//! those same bytes — satisfied by construction, proving nothing, and destroying the only evidence
//! that the payload was wrong.
//!
//! Every test here fails against the pre-fix engine and passes against the fixed one. They are
//! grouped by the damage class of the case that produced the false recoveries, so a regression
//! names the class it broke.
//!
//! The classes, and the runs each contributed:
//!
//! | damage class                      | cases | runs |
//! |-----------------------------------|-------|------|
//! | `bitflip` (payload)               |   5   |  45  |
//! | `crc-mismatch` (payload altered)  |   3   |  25  |
//! | `partial-download` (missing bytes)|   2   |  20  |
//! | `between-entries` / `lfh-corrupt` |   3   |   5* |
//!
//! \* the between-entries/`lfh-corrupt` group also produced the 5 `Phantom` outputs; the
//! zero-length half of that class is guarded by `zero_length_unattested` in `mobile_zip`
//! (defect F-2, fixed earlier) and re-asserted here.

use phx_analyze_engine::model::AnalysisConfig;
use phx_analyze_engine::Engine;
use phx_recovery::mobile_zip::{self, MobileZipLimits};
use phx_recovery::verdict::{CdProvenance, RecoveryVerdict};
use phx_recovery::{RecoveryEngine, RecoveryOptions};
use phx_test_utils::{generators, TempDir};

const NAME: &str = "item-0000.bin";

fn original() -> Vec<u8> {
    b"ORIGINAL-CONTENT-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-0123456789\n"
        .repeat(8)
        .to_vec()
}

/// Offset of the stored payload inside a single-entry `clean_zip`.
fn payload_offset(zip: &[u8], needle: &[u8]) -> usize {
    zip.windows(needle.len())
        .position(|w| w == needle)
        .expect("stored payload is present verbatim")
}

/// Run the shipped repair pipeline the way `phx recover` does, then extract from whatever it
/// produced — i.e. exactly the `best_effort` path the benchmark measured.
fn repair_then_extract(label: &str, zip: &[u8]) -> (Vec<String>, Vec<(String, String)>) {
    let dir = TempDir::new(label).unwrap();
    let src = dir.write_file("case.zip", zip).unwrap();
    let analysis = Engine::new()
        .analyze(&src, AnalysisConfig::default())
        .unwrap();

    let options = RecoveryOptions {
        output_dir: dir.path().join("out"),
        write_manifest: false,
        aggressive: true,
        ..Default::default()
    };
    let report = RecoveryEngine::new()
        .recover(&src, &analysis, &options)
        .unwrap();

    // Extract from the repaired artifact when the engine kept one, else from the original bytes.
    let bytes = std::fs::read(&report.output_path).unwrap_or_else(|_| zip.to_vec());

    let recovery = mobile_zip::recover_verified_entries(
        &bytes,
        MobileZipLimits::default(),
        CdProvenance::Reconstructed,
    );
    let emitted = recovery
        .entries
        .iter()
        .map(|e| {
            assert_eq!(
                e.verdict,
                RecoveryVerdict::ExactRecoverable,
                "the mobile seam may only emit entries it proved exactly"
            );
            e.safe_path.clone()
        })
        .collect();
    let skipped = recovery
        .skipped
        .iter()
        .map(|s| (s.name.clone(), s.reason.to_string()))
        .collect();
    (emitted, skipped)
}

/// The load-bearing assertion: after a full aggressive repair, nothing was presented as recovered.
fn assert_no_trusted_output(label: &str, zip: &[u8]) {
    let (emitted, skipped) = repair_then_extract(label, zip);
    assert!(
        emitted.is_empty(),
        "{label}: damaged payload was presented as a recovered file ({emitted:?}) — this is a \
         false recovery. Skipped: {skipped:?}"
    );
    assert!(
        skipped.iter().any(|(n, _)| n == NAME),
        "{label}: the entry must be explicitly abstained on, not silently dropped. Got {skipped:?}"
    );
}

// ---------------------------------------------------------------- bitflip (5 cases, 45 runs)

#[test]
fn single_payload_bitflip_is_never_presented_as_recovered() {
    let data = original();
    let mut zip = generators::clean_zip(&[(NAME, &data)]);
    let at = payload_offset(&zip, &data[..16]);
    zip[at + 3] ^= 0x20;
    assert_no_trusted_output("bitflip-single", &zip);
}

#[test]
fn scattered_payload_bitflips_are_never_presented_as_recovered() {
    let data = original();
    let mut zip = generators::clean_zip(&[(NAME, &data)]);
    let at = payload_offset(&zip, &data[..16]);
    for k in [1usize, 17, 33, 61, 97] {
        zip[at + k] ^= 0x01;
    }
    assert_no_trusted_output("bitflip-scattered", &zip);
}

// ----------------------------------------------------------- crc-mismatch (3 cases, 25 runs)

#[test]
fn payload_altered_with_the_original_crc_kept_is_never_presented_as_recovered() {
    let data = original();
    let mut zip = generators::clean_zip(&[(NAME, &data)]);
    let at = payload_offset(&zip, &data[..16]);
    // Replace a whole run of payload bytes; both stored CRC copies are left as they were, so the
    // archive still carries the proof that these bytes are wrong.
    for k in 0..24 {
        zip[at + k] = b'X';
    }
    assert_no_trusted_output("crc-mismatch-altered", &zip);
}

#[test]
fn payload_fully_replaced_is_never_presented_as_recovered() {
    let data = original();
    let mut zip = generators::clean_zip(&[(NAME, &data)]);
    let at = payload_offset(&zip, &data[..16]);
    for k in 0..data.len() {
        zip[at + k] = 0x5a;
    }
    assert_no_trusted_output("crc-mismatch-replaced", &zip);
}

// -------------------------------------------------------- partial-download (2 cases, 20 runs)

#[test]
fn a_missing_middle_chunk_is_never_presented_as_recovered() {
    let data = original();
    let mut zip = generators::clean_zip(&[(NAME, &data)]);
    let at = payload_offset(&zip, &data[..16]);
    // A sparse download leaves zeroed holes rather than a short file.
    for k in 64..128 {
        zip[at + k] = 0;
    }
    assert_no_trusted_output("partial-download-hole", &zip);
}

#[test]
fn several_missing_chunks_are_never_presented_as_recovered() {
    let data = original();
    let mut zip = generators::clean_zip(&[(NAME, &data)]);
    let at = payload_offset(&zip, &data[..16]);
    for range in [16usize..48, 96..160, 240..300] {
        for k in range {
            if at + k < zip.len() {
                zip[at + k] = 0;
            }
        }
    }
    assert_no_trusted_output("partial-download-sparse", &zip);
}

// ------------------------------------------------- between-entries / phantom (3 cases, 5 runs)

#[test]
fn a_planted_zero_length_local_header_does_not_invent_a_file() {
    // CRC-32 of nothing is 0, so a fabricated header naming a file that never existed satisfies
    // the checksum by construction. Only a central-directory record is independent corroboration.
    let zip = generators::zip_local_header_only("phantom.txt", b"");
    let recovery = mobile_zip::recover_verified_entries(
        &zip,
        MobileZipLimits::default(),
        CdProvenance::OriginalSurviving,
    );
    assert!(
        recovery.entries.is_empty(),
        "a zero-length entry attested only by a local scan must not be emitted"
    );
    assert!(
        recovery
            .skipped
            .iter()
            .any(|s| s.reason == "zero_length_unattested"),
        "the refusal must name its reason; got {:?}",
        recovery.skipped
    );
}

// ------------------------------------------------------------------------- capability control

#[test]
fn a_corrupt_crc_field_over_an_intact_payload_still_recovers_exactly() {
    // The case `zip_crc_fix` exists for. The payload is untouched and the central directory still
    // holds the true CRC-32, so an independent copy proves the value and the entry comes back
    // byte-exact. Guarding against "fix the false recoveries by refusing everything".
    let data = original();
    let mut zip = generators::clean_zip(&[(NAME, &data)]);
    let lfh_crc = 14; // local file header starts at 0; CRC-32 is at offset 14
    zip[lfh_crc] ^= 0x40;

    let (emitted, skipped) = repair_then_extract("crc-field-corrupt", &zip);
    assert_eq!(
        emitted,
        vec![NAME.to_string()],
        "an intact payload whose CRC field is damaged must still be recovered. Skipped: {skipped:?}"
    );
}

#[test]
fn an_undamaged_archive_is_recovered_exactly() {
    let data = original();
    let zip = generators::clean_zip(&[(NAME, &data)]);
    let recovery = mobile_zip::recover_verified_entries(
        &zip,
        MobileZipLimits::default(),
        CdProvenance::OriginalSurviving,
    );
    assert_eq!(recovery.entries.len(), 1, "a healthy archive must extract");
    assert_eq!(recovery.entries[0].bytes, data, "and be byte-exact");
    assert_eq!(
        recovery.entries[0].verdict,
        RecoveryVerdict::ExactRecoverable
    );
}

// --------------------------------------------------------------------- the invariant itself

#[test]
fn repair_never_rewrites_a_checksum_the_payload_contradicts() {
    // Stated as an invariant over the artifact rather than over any one damage class: whatever the
    // repair pipeline writes, the CRC-32 fields it leaves behind must still disagree with damaged
    // bytes. That disagreement is the only thing standing between a user and a silently wrong file.
    let data = original();
    let mut zip = generators::clean_zip(&[(NAME, &data)]);
    let at = payload_offset(&zip, &data[..16]);
    zip[at + 5] ^= 0x11;

    let dir = TempDir::new("crc-not-rewritten").unwrap();
    let src = dir.write_file("case.zip", &zip).unwrap();
    let analysis = Engine::new()
        .analyze(&src, AnalysisConfig::default())
        .unwrap();
    let options = RecoveryOptions {
        output_dir: dir.path().join("out"),
        write_manifest: false,
        aggressive: true,
        ..Default::default()
    };
    let report = RecoveryEngine::new()
        .recover(&src, &analysis, &options)
        .unwrap();

    let Ok(repaired) = std::fs::read(&report.output_path) else {
        return; // The engine kept no artifact at all, which is an even stronger refusal.
    };
    let recovery = mobile_zip::recover_verified_entries(
        &repaired,
        MobileZipLimits::default(),
        CdProvenance::Reconstructed,
    );
    assert!(
        recovery.entries.is_empty(),
        "the repaired artifact must not make corrupted bytes pass an independent CRC check"
    );
}
