//! Physical directory discovery, record reconciliation and the piecewise offset map.
//!
//! Ground truth comes from the corpus mutation journal and from fixture construction — never from
//! engine output and never from a filename. Every absence assertion is paired with a positive one:
//! "no false entries" is trivially true of an empty result, and this repository has already been
//! bitten once by a nested test that passed on an empty list.

use phx_recovery::zip_index::LocalHeaderIndex;
use phx_recovery::zip_offset_map::OffsetMapKind;
use phx_recovery::zip_policy::ZipRecoveryPolicy;
use phx_test_utils::generators;
use phx_zip_core::opc_zip::{parse_zip, parse_zip_with_policy};

/// The two fixtures whose directory is intact but whose offsets are stale by an interior deletion.
/// Ground truth (mutation journal): six entries, none named `inner/*`.
const INTERIOR_EDIT_CASES: &[&str] = &[
    "ci-nested-one-level-between-entries-delete_256_bytes_across_boundary",
    "ci-nested-three-levels-between-entries-delete_256_bytes_across_boundary",
];

const EXPECTED_SIX: &[&str] = &[
    "files/item-0000.txt",
    "files/item-0001.zip",
    "files/item-0002.txt",
    "files/item-0003.zip",
    "files/item-0004.txt",
    "files/item-0005.zip",
];

fn corpus_case(id: &str) -> Vec<u8> {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("corpus/corrupted")
        .join(format!("{id}.zip"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("corpus case {id} must exist: {e}"))
}

fn names(z: &[u8]) -> Vec<String> {
    parse_zip(z)
        .entries
        .iter()
        .map(|e| e.name.clone())
        .collect()
}

// ───────────────────────────────────────────── the two target fixtures

#[test]
fn interior_edit_cases_recover_all_six_entries_and_no_inner_ones() {
    for case in INTERIOR_EDIT_CASES {
        let zip = corpus_case(case);
        let parsed = parse_zip(&zip);
        let got = names(&zip);

        // POSITIVE: the directory was found physically and every record is there.
        assert!(
            parsed.cd_found,
            "{case}: the intact directory must be located despite a stale EOCD offset"
        );
        assert!(
            parsed.cd_located_by_size,
            "{case}: it is found by measuring back from the EOCD, not by the declared offset"
        );
        for want in EXPECTED_SIX {
            assert!(
                got.iter().any(|n| n == want),
                "{case}: outer entry {want} missing. Got {got:?}"
            );
        }

        // The shape of the damage: one interior deletion is two segments.
        assert_eq!(
            parsed.offset_map_kind,
            Some(OffsetMapKind::Piecewise),
            "{case}: an interior edit needs a piecewise map, not a single delta"
        );
        assert_eq!(
            parsed.offset_segments, 2,
            "{case}: exactly two shift regions"
        );
        assert!(
            parsed.records_repointed > 0,
            "{case}: stale records must actually be re-pointed"
        );

        // ABSENCE, only after the positives.
        let inner: Vec<&String> = got.iter().filter(|n| n.starts_with("inner/")).collect();
        assert!(
            inner.is_empty(),
            "{case}: embedded-archive members attributed to the outer archive: {inner:?}"
        );
    }
}

#[test]
fn a_planted_header_at_a_records_own_offset_does_not_capture_that_record() {
    // The subtlest failure this suite exists for. The ghost header was inserted at exactly the
    // offset files/item-0001.jpg's record points at, so a signature-only resolution check called
    // the record resolved while it read the ghost's fields — and a genuine file came back damaged.
    let zip = corpus_case(
        "ci-few-binary-small-between-entries-fake_local_header_inserted_between_entries",
    );
    let got = names(&zip);

    for want in [
        "files/item-0000.bin",
        "files/item-0001.jpg",
        "files/item-0002.bin",
    ] {
        assert!(
            got.iter().any(|n| n == want),
            "genuine outer entry {want} must survive. Got {got:?}"
        );
    }

    let parsed = parse_zip(&zip);
    let jpg = parsed
        .entries
        .iter()
        .find(|e| e.name == "files/item-0001.jpg")
        .expect("the record must be present");
    assert_ne!(
        jpg.local_header_offset, 102449,
        "102449 is where the ghost header was inserted; the record must point at its OWN header"
    );
}

#[test]
fn head_truncation_still_resolves_as_a_single_delta() {
    // E2's case must stay on the cheap path: one shift, not a piecewise map.
    let zip = corpus_case("ci-nested-one-level-trunc-head-head_10_percent");
    let parsed = parse_zip(&zip);
    assert_eq!(parsed.offset_map_kind, Some(OffsetMapKind::SingleDelta));
    assert_eq!(parsed.offset_segments, 1);
    assert!(parsed.records_repointed > 0);
    assert_eq!(parsed.entries.len(), 6);
}

#[test]
fn an_undamaged_archive_needs_no_remapping() {
    let zip = generators::clean_zip(&[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    let parsed = parse_zip(&zip);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.records_repointed, 0, "nothing to re-point");
    assert!(!parsed.cd_located_by_size, "the declared offset is correct");
    assert_eq!(parsed.records_reconciled, 2);
}

// ───────────────────────────────────────────── the operation-count gate

#[test]
fn base_lookup_is_bounded_by_the_bucket_not_the_archive() {
    // A return to linear probing would make probes scale with the number of headers. This is
    // deterministic — unlike wall-clock, it cannot pass on a fast machine.
    let bodies: Vec<Vec<u8>> = (0..80)
        .map(|i| format!("payload for entry {i}").repeat(4).into_bytes())
        .collect();
    let named: Vec<(String, &[u8])> = bodies
        .iter()
        .enumerate()
        .map(|(i, b)| (format!("files/item-{i:04}.bin"), b.as_slice()))
        .collect();
    let refs: Vec<(&str, &[u8])> = named.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    let zip = generators::clean_zip(&refs);

    let parsed = parse_zip(&zip);
    assert_eq!(parsed.entries.len(), 80);
    let s = parsed.index_stats;
    assert_eq!(
        s.fallback_linear_probes, 0,
        "no tested recovery path may sweep offsets linearly"
    );
    assert!(
        s.base_candidate_probes <= s.indexed_lfh_count,
        "probes ({}) must not exceed the number of indexed headers ({}) — that is the signature \
         of a per-record sweep",
        s.base_candidate_probes,
        s.indexed_lfh_count
    );
}

#[test]
fn duplicate_names_offer_every_candidate_rather_than_the_first() {
    let zip = generators::clean_zip(&[("same.txt", b"first copy"), ("same.txt", b"second copy")]);
    let mut idx = LocalHeaderIndex::build(&zip, &ZipRecoveryPolicy::default());
    let hits = idx.candidates_named(&zip, b"same.txt");
    assert_eq!(
        hits.len(),
        2,
        "both candidates must be offered to the caller"
    );
    // And the parse keeps both entries: identity is physical.
    assert_eq!(names(&zip).iter().filter(|n| *n == "same.txt").count(), 2);
}

// ───────────────────────────────────────────── piecewise map safety

#[test]
fn a_segment_limit_of_one_refuses_an_interior_edit_rather_than_guessing() {
    // With only one segment permitted, a two-region archive cannot be mapped. The correct result
    // is no remapping at all — never a map that averages the two shifts into a wrong one.
    let zip = corpus_case(INTERIOR_EDIT_CASES[0]);
    let policy = ZipRecoveryPolicy {
        max_offset_segments: 1,
        ..ZipRecoveryPolicy::default()
    };
    let parsed = parse_zip_with_policy(&zip, &policy);
    assert_eq!(
        parsed.offset_map_kind,
        Some(OffsetMapKind::Rejected),
        "an over-complicated map must be refused, not approximated"
    );
    assert_eq!(
        parsed.records_repointed, 0,
        "a rejected map re-points nothing"
    );
}

#[test]
fn reconciliation_is_deterministic_and_never_mutates_the_source() {
    for case in INTERIOR_EDIT_CASES {
        let zip = corpus_case(case);
        let before = zip.clone();
        let a = names(&zip);
        let b = names(&zip);
        assert_eq!(a, b, "{case}: reconciliation must be deterministic");
        assert_eq!(before, zip, "{case}: the source must not be touched");
    }
}

#[test]
fn bounded_mutation_sweep_over_a_stale_offset_archive() {
    // Deterministic, bounded, fixed seed. Asserts the invariants enumeration owns: no panic, no
    // source mutation, ordered offsets, and probe counts that stay indexed.
    let base = corpus_case(INTERIOR_EDIT_CASES[0]);
    let mut state = 0x00D1_2E45_2026_0801_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for i in 0..256 {
        let mut z = base.clone();
        for _ in 0..(1 + (next() % 3)) {
            let pos = (next() as usize) % z.len();
            z[pos] = (next() % 256) as u8;
        }
        let before = z.clone();
        let parsed = parse_zip(&z);
        assert_eq!(before, z, "iteration {i}: source mutated");
        assert_eq!(
            parsed.index_stats.fallback_linear_probes, 0,
            "iteration {i}: linear fallback engaged"
        );
        let offs: Vec<u64> = parsed
            .entries
            .iter()
            .map(|e| e.local_header_offset)
            .collect();
        let mut sorted = offs.clone();
        sorted.sort_unstable();
        assert_eq!(offs, sorted, "iteration {i}: ordering broke");
    }
}
