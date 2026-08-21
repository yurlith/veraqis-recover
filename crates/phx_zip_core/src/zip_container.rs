//! Container ownership — which archive does a byte range belong to?
//!
//! A ZIP stored inside another ZIP contains real local file headers, a real central directory and
//! a real EOCD. Every structural check an outer scan applies, they pass — because they *are* valid
//! ZIP structures. They simply belong to a different container.
//!
//! Run 3 shipped a scan that runs alongside a partially-readable directory (F-4) and, on nested
//! archives, that scan started reporting an inner archive's members as entries of the outer file.
//! Two distinct mechanisms produced it, and a fix for either alone would have left the other:
//!
//! 1. **Directory adoption.** With the outer tail truncated away, the surviving-directory scan
//!    (E2) found a coherent central directory — the *inner* archive's — and adopted it as the
//!    outer one. Its records then arrived flagged `from_central_dir`, i.e. as the most trusted
//!    kind of entry there is, and the genuine outer entry that physically contained them was
//!    evicted for overlapping "its own" contents.
//! 2. **Payload descent.** With an outer local header destroyed by a deletion, the forward scan
//!    had nothing to tell it where that entry's payload began, walked into it, and found the inner
//!    headers directly.
//!
//! ## What establishes ownership
//!
//! Not a signature. `PK\x05\x06` occurs in ordinary binary data, in comments, in compressed
//! payloads, and in anything an attacker chooses to write. Searching for one and believing it is
//! how the outer parser was fooled in the first place, at a different offset.
//!
//! What establishes ownership is an **arithmetic identity that random bytes do not satisfy**. In a
//! ZIP embedded at base `B`, every stored offset is relative to `B`. So for an EOCD at absolute
//! position `P` declaring a directory of `cd_size` bytes at relative `cd_offset`:
//!
//! ```text
//! B = P - cd_size - cd_offset
//! ```
//!
//! and the directory must actually be at `B + cd_offset`, walk coherently for exactly `cd_size`
//! bytes, and every record's rebased local-header offset must land on a real local header whose
//! name matches that record. A coincidental EOCD fails this immediately: its arithmetic points at
//! nothing.
//!
//! Measured on the regression fixture `ci-nested-one-level-trunc-tail-tail_50_percent`:
//! `EOCD@27499, cd_size=122, cd_offset=19806` → `B = 7571`, which is exactly the payload start of
//! the outer entry `files/item-0001.zip`. The inner archive is found without ever reading a
//! filename.
//!
//! ## What this module does NOT do
//!
//! It does not extract nested archives, expose their entries, or recurse. Detecting a container is
//! an ownership fact used to *withhold* something from the outer entry list; it grants nothing.

use crate::zip_policy::ZipRecoveryPolicy;

const LFH_SIG: u32 = 0x0403_4b50;
const CDFH_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;

/// Smallest possible EOCD record.
const EOCD_LEN: usize = 22;

/// Most embedded archives to detect in one source. Bounded like every other walk: an attacker
/// must not be able to turn ownership analysis into the denial of service it exists to prevent.
const MAX_EMBEDDED_ARCHIVES: usize = 4096;

fn u16le(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(o)?, *d.get(o + 1)?]))
}
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}

/// A ZIP archive proven to be embedded inside this source at a non-zero base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedArchive {
    /// Absolute offset of the embedded archive's byte zero.
    pub base: u64,
    /// Absolute end, exclusive — past its EOCD and comment.
    pub end: u64,
    /// Absolute offset of its central directory.
    pub cd_start: u64,
    /// Absolute offset of its EOCD.
    pub eocd: u64,
    /// How many records its directory walked coherently.
    pub records: usize,
    /// How many of those records' rebased offsets landed on a matching local header.
    pub confirmed_records: usize,
}

impl EmbeddedArchive {
    /// Does this container hold `offset`? Half-open `[base, end)` — the base **is** contained.
    ///
    /// This was initially written as `offset > base`, reasoning that the base is where the
    /// container begins and so a candidate exactly there is the container rather than its
    /// content. That reasoning is wrong for ZIP, and the fixture caught it: a ZIP has no
    /// container header of its own, so an embedded archive's base *is* the offset of its first
    /// local file header. Excluding the base let exactly one inner entry per archive survive as
    /// an outer entry — `inner/notes.txt` in
    /// `ci-nested-one-level-between-entries-delete_16_bytes_across_boundary`.
    ///
    /// An outer entry can never collide with this: its own local header lies *before* the payload
    /// that holds the embedded archive, never at the same offset.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.base && offset < self.end
    }
}

/// Why a candidate is not an entry of the outer archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerOwnership {
    /// Belongs to the archive being parsed.
    OuterContainer,
    /// Lies inside a validated embedded archive.
    NestedContainer,
    /// Inside a region that looks owned, but the owning range could not be validated. Neither
    /// emitted nor silently dropped — the uncertainty is the finding.
    AmbiguousContainer,
}

impl ContainerOwnership {
    /// Stable code for evidence records and reports.
    pub fn code(self) -> &'static str {
        match self {
            ContainerOwnership::OuterContainer => "OUTER_CONTAINER",
            ContainerOwnership::NestedContainer => "NESTED_CONTAINER_DETECTED",
            ContainerOwnership::AmbiguousContainer => "AMBIGUOUS_CONTAINER_OWNERSHIP",
        }
    }
}

/// Sorted, non-overlapping-at-query-time ownership intervals over one source.
///
/// Built once per parse and queried per candidate by binary search, so ownership assignment is
/// `O(n log n)` overall rather than a containment test against every range for every candidate.
#[derive(Debug, Default, Clone)]
pub struct ContainerOwnershipMap {
    /// Validated embedded archives, sorted by base.
    archives: Vec<EmbeddedArchive>,
}

impl ContainerOwnershipMap {
    /// Detect every embedded archive in `data`, with full structural validation.
    ///
    /// The scan is over EOCD *candidates*; each is then required to satisfy the rebasing identity
    /// and to have a directory that walks. A candidate at base 0 is the outer archive itself and
    /// is deliberately not recorded — the outer archive does not contain itself.
    pub fn detect(data: &[u8], policy: &ZipRecoveryPolicy) -> Self {
        let mut archives = Vec::new();
        if data.len() < EOCD_LEN {
            return Self { archives };
        }

        let horizon = data.len().min(policy.max_scan_bytes);
        let mut p = 0usize;
        while p + EOCD_LEN <= horizon {
            if u32le(data, p) != Some(EOCD_SIG) {
                p += 1;
                continue;
            }
            if archives.len() >= MAX_EMBEDDED_ARCHIVES {
                break;
            }
            if let Some(a) = validate_embedded(data, p, policy) {
                archives.push(a);
            }
            // Always make progress, whether or not this candidate validated.
            p += 1;
        }

        archives.sort_by_key(|a| (a.base, a.end));
        // Keep the widest container for any given base: a nested-in-nested archive shares no base
        // with its parent, so this only collapses genuine duplicates.
        archives.dedup_by_key(|a| a.base);
        Self { archives }
    }

    /// How many embedded archives were validated.
    pub fn len(&self) -> usize {
        self.archives.len()
    }

    pub fn is_empty(&self) -> bool {
        self.archives.is_empty()
    }

    pub fn archives(&self) -> &[EmbeddedArchive] {
        &self.archives
    }

    /// The innermost validated archive containing `offset`, if any.
    ///
    /// Binary search to the last archive whose base is at or below `offset`, then walk back over
    /// the few candidates that can still contain it. Nesting depth is what bounds that walk, and
    /// it is small in practice; it terminates on the first archive whose end is at or below the
    /// offset because the list is base-sorted.
    pub fn owner_of(&self, offset: u64) -> Option<&EmbeddedArchive> {
        let idx = self.archives.partition_point(|a| a.base <= offset);
        let mut best: Option<&EmbeddedArchive> = None;
        for a in self.archives[..idx].iter().rev() {
            if a.contains(offset) {
                // Innermost wins: later base = deeper nesting.
                if best.is_none_or(|b| a.base > b.base) {
                    best = Some(a);
                }
            }
            // Everything further back begins earlier; it may still contain the offset, so keep
            // going while its end could reach. A container that ends before the offset cannot,
            // and neither can anything starting earlier AND ending earlier — but ends are not
            // sorted, so the guard is the archive count, which MAX_EMBEDDED_ARCHIVES bounds.
        }
        best
    }

    /// Ownership verdict for a candidate at `offset`.
    pub fn ownership_of(&self, offset: u64) -> ContainerOwnership {
        match self.owner_of(offset) {
            Some(_) => ContainerOwnership::NestedContainer,
            None => ContainerOwnership::OuterContainer,
        }
    }
}

/// Validate one EOCD candidate as an embedded archive. `None` unless every check holds.
fn validate_embedded(
    data: &[u8],
    eocd: usize,
    policy: &ZipRecoveryPolicy,
) -> Option<EmbeddedArchive> {
    let total = u16le(data, eocd + 10)? as usize;
    let cd_size = u32le(data, eocd + 12)? as usize;
    let cd_offset = u32le(data, eocd + 16)? as usize;
    let comment_len = u16le(data, eocd + 20)? as usize;

    if total == 0 || cd_size == 0 {
        return None; // an empty directory proves no containment
    }
    if comment_len > policy.max_comment_bytes {
        return None;
    }

    // Where the directory physically is. The declared size is measured back from the EOCD, which
    // holds whenever the directory abuts its EOCD — the normal layout, and one that survives a
    // stale *offset*.
    let cd_start = eocd.checked_sub(cd_size)?;
    let cd_end = eocd;
    if cd_end > data.len() || u32le(data, cd_start) != Some(CDFH_SIG) {
        return None;
    }

    // The base. Two derivations, in order of strength.
    //
    // 1. The rebasing identity `base = eocd - cd_size - cd_offset`. Exact when the archive is
    //    undamaged, and random bytes essentially never satisfy it.
    // 2. From the records themselves, when a deletion has made `cd_offset` stale: the first
    //    record's relative local-header offset, matched against a real local header carrying that
    //    record's name, pins the base directly. This is what recovers a container whose host was
    //    edited — `ci-nested-*-between-entries-delete_256_bytes_across_boundary` deletes bytes
    //    ahead of the directory, so the stored offset no longer points at it while the records
    //    themselves remain perfectly readable.
    //
    // Either way, EVERY record is then re-confirmed against the chosen base below. The derivation
    // only proposes; the confirmation decides.
    let base = match cd_start.checked_sub(cd_offset) {
        Some(b) if b > 0 && candidate_base_confirms(data, cd_start, cd_end, b, policy) => b,
        _ => derive_base_from_records(data, cd_start, cd_end, policy)?,
    };
    if base == 0 || base >= cd_start {
        return None; // an embedded archive's data precedes its own directory
    }

    // The directory must walk coherently for exactly the declared span, and each record's
    // rebased local-header offset must land on a real local header carrying the same name. That
    // last check is what makes this a proof rather than a plausible reading: a coincidence would
    // have to place matching filenames at computed offsets.
    let mut o = cd_start;
    let mut records = 0usize;
    let mut confirmed = 0usize;
    while o + 46 <= cd_end && records < policy.max_central_records {
        if u32le(data, o) != Some(CDFH_SIG) {
            break;
        }
        let name_len = u16le(data, o + 28)? as usize;
        let extra_len = u16le(data, o + 30)? as usize;
        let cmt_len = u16le(data, o + 32)? as usize;
        let rel_lho = u32le(data, o + 42)? as usize;
        if name_len > policy.max_name_bytes || extra_len > policy.max_extra_bytes {
            return None;
        }
        let name_start = o.checked_add(46)?;
        let name_end = name_start.checked_add(name_len)?;
        let rec_end = name_end.checked_add(extra_len)?.checked_add(cmt_len)?;
        if rec_end > cd_end {
            return None; // a record crossing the directory's own declared end
        }
        let name = data.get(name_start..name_end)?;

        // Rebase: the record's offset is relative to the embedded archive's base, never to the
        // outer file's start. Comparing it to an absolute offset is the mistake this line exists
        // to prevent.
        if let Some(abs) = base.checked_add(rel_lho) {
            if abs + 30 <= data.len()
                && u32le(data, abs) == Some(LFH_SIG)
                && abs < cd_start
                && u16le(data, abs + 26).is_some_and(|nl| {
                    let ns = abs + 30;
                    nl as usize == name.len()
                        && data.get(ns..ns + nl as usize).is_some_and(|n| n == name)
                })
            {
                confirmed += 1;
            }
        }

        records += 1;
        o = rec_end;
    }

    // The record count must match what the EOCD declares.
    //
    // `confirmed == records` is checked too, and it is **redundant by construction**: both base
    // derivations above accept a base only when `candidate_base_confirms` finds every record
    // resolving to a matching local header. It is kept as a cheap, local restatement of that
    // invariant rather than a load-bearing guard, and the honest consequence is recorded in
    // RUST_ZIP_SAFETY_RUN3B: removing it turns no test red, because base selection already
    // enforces it.
    //
    // Historical note on why "at least one confirmed record" was not enough. A damaged OUTER
    // archive — bytes inserted before its directory — has an EOCD whose stored offset is stale by
    // the inserted length, so `eocd - cd_size - cd_offset` yields a plausible non-zero base at
    // which *some* records still resolve. On
    // `ci-few-binary-small-between-entries-fake_local_header_inserted_between_entries` that
    // produced a phantom container at base 39 spanning almost the whole file, and it suppressed
    // two genuine outer entries.
    if records == 0 || records != total {
        return None;
    }
    debug_assert_eq!(
        confirmed, records,
        "base selection must already have confirmed every record"
    );

    let end = eocd
        .checked_add(EOCD_LEN)?
        .checked_add(comment_len)?
        .min(data.len());

    // An embedded archive is by definition followed by more of its host: the host's remaining
    // entries, its directory and its own EOCD. A candidate running to the end of the file is not
    // embedded in anything — it is the outer archive read through a stale offset. Erring toward
    // "outer" is the safe direction for a rule whose only power is to WITHHOLD entries.
    //
    // Defence in depth: no fixture currently reaches it, because the base derivations reject the
    // shifted-outer-archive case earlier. Removing it turns no test red today. It is kept because
    // it is a cheap invariant about what "embedded" means, not because a test proves it fires —
    // and that distinction is recorded rather than glossed.
    if end >= data.len() {
        return None;
    }

    Some(EmbeddedArchive {
        base: base as u64,
        end: end as u64,
        cd_start: cd_start as u64,
        eocd: eocd as u64,
        records,
        confirmed_records: confirmed,
    })
}

/// Walk a directory chain and yield each record's `(name, relative local-header offset)`.
fn chain_records<'a>(
    data: &'a [u8],
    cd_start: usize,
    cd_end: usize,
    policy: &ZipRecoveryPolicy,
) -> Option<Vec<(&'a [u8], usize)>> {
    let mut out = Vec::new();
    let mut o = cd_start;
    while o + 46 <= cd_end && out.len() < policy.max_central_records {
        if u32le(data, o) != Some(CDFH_SIG) {
            break;
        }
        let name_len = u16le(data, o + 28)? as usize;
        let extra_len = u16le(data, o + 30)? as usize;
        let cmt_len = u16le(data, o + 32)? as usize;
        let rel_lho = u32le(data, o + 42)? as usize;
        if name_len > policy.max_name_bytes || extra_len > policy.max_extra_bytes {
            return None;
        }
        let name_start = o.checked_add(46)?;
        let name_end = name_start.checked_add(name_len)?;
        let rec_end = name_end.checked_add(extra_len)?.checked_add(cmt_len)?;
        if rec_end > cd_end {
            return None;
        }
        out.push((data.get(name_start..name_end)?, rel_lho));
        o = rec_end;
    }
    if o != cd_end {
        return None; // the chain must consume the directory exactly
    }
    Some(out)
}

/// Does a local header carrying `name` sit at `abs`?
fn header_named_at(data: &[u8], abs: usize, name: &[u8]) -> bool {
    abs.checked_add(30).is_some_and(|e| e <= data.len())
        && u32le(data, abs) == Some(LFH_SIG)
        && u16le(data, abs + 26).is_some_and(|nl| {
            nl as usize == name.len()
                && data
                    .get(abs + 30..abs + 30 + name.len())
                    .is_some_and(|n| n == name)
        })
}

/// Would `base` confirm every record of this chain?
fn candidate_base_confirms(
    data: &[u8],
    cd_start: usize,
    cd_end: usize,
    base: usize,
    policy: &ZipRecoveryPolicy,
) -> bool {
    let Some(recs) = chain_records(data, cd_start, cd_end, policy) else {
        return false;
    };
    !recs.is_empty()
        && recs.iter().all(|(name, rel)| {
            base.checked_add(*rel)
                .is_some_and(|abs| abs < cd_start && header_named_at(data, abs, name))
        })
}

/// Pin the base from the first record, then require every record to agree with it.
fn derive_base_from_records(
    data: &[u8],
    cd_start: usize,
    cd_end: usize,
    policy: &ZipRecoveryPolicy,
) -> Option<usize> {
    let recs = chain_records(data, cd_start, cd_end, policy)?;
    let (first_name, first_rel) = *recs.first()?;

    // Candidate bases are the offsets of real local headers carrying the first record's name.
    // Bounded by the number of such headers, which the scan limits already cap.
    let mut probe = 0usize;
    while probe + 30 <= cd_start {
        if u32le(data, probe) == Some(LFH_SIG)
            && header_named_at(data, probe, first_name)
            && probe >= first_rel
        {
            let base = probe - first_rel;
            if base > 0 && candidate_base_confirms(data, cd_start, cd_end, base, policy) {
                return Some(base);
            }
        }
        probe += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ZipRecoveryPolicy {
        ZipRecoveryPolicy::default()
    }

    #[test]
    fn an_empty_source_has_no_containers() {
        assert!(ContainerOwnershipMap::detect(&[], &policy()).is_empty());
        assert!(ContainerOwnershipMap::detect(&[0u8; 8], &policy()).is_empty());
    }

    #[test]
    fn a_bare_eocd_signature_is_not_a_container() {
        // The signature alone, with nothing that satisfies the rebasing identity.
        let mut d = vec![0u8; 200];
        d[100..104].copy_from_slice(&EOCD_SIG.to_le_bytes());
        assert!(
            ContainerOwnershipMap::detect(&d, &policy()).is_empty(),
            "a raw signature must never establish ownership"
        );
    }

    #[test]
    fn random_eocd_like_bytes_do_not_validate() {
        let mut d = vec![0x41u8; 4096];
        for at in [64usize, 1000, 2048] {
            d[at..at + 4].copy_from_slice(&EOCD_SIG.to_le_bytes());
        }
        assert!(ContainerOwnershipMap::detect(&d, &policy()).is_empty());
    }

    #[test]
    fn the_outer_archives_own_eocd_is_not_an_embedded_container() {
        let zip = phx_test_utils::generators::clean_zip(&[("a.txt", b"hello world")]);
        let map = ContainerOwnershipMap::detect(&zip, &policy());
        assert!(
            map.is_empty(),
            "an archive does not contain itself; base 0 must be excluded"
        );
    }

    #[test]
    fn containment_is_half_open_and_includes_the_base() {
        let a = EmbeddedArchive {
            base: 100,
            end: 200,
            cd_start: 180,
            eocd: 190,
            records: 1,
            confirmed_records: 1,
        };
        assert!(!a.contains(99));
        assert!(
            a.contains(100),
            "the base is an embedded archive's FIRST local header — excluding it lets exactly \
             one inner entry per archive escape as an outer entry"
        );
        assert!(a.contains(199));
        assert!(!a.contains(200), "end is exclusive");
        assert!(!a.contains(201));
    }

    #[test]
    fn a_zero_length_range_contains_nothing() {
        let a = EmbeddedArchive {
            base: 50,
            end: 50,
            cd_start: 50,
            eocd: 50,
            records: 1,
            confirmed_records: 1,
        };
        for o in 48..53 {
            assert!(!a.contains(o));
        }
    }
}
