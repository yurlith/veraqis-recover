//! Slice OPC-A — recovery-oriented ZIP reader.
//!
//! A bounds-checked ZIP enumerator + extractor built for *recovery*, not for the
//! happy path: it reads the central directory when present and falls back to a
//! forward local-file-header scan when the CD is gone (the `zip -FF` idea). Each
//! entry's bytes are extracted (stored or DEFLATE) and CRC-32 verified — a CRC
//! match is the exact, checksum-backed proof a part is recovered, not guessed.
//!
//! Never panics on malformed input; no `unsafe`. Decompression is output-capped
//! (bomb guard). Reference: APPNOTE.TXT (ZIP file format).

use std::io::Read;

use crate::zip_container::{ContainerOwnership, ContainerOwnershipMap};
use crate::zip_index::{IndexStats, LocalHeaderIndex};
use crate::zip_offset_map::{OffsetMap, OffsetMapKind, OffsetObservation};
use crate::zip_policy::{LimitHit, ZipRecoveryPolicy};

const LFH_SIG: u32 = 0x0403_4b50; // "PK\x03\x04"
const CDFH_SIG: u32 = 0x0201_4b50; // "PK\x01\x02"
const EOCD_SIG: u32 = 0x0605_4b50; // "PK\x05\x06"

/// Hard cap on a single decompressed entry (bomb guard); fixtures are tiny.
const MAX_INFLATE_BYTES: usize = 512 * 1024 * 1024;

/// One ZIP entry's metadata (from the central directory, or a local-header scan).
#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    /// False when the raw name required lossy UTF-8 replacement. Mobile recovery abstains rather
    /// than publishing a path different from the archive's surviving bytes.
    pub name_valid_utf8: bool,
    pub method: u16, // 0 = stored, 8 = deflate
    pub crc32: u32,
    pub comp_size: u64,
    pub uncomp_size: u64,
    pub local_header_offset: u64,
    /// General-purpose bit flag (bit 0 = encrypted, bit 3 = data descriptor, …).
    pub flags: u16,
    /// A ZIP64 sentinel (0xFFFFFFFF) was seen in a size/offset field — the true
    /// value lives in a ZIP64 extra record this foundation does not parse.
    pub zip64: bool,
    /// Provenance: came from the central directory (true) or a local scan (false).
    pub from_central_dir: bool,
}

impl ZipEntry {
    /// Encrypted entry (traditional PKWARE bit 0 or strong-encryption bit 6).
    /// PHX abstains on these — it never bypasses encryption.
    pub fn is_encrypted(&self) -> bool {
        self.flags & 0x0001 != 0 || self.flags & 0x0040 != 0
    }
    /// Streaming entry: CRC/sizes were written to a trailing data descriptor
    /// (bit 3), so the *local* header sizes are zero and only the central
    /// directory is authoritative.
    pub fn has_data_descriptor(&self) -> bool {
        self.flags & 0x0008 != 0
    }
}

/// ZIP64 size sentinel — the 32-bit field is overflowed; the real value is in a
/// ZIP64 extended-information extra field.
const ZIP64_SENTINEL_U32: u32 = 0xFFFF_FFFF;

/// Result of enumerating a ZIP container.
#[derive(Debug, Default)]
pub struct ZipParse {
    pub entries: Vec<ZipEntry>,
    pub eocd_found: bool,
    pub cd_found: bool,
    pub used_local_scan: bool,
    pub warnings: Vec<String>,
    /// Entries contributed by the local-header scan that no directory record described (F-4).
    pub scan_only_entries: usize,
    /// Field disagreements between directory records and their local headers. Recorded, not
    /// resolved — see [`EntryConflict`].
    pub conflicts: Vec<EntryConflict>,
    /// Scan candidates reconciliation refused, with the reason.
    pub rejected_candidates: Vec<RejectedCandidate>,
    /// Policy limits reached during the walk. Non-empty means the enumeration stopped for OUR
    /// reasons, not the file's, and is therefore incomplete.
    pub limits_hit: Vec<LimitHit>,
    /// Byte shift applied to recovered directory offsets after a head truncation (E2).
    pub cd_offset_shift: Option<i64>,
    /// The directory was found by scanning, not by following the EOCD offset.
    pub cd_recovered_by_scan: bool,
    /// The EOCD's declared entry count agrees with the number of records actually walked.
    ///
    /// This is what licenses treating the directory's *silence* as evidence. A complete directory
    /// enumerates every entry the archive claims to have, so a local header it does not name did
    /// not belong to this archive. A directory that is missing records — half of it deleted, its
    /// tail truncated — says nothing about what is absent from it, and its silence must not be
    /// read as a denial. Getting this backwards either invents entries or loses real ones.
    pub cd_count_consistent: bool,
    /// The EOCD's declared entry count, when one was readable. A hint, never a bound (F-3).
    pub cd_declared_count: Option<usize>,
    /// Validated ZIP archives embedded inside this source. Detected so their contents are not
    /// attributed to this archive — **not** extracted, and not exposed as entries.
    pub nested_containers: usize,
    /// Candidates withheld from the outer entry list because they belong to an embedded archive.
    pub nested_candidates: usize,
    /// The directory was located by measuring back from the EOCD because its stored offset was
    /// stale — an edit ahead of the directory invalidates the pointer, not the records.
    pub cd_located_by_size: bool,
    /// Directory records whose stored offset was translated through the piecewise offset map.
    pub records_repointed: usize,
    /// Directory records that now point at their own physical local header.
    pub records_reconciled: usize,
    /// Segments in the inferred offset map. 1 = a single shift, more = an interior edit.
    pub offset_segments: usize,
    /// What the offset observations supported.
    pub offset_map_kind: Option<OffsetMapKind>,
    /// Operation counts from the local-header index — the deterministic latency gate.
    pub index_stats: IndexStats,
}

/// Why an entry's bytes could (not) be recovered exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractStatus {
    /// Decoded and CRC-32 matched the stored checksum — exact, verified.
    VerifiedCrc,
    /// Decoded but CRC-32 disagreed — bytes present but unproven.
    CrcMismatch,
    /// DEFLATE/stored decode failed (corrupt compressed data).
    DecodeFailed,
    /// Local header missing/garbled at the recorded offset.
    BadLocalHeader,
    /// Data range runs past the file.
    Truncated,
    /// Unsupported compression method.
    Unsupported(u16),
    /// Encrypted entry — out of scope; PHX detects and abstains, never bypasses.
    Encrypted,
    /// ZIP64 extended sizes/offsets in use — not parsed by this foundation; abstain.
    Zip64Unsupported,
    /// Streaming (data-descriptor) entry whose true size is only in the central
    /// directory, which is gone — cannot size the payload from a local scan; abstain.
    StreamedUnsized,
}

/// An entry's extracted bytes + verification outcome.
#[derive(Debug, Clone)]
pub struct ExtractedPart {
    pub name: String,
    pub bytes: Vec<u8>, // empty unless decode succeeded
    pub status: ExtractStatus,
    pub crc_expected: u32,
    pub crc_actual: u32,
}

// ── helpers ──────────────────────────────────────────────────────────────────

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

fn crc32(bytes: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(bytes);
    c.sum()
}

fn inflate_bounded(data: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut dec = flate2::read::DeflateDecoder::new(data);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match dec.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > max {
                    return None; // bomb guard
                }
            }
            Err(_) => return None, // corrupt stream
        }
    }
    Some(out)
}

// ── enumeration ────────────────────────────────────────────────────────────────

/// Enumerate entries from the central directory and, independently, from a local-header scan.
pub fn parse_zip(data: &[u8]) -> ZipParse {
    parse_zip_with_policy(data, &ZipRecoveryPolicy::default())
}

/// As [`parse_zip`], with explicit bounds.
///
/// **F-4.** The central directory and the local headers are two *independent* evidence sources,
/// and this used to treat them as one with a fallback: the scan ran only `if entries.is_empty()`.
/// A half-destroyed directory yields some entries, so the scan never ran and the rest were lost
/// even though their local headers were perfectly intact — 3 of 6 recovered where 7-Zip got 6 of 6.
///
/// Now the directory is walked, the scan runs whenever the directory did not clearly account for
/// the whole archive, and the two are reconciled. Directory records win where they are physically
/// confirmed; scan-only headers are *added*, never substituted; and disagreement is recorded as
/// conflict rather than silently resolved in favour of whichever source is more convenient.
pub fn parse_zip_with_policy(data: &[u8], policy: &ZipRecoveryPolicy) -> ZipParse {
    let mut out = ZipParse::default();
    let mut declared_count: Option<usize> = None;
    let mut cd_region_start: Option<u64> = None;

    // Container ownership is resolved BEFORE any directory is adopted or any candidate accepted.
    // A ZIP embedded in this file has valid headers, a valid directory and a valid EOCD; without
    // knowing where those containers begin and end, every later check is being applied to the
    // wrong archive's structures. See `zip_container` for why a signature alone proves nothing.
    let containers = ContainerOwnershipMap::detect(data, policy);
    out.nested_containers = containers.len();

    if let Some(eocd_off) = find_eocd(data) {
        out.eocd_found = true;
        if let (Some(cd_size), Some(cd_offset), Some(total)) = (
            u32le(data, eocd_off + 12),
            u32le(data, eocd_off + 16),
            u16le(data, eocd_off + 10),
        ) {
            declared_count = Some(total as usize);

            // Where the directory physically is, not only where the EOCD says it is.
            //
            // The stored offset is a pointer, so any edit ahead of the directory invalidates it
            // while leaving the directory itself untouched. The directory's SIZE survives that
            // edit, because it measures the directory rather than pointing at it, and in the
            // normal layout the directory abuts its EOCD. So `eocd - cd_size` is tried whenever
            // the declared offset does not land on a record signature.
            //
            // This is not a guess: the fallback is used only if a CDFH is really there and the
            // strict walk below still succeeds. Measured on
            // `ci-nested-one-level-between-entries-delete_256_bytes_across_boundary`, the EOCD
            // declares 82586 and the directory is at 82330 — stale by exactly the 256 deleted
            // bytes, with all six records intact behind it. Without this the engine discarded a
            // fully intact directory and fell back to a bare local-header scan, which is how an
            // inner archive's members came to be reported as outer entries.
            let declared_start = cd_offset as usize;
            let declared_ok =
                declared_start + 4 <= data.len() && u32le(data, declared_start) == Some(CDFH_SIG);
            let cd_start = if declared_ok {
                declared_start
            } else {
                match eocd_off.checked_sub(cd_size as usize) {
                    Some(s) if s + 4 <= data.len() && u32le(data, s) == Some(CDFH_SIG) => {
                        out.cd_located_by_size = true;
                        out.warnings.push(format!(
                            "EOCD_DIRECTORY_OFFSET_STALE: declared at {declared_start}, located \
                             at {s} by directory size"
                        ));
                        s
                    }
                    _ => declared_start,
                }
            };

            // A directory inside a validated embedded archive belongs to that archive, whichever
            // path located it. The outer tail can be truncated away entirely, leaving an inner
            // archive's EOCD as the last one in the file — and then `eocd - cd_size` faithfully
            // locates the INNER directory. Adopting it re-creates the Run 3 defect by a new route:
            // the inner members become outer entries and evict the genuine entry containing them.
            let cd_start = if containers.owner_of(cd_start as u64).is_some() {
                out.warnings.push(
                    "NESTED_CONTAINER_DETECTED: the located directory lies inside an embedded \
                     archive; not adopted as this archive's directory"
                        .into(),
                );
                out.cd_located_by_size = false;
                data.len() // deliberately out of range: no directory is adopted here
            } else {
                cd_start
            };

            let cd_end = cd_start.saturating_add(cd_size as usize).min(data.len());
            if cd_start < data.len() && cd_start < cd_end {
                cd_region_start = Some(cd_start as u64);
                let (entries, limit) = parse_central_directory_bounded(
                    &data[cd_start..cd_end],
                    total as usize,
                    policy,
                );
                if let Some(l) = limit {
                    out.warnings.push(l.code().to_string());
                    out.limits_hit.push(l);
                }
                if !entries.is_empty() {
                    out.cd_found = true;
                    out.entries = entries;
                }
            }
        }
    }

    if out.entries.is_empty() {
        // E2: the EOCD offset is unusable, but head truncation shifts offsets without destroying
        // the directory itself. Look for a surviving original chain proven by a single offset
        // shift and by agreement with the EOCD, before falling back to a local-header scan.
        let scan = crate::cd_scan::scan_surviving_cd(data);
        // Mechanism 1 of the Run 3 nested regression: with the outer tail truncated away, this
        // scan found a coherent directory — the INNER archive's — and adopted it as the outer
        // one. Its records then arrived flagged `from_central_dir`, the most trusted provenance
        // there is, and the genuine outer entry that physically contained them was evicted for
        // overlapping its own contents. A directory inside a validated embedded archive belongs
        // to that archive.
        let adopted_from_nested = scan
            .accepted_candidate()
            .is_some_and(|c| containers.owner_of(c.start as u64).is_some());
        if adopted_from_nested {
            out.warnings.push(
                "NESTED_CONTAINER_DETECTED: the surviving directory found by scanning belongs to \
                 an embedded archive, not to this one; not adopted"
                    .into(),
            );
        }
        if let Some(c) = scan.accepted_candidate().filter(|_| !adopted_from_nested) {
            let (mut entries, limit) =
                parse_central_directory_bounded(&data[c.start..c.end], c.record_count, policy);
            if let Some(l) = limit {
                out.warnings.push(l.code().to_string());
                out.limits_hit.push(l);
            }
            if !entries.is_empty() {
                // The records survived; their stored offsets did not. Head truncation shifted
                // every offset by the number of bytes removed, and the scan proved a single delta
                // explains the whole chain. Applying it is what makes these records point at real
                // local headers again — without it the directory is recovered but unusable, which
                // is how six intact entries were reported and none extracted.
                // `accepted_delta` is ADDED to a stored offset, so a head truncation makes it
                // negative. An entry whose shifted offset lands before the start of the file was
                // physically removed by the truncation: it is kept as a record (it really was an
                // entry of this archive) but its offset is left unusable, so extraction reports a
                // bad local header rather than reading some unrelated byte at offset 0.
                let delta = c.accepted_delta.unwrap_or(0);
                if delta != 0 {
                    for e in &mut entries {
                        match (e.local_header_offset as i64).checked_add(delta) {
                            Some(x) if x >= 0 => e.local_header_offset = x as u64,
                            _ => e.local_header_offset = u64::MAX,
                        }
                    }
                    out.cd_offset_shift = Some(delta);
                }
                out.cd_found = true;
                out.cd_recovered_by_scan = true;
                cd_region_start = Some(c.start as u64);
                out.entries = entries;
                out.warnings.push(format!(
                    "surviving original central directory recovered at [{}..{}): {} records, \
                     offset shift {}",
                    c.start, c.end, c.record_count, delta
                ));
            }
        }
    }

    // ── Directory reconciliation, before anything is decided about completeness ──────────────
    //
    // A directory that is physically readable is not yet a directory whose offsets are usable.
    // Those are separate problems, and conflating them is what suppressed a genuine entry in the
    // Run 3C prototype: reading the directory armed the completeness guard, and records whose
    // pointers were stale then failed to match their own headers, so real entries were refused as
    // "unattested".
    //
    // So each record is matched to a physical header through the index, the observed shifts are
    // turned into a bounded piecewise map, and unmatched records are re-pointed through that map.
    // Only what survives this stage may inform the completeness decision.
    if !out.entries.is_empty() {
        let mut index = LocalHeaderIndex::build(data, policy);
        let mut observations: Vec<OffsetObservation> = Vec::new();

        for e in &out.entries {
            let stored = e.local_header_offset;
            // Direct hit: the pointer is still good.
            if let Some(rec) = index.at_offset(stored) {
                if rec.raw_name(data) == Some(e.name.as_bytes()) {
                    observations.push(OffsetObservation {
                        stored,
                        physical: stored,
                    });
                    continue;
                }
            }
            // Otherwise ask the index for headers carrying this record's raw name, and accept one
            // only if it is unique AND its structural fields agree. The name narrows; the
            // structure decides.
            let matches: Vec<u64> = index
                .candidates_named(data, e.name.as_bytes())
                .into_iter()
                .filter(|r| r.method == e.method && (r.crc32 == e.crc32 || r.crc32 == 0))
                .map(|r| r.offset)
                .collect();
            if matches.len() == 1 {
                observations.push(OffsetObservation {
                    stored,
                    physical: matches[0],
                });
            }
        }

        let map = OffsetMap::infer(observations, policy.max_offset_segments);
        out.offset_segments = map.segments.len();
        out.offset_map_kind = Some(map.kind);

        if map.is_usable() {
            let mut repointed = 0usize;
            for e in out.entries.iter_mut() {
                // "A header is there" is not "this record's header is there". An inserted header
                // can occupy exactly the offset a record points at — that is what a planted entry
                // does — and a signature-only check then calls the record resolved while it reads
                // somebody else's fields. Measured on the planted-header fixture: the record for
                // `files/item-0001.jpg` pointed at 102449, which is where the ghost header was
                // inserted, while the real one sat 39 bytes later at 102488. The entry came back
                // as a CRC mismatch, i.e. a genuine file reported as damaged.
                if header_named_at(data, e.local_header_offset, e.name.as_bytes()) {
                    continue;
                }
                if let Some(phys) = map.map(e.local_header_offset) {
                    // Only accept a re-point that actually lands on this record's own header.
                    // The map proposes; the bytes decide.
                    if index
                        .at_offset(phys)
                        .and_then(|r| r.raw_name(data))
                        .is_some_and(|n| n == e.name.as_bytes())
                    {
                        e.local_header_offset = phys;
                        repointed += 1;
                    }
                }
            }
            out.records_repointed = repointed;
            if repointed > 0 {
                out.warnings.push(format!(
                    "ENTRY_OFFSETS_REMAPPED: {repointed} directory record(s) re-pointed through a \
                     {}-segment offset map",
                    map.segments.len()
                ));
            }
        }

        out.records_reconciled = out
            .entries
            .iter()
            .filter(|e| header_named_at(data, e.local_header_offset, e.name.as_bytes()))
            .count();
        out.index_stats = index.stats();
    }

    // ── F-4: the local-header scan is an independent source, not a fallback ──────────────────
    //
    // It runs unless the directory is *complete and confirmed*: every record it produced points
    // at a local header that is really there, and the declared count agrees. Anything less and
    // the archive may hold entries the directory no longer describes.
    let cd_entries = out.entries.len();
    let counts_agree = out.cd_found
        && !out.entries.is_empty()
        && declared_count.is_some_and(|n| n == cd_entries)
        && out
            .entries
            .iter()
            .all(|e| local_header_present(data, e.local_header_offset));

    // Even a directory whose count agrees can be missing something, because a directory only
    // describes the entries it knows about — it cannot describe bytes nobody told it about. If
    // the records do not account for the whole payload area, something is sitting in the gap.
    //
    // This is what a planted local header looks like from the directory's point of view: every
    // record is correct, the count is correct, and there is a hole between two entries that the
    // directory never mentions. Skipping the scan because the directory "looks complete" is how
    // that hole stays invisible — the same fallback reasoning F-4 removed, wearing a better suit.
    //
    // On an undamaged archive the entries tile the payload area exactly, so there is no gap and
    // no scan: this costs intact files nothing.
    let unaccounted_gap = out.cd_found && !out.entries.is_empty() && {
        let horizon = cd_region_start.unwrap_or(data.len() as u64);
        let mut ranges: Vec<(u64, u64)> = out
            .entries
            .iter()
            .filter_map(|e| payload_range(data, e))
            .collect();
        ranges.sort_unstable();
        let mut cursor = 0u64;
        let mut gap = false;
        for (s, e) in ranges {
            // A local file header is 30 bytes before its name; a gap smaller than that cannot
            // hold one, so trailing alignment padding is not treated as a finding.
            if s > cursor && s - cursor >= 30 {
                gap = true;
                break;
            }
            cursor = cursor.max(e);
        }
        gap || horizon.saturating_sub(cursor) >= 30
    };

    let cd_complete = counts_agree && !unaccounted_gap;

    out.cd_declared_count = declared_count;
    out.cd_count_consistent =
        out.cd_found && declared_count.is_some_and(|n| n == cd_entries) && cd_entries > 0;

    if let Some(n) = declared_count {
        if out.cd_found && n != cd_entries {
            // The count is a hint that disagreed. Recorded, never obeyed.
            out.warnings.push(format!(
                "EOCD_ENTRY_COUNT_INCONSISTENT: EOCD declares {n} entries, {cd_entries} \
                 structurally valid records were walked"
            ));
        }
    }

    if !cd_complete {
        out.used_local_scan = true;
        if out.entries.is_empty() {
            out.warnings
                .push("central directory missing/unusable; scanning local file headers".into());
        } else {
            out.warnings.push("LOCAL_HEADER_SCAN_REQUIRED".into());
        }
        let (scanned, limit) = scan_local_headers_bounded(data, policy);
        if let Some(l) = limit {
            out.warnings.push(l.code().to_string());
            out.limits_hit.push(l);
        }
        let report = reconcile_cd_and_scan(
            data,
            std::mem::take(&mut out.entries),
            scanned,
            cd_region_start,
            &containers,
            policy,
        );
        out.nested_candidates = report.nested_candidates;
        out.entries = report.entries;
        out.scan_only_entries = report.scan_only;
        out.conflicts = report.conflicts;
        out.rejected_candidates = report.rejected;
        out.warnings.extend(report.warnings);
    }

    out
}

/// Is there a local file header exactly at `offset`? Cheap physical confirmation of a directory
/// record — the difference between "the directory says so" and "the file agrees".
fn local_header_present(data: &[u8], offset: u64) -> bool {
    let Ok(o) = usize::try_from(offset) else {
        return false;
    };
    // Checked: `offset` may be the "removed by truncation" sentinel (u64::MAX), which converts to
    // usize cleanly on a 64-bit target and then overflows a bare `o + 30`.
    o.checked_add(30).is_some_and(|end| end <= data.len()) && u32le(data, o) == Some(LFH_SIG)
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < 22 {
        return None;
    }
    // EOCD is within the last 22 + 65535 bytes (max comment). Scan backward.
    let scan_start = data.len().saturating_sub(22 + 65_535);
    let mut i = data.len() - 22;
    loop {
        if u32le(data, i) == Some(EOCD_SIG) {
            return Some(i);
        }
        if i == scan_start {
            return None;
        }
        i -= 1;
    }
}

/// Walk the central directory.
///
/// **F-3.** `declared_count` is the EOCD's entry count, and it is a *hint*, never the bound. It
/// used to be both: `max_entries.clamp(1, 1_000_000)` meant a declared count of zero — which a
/// damaged EOCD very often carries — clamped to one, and the walk stopped after a single record
/// even though the directory behind it was completely intact. Measured: 1 of 6 entries recovered
/// where 7-Zip recovered 6 of 6.
///
/// The walk is now bounded by things that are true of the *source*: the slice length, a valid
/// `CDFH` signature at each step, variable-length fields that fit inside the region, forward
/// progress, and the explicit limits in [`ZipRecoveryPolicy`]. The declared count is compared
/// afterwards and reported when it disagrees, because a disagreement is evidence about the damage
/// — it is just not permission to stop reading.
fn parse_central_directory_bounded(
    cd: &[u8],
    declared_count: usize,
    policy: &ZipRecoveryPolicy,
) -> (Vec<ZipEntry>, Option<LimitHit>) {
    let mut entries = Vec::new();
    let mut o = 0usize;
    let mut metadata_bytes = 0usize;
    let mut limit: Option<LimitHit> = None;
    let region = cd.len().min(policy.max_central_bytes);
    let _ = declared_count; // a hint; the caller reports disagreement, the walk ignores it

    while o + 46 <= region {
        if entries.len() >= policy.max_central_records {
            limit = Some(LimitHit::CentralRecords);
            break;
        }
        if u32le(cd, o) != Some(CDFH_SIG) {
            break;
        }
        let flags = u16le(cd, o + 8).unwrap_or(0);
        let method = u16le(cd, o + 10).unwrap_or(0);
        let crc32 = u32le(cd, o + 16).unwrap_or(0);
        let comp_raw = u32le(cd, o + 20).unwrap_or(0);
        let uncomp_raw = u32le(cd, o + 24).unwrap_or(0);
        let name_len = u16le(cd, o + 28).unwrap_or(0) as usize;
        let extra_len = u16le(cd, o + 30).unwrap_or(0) as usize;
        let comment_len = u16le(cd, o + 32).unwrap_or(0) as usize;
        let lho_raw = u32le(cd, o + 42).unwrap_or(0);

        // Variable-length fields must fit inside the region AND inside the policy's per-field
        // bounds. A record claiming a 65 535-byte name in a 200-byte tail is not a record.
        if name_len > policy.max_name_bytes
            || extra_len > policy.max_extra_bytes
            || comment_len > policy.max_comment_bytes
        {
            break;
        }
        let name_start = o + 46;
        let Some(name_end) = name_start.checked_add(name_len) else {
            break; // CENTRAL_DIRECTORY_RECORD_OVERFLOW
        };
        let Some(record_end) = name_end
            .checked_add(extra_len)
            .and_then(|n| n.checked_add(comment_len))
        else {
            break; // CENTRAL_DIRECTORY_RECORD_OVERFLOW
        };
        if record_end > cd.len() {
            break; // CENTRAL_DIRECTORY_RECORD_TRUNCATED — a partial final record is not an entry
        }
        metadata_bytes = metadata_bytes.saturating_add(name_len + extra_len + comment_len);
        if metadata_bytes > policy.max_metadata_bytes {
            limit = Some(LimitHit::MetadataBytes);
            break;
        }

        let raw_name = cd.get(name_start..name_end);
        let name_valid_utf8 = raw_name.is_some_and(|bytes| std::str::from_utf8(bytes).is_ok());
        let name = raw_name
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let zip64 = is_zip64(comp_raw, uncomp_raw, lho_raw)
            || extra_has_zip64(cd.get(name_end..name_end + extra_len));

        entries.push(ZipEntry {
            name,
            name_valid_utf8,
            method,
            crc32,
            comp_size: comp_raw as u64,
            uncomp_size: uncomp_raw as u64,
            local_header_offset: lho_raw as u64,
            flags,
            zip64,
            from_central_dir: true,
        });

        // Forward progress is guaranteed: `record_end >= o + 46`, so the cursor always advances
        // by at least the fixed header. A record cannot send the walk backwards or stall it.
        debug_assert!(record_end > o, "central-directory walk must make progress");
        o = record_end;
    }
    (entries, limit)
}

/// A metadata disagreement between a directory record and the local header it points at.
///
/// Kept rather than resolved. ZIP stores each of these twice, and when the two copies disagree
/// one of them is damaged — but which one is not knowable from the disagreement alone, and
/// picking the more convenient side silently is how a wrong value becomes an authoritative one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryConflict {
    pub name: String,
    pub local_header_offset: u64,
    pub field: &'static str,
    pub central_value: u64,
    pub local_value: u64,
}

impl EntryConflict {
    pub fn code(&self) -> &'static str {
        "CD_LFH_METADATA_CONFLICT"
    }
}

/// A local-header candidate the scan produced and reconciliation refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedCandidate {
    pub local_header_offset: u64,
    pub name: String,
    /// Stable reason code — `NESTED_SIGNATURE_CANDIDATE`, `ENTRY_RANGE_OVERLAP`,
    /// `DUPLICATE_ENTRY_CANDIDATE`, `LOCAL_HEADER_CANDIDATE_REJECTED`.
    pub reason: &'static str,
}

struct ReconcileReport {
    nested_candidates: usize,
    entries: Vec<ZipEntry>,
    scan_only: usize,
    conflicts: Vec<EntryConflict>,
    rejected: Vec<RejectedCandidate>,
    warnings: Vec<String>,
}

/// Merge central-directory records with independently scanned local headers.
///
/// The merge key is **physical**, not the filename: a record is identified by the local-header
/// offset it occupies. Two records naming `a.txt` at different offsets are two entries; two
/// records at the same offset are one entry seen twice. Filenames are attacker-controlled and
/// duplicated legitimately, so they cannot carry identity.
///
/// Directory records are kept as-is and never demoted. Scan-only headers are *added* only when
/// they clear every guard below, and they carry `from_central_dir = false`, which is what stops
/// downstream verification from treating a scan as corroboration of itself.
fn reconcile_cd_and_scan(
    data: &[u8],
    central: Vec<ZipEntry>,
    scanned: Vec<ZipEntry>,
    cd_region_start: Option<u64>,
    containers: &ContainerOwnershipMap,
    policy: &ZipRecoveryPolicy,
) -> ReconcileReport {
    let mut conflicts = Vec::new();
    let mut rejected = Vec::new();
    let mut warnings = Vec::new();

    // Byte ranges already accounted for by an accepted entry: [header_start, payload_end).
    // A candidate inside one of these is a signature that occurs *within* another entry's bytes —
    // a nested archive, or compressed data that happens to spell `PK\x03\x04`.
    let mut claimed: Vec<(u64, u64)> = Vec::new();
    let mut by_offset: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for e in &central {
        by_offset.insert(e.local_header_offset);
        if let Some(r) = payload_range(data, e) {
            claimed.push(r);
        }
    }

    // Regions the directory *declares*, independent of whether the local header survived.
    //
    // `payload_range` needs a readable local header to learn the name/extra lengths, so an entry
    // whose header was cut away claims nothing — and then a `PK\x03\x04` inside that entry's
    // surviving payload looks like a free-standing candidate. That is exactly how a nested
    // archive's member gets misattributed to the outer container after a head truncation.
    //
    // The directory knows the layout regardless: entries are laid out in offset order, so entry
    // i owns everything from its header up to entry i+1's header, and the last owns the rest of
    // the payload area. Claiming those regions makes the guard independent of whether any
    // particular header survived.
    let mut declared: Vec<u64> = central
        .iter()
        .map(|e| e.local_header_offset)
        .filter(|&o| o != u64::MAX)
        .collect();
    declared.sort_unstable();
    declared.dedup();
    let horizon = cd_region_start.unwrap_or(data.len() as u64);

    // Only for records whose own header is unreadable. Where the header IS readable,
    // `payload_range` already claimed the entry's exact extent, and widening it to the next
    // record's offset would swallow whatever sits in between — which is the opposite of what this
    // is for. It would hide a planted header in a gap, and it would reject the genuine scan-only
    // entries that F-4 exists to recover, since those live precisely in the space a surviving
    // record does not cover.
    for e in central.iter() {
        if e.local_header_offset == u64::MAX || payload_range(data, e).is_some() {
            continue;
        }
        let start = e.local_header_offset;
        let end = declared
            .iter()
            .copied()
            .find(|&o| o > start)
            .unwrap_or(horizon);
        if end > start {
            claimed.push((start, end));
        }
    }
    // Everything before the first surviving header belonged to entries the truncation removed.
    // Their payload tails are still there, and candidates found in them are those entries' bytes.
    if central.iter().any(|e| e.local_header_offset == u64::MAX) {
        if let Some(&first) = declared.first() {
            if first > 0 {
                claimed.push((0, first));
            }
        }
    }

    // Confirm each directory record against the header it points at, and record disagreements.
    for e in &central {
        let Ok(o) = usize::try_from(e.local_header_offset) else {
            continue;
        };
        if !local_header_present(data, e.local_header_offset) {
            continue; // the record's target is gone; extraction reports BadLocalHeader
        }
        let l_method = u16le(data, o + 8).unwrap_or(0);
        let l_crc = u32le(data, o + 14).unwrap_or(0);
        let l_csize = u32le(data, o + 18).unwrap_or(0) as u64;
        // A streaming entry legitimately carries zeroes in the local header; the real values live
        // in the directory. That is not a conflict, so it is not reported as one.
        let streaming = e.has_data_descriptor();
        if !streaming {
            if l_crc != e.crc32 && l_crc != 0 {
                conflicts.push(EntryConflict {
                    name: e.name.clone(),
                    local_header_offset: e.local_header_offset,
                    field: "crc32",
                    central_value: e.crc32 as u64,
                    local_value: l_crc as u64,
                });
            }
            if l_csize != e.comp_size && l_csize != 0 {
                conflicts.push(EntryConflict {
                    name: e.name.clone(),
                    local_header_offset: e.local_header_offset,
                    field: "comp_size",
                    central_value: e.comp_size,
                    local_value: l_csize,
                });
            }
        }
        if l_method != e.method {
            conflicts.push(EntryConflict {
                name: e.name.clone(),
                local_header_offset: e.local_header_offset,
                field: "method",
                central_value: e.method as u64,
                local_value: l_method as u64,
            });
        }
    }

    // Ownership first, before any candidate is considered for emission. A directory record that
    // was adopted from an embedded archive is dropped here too: `from_central_dir` describes
    // where a record was read, not which archive it belongs to.
    let mut nested_candidates = 0usize;
    let mut entries: Vec<ZipEntry> = Vec::with_capacity(central.len());
    for e in central {
        if containers.owner_of(e.local_header_offset).is_some() {
            nested_candidates += 1;
            rejected.push(RejectedCandidate {
                local_header_offset: e.local_header_offset,
                name: e.name.clone(),
                reason: ContainerOwnership::NestedContainer.code(),
            });
            continue;
        }
        entries.push(e);
    }
    let mut scan_only = 0usize;

    for cand in scanned {
        if entries.len() >= policy.max_candidate_records {
            warnings.push(LimitHit::CandidateRecords.code().to_string());
            break;
        }
        let off = cand.local_header_offset;

        // Mechanism 2: a destroyed outer local header leaves the scan nothing to tell it where
        // that entry's payload began, so it walks in and finds the embedded archive's headers.
        // They are real headers of a real archive — just not this one.
        if containers.owner_of(off).is_some() {
            nested_candidates += 1;
            rejected.push(RejectedCandidate {
                local_header_offset: off,
                name: cand.name.clone(),
                reason: ContainerOwnership::NestedContainer.code(),
            });
            continue;
        }

        if by_offset.contains(&off) {
            // The directory already describes this header. Not a new entry, not a conflict —
            // it is the corroboration that makes the directory record physically confirmed.
            continue;
        }
        let Some((start, end, truncated)) = payload_range_lenient(data, &cand) else {
            rejected.push(RejectedCandidate {
                local_header_offset: off,
                name: cand.name.clone(),
                reason: "LOCAL_HEADER_CANDIDATE_REJECTED",
            });
            continue;
        };
        // Nested-signature guard: the candidate begins inside bytes another entry already owns.
        if claimed.iter().any(|&(s, e)| start >= s && start < e) {
            rejected.push(RejectedCandidate {
                local_header_offset: off,
                name: cand.name.clone(),
                reason: "NESTED_SIGNATURE_CANDIDATE",
            });
            continue;
        }
        // Overlap guard: the candidate's own (EOF-clamped) payload would run into a claimed range.
        if claimed.iter().any(|&(s, e)| start < e && end > s) {
            rejected.push(RejectedCandidate {
                local_header_offset: off,
                name: cand.name.clone(),
                reason: "ENTRY_RANGE_OVERLAP",
            });
            continue;
        }
        by_offset.insert(off);
        claimed.push((start, end));
        if truncated {
            warnings.push(format!(
                "LOCAL_HEADER_CANDIDATE_TRUNCATED: '{}' at {off} declares a payload that runs \
                 past the end of the file; surfaced so extraction reports Truncated rather than \
                 discarding a real archive member",
                cand.name
            ));
        }
        entries.push(cand);
        scan_only += 1;
    }

    // Deterministic ordering: by physical position, then by name for the degenerate equal case.
    // Idempotence depends on this — reconciling an already-reconciled set must not reorder it.
    entries.sort_by(|a, b| {
        a.local_header_offset
            .cmp(&b.local_header_offset)
            .then_with(|| a.name.cmp(&b.name))
    });

    if scan_only > 0 {
        warnings.push(format!(
            "reconciliation added {scan_only} scan-only entries the central directory did not \
             describe; they are not verified by the scan alone"
        ));
    }
    if !conflicts.is_empty() {
        warnings.push(format!(
            "CD_LFH_METADATA_CONFLICT: {} field disagreement(s) between directory records and \
             their local headers",
            conflicts.len()
        ));
    }

    ReconcileReport {
        nested_candidates,
        entries,
        scan_only,
        conflicts,
        rejected,
        warnings,
    }
}

/// Physical byte range an entry occupies: header start .. payload end.
///
/// `None` when the range cannot be computed — an unknown size, an overflow, or a range that runs
/// past the source. A candidate whose extent is unknown cannot be checked for overlap, and one
/// that cannot be checked is not accepted.
fn payload_range(data: &[u8], e: &ZipEntry) -> Option<(u64, u64)> {
    let o = usize::try_from(e.local_header_offset).ok()?;
    if o.checked_add(30)? > data.len() {
        return None;
    }
    let name_len = u16le(data, o + 26)? as usize;
    let extra_len = u16le(data, o + 28)? as usize;
    let data_start = o
        .checked_add(30)?
        .checked_add(name_len)?
        .checked_add(extra_len)?;
    let end = data_start.checked_add(usize::try_from(e.comp_size).ok()?)?;
    if end > data.len() {
        return None;
    }
    Some((o as u64, end as u64))
}

/// As [`payload_range`], but for a local-header-scan candidate whose declared
/// payload may run past the end of the file — the truncated-archive case.
///
/// A header is only ever rejected here for being genuinely unreadable: the fixed
/// 30-byte header, or the variable-length name/extra fields it declares, must
/// fit inside `data`. Once that much is confirmed, a declared `comp_size` that
/// overruns EOF does not make the candidate untrustworthy — it makes it
/// truncated, which is a fact about the archive, not a reason to discard the
/// entry. The returned end is clamped to `data.len()` so the overlap guard in
/// [`reconcile_cd_and_scan`] still has a well-formed range to test against;
/// `extract_entry` independently re-derives the untruncated declared range and
/// reports [`ExtractStatus::Truncated`] from it.
fn payload_range_lenient(data: &[u8], e: &ZipEntry) -> Option<(u64, u64, bool)> {
    let o = usize::try_from(e.local_header_offset).ok()?;
    if o.checked_add(30)? > data.len() {
        return None;
    }
    let name_len = u16le(data, o + 26)? as usize;
    let extra_len = u16le(data, o + 28)? as usize;
    let data_start = o
        .checked_add(30)?
        .checked_add(name_len)?
        .checked_add(extra_len)?;
    if data_start > data.len() {
        return None;
    }
    let declared_end = data_start.checked_add(usize::try_from(e.comp_size).ok()?)?;
    if declared_end <= data.len() {
        return Some((o as u64, declared_end as u64, false));
    }
    Some((o as u64, data.len() as u64, true))
}

/// Forward scan for local file headers, bounded by policy.
fn scan_local_headers_bounded(
    data: &[u8],
    policy: &ZipRecoveryPolicy,
) -> (Vec<ZipEntry>, Option<LimitHit>) {
    let mut entries = Vec::new();
    let mut limit = None;
    let mut i = 0usize;
    let horizon = data.len().min(policy.max_scan_bytes);
    while i + 30 <= horizon {
        if entries.len() >= policy.max_candidate_records {
            limit = Some(LimitHit::CandidateRecords);
            break;
        }
        if u32le(data, i) != Some(LFH_SIG) {
            i += 1;
            continue;
        }
        let flags = u16le(data, i + 6).unwrap_or(0);
        let method = u16le(data, i + 8).unwrap_or(0);
        let crc32 = u32le(data, i + 14).unwrap_or(0);
        let comp_raw = u32le(data, i + 18).unwrap_or(0);
        let uncomp_raw = u32le(data, i + 22).unwrap_or(0);
        let name_len = u16le(data, i + 26).unwrap_or(0) as usize;
        let extra_len = u16le(data, i + 28).unwrap_or(0) as usize;
        let name_start = i + 30;
        let name_end = name_start + name_len;
        let raw_name = data.get(name_start..name_end);
        let name_valid_utf8 = raw_name.is_some_and(|bytes| std::str::from_utf8(bytes).is_ok());
        let name = raw_name
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let zip64 = is_zip64(comp_raw, uncomp_raw, 0)
            || extra_has_zip64(data.get(name_end..name_end + extra_len));
        let comp_size = comp_raw as u64;

        entries.push(ZipEntry {
            name,
            name_valid_utf8,
            method,
            crc32,
            comp_size,
            uncomp_size: uncomp_raw as u64,
            local_header_offset: i as u64,
            flags,
            zip64,
            from_central_dir: false,
        });

        // Advance past this header + (known) data. When the size is unknown
        // (zero — typical of data-descriptor/streaming entries), jump to the next
        // ZIP signature instead of byte-walking through the payload (which would
        // mint spurious entries from compressed data).
        let data_start = name_end + extra_len;
        let next = if comp_size > 0 {
            data_start.saturating_add(comp_size as usize)
        } else {
            next_signature(data, data_start).unwrap_or(data.len())
        };
        // Forward progress, unconditionally. A record claiming a size that lands the cursor at or
        // before where it started would otherwise spin forever on the same bytes.
        i = if next > i { next } else { i + 1 };
    }
    (entries, limit)
}

/// First offset ≥ `from` that begins a local-file-header, central-directory, or
/// data-descriptor signature — the payload boundary for an unsized entry.
fn next_signature(data: &[u8], from: usize) -> Option<usize> {
    const DD_SIG: u32 = 0x0807_4b50; // "PK\x07\x08" data descriptor
    let mut i = from;
    while i + 4 <= data.len() {
        match u32le(data, i) {
            Some(LFH_SIG) | Some(CDFH_SIG) | Some(DD_SIG) => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// A 32-bit size/offset field set to the ZIP64 sentinel signals ZIP64 in use.
fn is_zip64(comp: u32, uncomp: u32, lho: u32) -> bool {
    comp == ZIP64_SENTINEL_U32 || uncomp == ZIP64_SENTINEL_U32 || lho == ZIP64_SENTINEL_U32
}

/// Does an extra field contain a ZIP64 extended-information record (id 0x0001)?
fn extra_has_zip64(extra: Option<&[u8]>) -> bool {
    let Some(extra) = extra else { return false };
    let mut o = 0usize;
    while o + 4 <= extra.len() {
        let id = u16le(extra, o).unwrap_or(0);
        let len = u16le(extra, o + 2).unwrap_or(0) as usize;
        if id == 0x0001 {
            return true;
        }
        o += 4 + len;
    }
    false
}

// ── extraction ────────────────────────────────────────────────────────────────

/// Extract and CRC-verify one entry's bytes from the container.
pub fn extract_entry(data: &[u8], entry: &ZipEntry) -> ExtractedPart {
    let base = ExtractedPart {
        name: entry.name.clone(),
        bytes: Vec::new(),
        status: ExtractStatus::BadLocalHeader,
        crc_expected: entry.crc32,
        crc_actual: 0,
    };

    // Abstain (never bypass) on out-of-scope entries, before touching payload.
    if entry.is_encrypted() {
        return ExtractedPart {
            status: ExtractStatus::Encrypted,
            ..base
        };
    }
    if entry.zip64 {
        return ExtractedPart {
            status: ExtractStatus::Zip64Unsupported,
            ..base
        };
    }
    // A streaming entry whose true size lives only in a (now-absent) central
    // directory cannot be sized from a local scan — abstain rather than guess.
    if !entry.from_central_dir && entry.has_data_descriptor() && entry.comp_size == 0 {
        return ExtractedPart {
            status: ExtractStatus::StreamedUnsized,
            ..base
        };
    }

    let lfh = entry.local_header_offset as usize;
    if u32le(data, lfh) != Some(LFH_SIG) {
        return base;
    }
    let name_len = match u16le(data, lfh + 26) {
        Some(v) => v as usize,
        None => return base,
    };
    let extra_len = match u16le(data, lfh + 28) {
        Some(v) => v as usize,
        None => return base,
    };
    let data_start = lfh + 30 + name_len + extra_len;
    let data_end = match data_start.checked_add(entry.comp_size as usize) {
        Some(e) => e,
        None => return base,
    };
    let Some(comp) = data.get(data_start..data_end) else {
        return ExtractedPart {
            status: ExtractStatus::Truncated,
            ..base
        };
    };

    let decoded = match entry.method {
        0 => Some(comp.to_vec()), // stored
        8 => inflate_bounded(comp, MAX_INFLATE_BYTES),
        m => {
            return ExtractedPart {
                status: ExtractStatus::Unsupported(m),
                ..base
            }
        }
    };

    match decoded {
        None => ExtractedPart {
            status: ExtractStatus::DecodeFailed,
            ..base
        },
        Some(bytes) => {
            let actual = crc32(&bytes);
            let status = if actual == entry.crc32 {
                ExtractStatus::VerifiedCrc
            } else {
                ExtractStatus::CrcMismatch
            };
            ExtractedPart {
                name: entry.name.clone(),
                bytes,
                status,
                crc_expected: entry.crc32,
                crc_actual: actual,
            }
        }
    }
}

/// Is there a local header at `offset` carrying exactly `name`?
///
/// Stronger than [`local_header_present`], and the distinction is load-bearing: a planted header
/// can sit at precisely the offset a directory record points at, so checking only the signature
/// declares the record resolved while it reads another entry's fields.
fn header_named_at(data: &[u8], offset: u64, name: &[u8]) -> bool {
    let Ok(o) = usize::try_from(offset) else {
        return false;
    };
    if !local_header_present(data, o as u64) {
        return false;
    }
    u16le(data, o + 26).is_some_and(|nl| {
        nl as usize == name.len()
            && data
                .get(o + 30..o + 30 + name.len())
                .is_some_and(|n| n == name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build;

    #[test]
    fn enumerates_and_verifies_stored_and_deflate() {
        let parts: Vec<(&str, &[u8])> = vec![
            ("[Content_Types].xml", b"<Types/>"),
            ("word/document.xml", b"<document>hello world</document>"),
        ];
        let zip = build::encode_zip(&parts);
        let parsed = parse_zip(&zip);
        assert!(parsed.eocd_found && parsed.cd_found);
        assert_eq!(parsed.entries.len(), 2);

        for e in &parsed.entries {
            let x = extract_entry(&zip, e);
            assert_eq!(
                x.status,
                ExtractStatus::VerifiedCrc,
                "entry {} must verify",
                e.name
            );
        }
    }

    #[test]
    fn crc_mismatch_is_flagged_not_verified() {
        let parts: Vec<(&str, &[u8])> = vec![("a.xml", b"<a>data</a>")];
        let mut zip = build::encode_zip(&parts);
        // Corrupt one byte of the (stored) payload so the CRC no longer matches.
        let parsed = parse_zip(&zip);
        let e = &parsed.entries[0];
        let lfh = e.local_header_offset as usize;
        let name_len = u16le(&zip, lfh + 26).unwrap() as usize;
        let extra_len = u16le(&zip, lfh + 28).unwrap() as usize;
        let data_start = lfh + 30 + name_len + extra_len;
        zip[data_start] ^= 0xFF;
        let x = extract_entry(&zip, &parsed.entries[0]);
        assert_eq!(x.status, ExtractStatus::CrcMismatch);
        assert_ne!(x.crc_actual, x.crc_expected);
    }

    #[test]
    fn local_scan_fallback_when_cd_removed() {
        let parts: Vec<(&str, &[u8])> = vec![("only.xml", b"<x/>")];
        let zip = build::encode_zip(&parts);
        // Truncate off the central directory + EOCD (keep only the local entry).
        let parsed_full = parse_zip(&zip);
        let e = &parsed_full.entries[0];
        // Cut just before the central directory: find first CDFH sig.
        let cd_pos = (0..zip.len() - 4)
            .find(|&i| u32le(&zip, i) == Some(CDFH_SIG))
            .unwrap();
        let truncated = &zip[..cd_pos];
        let parsed = parse_zip(truncated);
        assert!(parsed.used_local_scan);
        assert_eq!(parsed.entries.len(), 1);
        let x = extract_entry(truncated, &parsed.entries[0]);
        assert_eq!(x.status, ExtractStatus::VerifiedCrc);
        let _ = e;
    }

    #[test]
    fn malformed_bytes_no_panic() {
        let junk = vec![0x50u8, 0x4b, 0x03, 0x04, 0xff, 0xff, 0xff];
        let parsed = parse_zip(&junk);
        // No EOCD, local scan finds a bogus header; extraction must not panic.
        for e in &parsed.entries {
            let _ = extract_entry(&junk, e);
        }
    }

    /// Set the general-purpose flag bit(s) `mask` on a named entry, in both the
    /// local file header (offset +6) and the central directory record (offset +8).
    fn set_flags(zip: &mut [u8], name: &str, mask: u16) {
        let parsed = parse_zip(zip);
        let e = parsed
            .entries
            .iter()
            .find(|e| e.name == name)
            .expect("entry present");
        let lfh = e.local_header_offset as usize;
        let cur = u16le(zip, lfh + 6).unwrap();
        let new = (cur | mask).to_le_bytes();
        zip[lfh + 6] = new[0];
        zip[lfh + 7] = new[1];
        // Find this entry's CD record and patch its flag field too.
        let mut o = (0..zip.len().saturating_sub(4))
            .find(|&i| u32le(zip, i) == Some(CDFH_SIG))
            .unwrap();
        loop {
            if u32le(zip, o) != Some(CDFH_SIG) {
                break;
            }
            let name_len = u16le(zip, o + 28).unwrap() as usize;
            let extra_len = u16le(zip, o + 30).unwrap() as usize;
            let comment_len = u16le(zip, o + 32).unwrap() as usize;
            let nm = String::from_utf8_lossy(&zip[o + 46..o + 46 + name_len]).into_owned();
            if nm == name {
                let cur = u16le(zip, o + 8).unwrap();
                let new = (cur | mask).to_le_bytes();
                zip[o + 8] = new[0];
                zip[o + 9] = new[1];
                break;
            }
            o += 46 + name_len + extra_len + comment_len;
        }
    }

    #[test]
    fn encrypted_entry_abstains_never_bypasses() {
        let mut zip = build::encode_docx();
        set_flags(&mut zip, "word/document.xml", 0x0001); // encryption bit
        let parsed = parse_zip(&zip);
        let e = parsed
            .entries
            .iter()
            .find(|e| e.name == "word/document.xml")
            .unwrap();
        assert!(e.is_encrypted());
        assert_eq!(extract_entry(&zip, e).status, ExtractStatus::Encrypted);
    }

    #[test]
    fn zip64_sentinel_entry_abstains() {
        let mut zip = build::encode_docx();
        // Force the CD compressed-size field of one entry to the ZIP64 sentinel.
        let parsed = parse_zip(&zip);
        let target = "word/document.xml";
        let mut o = (0..zip.len().saturating_sub(4))
            .find(|&i| u32le(&zip, i) == Some(CDFH_SIG))
            .unwrap();
        loop {
            let name_len = u16le(&zip, o + 28).unwrap() as usize;
            let extra_len = u16le(&zip, o + 30).unwrap() as usize;
            let comment_len = u16le(&zip, o + 32).unwrap() as usize;
            let nm = String::from_utf8_lossy(&zip[o + 46..o + 46 + name_len]).into_owned();
            if nm == target {
                for b in zip[o + 20..o + 24].iter_mut() {
                    *b = 0xFF;
                }
                break;
            }
            o += 46 + name_len + extra_len + comment_len;
        }
        let parsed2 = parse_zip(&zip);
        let e = parsed2.entries.iter().find(|e| e.name == target).unwrap();
        assert!(e.zip64);
        assert_eq!(
            extract_entry(&zip, e).status,
            ExtractStatus::Zip64Unsupported
        );
        let _ = parsed;
    }

    #[test]
    fn streamed_entry_without_cd_abstains_unsized() {
        // Streaming entries (bit 3, zero local sizes); then drop the CD so only
        // the local scan remains — the true sizes are gone, so PHX abstains.
        let parts: Vec<(&str, &[u8])> = vec![
            ("[Content_Types].xml", b"<Types/>"),
            (
                "word/document.xml",
                b"<document>streamed payload here</document>",
            ),
        ];
        let zip = build::encode_zip_streamed(&parts);
        let cd_pos = (0..zip.len() - 4)
            .find(|&i| u32le(&zip, i) == Some(CDFH_SIG))
            .unwrap();
        let truncated = &zip[..cd_pos];
        let parsed = parse_zip(truncated);
        assert!(parsed.used_local_scan);
        // Every recovered local entry has bit 3 and abstains (never falsely verified).
        let mut saw_streamed = false;
        for e in &parsed.entries {
            let st = extract_entry(truncated, e).status;
            assert_ne!(st, ExtractStatus::VerifiedCrc);
            if e.has_data_descriptor() && e.comp_size == 0 {
                assert_eq!(st, ExtractStatus::StreamedUnsized);
                saw_streamed = true;
            }
        }
        assert!(saw_streamed);
    }

    /// Encode one raw local file header + name (no payload bytes): sig, version,
    /// flags, method, time, date, crc, comp size, uncomp size, name len, extra
    /// len (0), name. Exactly the 30-byte fixed layout `scan_local_headers_bounded`
    /// and `payload_range_lenient` read.
    fn raw_lfh(name: &str, method: u16, crc: u32, comp_size: u32, uncomp_size: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&LFH_SIG.to_le_bytes());
        b.extend_from_slice(&20u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes()); // flags
        b.extend_from_slice(&method.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes()); // time
        b.extend_from_slice(&0u16.to_le_bytes()); // date
        b.extend_from_slice(&crc.to_le_bytes());
        b.extend_from_slice(&comp_size.to_le_bytes());
        b.extend_from_slice(&uncomp_size.to_le_bytes());
        let name_bytes = name.as_bytes();
        b.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes()); // extra len
        b.extend_from_slice(name_bytes);
        b
    }

    // ── G1 fallback-scan tests (docs/web-studio/WASM_FEASIBILITY.md, Phase G) ──

    #[test]
    fn truncated_local_header_scan_surfaces_a_damaged_entry_instead_of_discarding_it() {
        // No EOCD, no central directory, and the local header declares more
        // payload than the file actually contains — the head-truncated-tail case
        // (site/tests/zip-checker/fixtures.mjs: `truncated-entry-data`). Before
        // this fix, `reconcile_cd_and_scan` discarded any scan candidate whose
        // declared payload ran past EOF; now it is surfaced so `extract_entry`
        // can report it Truncated.
        let payload = vec![7u8; 300];
        let crc = crc32(&payload);
        let mut data = raw_lfh("cut.bin", 0, crc, 600, 600); // declares 600 bytes
        data.extend_from_slice(&payload); // only 300 really present

        let parsed = parse_zip(&data);
        assert!(!parsed.eocd_found);
        assert!(!parsed.cd_found);
        assert!(parsed.used_local_scan);
        assert_eq!(
            parsed.entries.len(),
            1,
            "the truncated entry must be surfaced, not discarded"
        );
        assert_eq!(
            extract_entry(&data, &parsed.entries[0]).status,
            ExtractStatus::Truncated
        );
        assert!(parsed
            .warnings
            .iter()
            .any(|w| w.contains("LOCAL_HEADER_CANDIDATE_TRUNCATED")));
    }

    #[test]
    fn local_header_scan_skips_a_signature_embedded_in_another_entrys_declared_payload() {
        // `a.bin`'s real, correctly-declared payload happens to contain four
        // bytes that spell the local-file-header signature. The scanner advances
        // by the entry's own declared comp_size, not byte-by-byte through known
        // payload, so this must never be treated as a second entry — protection
        // against a false signature inside compressed/arbitrary data.
        let mut payload = vec![0x41u8; 40];
        payload[10..14].copy_from_slice(&LFH_SIG.to_le_bytes());
        let crc = crc32(&payload);
        let mut data = raw_lfh("a.bin", 0, crc, payload.len() as u32, payload.len() as u32);
        data.extend_from_slice(&payload);

        let parsed = parse_zip(&data);
        assert_eq!(
            parsed.entries.len(),
            1,
            "no entry may be minted from a signature inside a.bin's own declared payload"
        );
        assert_eq!(parsed.entries[0].name, "a.bin");
        assert_eq!(
            extract_entry(&data, &parsed.entries[0]).status,
            ExtractStatus::VerifiedCrc
        );
    }

    #[test]
    fn reconcile_rejects_a_scan_candidate_inside_a_directory_records_declared_span() {
        // `a.bin` is described by a central-directory record whose comp_size
        // field disagrees with a.bin's own local header and reaches past
        // `b.bin`'s real header — simulating a directory record whose size field
        // does not match reality. `b.bin` is not described by the directory at
        // all, so the local scan finds its real header independently; overlap
        // protection must reject it rather than mint it as a second entry.
        let a_payload = vec![0x41u8; 20];
        let a_crc = crc32(&a_payload);
        let mut data = raw_lfh(
            "a.bin",
            0,
            a_crc,
            a_payload.len() as u32,
            a_payload.len() as u32,
        );
        data.extend_from_slice(&a_payload);

        let b_payload = vec![0x42u8; 20];
        let b_crc = crc32(&b_payload);
        data.extend_from_slice(&raw_lfh(
            "b.bin",
            0,
            b_crc,
            b_payload.len() as u32,
            b_payload.len() as u32,
        ));
        data.extend_from_slice(&b_payload);

        // The directory's record for a.bin claims 50 bytes of payload — more
        // than a.bin's real 20, reaching well past b.bin's real header at 55,
        // but still inside the file (len 110).
        let central = vec![ZipEntry {
            name: "a.bin".to_string(),
            name_valid_utf8: true,
            method: 0,
            crc32: a_crc,
            comp_size: 50,
            uncomp_size: 50,
            local_header_offset: 0,
            flags: 0,
            zip64: false,
            from_central_dir: true,
        }];

        let policy = ZipRecoveryPolicy::default();
        let (scanned, _limit) = scan_local_headers_bounded(&data, &policy);
        assert!(
            scanned.iter().any(|e| e.name == "b.bin"),
            "the scan must independently find b.bin's real header"
        );

        let containers = ContainerOwnershipMap::detect(&data, &policy);
        let report = reconcile_cd_and_scan(&data, central, scanned, Some(0), &containers, &policy);

        assert!(
            !report.entries.iter().any(|e| e.name == "b.bin"),
            "b.bin must not be admitted while it lies inside a.bin's declared span"
        );
        assert!(report
            .rejected
            .iter()
            .any(|r| r.name == "b.bin" && r.reason == "NESTED_SIGNATURE_CANDIDATE"));
    }

    #[test]
    fn malformed_header_with_name_length_past_eof_is_rejected_not_guessed() {
        // The 30-byte fixed header is present and readable, but its declared
        // name length runs past the end of the file — the name cannot be read
        // at all. Must be refused outright, not guessed at, padded, or panic.
        let mut data = LFH_SIG.to_le_bytes().to_vec();
        data.extend_from_slice(&20u16.to_le_bytes()); // version
        data.extend_from_slice(&0u16.to_le_bytes()); // flags
        data.extend_from_slice(&0u16.to_le_bytes()); // method
        data.extend_from_slice(&0u16.to_le_bytes()); // time
        data.extend_from_slice(&0u16.to_le_bytes()); // date
        data.extend_from_slice(&0u32.to_le_bytes()); // crc
        data.extend_from_slice(&0u32.to_le_bytes()); // comp size
        data.extend_from_slice(&0u32.to_le_bytes()); // uncomp size
        data.extend_from_slice(&65535u16.to_le_bytes()); // name len: absurd
        data.extend_from_slice(&0u16.to_le_bytes()); // extra len
                                                     // No name bytes follow — the file ends here, at exactly 30 bytes.
        assert_eq!(data.len(), 30);

        let entry = ZipEntry {
            name: String::new(),
            name_valid_utf8: true,
            method: 0,
            crc32: 0,
            comp_size: 0,
            uncomp_size: 0,
            local_header_offset: 0,
            flags: 0,
            zip64: false,
            from_central_dir: false,
        };
        assert!(
            payload_range_lenient(&data, &entry).is_none(),
            "a header whose own name field cannot be read must be rejected, not clamped"
        );

        // Through the full pipeline: no EOCD, no CD, and the only header in the
        // file cannot be read past its fixed portion. Must not panic and must
        // not fabricate an entry.
        let parsed = parse_zip(&data);
        for e in &parsed.entries {
            let _ = extract_entry(&data, e);
        }
    }

    /// Decode a hex literal into bytes. Test-only.
    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // ── Contract-pinned intentional upgrades over the JS reference core ────────
    //
    // These two fixtures are byte-identical to `stale-cd-offset` and
    // `overlapping-range` in site/tests/zip-checker/fixtures.mjs (verified by
    // running that fixture's own `build()` and hex-dumping the result — not
    // reconstructed by hand). tools/wasm-zip-core/parity-contract.mjs cites
    // these two tests by name as the mechanism for why the Rust/WASM engine's
    // stronger result is the approved contract value, not an unexplained
    // divergence from the JS core.

    #[test]
    fn stale_central_directory_offset_is_located_by_size_and_verified() {
        // EOCD's declared central-directory offset (3) is wrong; the directory's
        // SIZE still correctly locates it at `eocd_offset - cd_size` (= 42),
        // where a real CDFH record is found and the entry verifies.
        let data = hex_bytes(concat!(
            "504b030414000000000000000000156a2c42070000000700000005000000",
            "782e7478747061796c6f6164504b0102140014000000000000000000156a",
            "2c420700000007000000050000000000000000000000000000000000782e",
            "747874504b0506000000000100010033000000030000000000"
        ));

        let parsed = parse_zip(&data);
        assert!(parsed.eocd_found);
        assert!(
            parsed.cd_found,
            "the directory must be located by its size when the declared offset is stale"
        );
        assert!(parsed.cd_located_by_size);
        assert!(!parsed.used_local_scan);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "x.txt");
        assert_eq!(
            extract_entry(&data, &parsed.entries[0]).status,
            ExtractStatus::VerifiedCrc
        );
        assert!(parsed
            .warnings
            .iter()
            .any(|w| w.starts_with("EOCD_DIRECTORY_OFFSET_STALE")));
    }

    #[test]
    fn two_directory_records_pointing_at_one_local_header_reconcile_to_three_entries_two_verified()
    {
        // The central directory's second record ("q.txt") was corrupted to point
        // at the first record's ("p.txt") local header. The orphaned real header
        // for q.txt is recovered by the independent local-header scan: three
        // entries result — p.txt (verified), the CD's q.txt record read against
        // p.txt's physical header (a genuine CRC mismatch, correctly reported
        // damaged, not silently dropped), and the scan-recovered q.txt (verified)
        // — not the two entries a directory-only reader would report.
        let data = hex_bytes(concat!(
            "504b0304140000000000000000000b5704bb100000001000000005000000702e",
            "74787441414141414141414141414141414141504b0304140000000000000000",
            "006cf558a2100000001000000005000000712e74787442424242424242424242",
            "424242424242504b01021400140000000000000000000b5704bb100000001000",
            "0000050000000000000000000000000000000000702e747874504b0102140014",
            "0000000000000000006cf558a210000000100000000500000000000000000000",
            "00000000000000712e747874504b050600000000020002006600000066000000",
            "0000",
        ));

        let parsed = parse_zip(&data);
        assert!(parsed.cd_found);
        assert!(parsed.used_local_scan);
        assert_eq!(parsed.entries.len(), 3);

        let statuses: Vec<(bool, ExtractStatus)> = parsed
            .entries
            .iter()
            .map(|e| (e.from_central_dir, extract_entry(&data, e).status))
            .collect();
        let verified = statuses
            .iter()
            .filter(|(_, s)| *s == ExtractStatus::VerifiedCrc)
            .count();
        let mismatched = statuses
            .iter()
            .filter(|(_, s)| *s == ExtractStatus::CrcMismatch)
            .count();
        assert_eq!(
            verified, 2,
            "p.txt and the scan-recovered q.txt must both verify"
        );
        assert_eq!(
            mismatched, 1,
            "the directory's q.txt record, read against p.txt's physical header, is a genuine \
             mismatch — reported damaged, not hidden"
        );
    }
}
