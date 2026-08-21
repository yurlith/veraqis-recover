//! Physical index of local file headers, built once per archive.
//!
//! Two problems in this crate both reduce to "given a directory record, find the local header it
//! describes" — and both were solved by scanning the whole source, per record:
//!
//! * **Reconciliation.** An edit anywhere in an archive shifts every offset after it, so a
//!   directory record's stored offset stops pointing at its header while the record itself stays
//!   perfectly valid. Finding the header again is a lookup, not a search.
//! * **Base derivation.** `derive_base_from_records` probed every byte offset below the directory
//!   looking for a header with a matching name. That is `O(source)` per record, and it is what
//!   put p99 at 156 ms and max at 1771 ms against a 45 ms / 189 ms baseline.
//!
//! So the headers are indexed once: a forward pass that records every structurally plausible local
//! header, bucketed by a hash of its raw filename bytes.
//!
//! **The name is a narrowing key, never an identity.** A bucket hit is a candidate; it becomes a
//! match only after the raw name bytes compare equal and the structural fields agree. Two entries
//! may legitimately share a name, and an attacker may plant a header with any name at all, so
//! every lookup returns *all* bucket candidates and the caller validates each one.

use std::collections::HashMap;

use crate::zip_policy::ZipRecoveryPolicy;

const LFH_SIG: u32 = 0x0403_4b50;

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

/// FNV-1a over the raw filename bytes. Bucketing only — never compared instead of the bytes.
fn name_hash(name: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// One structurally plausible local file header found in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHeaderRecord {
    pub offset: u64,
    pub name_start: usize,
    pub name_len: usize,
    pub method: u16,
    pub flags: u16,
    pub crc32: u32,
    pub comp_size: u64,
    pub uncomp_size: u64,
    /// First byte of the payload — after the header, name and extra field.
    pub data_start: u64,
}

impl LocalHeaderRecord {
    /// Raw filename bytes, borrowed from the source. Never lossily decoded here: a lossy decode
    /// would make two different names compare equal.
    pub fn raw_name<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        data.get(self.name_start..self.name_start.checked_add(self.name_len)?)
    }
}

/// Counters the operation-count gate reads. Wall-clock is evidence; these are the invariant.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IndexStats {
    /// Headers admitted to the index.
    pub indexed_lfh_count: usize,
    /// Byte positions examined while building it — one forward pass, so `O(source)` once.
    pub index_build_reads: usize,
    /// Bucket lookups performed.
    pub base_lookup_buckets: usize,
    /// Candidates examined across all lookups. Bounded by bucket size, not by source length.
    pub base_candidate_probes: usize,
    /// Byte offsets swept by any surviving linear fallback. **Must be 0** on tested paths.
    pub fallback_linear_probes: usize,
}

/// Local headers of one source, indexed by position and by filename hash.
#[derive(Debug, Default)]
pub struct LocalHeaderIndex {
    records: Vec<LocalHeaderRecord>,
    by_name: HashMap<u64, Vec<usize>>,
    by_offset: HashMap<u64, usize>,
    stats: IndexStats,
}

impl LocalHeaderIndex {
    /// One forward pass over the source. Every plausible header is recorded; validation of what a
    /// header *means* belongs to the caller, not to the index.
    pub fn build(data: &[u8], policy: &ZipRecoveryPolicy) -> Self {
        let mut idx = LocalHeaderIndex::default();
        let horizon = data.len().min(policy.max_scan_bytes);
        let mut i = 0usize;
        let mut reads = 0usize;

        while i + 30 <= horizon {
            reads += 1;
            if u32le(data, i) != Some(LFH_SIG) {
                i += 1;
                continue;
            }
            if idx.records.len() >= policy.max_candidate_records {
                break;
            }
            let flags = u16le(data, i + 6).unwrap_or(0);
            let method = u16le(data, i + 8).unwrap_or(0);
            let crc32 = u32le(data, i + 14).unwrap_or(0);
            let comp = u32le(data, i + 18).unwrap_or(0) as u64;
            let uncomp = u32le(data, i + 22).unwrap_or(0) as u64;
            let name_len = u16le(data, i + 26).unwrap_or(0) as usize;
            let extra_len = u16le(data, i + 28).unwrap_or(0) as usize;

            if name_len == 0
                || name_len > policy.max_name_bytes
                || extra_len > policy.max_extra_bytes
            {
                i += 1;
                continue;
            }
            let name_start = i + 30;
            let Some(name_end) = name_start.checked_add(name_len) else {
                i += 1;
                continue;
            };
            let Some(data_start) = name_end.checked_add(extra_len) else {
                i += 1;
                continue;
            };
            if data_start > data.len() {
                i += 1;
                continue;
            }
            let Some(name) = data.get(name_start..name_end) else {
                i += 1;
                continue;
            };

            let slot = idx.records.len();
            idx.by_name.entry(name_hash(name)).or_default().push(slot);
            idx.by_offset.insert(i as u64, slot);
            idx.records.push(LocalHeaderRecord {
                offset: i as u64,
                name_start,
                name_len,
                method,
                flags,
                crc32,
                comp_size: comp,
                uncomp_size: uncomp,
                data_start: data_start as u64,
            });

            // Advance past this entry's payload where the size is known, exactly as the scanner
            // does, so an entry's own contents do not mint further candidates. Always progress.
            let next = if comp > 0 {
                data_start.saturating_add(comp as usize)
            } else {
                data_start
            };
            i = if next > i { next } else { i + 1 };
        }

        idx.stats.indexed_lfh_count = idx.records.len();
        idx.stats.index_build_reads = reads;
        idx
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn stats(&self) -> IndexStats {
        self.stats
    }

    pub fn records(&self) -> &[LocalHeaderRecord] {
        &self.records
    }

    /// The header at exactly `offset`, if one was indexed there.
    pub fn at_offset(&self, offset: u64) -> Option<&LocalHeaderRecord> {
        self.by_offset.get(&offset).map(|&s| &self.records[s])
    }

    /// Every indexed header whose raw filename bytes equal `name`.
    ///
    /// The hash selects a bucket; the bytes decide membership, so a hash collision costs a
    /// comparison and never produces a wrong match. Probe counts are recorded so a regression to
    /// source-wide scanning is detectable by an operation count rather than by a stopwatch.
    pub fn candidates_named<'a>(
        &'a mut self,
        data: &'a [u8],
        name: &[u8],
    ) -> Vec<&'a LocalHeaderRecord> {
        self.stats.base_lookup_buckets += 1;
        let Some(slots) = self.by_name.get(&name_hash(name)) else {
            return Vec::new();
        };
        self.stats.base_candidate_probes += slots.len();
        slots
            .iter()
            .map(|&s| &self.records[s])
            .filter(|r| r.raw_name(data) == Some(name))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phx_test_utils::generators;

    #[test]
    fn indexes_every_entry_of_a_clean_archive() {
        let zip = generators::clean_zip(&[
            ("a.txt", b"alpha"),
            ("b.txt", b"bravo"),
            ("c.txt", b"charlie"),
        ]);
        let idx = LocalHeaderIndex::build(&zip, &ZipRecoveryPolicy::default());
        assert_eq!(idx.len(), 3);
        assert!(idx.stats().index_build_reads > 0);
        assert_eq!(idx.stats().fallback_linear_probes, 0);
    }

    #[test]
    fn lookup_is_by_bytes_not_by_hash() {
        let zip = generators::clean_zip(&[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
        let mut idx = LocalHeaderIndex::build(&zip, &ZipRecoveryPolicy::default());
        let hits = idx.candidates_named(&zip, b"a.txt");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 0);
        let miss = idx.candidates_named(&zip, b"nonexistent.txt");
        assert!(miss.is_empty());
    }

    #[test]
    fn duplicate_names_return_every_candidate() {
        // Identity is physical, so two headers with one name are two candidates and the caller
        // must decide between them — never the index by picking the first.
        let zip = generators::clean_zip(&[("same.txt", b"first"), ("same.txt", b"second")]);
        let mut idx = LocalHeaderIndex::build(&zip, &ZipRecoveryPolicy::default());
        let hits = idx.candidates_named(&zip, b"same.txt");
        assert_eq!(hits.len(), 2, "both must be offered");
        assert_ne!(hits[0].offset, hits[1].offset);
    }

    #[test]
    fn probe_count_is_bounded_by_the_bucket_not_the_source() {
        // Many entries, one looked-up name. A source-wide scan would probe proportionally to the
        // archive; an index probes proportionally to the bucket.
        let bodies: Vec<Vec<u8>> = (0..60)
            .map(|i| format!("payload {i}").into_bytes())
            .collect();
        let named: Vec<(String, &[u8])> = bodies
            .iter()
            .enumerate()
            .map(|(i, b)| (format!("file-{i:03}.txt"), b.as_slice()))
            .collect();
        let refs: Vec<(&str, &[u8])> = named.iter().map(|(n, b)| (n.as_str(), *b)).collect();
        let zip = generators::clean_zip(&refs);

        let mut idx = LocalHeaderIndex::build(&zip, &ZipRecoveryPolicy::default());
        assert_eq!(idx.len(), 60);
        let _ = idx.candidates_named(&zip, b"file-059.txt");
        let s = idx.stats();
        assert!(
            s.base_candidate_probes <= 2,
            "a unique name must cost about one probe, not a sweep: {}",
            s.base_candidate_probes
        );
        assert_eq!(s.fallback_linear_probes, 0);
    }

    #[test]
    fn an_empty_source_indexes_nothing_and_never_panics() {
        let idx = LocalHeaderIndex::build(&[], &ZipRecoveryPolicy::default());
        assert!(idx.is_empty());
        let idx = LocalHeaderIndex::build(&[0u8; 64], &ZipRecoveryPolicy::default());
        assert!(idx.is_empty());
    }
}
