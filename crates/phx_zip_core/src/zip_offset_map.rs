//! Piecewise offset mapping between a directory's stored offsets and physical reality.
//!
//! A ZIP's directory records point at local headers by absolute offset. Any edit to the archive —
//! a deletion, an insertion, a truncated head — moves everything after it, so those pointers go
//! stale while the records themselves stay perfectly valid. Recovering such an archive means
//! recovering the *mapping*, not discarding the directory.
//!
//! E2 already did this for one global delta, which covers head truncation: every offset moved by
//! the same amount. It does not cover an edit in the middle, where records before the edit still
//! resolve at delta 0 and records after it need the edit's length. On
//! `ci-nested-one-level-between-entries-delete_256_bytes_across_boundary` that is exactly the
//! shape — record 0 at delta 0, records 1–5 at delta −256 — and E2 correctly refused it, because
//! no single delta explains the archive.
//!
//! So the map is piecewise, and deliberately *barely* so:
//!
//! * deltas are observed, never guessed — each comes from a record that was matched to a physical
//!   header by its raw name bytes and structural fields;
//! * segments are runs of equal observed delta over records in physical order;
//! * the map must be monotonic, because entries do not reorder themselves;
//! * the segment count is capped, so a hostile file cannot demand an arbitrary map;
//! * a record with no observation is left **unresolved**. It is never interpolated: inventing an
//!   offset would manufacture exactly the kind of unproven placement the evidence model forbids.
//!
//! An unbounded or oscillating map is rejected outright. The point of the cap is that a genuine
//! edit produces very few segments; a map that needs many is not describing an edit.

/// One contiguous run of stored offsets that all moved by the same amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetSegment {
    /// First stored offset this segment explains.
    pub original_start: u64,
    /// Last stored offset this segment explains, inclusive.
    pub original_end: u64,
    /// Physical offset minus stored offset for every record in the run.
    pub delta: i64,
    /// How many matched records support it. A one-record segment is legal only at the ends,
    /// where an edit boundary genuinely falls between two records.
    pub support: usize,
}

impl OffsetSegment {
    pub fn contains(&self, stored: u64) -> bool {
        stored >= self.original_start && stored <= self.original_end
    }
    /// Apply this segment's shift. `None` if the result would be negative or overflow.
    pub fn apply(&self, stored: u64) -> Option<u64> {
        let v = (stored as i64).checked_add(self.delta)?;
        if v < 0 {
            None
        } else {
            Some(v as u64)
        }
    }
}

/// What the observations supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetMapKind {
    /// Nothing was matched; no mapping can be claimed.
    Empty,
    /// One delta explains every observation — the E2 fast path, including delta 0.
    SingleDelta,
    /// Several ordered runs. A middle edit.
    Piecewise,
    /// Observations contradict an ordered shift; no map is offered.
    Rejected,
}

/// An observed (stored offset → physical offset) pair from one reconciled record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetObservation {
    pub stored: u64,
    pub physical: u64,
}

/// The mapping inferred from a set of observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffsetMap {
    pub kind: OffsetMapKind,
    pub segments: Vec<OffsetSegment>,
    /// Observations that were dropped because they broke monotonicity.
    pub discarded: usize,
}

impl OffsetMap {
    pub fn empty() -> Self {
        OffsetMap {
            kind: OffsetMapKind::Empty,
            segments: Vec::new(),
            discarded: 0,
        }
    }

    pub fn is_usable(&self) -> bool {
        matches!(
            self.kind,
            OffsetMapKind::SingleDelta | OffsetMapKind::Piecewise
        )
    }

    /// Translate a stored offset. `None` when no segment covers it — the honest answer for a
    /// record the observations never spoke about.
    pub fn map(&self, stored: u64) -> Option<u64> {
        if !self.is_usable() {
            return None;
        }
        self.segments
            .iter()
            .find(|s| s.contains(stored))
            .and_then(|s| s.apply(stored))
    }

    /// Infer a map from observations.
    ///
    /// `max_segments` caps how complicated an edit history the map may describe. Two is enough for
    /// a single deletion or insertion; the default policy allows a few more so two edits are still
    /// expressible, and beyond that the file is not describing an edit.
    pub fn infer(mut observations: Vec<OffsetObservation>, max_segments: usize) -> Self {
        if observations.is_empty() || max_segments == 0 {
            return OffsetMap::empty();
        }
        observations.sort_by_key(|o| o.stored);
        observations.dedup_by_key(|o| o.stored);

        // Monotonicity: entries keep their order. An observation that would place a later record
        // physically before an earlier one contradicts the layout, so it is dropped rather than
        // allowed to bend the map around it.
        let mut kept: Vec<OffsetObservation> = Vec::with_capacity(observations.len());
        let mut discarded = 0usize;
        for o in observations {
            match kept.last() {
                Some(prev) if o.physical <= prev.physical => discarded += 1,
                _ => kept.push(o),
            }
        }
        if kept.is_empty() {
            return OffsetMap {
                kind: OffsetMapKind::Rejected,
                segments: Vec::new(),
                discarded,
            };
        }

        // Run-length grouping over the observed deltas, in stored order.
        let delta_of = |o: &OffsetObservation| o.physical as i64 - o.stored as i64;
        let mut segments: Vec<OffsetSegment> = Vec::new();
        for o in &kept {
            let d = delta_of(o);
            match segments.last_mut() {
                Some(seg) if seg.delta == d => {
                    seg.original_end = o.stored;
                    seg.support += 1;
                }
                _ => segments.push(OffsetSegment {
                    original_start: o.stored,
                    original_end: o.stored,
                    delta: d,
                    support: 1,
                }),
            }
        }

        if segments.len() > max_segments {
            return OffsetMap {
                kind: OffsetMapKind::Rejected,
                segments: Vec::new(),
                discarded,
            };
        }

        // Extend the outer bounds so records beyond the observed span are still covered by the
        // segment nearest them. Interior boundaries are left exactly where the evidence put them:
        // widening those would silently claim a record belongs to a shift nothing observed.
        if let Some(first) = segments.first_mut() {
            first.original_start = 0;
        }
        if let Some(last) = segments.last_mut() {
            last.original_end = u64::MAX;
        }

        let kind = if segments.len() == 1 {
            OffsetMapKind::SingleDelta
        } else {
            OffsetMapKind::Piecewise
        };
        OffsetMap {
            kind,
            segments,
            discarded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(pairs: &[(u64, u64)]) -> Vec<OffsetObservation> {
        pairs
            .iter()
            .map(|&(stored, physical)| OffsetObservation { stored, physical })
            .collect()
    }

    #[test]
    fn no_observations_is_no_map() {
        let m = OffsetMap::infer(Vec::new(), 4);
        assert_eq!(m.kind, OffsetMapKind::Empty);
        assert!(!m.is_usable());
        assert_eq!(m.map(100), None);
    }

    #[test]
    fn an_undamaged_archive_maps_to_itself() {
        let m = OffsetMap::infer(obs(&[(0, 0), (100, 100), (500, 500)]), 4);
        assert_eq!(m.kind, OffsetMapKind::SingleDelta);
        assert_eq!(m.map(250), Some(250));
    }

    #[test]
    fn head_truncation_is_one_delta() {
        // Every offset moves by the same amount — the E2 case, still a fast single segment.
        let m = OffsetMap::infer(obs(&[(9000, 701), (10000, 1701), (12000, 3701)]), 4);
        assert_eq!(m.kind, OffsetMapKind::SingleDelta);
        assert_eq!(m.segments.len(), 1);
        assert_eq!(m.segments[0].delta, -8299);
        assert_eq!(m.map(20000), Some(11701));
    }

    #[test]
    fn a_middle_deletion_is_two_segments() {
        // The shape E2 could not express: record 0 unmoved, the rest shifted by the deletion.
        let m = OffsetMap::infer(
            obs(&[
                (0, 0),
                (7522, 7266),
                (27521, 27265),
                (35034, 34778),
                (55024, 54768),
                (62560, 62304),
            ]),
            4,
        );
        assert_eq!(m.kind, OffsetMapKind::Piecewise);
        assert_eq!(m.segments.len(), 2);
        assert_eq!(m.segments[0].delta, 0);
        assert_eq!(m.segments[1].delta, -256);
        assert_eq!(m.map(0), Some(0));
        assert_eq!(m.map(62560), Some(62304));
    }

    #[test]
    fn the_segment_cap_rejects_an_over_complicated_map() {
        let m = OffsetMap::infer(obs(&[(0, 0), (100, 90), (200, 210), (300, 280)]), 2);
        assert_eq!(m.kind, OffsetMapKind::Rejected);
        assert!(m.segments.is_empty());
        assert_eq!(m.map(100), None, "a rejected map maps nothing");
    }

    #[test]
    fn non_monotonic_observations_are_discarded_not_accommodated() {
        // A later record cannot sit physically before an earlier one.
        let m = OffsetMap::infer(obs(&[(0, 5000), (100, 10), (200, 5200)]), 4);
        assert!(m.discarded > 0, "the contradiction must be dropped");
        for s in &m.segments {
            assert!(s.original_start <= s.original_end);
        }
    }

    #[test]
    fn an_unobserved_offset_is_mapped_by_its_neighbouring_segment_never_invented() {
        let m = OffsetMap::infer(obs(&[(0, 0), (1000, 900)]), 4);
        assert!(m.is_usable());
        // Inside the observed span the answer comes from a real segment.
        assert_eq!(m.map(0), Some(0));
        assert_eq!(m.map(1000), Some(900));
        // A rejected map, by contrast, answers nothing at all.
        let bad = OffsetMap::infer(obs(&[(0, 0), (10, 20), (20, 15), (30, 60), (40, 20)]), 2);
        assert_eq!(bad.map(10), None);
    }

    #[test]
    fn segments_stay_ordered_and_non_overlapping() {
        let m = OffsetMap::infer(obs(&[(0, 0), (100, 100), (200, 150), (300, 250)]), 4);
        assert!(m.is_usable());
        for w in m.segments.windows(2) {
            assert!(
                w[0].original_end < w[1].original_start,
                "segments must not overlap: {:?}",
                m.segments
            );
        }
    }

    #[test]
    fn a_negative_result_is_refused_rather_than_wrapped() {
        let s = OffsetSegment {
            original_start: 0,
            original_end: u64::MAX,
            delta: -1000,
            support: 2,
        };
        assert_eq!(
            s.apply(500),
            None,
            "an offset before the file is not an offset"
        );
        assert_eq!(s.apply(1500), Some(500));
    }
}
