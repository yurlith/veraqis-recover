//! E2 — locate a *surviving original* central directory when the EOCD offset is unusable.
//!
//! Head truncation cannot destroy the central directory: it lives at the tail. It only shifts
//! every stored offset by the number of bytes removed, so following the EOCD's recorded offset
//! lands on nothing and the one witness that survived is discarded.
//!
//! A `PK\x01\x02` signature is **discovery only**. In the measurement fixture three of the four
//! structurally walkable chains are the central directories of a *nested* archive lying inside the
//! outer payload; each is a complete, well-formed chain. What separates the real directory from
//! them is not position, length or proximity to the EOCD — the real one happens to be both last
//! and longest there, so any of those heuristics would pass by luck — but two structural proofs:
//!
//! * every record of the chain is explained by **one** offset shift, and
//! * the chain matches what the surviving EOCD says about count, size and where it ends.
//!
//! Records whose shifted offset falls before the start of the file are *explained* by the removed
//! head, not conflicts. Records whose shifted offset lands inside the file with no matching local
//! header are conflicts, and one conflict disqualifies the whole chain. Unmatched records are
//! never dropped to make a chain look cleaner.

use std::collections::HashMap;

use crate::verdict::CdProvenance;

const CDFH_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];

/// Bounds. The scan is one linear pass plus bounded validation per candidate; these cap the
/// pathological input rather than the normal one.
const MAX_CANDIDATES: usize = 4096;
const MAX_RECORDS_PER_CHAIN: usize = 65_536;

/// How one central-directory record relates to the local headers that survived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSupport {
    /// Shifted offset lands on a matching local header.
    Supported,
    /// Shifted offset falls before the start of the file: the header was in the removed head.
    MissingByHeadTruncation,
    /// Shifted offset is inside the file but there is no matching header, or metadata disagrees.
    Conflicting,
    /// Neither support nor conflict could be established.
    Unresolved,
}

#[derive(Debug, Clone)]
pub struct CdCandidate {
    pub start: usize,
    pub end: usize,
    pub record_count: usize,
    pub byte_len: usize,
    pub eocd_consistent: bool,
    pub supported: usize,
    pub missing_by_truncation: usize,
    pub conflicting: usize,
    pub unresolved: usize,
    /// Every distinct shift the records imply, sorted.
    pub delta_candidates: Vec<i64>,
    pub accepted_delta: Option<i64>,
    pub rejection: Option<&'static str>,
}

#[derive(Debug, Clone, Default)]
pub struct CdScanReport {
    pub candidates: Vec<CdCandidate>,
    /// Index into `candidates` of the one chain proven to be the surviving original.
    pub accepted: Option<usize>,
    pub scanned_bytes: usize,
    pub signature_candidates: usize,
    pub provenance: Option<CdProvenance>,
}

impl CdScanReport {
    pub fn accepted_candidate(&self) -> Option<&CdCandidate> {
        self.accepted.and_then(|i| self.candidates.get(i))
    }
}

fn u16le(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(at)?, *d.get(at + 1)?]))
}
fn u32le(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(at)?,
        *d.get(at + 1)?,
        *d.get(at + 2)?,
        *d.get(at + 3)?,
    ]))
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    let start = data.len().saturating_sub(65_557);
    (start..data.len().checked_sub(21)?)
        .rev()
        .find(|&i| data[i..i + 4] == EOCD_SIG)
}

/// One CD record, parsed with every length bounds-checked.
struct CdRecord {
    end: usize,
    name: String,
    lfh_offset: u32,
    method: u16,
}

fn parse_record(data: &[u8], at: usize) -> Option<CdRecord> {
    if at.checked_add(46)? > data.len() || data.get(at..at + 4)? != CDFH_SIG {
        return None;
    }
    let name_len = u16le(data, at + 28)? as usize;
    let extra_len = u16le(data, at + 30)? as usize;
    let comment_len = u16le(data, at + 32)? as usize;
    // Checked throughout: a crafted length must not wrap into a small number.
    let end = at
        .checked_add(46)?
        .checked_add(name_len)?
        .checked_add(extra_len)?
        .checked_add(comment_len)?;
    if end > data.len() || name_len == 0 {
        return None;
    }
    let raw = data.get(at + 46..at + 46 + name_len)?;
    // A name full of control bytes is a signature coincidence, not a filename.
    if raw.iter().any(|b| *b < 0x20 || *b == 0x7f) {
        return None;
    }
    Some(CdRecord {
        end,
        name: String::from_utf8_lossy(raw).into_owned(),
        lfh_offset: u32le(data, at + 42)?,
        method: u16le(data, at + 10)?,
    })
}

/// Index every local file header once, by name. One linear pass, reused by every candidate.
fn index_local_headers(data: &[u8]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    let mut i = 0usize;
    while i + 30 <= data.len() {
        if data[i..i + 4] != LFH_SIG {
            i += 1;
            continue;
        }
        if let Some(name_len) = u16le(data, i + 26) {
            let nl = name_len as usize;
            if nl > 0 && i + 30 + nl <= data.len() {
                let raw = &data[i + 30..i + 30 + nl];
                if !raw.iter().any(|b| *b < 0x20 || *b == 0x7f) {
                    map.entry(String::from_utf8_lossy(raw).into_owned())
                        .or_insert(i);
                }
            }
        }
        i += 4;
    }
    map
}

/// Scan for a surviving original central directory.
///
/// Enumerates **all** structurally walkable chains — stopping at the first would pick a nested
/// archive's directory in the measurement fixture — then accepts at most one on proof.
pub fn scan_surviving_cd(data: &[u8]) -> CdScanReport {
    let mut report = CdScanReport {
        scanned_bytes: data.len(),
        ..Default::default()
    };
    if data.len() < 46 {
        return report;
    }

    let lfh = index_local_headers(data);
    let eocd = find_eocd(data);
    let (declared_count, declared_size) = match eocd {
        Some(e) => (
            u16le(data, e + 10).map(|v| v as usize),
            u32le(data, e + 12).map(|v| v as usize),
        ),
        None => (None, None),
    };

    // --- one linear pass to collect candidate starts -------------------------------------
    let mut starts = Vec::new();
    let mut i = 0usize;
    while i + 4 <= data.len() && starts.len() < MAX_CANDIDATES {
        if data[i..i + 4] == CDFH_SIG {
            starts.push(i);
        }
        i += 1;
    }
    report.signature_candidates = starts.len();

    // --- bounded validation per candidate --------------------------------------------------
    let mut walked_end = 0usize;
    for start in starts {
        // Records already consumed by an earlier chain are not new chains.
        if start < walked_end {
            continue;
        }
        let mut pos = start;
        let mut records = Vec::new();
        while records.len() < MAX_RECORDS_PER_CHAIN {
            let Some(rec) = parse_record(data, pos) else {
                break;
            };
            if rec.end <= pos {
                break; // must always advance
            }
            pos = rec.end;
            records.push(rec);
        }
        if records.is_empty() {
            continue;
        }
        walked_end = pos;

        let byte_len = pos - start;
        let mut cand = CdCandidate {
            start,
            end: pos,
            record_count: records.len(),
            byte_len,
            eocd_consistent: false,
            supported: 0,
            missing_by_truncation: 0,
            conflicting: 0,
            unresolved: 0,
            delta_candidates: Vec::new(),
            accepted_delta: None,
            rejection: None,
        };

        // EOCD consistency: count, size, and the chain ending where the EOCD begins.
        cand.eocd_consistent = match (eocd, declared_count, declared_size) {
            (Some(e), Some(c), Some(s)) => c == records.len() && s == byte_len && pos == e,
            _ => false,
        };

        // Delta candidates from records whose local header survived under its own name.
        let mut deltas: Vec<i64> = Vec::new();
        for r in &records {
            if let Some(&actual) = lfh.get(&r.name) {
                if let Some(d) = (actual as i64).checked_sub(r.lfh_offset as i64) {
                    deltas.push(d);
                }
            }
        }
        let mut uniq: Vec<i64> = deltas.clone();
        uniq.sort_unstable();
        uniq.dedup();
        cand.delta_candidates = uniq.clone();

        if uniq.is_empty() {
            // Nothing survived to pin the shift. Guessing one is forbidden.
            cand.unresolved = records.len();
            cand.rejection = Some("no surviving local header pins the offset shift");
            report.candidates.push(cand);
            continue;
        }
        if uniq.len() > 1 {
            // The decoy signature: nested directories need a different shift per record.
            cand.conflicting = records.len();
            cand.rejection = Some("records require different offset shifts; no single delta");
            report.candidates.push(cand);
            continue;
        }

        let delta = uniq[0];
        for r in &records {
            let shifted = (r.lfh_offset as i64).checked_add(delta);
            match shifted {
                None => cand.unresolved += 1,
                Some(x) if x < 0 => cand.missing_by_truncation += 1,
                Some(x) if (x as usize) + 30 <= data.len() => {
                    let at = x as usize;
                    let name_ok = u16le(data, at + 26)
                        .map(|nl| nl as usize)
                        .filter(|nl| at + 30 + nl <= data.len())
                        .map(|nl| &data[at + 30..at + 30 + nl] == r.name.as_bytes())
                        .unwrap_or(false);
                    let method_ok = u16le(data, at + 8) == Some(r.method);
                    if data[at..at + 4] == LFH_SIG && name_ok && method_ok {
                        cand.supported += 1;
                    } else {
                        cand.conflicting += 1;
                    }
                }
                Some(_) => cand.conflicting += 1, // past EOF: not explained by a removed head
            }
        }

        if cand.conflicting > 0 {
            cand.rejection = Some("a record's shifted offset is in-bounds but has no local header");
        } else if cand.supported == 0 {
            cand.rejection = Some("no supported record");
        } else if !cand.eocd_consistent {
            cand.rejection = Some("chain does not match the surviving EOCD count/size/boundary");
        } else {
            cand.accepted_delta = Some(delta);
        }
        report.candidates.push(cand);
    }

    // --- acceptance: exactly one proven chain, else fail closed ----------------------------
    let proven: Vec<usize> = report
        .candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| c.rejection.is_none() && c.accepted_delta.is_some())
        .map(|(i, _)| i)
        .collect();
    match proven.len() {
        1 => {
            report.accepted = Some(proven[0]);
            report.provenance = Some(CdProvenance::OriginalSurviving);
        }
        0 => report.provenance = None,
        _ => {
            // Two equally proven chains: ambiguity is not resolved by picking one.
            for i in proven {
                report.candidates[i].rejection =
                    Some("ambiguous: another chain is equally well proven");
                report.candidates[i].accepted_delta = None;
            }
            report.provenance = Some(CdProvenance::Unknown);
        }
    }
    report
}
