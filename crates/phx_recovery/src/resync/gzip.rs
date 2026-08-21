//! Slice B — GZIP multi-member salvage.
//!
//! A `.gz` file is a concatenation of independent **members**, each ending in an
//! 8-byte trailer: CRC32 of the member plaintext + ISIZE (plaintext length mod
//! 2^32). The stock `gunzip` / `MultiGzDecoder` stops at the first corrupt member,
//! discarding every intact member after it. This salvager instead recovers **every
//! member that inflates and whose trailer matches** — exact, checksum-proven bytes
//! — and merely flags the corrupt one (best-effort partial / stored-block salvage,
//! never counted as verified).
//!
//! This is a real exact win for concatenated streams (rotated logs, `cat a.gz
//! b.gz`, journald exports): one bad member no longer poisons the rest.

use std::io::Read;

use super::deflate::scan_stored_blocks;
use super::{SalvageResult, Segment, SegmentKind};

/// Hard cap on a single decompressed member (bomb guard).
const MAX_MEMBER_BYTES: usize = 1024 * 1024 * 1024;

/// Recover every CRC-verified member from a (possibly multi-member, possibly
/// corrupt) GZIP byte stream. Read-only; never panics.
pub fn salvage_gzip(data: &[u8]) -> SalvageResult {
    let mut res = SalvageResult::new("gzip");
    let starts = member_starts(data);
    if starts.is_empty() {
        res.warnings
            .push("no GZIP member magic (1F 8B 08) found".into());
        return res;
    }

    let mut cursor = 0usize;
    for (k, &start) in starts.iter().enumerate() {
        if start < cursor {
            continue; // inside a member we've already consumed
        }
        let next_start = starts.get(k + 1).copied().unwrap_or(data.len());
        res.members_total += 1;
        let label = format!("member#{}", res.members_total);

        let Some(hlen) = gz_header_len(data, start) else {
            res.warnings
                .push(format!("{label} at {start}: malformed header — skipped"));
            cursor = next_start;
            continue;
        };
        let body_start = start + hlen;
        let outcome = inflate_member(&data[body_start..]);

        if outcome.ok {
            let trailer_at = body_start + outcome.consumed as usize;
            if let Some((crc, isize_)) = read_trailer(data, trailer_at) {
                if crc32(&outcome.plain) == crc && (outcome.plain.len() as u32) == isize_ {
                    let n = outcome.plain.len();
                    let member_end = (trailer_at + 8).min(data.len());
                    res.push(Segment {
                        kind: SegmentKind::VerifiedGzipMember,
                        name: Some(label),
                        source_offset: start,
                        source_end: member_end,
                        bytes: outcome.plain,
                        note: format!("CRC32+ISIZE verified ({n} B)"),
                    });
                    cursor = trailer_at + 8;
                    continue;
                }
                res.warnings.push(format!(
                    "{label}: inflated but trailer mismatch — best-effort only"
                ));
            } else {
                res.warnings
                    .push(format!("{label}: inflated but trailer truncated"));
            }
            // Inflated cleanly but unprovable → best-effort partial.
            salvage_unverified(
                &mut res,
                start,
                body_start,
                outcome.plain,
                &data[body_start..next_start],
            );
        } else {
            res.warnings
                .push(format!("{label}: DEFLATE decode failed — resync salvage"));
            salvage_unverified(
                &mut res,
                start,
                body_start,
                outcome.plain,
                &data[body_start..next_start],
            );
        }
        cursor = next_start;
    }

    if res.members_verified == 0 {
        res.warnings
            .push("no member could be CRC-verified; nothing returned as exact".into());
    }
    res
}

/// Emit best-effort (never verified) salvage for a corrupt member: the partial
/// inflate prefix, then any DEFLATE stored-block payloads in the member body.
fn salvage_unverified(
    res: &mut SalvageResult,
    start: usize,
    body_start: usize,
    partial: Vec<u8>,
    body: &[u8],
) {
    if !partial.is_empty() {
        let n = partial.len();
        res.push(Segment {
            kind: SegmentKind::PartialInflate,
            name: None,
            source_offset: start,
            source_end: start, // unverified — no exact source span to splice
            bytes: partial,
            note: format!("partial inflate before corruption ({n} B, UNVERIFIED)"),
        });
    }
    for b in scan_stored_blocks(body) {
        let off = body_start + b.header_offset;
        res.push(Segment {
            kind: SegmentKind::StoredBlockSalvage,
            name: None,
            source_offset: off,
            source_end: off, // best-effort — not used for splicing
            bytes: b.payload,
            note: format!("DEFLATE stored block ({} B, UNVERIFIED)", b.len),
        });
    }
}

/// Offsets of every GZIP member magic `1F 8B 08` in `data`.
fn member_starts(data: &[u8]) -> Vec<usize> {
    let mut v = Vec::new();
    if data.len() < 3 {
        return v;
    }
    for i in 0..=data.len() - 3 {
        if data[i] == 0x1F && data[i + 1] == 0x8B && data[i + 2] == 0x08 {
            v.push(i);
        }
    }
    v
}

/// Byte length of the GZIP header at `off` (fixed 10 + optional FEXTRA / FNAME /
/// FCOMMENT / FHCRC), or `None` if it isn't a valid member header.
fn gz_header_len(data: &[u8], off: usize) -> Option<usize> {
    let h = data.get(off..off + 10)?;
    if h[0] != 0x1F || h[1] != 0x8B || h[2] != 0x08 {
        return None;
    }
    let flags = h[3];
    let mut pos = off + 10;
    if flags & 0x04 != 0 {
        // FEXTRA: 2-byte length + payload.
        let lo = *data.get(pos)? as usize;
        let hi = *data.get(pos + 1)? as usize;
        pos += 2 + (lo | (hi << 8));
    }
    if flags & 0x08 != 0 {
        pos = skip_zstring(data, pos)?; // FNAME
    }
    if flags & 0x10 != 0 {
        pos = skip_zstring(data, pos)?; // FCOMMENT
    }
    if flags & 0x02 != 0 {
        pos += 2; // FHCRC
    }
    if pos > data.len() {
        return None;
    }
    Some(pos - off)
}

/// Advance past a NUL-terminated string; `None` if the terminator is absent.
fn skip_zstring(data: &[u8], mut pos: usize) -> Option<usize> {
    while *data.get(pos)? != 0 {
        pos += 1;
    }
    Some(pos + 1)
}

struct InflateOutcome {
    plain: Vec<u8>,
    consumed: u64,
    ok: bool,
}

/// Inflate one raw-DEFLATE member from `body`, bounded. `consumed` is the number
/// of compressed bytes the decoder read (the member's DEFLATE length), which lets
/// the caller find the trailer even across concatenated members.
fn inflate_member(body: &[u8]) -> InflateOutcome {
    let mut dec = flate2::read::DeflateDecoder::new(body);
    let mut plain = Vec::new();
    let mut buf = [0u8; 16384];
    let mut ok = true;
    loop {
        match dec.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                plain.extend_from_slice(&buf[..n]);
                if plain.len() > MAX_MEMBER_BYTES {
                    ok = false;
                    break;
                }
            }
            Err(_) => {
                ok = false;
                break;
            }
        }
    }
    InflateOutcome {
        plain,
        consumed: dec.total_in(),
        ok,
    }
}

fn read_trailer(data: &[u8], at: usize) -> Option<(u32, u32)> {
    let t = data.get(at..at + 8)?;
    let crc = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
    let isize_ = u32::from_le_bytes([t[4], t[5], t[6], t[7]]);
    Some((crc, isize_))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(bytes);
    c.sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resync::build;

    #[test]
    fn recovers_all_members_of_a_clean_multimember_gzip() {
        let m = [b"first member\n".as_ref(), b"second member\n", b"third\n"];
        let gz = build::concat_gzip_members(&m);
        let r = salvage_gzip(&gz);
        assert_eq!(r.members_total, 3);
        assert_eq!(r.members_verified, 3);
        assert_eq!(
            r.verified_payload(),
            b"first member\nsecond member\nthird\n"
        );
    }

    #[test]
    fn corrupt_middle_member_does_not_poison_the_others() {
        let m = [
            b"alpha alpha alpha\n".as_ref(),
            b"bravo bravo bravo\n",
            b"charlie charlie\n",
        ];
        let mut gz = build::concat_gzip_members(&m);
        // Corrupt deep inside the second member's body (not its magic).
        let second = gz
            .windows(3)
            .enumerate()
            .filter(|(_, w)| w == b"\x1f\x8b\x08")
            .nth(1)
            .map(|(i, _)| i)
            .unwrap();
        gz[second + 14] ^= 0xFF;
        let r = salvage_gzip(&gz);
        // Members 1 and 3 still verify exactly; nothing false is emitted.
        let payload = r.verified_payload();
        assert!(payload.windows(17).any(|w| w == b"alpha alpha alpha"));
        assert!(payload.windows(15).any(|w| w == b"charlie charlie"));
        assert!(r.members_verified >= 2);
        // No verified segment ever contains wrong bytes.
        for s in &r.segments {
            if s.verified() {
                assert!(m.iter().any(|orig| s.bytes == *orig));
            }
        }
    }

    #[test]
    fn random_bytes_recover_zero_verified_members() {
        let mut v = vec![0u8; 8192];
        let mut s: u64 = 0xBADC_0FFE_E0DD_F00D;
        for b in v.iter_mut() {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *b = (s >> 56) as u8;
        }
        let r = salvage_gzip(&v);
        assert_eq!(r.members_verified, 0);
        assert!(r.verified_payload().is_empty());
    }
}
