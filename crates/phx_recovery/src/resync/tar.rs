//! Slice C — TAR continuation salvage (`--ignore-zeros`).
//!
//! TAR is a stream of 512-byte blocks: a ustar header block (with a checksum over
//! its own bytes) followed by `ceil(size/512)` data blocks. Stock `tar` stops at
//! the first all-zero block (it reads it as end-of-archive) and at the first
//! unreadable header. This salvager walks the whole stream, **skipping zero blocks
//! and resyncing past corrupt headers** (the `--ignore-zeros` idea), and returns
//! every member whose **ustar header checksum validates** and whose data range is
//! present — exact, header-proven bytes.
//!
//! Honest limit: classic TAR has **no per-file data CRC**, so "verified" here means
//! the member *structure* is checksum-proven and its data is copied verbatim — the
//! same trust model as `tar -x`. Data-region bit-rot inside an otherwise valid
//! member is not detectable from the archive alone (documented, not hidden).

use super::{SalvageResult, Segment, SegmentKind};

const BLOCK: usize = 512;

/// Recover every checksum-verified member from a (possibly interrupted or
/// partly-corrupt) TAR byte stream. Read-only; never panics.
pub fn salvage_tar(data: &[u8]) -> SalvageResult {
    let mut res = SalvageResult::new("tar");
    if data.len() < BLOCK {
        res.warnings
            .push("input shorter than one 512-byte TAR block".into());
        return res;
    }

    let mut pos = 0usize;
    let mut zero_blocks = 0usize;
    let mut skipped_headers = 0usize;

    while pos + BLOCK <= data.len() {
        let block = &data[pos..pos + BLOCK];

        // Continuation: ignore zero blocks rather than treating them as the end.
        if block.iter().all(|&b| b == 0) {
            zero_blocks += 1;
            pos += BLOCK;
            continue;
        }
        // Resync: a block without the ustar magic is garbage/corrupt — step over it.
        if block.get(257..262) != Some(b"ustar") {
            skipped_headers += 1;
            pos += BLOCK;
            continue;
        }
        // Verify the header checksum before trusting any field.
        let computed = compute_checksum(block);
        if read_checksum(block) != Some(computed) {
            skipped_headers += 1;
            res.warnings.push(format!(
                "block {}: ustar checksum mismatch — skipped",
                pos / BLOCK
            ));
            pos += BLOCK;
            continue;
        }

        res.members_total += 1;
        let name = read_name(block);
        let size = octal(&block[124..136]).unwrap_or(0) as usize;
        let data_start = pos + BLOCK;
        let data_blocks = size.div_ceil(BLOCK);

        match data_start.checked_add(size) {
            Some(data_end) if data_end <= data.len() => {
                let bytes = data[data_start..data_end].to_vec();
                // Whole on-disk member span (header + padded data), clamped.
                let member_end = (data_start + data_blocks * BLOCK).min(data.len());
                res.push(Segment {
                    kind: SegmentKind::VerifiedTarMember,
                    name: Some(name),
                    source_offset: pos,
                    source_end: member_end,
                    bytes,
                    note: format!("ustar checksum verified; {size} B data (header-proven)"),
                });
                pos = data_start + data_blocks * BLOCK;
            }
            _ => {
                // Header proven, but the data runs past the file — abstain (never
                // pad or guess the missing tail).
                res.warnings.push(format!(
                    "member '{name}': declared {size} B data is truncated — abstained"
                ));
                pos = data.len();
            }
        }
    }

    if zero_blocks > 0 {
        res.warnings.push(format!(
            "skipped {zero_blocks} zero block(s) and continued (ignore-zeros)"
        ));
    }
    if skipped_headers > 0 {
        res.warnings.push(format!(
            "resynced past {skipped_headers} unreadable block(s)"
        ));
    }
    if res.members_verified == 0 {
        res.warnings
            .push("no member could be checksum-verified".into());
    }
    res
}

/// Member path: `name` (and, for ustar, the `prefix` field joined with `/`).
fn read_name(block: &[u8]) -> String {
    let name = cstr(&block[0..100]);
    let prefix = cstr(&block[345..500]);
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// ustar header checksum: the unsigned sum of all 512 bytes with the 8-byte
/// checksum field (148..156) treated as ASCII spaces.
fn compute_checksum(block: &[u8]) -> u32 {
    let mut sum = 0u32;
    for (i, &b) in block.iter().enumerate() {
        sum += if (148..156).contains(&i) {
            0x20
        } else {
            b as u32
        };
    }
    sum
}

fn read_checksum(block: &[u8]) -> Option<u32> {
    octal(&block[148..156]).map(|v| v as u32)
}

/// Parse a NUL/space-terminated octal ASCII field.
fn octal(field: &[u8]) -> Option<u64> {
    let s = field
        .split(|&b| b == 0 || b == b' ')
        .find(|s| !s.is_empty())?;
    u64::from_str_radix(std::str::from_utf8(s).ok()?, 8).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resync::build;

    #[test]
    fn recovers_all_members_of_a_clean_tar() {
        let tar = build::tar_archive(&[
            ("a.txt", b"alpha contents".as_ref()),
            ("dir/b.bin", b"\x00\x01\x02\x03 binary"),
            ("c.log", b"line one\nline two\n"),
        ]);
        let r = salvage_tar(&tar);
        assert_eq!(r.members_verified, 3);
        let names: Vec<_> = r.segments.iter().filter_map(|s| s.name.clone()).collect();
        assert!(names.iter().any(|n| n == "a.txt"));
        assert!(names.iter().any(|n| n == "dir/b.bin"));
        let a = r
            .segments
            .iter()
            .find(|s| s.name.as_deref() == Some("a.txt"))
            .unwrap();
        assert_eq!(a.bytes, b"alpha contents");
    }

    #[test]
    fn continues_past_zero_block_and_corrupt_header() {
        // member1 | zero block | member2 | garbage block | member3
        let m1 = build::tar_member("first.txt", b"first body here");
        let m2 = build::tar_member("second.txt", b"second body");
        let m3 = build::tar_member("third.txt", b"third body!!");
        let mut tar = Vec::new();
        tar.extend_from_slice(&m1);
        tar.extend_from_slice(&[0u8; BLOCK]); // premature zero block
        tar.extend_from_slice(&m2);
        tar.extend_from_slice(&[0x55u8; BLOCK]); // garbage block (no ustar)
        tar.extend_from_slice(&m3);
        let r = salvage_tar(&tar);
        assert_eq!(
            r.members_verified, 3,
            "all three recovered past interruptions"
        );
        assert_eq!(
            r.segments
                .iter()
                .find(|s| s.name.as_deref() == Some("third.txt"))
                .unwrap()
                .bytes,
            b"third body!!"
        );
    }

    #[test]
    fn corrupt_header_member_is_skipped_not_falsely_verified() {
        let m1 = build::tar_member("good.txt", b"good data");
        let mut m2 = build::tar_member("bad.txt", b"unreachable");
        m2[100] ^= 0xFF; // corrupt the mode field → checksum no longer matches
        let mut tar = Vec::new();
        tar.extend_from_slice(&m1);
        tar.extend_from_slice(&m2);
        tar.extend_from_slice(&[0u8; 2 * BLOCK]);
        let r = salvage_tar(&tar);
        // good.txt verifies; bad.txt fails checksum and is never emitted verified.
        assert!(r
            .segments
            .iter()
            .any(|s| s.name.as_deref() == Some("good.txt") && s.verified()));
        assert!(!r
            .segments
            .iter()
            .any(|s| s.name.as_deref() == Some("bad.txt")));
    }

    #[test]
    fn random_bytes_recover_zero_members() {
        let mut v = vec![0u8; 4096];
        let mut s: u64 = 0x7A1F_C0DE_0BAD_F00D;
        for b in v.iter_mut() {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *b = (s >> 56) as u8;
        }
        assert_eq!(salvage_tar(&v).members_verified, 0);
    }
}
