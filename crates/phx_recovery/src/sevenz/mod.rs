//! 7-Zip structural recovery — clean-room, signature + Start-Header level.
//!
//! The 32-byte 7z **SignatureHeader**:
//! ```text
//!   [0..6)   signature      37 7A BC AF 27 1C
//!   [6..8)   version        (major, minor)
//!   [8..12)  StartHeaderCRC = CRC32(bytes[12..32])         (LE u32)
//!   [12..20) NextHeaderOffset (u64 LE)  — relative to byte 32
//!   [20..28) NextHeaderSize   (u64 LE)
//!   [28..32) NextHeaderCRC    (u32 LE)  = CRC32(end header)
//! ```
//! The **end header** (the only structure map: coders, sizes, per-file CRCs)
//! lives at `32 + NextHeaderOffset`, length `NextHeaderSize`.
//!
//! ## What this module recovers EXACTLY (`false_recovered_bytes = 0`)
//! A corrupted 6-byte **signature**, *only when* the Start-Header CRC over
//! `[12,32)` still validates — i.e. the structure is provably intact. We then
//! restore the spec-mandated constant. It is a known constant gated by an
//! **independent** CRC (Axis-P), not a guess; cf. the shipped `GzMagicRestore`.
//!
//! ## Documented NO-GO (see `SEVENZIP_RAR_RECOVERY.md`)
//! * **Solid LZMA2 payload** salvage — LZ-coupled, no independent per-block CRC,
//!   no resync points (the zstd/lz4 fundamental class).
//! * **Truncation that removes the end header** — 7z has no per-folder local
//!   headers, so losing the tail loses the entire structure map.
//! * **Encrypted-header archives** (`-mhe=on`) — detect & abstain, never decode.
//!
//! Nothing here in the signature path ever decompresses attacker-controlled
//! payload; it reads at most the 32-byte signature header. Bounds-checked, never
//! panics.

use crate::CRC32_ISO_HDLC;

/// The fixed 7z signature.
pub const SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Size of the SignatureHeader.
pub const SIGNATURE_HEADER_LEN: usize = 32;

/// Structural facts read from the 32-byte signature header (no payload touched).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inspect {
    /// The 6-byte signature equals [`SIGNATURE`].
    pub signature_ok: bool,
    /// `CRC32(bytes[12..32]) == stored StartHeaderCRC` — the structure is intact.
    pub start_header_crc_ok: bool,
    /// `NextHeaderOffset` (relative to byte 32).
    pub next_header_offset: u64,
    /// `NextHeaderSize`.
    pub next_header_size: u64,
    /// The pointed-to end header lies fully within the file.
    pub end_header_in_bounds: bool,
    /// `CRC32(end header) == stored NextHeaderCRC` — the structure map is intact.
    pub end_header_crc_ok: bool,
}

fn le_u32(d: &[u8]) -> u32 {
    u32::from_le_bytes([d[0], d[1], d[2], d[3]])
}
fn le_u64(d: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[..8]);
    u64::from_le_bytes(b)
}

/// True when the first six bytes are the 7z signature.
pub fn signature_ok(data: &[u8]) -> bool {
    data.len() >= 6 && data[..6] == SIGNATURE
}

/// True when the Start-Header CRC validates the start header (`[12,32)`).
///
/// This is the **independent verifier** that the structure is intact: the CRC is
/// computed over bytes the signature/version bytes are *not* part of, so a
/// validating CRC proves `[12,32)` is correct without trusting `[0,8)`.
pub fn start_header_crc_ok(data: &[u8]) -> bool {
    if data.len() < SIGNATURE_HEADER_LEN {
        return false;
    }
    let stored = le_u32(&data[8..12]);
    let computed = CRC32_ISO_HDLC.checksum(&data[12..32]) as u32;
    stored == computed
}

/// Read the structural facts from the signature header (bounds-checked).
pub fn inspect(data: &[u8]) -> Inspect {
    if data.len() < SIGNATURE_HEADER_LEN {
        return Inspect {
            signature_ok: signature_ok(data),
            start_header_crc_ok: false,
            next_header_offset: 0,
            next_header_size: 0,
            end_header_in_bounds: false,
            end_header_crc_ok: false,
        };
    }
    let next_off = le_u64(&data[12..20]);
    let next_size = le_u64(&data[20..28]);
    let next_crc = le_u32(&data[28..32]);
    // End header position relative to byte 32; guard every arithmetic step.
    let in_bounds = (SIGNATURE_HEADER_LEN as u64)
        .checked_add(next_off)
        .and_then(|s| s.checked_add(next_size))
        .map(|end| end <= data.len() as u64)
        .unwrap_or(false);
    let end_crc_ok = if in_bounds && next_size > 0 {
        let start = SIGNATURE_HEADER_LEN + next_off as usize;
        let stop = start + next_size as usize;
        CRC32_ISO_HDLC.checksum(&data[start..stop]) as u32 == next_crc
    } else {
        false
    };
    Inspect {
        signature_ok: signature_ok(data),
        start_header_crc_ok: start_header_crc_ok(data),
        next_header_offset: next_off,
        next_header_size: next_size,
        end_header_in_bounds: in_bounds,
        end_header_crc_ok: end_crc_ok,
    }
}

/// An exact 7z signature repair, with the bytes that were written and the
/// independent verifier that licensed it.
#[derive(Debug, Clone)]
pub struct SignatureRepair {
    /// The repaired file bytes (signature restored to the spec constant).
    pub data: Vec<u8>,
    /// How many bytes were written (the corrupted signature bytes only).
    pub bytes_written: usize,
    /// The independent verifier: the Start-Header CRC over `[12,32)`.
    pub verified_by: &'static str,
}

/// Restore a corrupted 7z signature **iff** the Start-Header CRC proves the rest
/// of the signature header is intact. Returns `None` (abstain) when:
/// * the file is shorter than a signature header (cannot verify), or
/// * the signature is already correct (nothing to do), or
/// * the Start-Header CRC does **not** validate (structure not provably intact —
///   we never restore a constant onto unverified bytes; that would be a guess).
///
/// `false_recovered_bytes = 0` by construction: the only bytes written are the
/// invariant [`SIGNATURE`] constant, and they are written only behind an
/// independent CRC that proves the surrounding structure is the true original.
pub fn repair_signature(data: &[u8]) -> Option<SignatureRepair> {
    if data.len() < SIGNATURE_HEADER_LEN {
        return None;
    }
    if signature_ok(data) {
        return None; // signature intact — nothing to repair
    }
    if !start_header_crc_ok(data) {
        return None; // structure not provably intact — abstain
    }
    let mut out = data.to_vec();
    let mut written = 0;
    for (i, &b) in SIGNATURE.iter().enumerate() {
        if out[i] != b {
            out[i] = b;
            written += 1;
        }
    }
    Some(SignatureRepair {
        data: out,
        bytes_written: written,
        verified_by: "7z Start-Header CRC-32 over [12,32)",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but structurally valid 7z: 32-byte signature header + a 1-byte
    /// `kEnd` end header, all CRCs correct.
    fn synthetic_7z() -> Vec<u8> {
        let end = vec![0x00u8]; // kEnd
        let next_off: u64 = 0;
        let next_size = end.len() as u64;
        let next_crc = CRC32_ISO_HDLC.checksum(&end) as u32;

        let mut start = Vec::new(); // bytes [12,32)
        start.extend_from_slice(&next_off.to_le_bytes());
        start.extend_from_slice(&next_size.to_le_bytes());
        start.extend_from_slice(&next_crc.to_le_bytes());
        let sh_crc = CRC32_ISO_HDLC.checksum(&start) as u32;

        let mut v = Vec::new();
        v.extend_from_slice(&SIGNATURE); // [0,6)
        v.extend_from_slice(&[0x00, 0x04]); // version [6,8)
        v.extend_from_slice(&sh_crc.to_le_bytes()); // [8,12)
        v.extend_from_slice(&start); // [12,32)
        v.extend_from_slice(&end); // end header @32
        v
    }

    #[test]
    fn clean_archive_inspects_fully_valid() {
        let v = synthetic_7z();
        let i = inspect(&v);
        assert!(i.signature_ok && i.start_header_crc_ok);
        assert!(i.end_header_in_bounds && i.end_header_crc_ok);
    }

    #[test]
    fn clean_archive_is_not_repaired() {
        assert!(repair_signature(&synthetic_7z()).is_none());
    }

    #[test]
    fn corrupted_signature_restored_exactly() {
        let mut v = synthetic_7z();
        v[1] = 0xFF;
        v[4] = 0x00; // damage two signature bytes
        let r = repair_signature(&v).expect("CRC-licensed repair");
        assert_eq!(r.bytes_written, 2);
        assert_eq!(&r.data[..6], &SIGNATURE);
        assert!(signature_ok(&r.data) && start_header_crc_ok(&r.data));
    }

    #[test]
    fn abstains_when_start_header_crc_invalid() {
        // Signature corrupt AND a start-header byte corrupt → CRC fails → abstain.
        let mut v = synthetic_7z();
        v[0] = 0x00; // break signature
        v[12] ^= 0x01; // break start header (CRC no longer validates)
        assert!(repair_signature(&v).is_none());
    }

    #[test]
    fn too_short_abstains() {
        assert!(repair_signature(&[0x37, 0x7A, 0xBC]).is_none());
        assert!(!inspect(&[0u8; 4]).start_header_crc_ok);
    }
}
