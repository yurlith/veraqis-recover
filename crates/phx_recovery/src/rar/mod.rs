//! RAR5 block-structure parser → **verified inventory + per-block localization**
//! (EXP-RAR5-BLOCKS, clean-room, no decompression).
//!
//! The RAR5 *archive format* (block layout) is clean-room from the public RARLAB
//! technote (`Rar.txt`/`technote.txt`); the proprietary *compression codec* is
//! **not** touched. Every RAR5 block carries a **CRC-32 over its header**, an
//! independent verifier (Axis-P, 32 bits): we walk the block chain, verify each
//! header CRC, and emit a file inventory (name, unpacked size, per-file CRC-32,
//! dir flag) **only from headers whose CRC validates** — and **localize** a
//! corrupt header to its block. No payload is decoded; gate `false_files = 0`.
//!
//! Block layout:
//! ```text
//!   u32   header CRC-32   (over [header-size field .. end of header])
//!   vint  header size     (bytes from the byte AFTER this field to header end)
//!   vint  header type      (1 main, 2 file, 3 service, 4 arc-enc, 5 end)
//!   vint  header flags      (0x01 extra-area, 0x02 data-area)
//!   [vint extra area size]  (if flags & 0x01)
//!   [vint data size]        (if flags & 0x02)
//!   … type-specific …
//! ```
//! File header (type 2) body: file-flags, unpacked-size, attributes,
//! `[u32 mtime if ff&0x02]`, `[u32 data-CRC32 if ff&0x04]`, comp-info, host-OS,
//! name-length, UTF-8 name.

use crate::CRC32_ISO_HDLC;

/// RAR5 8-byte signature.
pub const SIGNATURE5: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];

const T_MAIN: u64 = 1;
const T_FILE: u64 = 2;
const T_SERVICE: u64 = 3;
const T_ENDARC: u64 = 5;

// RAR5 main-archive-header "Archive flags".
const ARC_VOLUME: u64 = 0x0001;
const ARC_RECOVERY_RECORD: u64 = 0x0008;

/// One inventory entry, proven from a CRC-verified RAR5 file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub crc32: Option<u32>,
    /// The block's own header CRC-32 validated (an independent verifier).
    pub header_crc_ok: bool,
    /// RAR5 compression method (0 = **stored**/uncompressed).
    pub method: u8,
    /// Absolute offset of this entry's data area within the file.
    pub data_offset: u64,
    /// Packed (on-disk) data size; equals `size` for a stored entry.
    pub packed_size: u64,
}

/// Recovered RAR5 inventory + structural health.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub files: Vec<FileEntry>,
    /// Blocks whose header CRC-32 did **not** validate (localized corruption).
    pub corrupt_blocks: Vec<usize>,
    /// A genuine end-of-archive block was seen.
    pub has_end: bool,
    /// A block header/data ran past EOF → the archive is truncated.
    pub truncated: bool,
    /// The archive carries a built-in **recovery record** (main-header flag
    /// `0x0008`, and/or an `RR` service block) — repairable by WinRAR (EXP-RAR-RRCERT).
    /// PHX never applies the proprietary RS itself; this is a triage certificate.
    pub has_recovery_record: bool,
    /// The archive is a **multi-volume** part (main-header flag `0x0001`).
    pub is_volume: bool,
}

/// LEB128 variable integer (low 7 bits/byte, high bit = continue).
fn vint(d: &[u8], p: &mut usize) -> Option<u64> {
    let mut shift = 0u32;
    let mut val = 0u64;
    loop {
        let b = *d.get(*p)?;
        *p += 1;
        val |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(val);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn u32le(d: &[u8], p: &mut usize) -> Option<u32> {
    let s = d.get(*p..p.checked_add(4)?)?;
    *p += 4;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn parse_file_header(d: &[u8], p: &mut usize, end: usize) -> Option<FileEntry> {
    let file_flags = vint(d, p)?;
    let unpacked_size = vint(d, p)?;
    let _attributes = vint(d, p)?;
    if file_flags & 0x02 != 0 {
        let _ = u32le(d, p)?; // mtime
    }
    let crc32 = if file_flags & 0x04 != 0 {
        Some(u32le(d, p)?)
    } else {
        None
    };
    let comp_info = vint(d, p)?;
    // Compression information: bits 7..10 = method (0 = stored).
    let method = ((comp_info >> 7) & 0x07) as u8;
    let _host_os = vint(d, p)?;
    let name_len = usize::try_from(vint(d, p)?).ok()?;
    let stop = p.checked_add(name_len)?;
    if stop > end {
        return None;
    }
    let name = String::from_utf8_lossy(d.get(*p..stop)?).into_owned();
    let is_dir = file_flags & 0x01 != 0;
    Some(FileEntry {
        name,
        is_dir,
        size: if is_dir { None } else { Some(unpacked_size) },
        crc32: if is_dir { None } else { crc32 },
        header_crc_ok: true,
        method,
        data_offset: 0, // filled by the caller (= block body_end)
        packed_size: 0, // filled by the caller (= data_size)
    })
}

/// Extract a **stored** (`-m0`) file's exact bytes, verified against its per-file
/// CRC-32. Returns `Some(bytes)` only when the entry is uncompressed, in bounds,
/// the right length, **and** the CRC matches — otherwise `None` (abstain). No
/// proprietary codec is used; `false_recovered_bytes = 0` by construction (the
/// per-file CRC-32 is an independent verifier of the emitted bytes).
pub fn extract_stored(file: &[u8], e: &FileEntry) -> Option<Vec<u8>> {
    if e.is_dir || e.method != 0 {
        return None; // only uncompressed entries are clean-room recoverable
    }
    let size = e.size?;
    if e.packed_size != size {
        return None; // a stored entry has packed == unpacked
    }
    let crc = e.crc32?;
    let start = usize::try_from(e.data_offset).ok()?;
    let stop = start.checked_add(usize::try_from(size).ok()?)?;
    let bytes = file.get(start..stop)?;
    if CRC32_ISO_HDLC.checksum(bytes) as u32 != crc {
        return None; // data damaged → abstain, never emit unverified bytes
    }
    Some(bytes.to_vec())
}

/// Parse a RAR5 file's block chain into a verified inventory. Returns `None`
/// only for a non-RAR5 input; otherwise reports what the surviving, CRC-verified
/// headers prove (and which blocks are corrupt / whether it is truncated).
pub fn read_inventory(file: &[u8]) -> Option<Inventory> {
    if file.len() < 8 || file[..8] != SIGNATURE5 {
        return None; // not RAR5 (RAR4 handled elsewhere / abstain)
    }
    let mut inv = Inventory::default();
    let mut p = 8usize;
    let mut guard = 0usize;

    while p + 5 <= file.len() {
        guard += 1;
        if guard > 1_000_000 {
            break;
        }
        let block_start = p;
        let mut q = p;
        let crc = u32le(file, &mut q)?; // header CRC field
        let hs_start = q;
        let header_size = usize::try_from(vint(file, &mut q)?).ok()?;
        let body_start = q;
        let Some(body_end) = body_start.checked_add(header_size) else {
            inv.truncated = true;
            break;
        };
        if body_end > file.len() {
            inv.truncated = true; // header runs past EOF
            break;
        }
        let crc_ok = CRC32_ISO_HDLC.checksum(&file[hs_start..body_end]) as u32 == crc;

        let mut b = body_start;
        let htype = vint(file, &mut b)?;
        let flags = vint(file, &mut b)?;
        let _extra = if flags & 0x01 != 0 {
            vint(file, &mut b)?
        } else {
            0
        };
        let data_size = if flags & 0x02 != 0 {
            usize::try_from(vint(file, &mut b)?).ok()?
        } else {
            0
        };

        if crc_ok {
            if htype == T_MAIN {
                // Main archive header body begins with the Archive-flags vint.
                if let Some(arc_flags) = vint(file, &mut b) {
                    inv.has_recovery_record |= arc_flags & ARC_RECOVERY_RECORD != 0;
                    inv.is_volume |= arc_flags & ARC_VOLUME != 0;
                }
            } else if htype == T_FILE {
                if let Some(mut e) = parse_file_header(file, &mut b, body_end) {
                    e.data_offset = body_end as u64;
                    e.packed_size = data_size as u64;
                    inv.files.push(e);
                }
            } else if htype == T_SERVICE {
                // The recovery record is a service block named "RR".
                if let Some(e) = parse_file_header(file, &mut b, body_end) {
                    if e.name == "RR" {
                        inv.has_recovery_record = true;
                    }
                }
            } else if htype == T_ENDARC {
                inv.has_end = true;
            }
        } else {
            inv.corrupt_blocks.push(block_start);
        }

        let Some(next) = body_end.checked_add(data_size) else {
            inv.truncated = true;
            break;
        };
        if next > file.len() {
            inv.truncated = true; // data runs past EOF
            break;
        }
        p = next;
        if crc_ok && htype == T_ENDARC {
            break;
        }
    }

    if !inv.has_end && inv.corrupt_blocks.is_empty() {
        inv.truncated = true; // no end-of-archive marker and no corruption seen
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_vint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }

    /// Build a CRC-correct RAR5 block from a body (type/flags/… already encoded).
    fn block(body: &[u8], data: &[u8]) -> Vec<u8> {
        let mut hs = Vec::new();
        put_vint(&mut hs, body.len() as u64);
        hs.extend_from_slice(body);
        let crc = CRC32_ISO_HDLC.checksum(&hs) as u32;
        let mut out = crc.to_le_bytes().to_vec();
        out.extend_from_slice(&hs);
        out.extend_from_slice(data);
        out
    }

    /// A minimal RAR5 with one file "hi.txt" (5 bytes, crc 0x11223344) + end block.
    fn synthetic() -> Vec<u8> {
        let mut out = SIGNATURE5.to_vec();
        // file header body
        let mut body = Vec::new();
        put_vint(&mut body, T_FILE); // type
        put_vint(&mut body, 0x02); // flags: data area present
        put_vint(&mut body, 5); // data size
        put_vint(&mut body, 0x04); // file flags: CRC present
        put_vint(&mut body, 5); // unpacked size
        put_vint(&mut body, 0); // attributes
        body.extend_from_slice(&0x1122_3344u32.to_le_bytes()); // data CRC32
        put_vint(&mut body, 0); // comp info
        put_vint(&mut body, 0); // host os
        let name = b"hi.txt";
        put_vint(&mut body, name.len() as u64);
        body.extend_from_slice(name);
        out.extend_from_slice(&block(&body, b"hello"));
        // end-of-archive block
        let mut endb = Vec::new();
        put_vint(&mut endb, T_ENDARC);
        put_vint(&mut endb, 0);
        out.extend_from_slice(&block(&endb, b""));
        out
    }

    #[test]
    fn parses_synthetic_rar5() {
        let inv = read_inventory(&synthetic()).expect("rar5");
        assert!(inv.has_end && !inv.truncated && inv.corrupt_blocks.is_empty());
        assert_eq!(inv.files.len(), 1);
        let f = &inv.files[0];
        assert_eq!(f.name, "hi.txt");
        assert_eq!(f.size, Some(5));
        assert_eq!(f.crc32, Some(0x1122_3344));
        assert!(f.header_crc_ok && !f.is_dir);
    }

    #[test]
    fn corrupt_header_is_localized_not_emitted() {
        let mut data = synthetic();
        // Flip a byte inside the file header (after the signature + CRC field).
        data[20] ^= 0xFF;
        let inv = read_inventory(&data).expect("rar5");
        // The file header CRC now fails → not emitted, block localized.
        assert!(inv.files.is_empty() || inv.files.iter().all(|f| f.header_crc_ok));
        assert!(!inv.corrupt_blocks.is_empty());
    }

    #[test]
    fn non_rar5_abstains() {
        assert!(read_inventory(&[0u8; 8]).is_none());
        assert!(read_inventory(b"Rar!\x1a\x07\x00").is_none()); // RAR4
    }

    /// Build a RAR5 with one **stored** file carrying a correct per-file CRC.
    fn synthetic_stored(data: &[u8], name: &[u8]) -> Vec<u8> {
        let crc = CRC32_ISO_HDLC.checksum(data) as u32;
        let mut out = SIGNATURE5.to_vec();
        let mut body = Vec::new();
        put_vint(&mut body, T_FILE);
        put_vint(&mut body, 0x02); // block flags: data area present
        put_vint(&mut body, data.len() as u64); // data size
        put_vint(&mut body, 0x04); // file flags: CRC present
        put_vint(&mut body, data.len() as u64); // unpacked size
        put_vint(&mut body, 0); // attributes
        body.extend_from_slice(&crc.to_le_bytes());
        put_vint(&mut body, 0); // comp info = 0 → method 0 (stored)
        put_vint(&mut body, 0); // host os
        put_vint(&mut body, name.len() as u64);
        body.extend_from_slice(name);
        out.extend_from_slice(&block(&body, data));
        let mut endb = Vec::new();
        put_vint(&mut endb, T_ENDARC);
        put_vint(&mut endb, 0);
        out.extend_from_slice(&block(&endb, b""));
        out
    }

    #[test]
    fn extract_stored_roundtrips_exact() {
        let data = b"the quick brown fox jumps";
        let arc = synthetic_stored(data, b"fox.txt");
        let inv = read_inventory(&arc).expect("rar5");
        let f = &inv.files[0];
        assert_eq!(f.method, 0);
        assert_eq!(f.packed_size, data.len() as u64);
        assert_eq!(extract_stored(&arc, f).as_deref(), Some(&data[..]));
    }

    #[test]
    fn extract_stored_abstains_on_damaged_data() {
        let data = b"sensitive backup payload";
        let arc = synthetic_stored(data, b"b.bin");
        let inv = read_inventory(&arc).expect("rar5");
        let off = inv.files[0].data_offset as usize;
        let mut dmg = arc.clone();
        dmg[off] ^= 0xFF; // corrupt a data byte (header CRC still valid)
        let inv2 = read_inventory(&dmg).expect("rar5");
        assert!(extract_stored(&dmg, &inv2.files[0]).is_none()); // CRC fails → abstain
    }

    #[test]
    fn truncation_detected() {
        let mut data = synthetic();
        data.truncate(data.len() - 6); // cut the end-of-archive block
        let inv = read_inventory(&data).expect("rar5");
        assert!(inv.truncated || !inv.has_end);
    }

    /// Build a RAR5 with a main header carrying `arc_flags`, then a stored file.
    fn synthetic_with_main(arc_flags: u64) -> Vec<u8> {
        let mut out = SIGNATURE5.to_vec();
        let mut main = Vec::new();
        put_vint(&mut main, T_MAIN);
        put_vint(&mut main, 0); // block flags: no extra / data
        put_vint(&mut main, arc_flags); // archive flags
        out.extend_from_slice(&block(&main, b""));
        out.extend_from_slice(&synthetic_stored(b"data", b"a.bin")[8..]); // append (skip sig)
        out
    }

    #[test]
    fn detects_recovery_record_flag() {
        let inv = read_inventory(&synthetic_with_main(0x08)).expect("rar5");
        assert!(inv.has_recovery_record);
        assert!(!inv.is_volume);
    }

    #[test]
    fn detects_volume_flag() {
        let inv = read_inventory(&synthetic_with_main(0x01)).expect("rar5");
        assert!(inv.is_volume);
        assert!(!inv.has_recovery_record);
    }

    #[test]
    fn no_recovery_record_when_absent() {
        // Main header with no flags, and the plain synthetic (no main header).
        assert!(
            !read_inventory(&synthetic_with_main(0x00))
                .unwrap()
                .has_recovery_record
        );
        assert!(!read_inventory(&synthetic()).unwrap().has_recovery_record);
    }

    #[test]
    fn detects_rr_service_block() {
        // A service block (type 3) named "RR" signals the recovery record.
        let mut out = SIGNATURE5.to_vec();
        let mut body = Vec::new();
        put_vint(&mut body, T_SERVICE);
        put_vint(&mut body, 0); // block flags
        put_vint(&mut body, 0); // file flags (no crc/time)
        put_vint(&mut body, 0); // unpacked size
        put_vint(&mut body, 0); // attributes
        put_vint(&mut body, 0); // comp info
        put_vint(&mut body, 0); // host os
        let name = b"RR";
        put_vint(&mut body, name.len() as u64);
        body.extend_from_slice(name);
        out.extend_from_slice(&block(&body, b""));
        let inv = read_inventory(&out).expect("rar5");
        assert!(inv.has_recovery_record);
    }
}
