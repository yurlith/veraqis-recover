//! Synthetic data generators for tests: well-formed and deliberately damaged
//! archives, plus byte-level corruption helpers.
//!
//! The Phase 1 [`CorpusGenerator`] is re-exported here so it is reachable as
//! `phx_test_utils::generators::CorpusGenerator` per the spec.

use phx_analyze_engine::integrity::crc32;

pub use crate::corpus_generator::CorpusGenerator;

/// Build a well-formed ZIP with STORED (uncompressed) members and correct
/// CRC-32s, a central directory, and an EOCD. Suitable as a clean corpus
/// reference whose CRC checks pass in the engine.
pub fn clean_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    // (lfh_offset, name, crc, size) for the central directory.
    let mut records: Vec<(u32, Vec<u8>, u32, u32)> = Vec::new();

    for (name, data) in files {
        let lfh_offset = out.len() as u32;
        let name_b = name.as_bytes();
        let crc = crc32(data);
        let size = data.len() as u32;

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // LFH sig
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed size
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_b);
        out.extend_from_slice(data);

        records.push((lfh_offset, name_b.to_vec(), crc, size));
    }

    let cd_offset = out.len() as u32;
    for (lfh_offset, name_b, crc, size) in &records {
        out.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // CDFH sig
        out.extend_from_slice(&20u16.to_le_bytes()); // version made by
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed size
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out.extend_from_slice(&0u16.to_le_bytes()); // disk start
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        out.extend_from_slice(&lfh_offset.to_le_bytes());
        out.extend_from_slice(name_b);
    }
    let cd_size = out.len() as u32 - cd_offset;

    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // EOCD sig
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk w/ cd
    out.extend_from_slice(&(records.len() as u16).to_le_bytes());
    out.extend_from_slice(&(records.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

/// Build a well-formed multi-member UStar TAR with correct header checksums
/// and the two-zero-block terminator.
pub fn clean_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in files {
        let mut block = [0u8; 512];
        let nb = name.as_bytes();
        block[..nb.len()].copy_from_slice(nb);
        // mode, uid, gid (octal) — fill plausible values.
        block[100..107].copy_from_slice(b"0000644");
        block[108..115].copy_from_slice(b"0000000");
        block[116..123].copy_from_slice(b"0000000");
        let size = format!("{:011o}\0", data.len());
        block[124..124 + size.len()].copy_from_slice(size.as_bytes());
        block[136..147].copy_from_slice(b"00000000000"); // mtime
        block[156] = b'0'; // typeflag: regular file
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        for b in &mut block[148..156] {
            *b = b' ';
        }
        let sum: u64 = block.iter().map(|&b| b as u64).sum();
        let chk = format!("{sum:06o}\0 ");
        block[148..148 + chk.len()].copy_from_slice(chk.as_bytes());

        out.extend_from_slice(&block);
        out.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat(0u8).take(pad));
    }
    out.extend(std::iter::repeat(0u8).take(1024)); // terminator
    out
}

/// Build a minimal but genuinely-valid ISO 9660 image that real tools (7-Zip,
/// isoinfo) accept: a Primary Volume Descriptor, a volume-descriptor-set
/// terminator, little/big-endian path tables, and a root directory extent with
/// `.` and `..` records.
///
/// Layout (2048-byte sectors): 0–15 system area, 16 PVD, 17 terminator,
/// 18 L-path-table, 19 M-path-table, 20 root directory extent.
pub fn clean_iso() -> Vec<u8> {
    const SECTOR: usize = 2048;
    const TOTAL: u32 = 21;
    const ROOT_LBA: u32 = 20;
    const L_PATH_LBA: u32 = 18;
    const M_PATH_LBA: u32 = 19;

    let mut v = vec![0u8; TOTAL as usize * SECTOR];

    // Primary Volume Descriptor (sector 16).
    let pvd = 16 * SECTOR;
    v[pvd] = 1;
    v[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    v[pvd + 6] = 1;
    both_endian_u32(&mut v[pvd + 80..pvd + 88], TOTAL); // volume space size
    both_endian_u16(&mut v[pvd + 120..pvd + 124], 1); // volume set size
    both_endian_u16(&mut v[pvd + 124..pvd + 128], 1); // volume sequence number
    both_endian_u16(&mut v[pvd + 128..pvd + 132], SECTOR as u16); // logical block size
    both_endian_u32(&mut v[pvd + 132..pvd + 140], 10); // path table size (bytes)
    v[pvd + 140..pvd + 144].copy_from_slice(&L_PATH_LBA.to_le_bytes()); // L-path table
    v[pvd + 148..pvd + 152].copy_from_slice(&M_PATH_LBA.to_be_bytes()); // M-path table
    write_dir_record(&mut v[pvd + 156..pvd + 190], ROOT_LBA, SECTOR as u32, 0x00);

    // Volume descriptor set terminator (sector 17).
    let term = 17 * SECTOR;
    v[term] = 0xFF;
    v[term + 1..term + 6].copy_from_slice(b"CD001");
    v[term + 6] = 1;

    // Path tables: one entry for the root directory.
    let lp = L_PATH_LBA as usize * SECTOR;
    v[lp] = 1;
    v[lp + 2..lp + 6].copy_from_slice(&ROOT_LBA.to_le_bytes());
    v[lp + 6..lp + 8].copy_from_slice(&1u16.to_le_bytes());
    v[lp + 8] = 0x00;
    let mp = M_PATH_LBA as usize * SECTOR;
    v[mp] = 1;
    v[mp + 2..mp + 6].copy_from_slice(&ROOT_LBA.to_be_bytes());
    v[mp + 6..mp + 8].copy_from_slice(&1u16.to_be_bytes());
    v[mp + 8] = 0x00;

    // Root directory extent (sector 20): '.' and '..' records.
    let root = ROOT_LBA as usize * SECTOR;
    write_dir_record(&mut v[root..root + 34], ROOT_LBA, SECTOR as u32, 0x00);
    write_dir_record(&mut v[root + 34..root + 68], ROOT_LBA, SECTOR as u32, 0x01);

    v
}

/// Write a 34-byte ISO 9660 directory record for `.` (`0x00`) or `..` (`0x01`).
fn write_dir_record(rec: &mut [u8], extent_lba: u32, data_len: u32, name_byte: u8) {
    rec[0] = 34;
    rec[1] = 0;
    both_endian_u32(&mut rec[2..10], extent_lba);
    both_endian_u32(&mut rec[10..18], data_len);
    rec[18..25].copy_from_slice(&[125, 1, 1, 0, 0, 0, 0]); // 2025-01-01
    rec[25] = 0x02; // directory flag
    both_endian_u16(&mut rec[28..32], 1);
    rec[32] = 1;
    rec[33] = name_byte;
}

fn both_endian_u32(out: &mut [u8], val: u32) {
    out[0..4].copy_from_slice(&val.to_le_bytes());
    out[4..8].copy_from_slice(&val.to_be_bytes());
}

fn both_endian_u16(out: &mut [u8], val: u16) {
    out[0..2].copy_from_slice(&val.to_le_bytes());
    out[2..4].copy_from_slice(&val.to_be_bytes());
}

// ── Hand-crafted clean files for formats without an installed encoder ────────

/// XXH32 (xxHash, 32-bit) — needed for the LZ4 frame header checksum.
fn xxh32(data: &[u8], seed: u32) -> u32 {
    const P1: u32 = 0x9E37_79B1;
    const P2: u32 = 0x85EB_CA77;
    const P3: u32 = 0xC2B2_AE3D;
    const P4: u32 = 0x27D4_EB2F;
    const P5: u32 = 0x1656_67B1;

    let mut idx = 0usize;
    let len = data.len();
    let mut h: u32;

    if len >= 16 {
        let mut v1 = seed.wrapping_add(P1).wrapping_add(P2);
        let mut v2 = seed.wrapping_add(P2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(P1);
        let round = |mut acc: u32, lane: u32| -> u32 {
            acc = acc.wrapping_add(lane.wrapping_mul(P2));
            acc = acc.rotate_left(13);
            acc.wrapping_mul(P1)
        };
        while idx + 16 <= len {
            v1 = round(v1, le32(&data[idx..]));
            v2 = round(v2, le32(&data[idx + 4..]));
            v3 = round(v3, le32(&data[idx + 8..]));
            v4 = round(v4, le32(&data[idx + 12..]));
            idx += 16;
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h = seed.wrapping_add(P5);
    }

    h = h.wrapping_add(len as u32);

    while idx + 4 <= len {
        h = h.wrapping_add(le32(&data[idx..]).wrapping_mul(P3));
        h = h.rotate_left(17).wrapping_mul(P4);
        idx += 4;
    }
    while idx < len {
        h = h.wrapping_add((data[idx] as u32).wrapping_mul(P5));
        h = h.rotate_left(11).wrapping_mul(P1);
        idx += 1;
    }

    h ^= h >> 15;
    h = h.wrapping_mul(P2);
    h ^= h >> 13;
    h = h.wrapping_mul(P3);
    h ^= h >> 16;
    h
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Build a valid GZIP stream (RFC 1952) wrapping `data` in DEFLATE *stored*
/// (uncompressed) blocks — no compressor required, and `gzip -t` / `7z t`
/// accept it.
pub fn clean_gzip(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF];
    // DEFLATE stored blocks, up to 65535 bytes each.
    if data.is_empty() {
        v.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]); // final empty stored block
    } else {
        let mut off = 0;
        while off < data.len() {
            let chunk = (data.len() - off).min(0xFFFF);
            let final_block = off + chunk >= data.len();
            v.push(if final_block { 0x01 } else { 0x00 });
            v.extend_from_slice(&(chunk as u16).to_le_bytes());
            v.extend_from_slice(&(!(chunk as u16)).to_le_bytes());
            v.extend_from_slice(&data[off..off + chunk]);
            off += chunk;
        }
    }
    v.extend_from_slice(&crc32(data).to_le_bytes());
    v.extend_from_slice(&(data.len() as u32).to_le_bytes()); // ISIZE
    v
}

/// Build a valid ZSTD frame (RFC 8878) with a single raw (uncompressed) block
/// and no content checksum. `data` must be ≤ 255 bytes (single-segment, 1-byte
/// content size) — callers pass a small reference payload.
pub fn clean_zstd(data: &[u8]) -> Vec<u8> {
    let data = &data[..data.len().min(255)];
    let mut v = vec![0x28, 0xB5, 0x2F, 0xFD]; // magic
    v.push(0x20); // descriptor: single-segment, FCS=1 byte, no checksum/dict
    v.push(data.len() as u8); // frame content size (1 byte)
                              // One raw, last block: header = (size<<3) | (raw<<1) | last.
    let header = ((data.len() as u32) << 3) | 0b001;
    let hb = header.to_le_bytes();
    v.extend_from_slice(&hb[..3]);
    v.extend_from_slice(data);
    v
}

/// Build a valid LZ4 frame with a single uncompressed block and no checksums
/// (only the mandatory header checksum).
pub fn clean_lz4(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x04, 0x22, 0x4D, 0x18]; // magic
    let flg = 0x60u8; // version=01, block-independence=1
    let bd = 0x40u8; // block max size = 64 KiB
    v.push(flg);
    v.push(bd);
    let hc = ((xxh32(&[flg, bd], 0) >> 8) & 0xFF) as u8;
    v.push(hc);
    // One uncompressed block: size with high bit set, then raw bytes.
    let size = data.len() as u32;
    v.extend_from_slice(&(size | 0x8000_0000).to_le_bytes());
    v.extend_from_slice(data);
    v.extend_from_slice(&0u32.to_le_bytes()); // EndMark
    v
}

/// Build a minimal but valid 3-page PDF with a correct cross-reference table.
pub fn clean_pdf() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"%PDF-1.4\n");

    // Append an object, recording its absolute byte offset for the xref table.
    let mut offsets: Vec<usize> = Vec::new();
    let emit = |out: &mut Vec<u8>, offsets: &mut Vec<usize>, s: String| {
        offsets.push(out.len());
        out.extend_from_slice(s.as_bytes());
    };

    emit(
        &mut out,
        &mut offsets,
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
    );
    emit(
        &mut out,
        &mut offsets,
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R] /Count 3 >>\nendobj\n".to_string(),
    );
    for n in 3..=5 {
        emit(
            &mut out,
            &mut offsets,
            format!("{n} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"),
        );
    }

    let xref_pos = out.len();
    let n_objs = offsets.len() + 1; // +1 for the free object 0
    out.extend_from_slice(format!("xref\n0 {n_objs}\n").as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< /Size {n_objs} /Root 1 0 R >>\n").as_bytes());
    out.extend_from_slice(format!("startxref\n{xref_pos}\n").as_bytes());
    out.extend_from_slice(b"%%EOF\n");
    out
}

/// Build a minimal, valid empty ZIP (EOCD only, zero entries).
pub fn empty_zip() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // EOCD sig
    v.extend_from_slice(&0u16.to_le_bytes()); // disk
    v.extend_from_slice(&0u16.to_le_bytes()); // disk w/ cd
    v.extend_from_slice(&0u16.to_le_bytes()); // entries this disk
    v.extend_from_slice(&0u16.to_le_bytes()); // total entries
    v.extend_from_slice(&0u32.to_le_bytes()); // cd size
    v.extend_from_slice(&0u32.to_le_bytes()); // cd offset
    v.extend_from_slice(&0u16.to_le_bytes()); // comment len
    v
}

/// A ZIP-looking blob with no EOCD record (structural catastrophe).
pub fn zip_without_eocd() -> Vec<u8> {
    let mut v = b"PK\x03\x04".to_vec();
    v.extend(std::iter::repeat(0xABu8).take(256));
    v
}

/// Build a ZIP containing a single stored local file header and data, but
/// **no central directory or EOCD** — the case `zip-rebuild` repairs.
pub fn zip_local_header_only(name: &str, data: &[u8]) -> Vec<u8> {
    let name_b = name.as_bytes();
    let size = data.len() as u32;
    let mut v = Vec::new();
    v.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // LFH sig
    v.extend_from_slice(&20u16.to_le_bytes()); // version needed
    v.extend_from_slice(&0u16.to_le_bytes()); // flags
    v.extend_from_slice(&0u16.to_le_bytes()); // method: stored
    v.extend_from_slice(&0u16.to_le_bytes()); // time
    v.extend_from_slice(&0u16.to_le_bytes()); // date
    v.extend_from_slice(&0u32.to_le_bytes()); // crc
    v.extend_from_slice(&size.to_le_bytes()); // comp size
    v.extend_from_slice(&size.to_le_bytes()); // uncomp size
    v.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // extra len
    v.extend_from_slice(name_b);
    v.extend_from_slice(data);
    v
}

/// Build a single-entry ZIP whose member is flagged encrypted (GP bit 0).
/// The data is not actually encrypted — the flag alone is what PHX detects.
pub fn encrypted_zip(name: &str, data: &[u8]) -> Vec<u8> {
    let name_b = name.as_bytes();
    let n = name_b.len() as u16;
    let size = data.len() as u32;
    let mut v = Vec::new();

    // Local file header (offset 0).
    v.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    v.extend_from_slice(&20u16.to_le_bytes()); // version needed
    v.extend_from_slice(&0x0001u16.to_le_bytes()); // flags: encrypted
    v.extend_from_slice(&0u16.to_le_bytes()); // method: stored
    v.extend_from_slice(&0u16.to_le_bytes()); // time
    v.extend_from_slice(&0u16.to_le_bytes()); // date
    v.extend_from_slice(&0u32.to_le_bytes()); // crc
    v.extend_from_slice(&size.to_le_bytes()); // comp size
    v.extend_from_slice(&size.to_le_bytes()); // uncomp size
    v.extend_from_slice(&n.to_le_bytes()); // name len
    v.extend_from_slice(&0u16.to_le_bytes()); // extra len
    v.extend_from_slice(name_b);
    v.extend_from_slice(data);

    let cd_offset = v.len() as u32;

    // Central directory file header.
    v.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    v.extend_from_slice(&20u16.to_le_bytes()); // version made by
    v.extend_from_slice(&20u16.to_le_bytes()); // version needed
    v.extend_from_slice(&0x0001u16.to_le_bytes()); // flags: encrypted
    v.extend_from_slice(&0u16.to_le_bytes()); // method
    v.extend_from_slice(&0u16.to_le_bytes()); // time
    v.extend_from_slice(&0u16.to_le_bytes()); // date
    v.extend_from_slice(&0u32.to_le_bytes()); // crc
    v.extend_from_slice(&size.to_le_bytes()); // comp size
    v.extend_from_slice(&size.to_le_bytes()); // uncomp size
    v.extend_from_slice(&n.to_le_bytes()); // name len
    v.extend_from_slice(&0u16.to_le_bytes()); // extra len
    v.extend_from_slice(&0u16.to_le_bytes()); // comment len
    v.extend_from_slice(&0u16.to_le_bytes()); // disk start
    v.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    v.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    v.extend_from_slice(&0u32.to_le_bytes()); // lfh offset
    v.extend_from_slice(name_b);

    let cd_size = v.len() as u32 - cd_offset;

    // EOCD.
    v.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
    v.extend_from_slice(&1u16.to_le_bytes()); // total entries
    v.extend_from_slice(&cd_size.to_le_bytes());
    v.extend_from_slice(&cd_offset.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // comment len
    v
}

/// Build a single-file UStar TAR with a valid header checksum and the
/// two-zero-block terminator.
pub fn tar_with_file(name: &str, data: &[u8]) -> Vec<u8> {
    let mut block = [0u8; 512];
    let nb = name.as_bytes();
    block[..nb.len()].copy_from_slice(nb);
    let size = format!("{:011o}\0", data.len());
    block[124..124 + size.len()].copy_from_slice(size.as_bytes());
    block[257..263].copy_from_slice(b"ustar\0");
    for b in &mut block[148..156] {
        *b = b' ';
    }
    let sum: u64 = block.iter().map(|&b| b as u64).sum();
    let chk = format!("{sum:06o}\0 ");
    block[148..148 + chk.len()].copy_from_slice(chk.as_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(&block);
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat(0u8).take(pad));
    out.extend(std::iter::repeat(0u8).take(1024)); // terminator
    out
}

/// Build a minimal ISO 9660 image with a valid PVD at sector 16.
pub fn iso_with_pvd(volume_sectors: u32, path_table_lba: u32) -> Vec<u8> {
    const SECTOR: usize = 2048;
    const PVD: usize = 16 * SECTOR;
    let mut v = vec![0u8; PVD + SECTOR];
    v[PVD] = 1;
    v[PVD + 1..PVD + 6].copy_from_slice(b"CD001");
    v[PVD + 80..PVD + 84].copy_from_slice(&volume_sectors.to_le_bytes());
    v[PVD + 140..PVD + 144].copy_from_slice(&path_table_lba.to_le_bytes());
    v
}

/// Flip a single bit at `byte_index` (bit 0) in a copy of `data`.
pub fn flip_bit(data: &[u8], byte_index: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    if byte_index < out.len() {
        out[byte_index] ^= 0x01;
    }
    out
}

/// Truncate `data` to `len` bytes.
pub fn truncate(data: &[u8], len: usize) -> Vec<u8> {
    data.iter().take(len).copied().collect()
}

/// Capped security fixtures (Phase 0.5, Architecture Addendum corpus).
///
/// Every fixture is constructed so its *declared* structure trips sandbox
/// detection while its actual expansion stays ≤ 1 MiB — the detector fires on
/// signature, never on real detonation. CI asserts detection, never expands.
pub mod security {
    use super::clean_zip;

    /// A leaf ZIP wrapped `depth` times as a stored `inner.zip` member — trips
    /// the depth gate when `depth` exceeds `max_depth`.
    pub fn nested_zip(depth: u32) -> Vec<u8> {
        let mut cur = clean_zip(&[("leaf.txt", b"leaf")]);
        for _ in 0..depth {
            cur = clean_zip(&[("inner.zip", &cur)]);
        }
        cur
    }

    /// A ZIP whose single member name is a path-escape attempt (traversal,
    /// absolute, drive-relative, UNC, or reserved device name).
    pub fn escape_name_zip(name: &str) -> Vec<u8> {
        clean_zip(&[(name, b"escape")])
    }

    /// A ZIP with `n` tiny members — trips the entry-count gate.
    pub fn many_entries_zip(n: usize) -> Vec<u8> {
        let names: Vec<String> = (0..n).map(|i| format!("f{i}.txt")).collect();
        let files: Vec<(&str, &[u8])> = names.iter().map(|s| (s.as_str(), &b"x"[..])).collect();
        clean_zip(&files)
    }

    /// A ZIP with one large stored member (`size` bytes, kept ≤ 1 MiB) — trips
    /// the cumulative-output gate under a tight cap.
    pub fn large_stored_zip(size: usize) -> Vec<u8> {
        let data = vec![0u8; size];
        clean_zip(&[("big.bin", &data)])
    }

    /// A UStar TAR with a single symlink entry (typeflag `2`) whose target
    /// escapes the sandbox — trips the symlink gate. The link is never followed
    /// or materialized.
    pub fn symlink_tar(name: &str, target: &str) -> Vec<u8> {
        let mut block = [0u8; 512];
        let nb = name.as_bytes();
        let n = nb.len().min(100);
        block[..n].copy_from_slice(&nb[..n]);
        block[100..107].copy_from_slice(b"0000777");
        block[108..115].copy_from_slice(b"0000000");
        block[116..123].copy_from_slice(b"0000000");
        let size = format!("{:011o}\0", 0); // symlinks carry no data
        block[124..124 + size.len()].copy_from_slice(size.as_bytes());
        block[136..147].copy_from_slice(b"00000000000"); // mtime
        block[156] = b'2'; // typeflag: symlink
        let tb = target.as_bytes();
        let t = tb.len().min(100);
        block[157..157 + t].copy_from_slice(&tb[..t]); // linkname (target)
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        for b in &mut block[148..156] {
            *b = b' ';
        }
        let sum: u64 = block.iter().map(|&b| b as u64).sum();
        let chk = format!("{sum:06o}\0 ");
        block[148..148 + chk.len()].copy_from_slice(chk.as_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(&block);
        out.extend(std::iter::repeat(0u8).take(1024)); // terminator
        out
    }

    /// A ZIP with a single Unix-symlink member: the central-directory external
    /// attributes carry mode `S_IFLNK` (0o120000) in their high 16 bits and the
    /// member data is the link target. Trips the symlink gate; never followed or
    /// materialized.
    pub fn symlink_zip(name: &str, target: &str) -> Vec<u8> {
        let mut z = clean_zip(&[(name, target.as_bytes())]);
        // Patch the (single) central-directory header's external attributes to
        // S_IFLNK | 0777 in the high 16 bits.
        let sig = 0x0201_4b50u32.to_le_bytes();
        if let Some(pos) = z.windows(4).position(|w| w == sig) {
            let attrs: u32 = 0xA1FF << 16; // S_IFLNK | 0777
            z[pos + 38..pos + 42].copy_from_slice(&attrs.to_le_bytes());
        }
        z
    }

    /// A ZIP whose two central-directory entries point at overlapping local
    /// data (Fifield overlap-bomb signature). Built by aliasing the second
    /// entry's local-header offset onto the first.
    pub fn overlap_zip() -> Vec<u8> {
        let mut z = clean_zip(&[("a.bin", &[0u8; 64]), ("b.bin", &[1u8; 64])]);
        // Central-directory file headers carry signature 0x02014b50 and store
        // the local-header offset at byte +42. Rewrite the second header's
        // offset to 0 so both entries claim the same [0, 64) data range.
        let sig = 0x0201_4b50u32.to_le_bytes();
        let positions: Vec<usize> = (0..z.len().saturating_sub(4))
            .filter(|&i| z[i..i + 4] == sig)
            .collect();
        if let Some(&second) = positions.get(1) {
            let off = second + 42;
            if off + 4 <= z.len() {
                z[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
            }
        }
        z
    }
}
