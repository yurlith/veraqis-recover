//! Deterministic GZIP / TAR fixture encoders for the resync salvage tests and
//! benchmark. Real GZIP members (header + DEFLATE + CRC32/ISIZE trailer) and real
//! ustar TAR headers (with correct checksums) so ground truth is exact and damage
//! can be injected precisely — no committed binaries, no external tools.

use std::io::Write;

const BLOCK: usize = 512;

/// Encode one GZIP member (10-byte header, DEFLATE body, CRC32+ISIZE trailer).
pub fn gzip_member(plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
        let _ = enc.write_all(plaintext);
        let _ = enc.finish();
    }
    out
}

/// Concatenate several GZIP members into one multi-member `.gz` stream.
pub fn concat_gzip_members(members: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in members {
        out.extend_from_slice(&gzip_member(m));
    }
    out
}

/// Encode one ustar TAR member: a 512-byte header (correct checksum) followed by
/// the data padded to a 512-byte boundary.
pub fn tar_member(name: &str, data: &[u8]) -> Vec<u8> {
    let mut hdr = [0u8; BLOCK];

    // name [0..100]
    let nb = name.as_bytes();
    let n = nb.len().min(100);
    hdr[..n].copy_from_slice(&nb[..n]);
    // mode [100..108], uid [108..116], gid [116..124]
    write_octal(&mut hdr[100..108], 0o644);
    write_octal(&mut hdr[108..116], 0);
    write_octal(&mut hdr[116..124], 0);
    // size [124..136], mtime [136..148]
    write_octal(&mut hdr[124..136], data.len() as u64);
    write_octal(&mut hdr[136..148], 0);
    // typeflag [156] = '0' regular file
    hdr[156] = b'0';
    // magic [257..263] "ustar\0", version [263..265] "00"
    hdr[257..263].copy_from_slice(b"ustar\0");
    hdr[263..265].copy_from_slice(b"00");

    // checksum [148..156]: compute with the field treated as spaces, then write
    // 6 octal digits + NUL + space (the canonical encoding).
    for b in &mut hdr[148..156] {
        *b = b' ';
    }
    let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
    let cks = format!("{sum:06o}\0 ");
    hdr[148..156].copy_from_slice(&cks.as_bytes()[..8]);

    let mut out = Vec::with_capacity(BLOCK + data.len().div_ceil(BLOCK) * BLOCK);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(data);
    let pad = data.len().div_ceil(BLOCK) * BLOCK - data.len();
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Encode a complete TAR archive: the members plus the two-block zero terminator.
pub fn tar_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in members {
        out.extend_from_slice(&tar_member(name, data));
    }
    out.extend(std::iter::repeat_n(0u8, 2 * BLOCK)); // end-of-archive terminator
    out
}

/// Write a value as a zero-padded octal ASCII field terminated by a NUL byte
/// (width-1 octal digits + NUL), the classic GNU/ustar numeric encoding.
fn write_octal(field: &mut [u8], value: u64) {
    let width = field.len();
    let s = format!("{value:0w$o}", w = width - 1);
    let b = s.as_bytes();
    let take = b.len().min(width - 1);
    field[..take].copy_from_slice(&b[..take]);
    field[take] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_member_roundtrips_via_multi_decoder() {
        use std::io::Read;
        let gz = concat_gzip_members(&[b"one", b"two", b"three"]);
        let mut d = flate2::read::MultiGzDecoder::new(&gz[..]);
        let mut out = Vec::new();
        d.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"onetwothree");
    }

    #[test]
    fn tar_member_block_aligned_with_valid_magic() {
        let m = tar_member("x.txt", b"hello");
        assert_eq!(m.len() % BLOCK, 0);
        assert_eq!(&m[257..262], b"ustar");
    }
}
