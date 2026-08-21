//! Read-only TAR (UStar) reader.
//!
//! Walks the 512-byte block structure, verifies UStar header checksums, and
//! checks for the two-zero-block terminator. No extraction is performed.

use std::path::PathBuf;

use crate::error::EngineError;
use crate::model::ArchiveFormat;

use super::{ArchiveEntry, ArchiveReader, DataSource};

const BLOCK: u64 = 512;
const MAGIC_OFFSET: usize = 257;

/// Structural facts extracted from a TAR archive.
pub(crate) struct TarParse {
    /// `true` if `ustar` magic is present in the first header block.
    pub magic_ok: bool,
    /// Members enumerated from header blocks.
    pub entries: Vec<ArchiveEntry>,
    /// `(offset, name)` of headers whose stored checksum did not verify.
    pub checksum_failures: Vec<(u64, String)>,
    /// `true` if the archive ends with two zero blocks.
    pub zero_terminator_present: bool,
    /// `true` if the stream ended mid-record (size runs past EOF).
    pub truncated: bool,
}

/// Reader for the TAR format.
pub struct TarReader;

impl TarReader {
    pub(crate) fn parse(&self, source: &DataSource) -> TarParse {
        let mut parse = TarParse {
            magic_ok: false,
            entries: Vec::new(),
            checksum_failures: Vec::new(),
            zero_terminator_present: false,
            truncated: false,
        };

        let len = source.len();
        let mut offset = 0u64;
        let mut zero_blocks = 0u32;
        let mut first = true;

        while offset + BLOCK <= len {
            let block = match source.read_exact_at(offset, BLOCK as usize) {
                Ok(b) => b,
                Err(_) => {
                    parse.truncated = true;
                    break;
                }
            };

            if block.iter().all(|&b| b == 0) {
                zero_blocks += 1;
                if zero_blocks >= 2 {
                    parse.zero_terminator_present = true;
                    break;
                }
                offset += BLOCK;
                continue;
            }
            zero_blocks = 0;

            if first {
                parse.magic_ok = &block[MAGIC_OFFSET..MAGIC_OFFSET + 5] == b"ustar";
                first = false;
            }

            // Verify header checksum.
            let stored = parse_octal(&block[148..156]);
            let computed = unsigned_checksum(&block);
            let name = parse_name(&block[0..100]);
            if stored != Some(computed) {
                parse.checksum_failures.push((offset, name.clone()));
            }

            let size = parse_octal(&block[124..136]).unwrap_or(0);
            let data_offset = offset + BLOCK;
            // typeflag '2' = symlink, '1' = hardlink; linkname is the 100-byte
            // field at 157. Detected, never followed — the sandbox flags it.
            let is_link = block[156] == b'1' || block[156] == b'2';
            let link_target = if is_link {
                Some(parse_name(&block[157..257]))
            } else {
                None
            };
            parse.entries.push(ArchiveEntry {
                path: PathBuf::from(name),
                size,
                compressed_size: size,
                offset: data_offset,
                encrypted: false,
                stored_crc32: None,
                is_link,
                link_target,
            });

            // Advance past header + data (rounded up to a block boundary).
            let data_blocks = size.div_ceil(BLOCK);
            let next = data_offset + data_blocks * BLOCK;
            if next > len {
                parse.truncated = true;
                break;
            }
            offset = next;
        }

        parse
    }
}

impl ArchiveReader for TarReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Tar
    }

    fn entries(&self, source: &DataSource) -> Result<Vec<ArchiveEntry>, EngineError> {
        Ok(self.parse(source).entries)
    }
}

/// UStar header checksum: sum of all 512 bytes, with the 8-byte checksum field
/// treated as ASCII spaces.
fn unsigned_checksum(block: &[u8]) -> u64 {
    let mut sum = 0u64;
    for (i, &b) in block.iter().enumerate() {
        if (148..156).contains(&i) {
            sum += b' ' as u64;
        } else {
            sum += b as u64;
        }
    }
    sum
}

/// Parse a NUL/space-terminated octal field.
fn parse_octal(field: &[u8]) -> Option<u64> {
    let s: String = field
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .map(|&b| b as char)
        .collect();
    if s.is_empty() {
        return None;
    }
    u64::from_str_radix(s.trim(), 8).ok()
}

/// Parse a NUL-terminated name field.
fn parse_name(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a single-file UStar archive with a correct checksum.
    fn tar_with_file(name: &str, data: &[u8]) -> Vec<u8> {
        let mut block = [0u8; 512];
        block[..name.len()].copy_from_slice(name.as_bytes());
        // size field (octal, 11 digits + space)
        let size = format!("{:011o}\0", data.len());
        block[124..124 + size.len()].copy_from_slice(size.as_bytes());
        block[MAGIC_OFFSET..MAGIC_OFFSET + 6].copy_from_slice(b"ustar\0");
        // checksum field: spaces, then compute
        for b in &mut block[148..156] {
            *b = b' ';
        }
        let sum = unsigned_checksum(&block);
        let chk = format!("{sum:06o}\0 ");
        block[148..148 + chk.len()].copy_from_slice(chk.as_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(&block);
        out.extend_from_slice(data);
        // pad data to block boundary
        let pad = (512 - data.len() % 512) % 512;
        out.extend(std::iter::repeat(0u8).take(pad));
        // two zero-block terminator
        out.extend(std::iter::repeat(0u8).take(1024));
        out
    }

    #[test]
    fn parses_single_file_with_valid_checksum() {
        let src = DataSource::from_bytes("a.tar", tar_with_file("hello.txt", b"hi"));
        let parse = TarReader.parse(&src);
        assert!(parse.magic_ok);
        assert_eq!(parse.entries.len(), 1);
        assert_eq!(parse.entries[0].size, 2);
        assert!(parse.checksum_failures.is_empty());
        assert!(parse.zero_terminator_present);
    }
}
