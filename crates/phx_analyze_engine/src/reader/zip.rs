//! Read-only ZIP reader.
//!
//! Parses the End Of Central Directory (EOCD) record and the central
//! directory. Encrypted members are *detected* (general-purpose bit 0) and
//! flagged — never decrypted or decompressed here.

use std::path::PathBuf;

use crate::error::EngineError;
use crate::model::ArchiveFormat;

use super::{ArchiveEntry, ArchiveReader, DataSource};

const EOCD_SIG: u32 = 0x0605_4b50; // "PK\x05\x06"
const CDFH_SIG: u32 = 0x0201_4b50; // "PK\x01\x02"
const LFH_SIG: u32 = 0x0403_4b50; // "PK\x03\x04"
const EOCD_MIN_LEN: usize = 22;
/// Max bytes to scan back for the EOCD (22 + max 65535-byte comment).
const EOCD_SCAN_WINDOW: u64 = 22 + 0xFFFF;

/// Structural facts extracted from a ZIP container. Consumed by the corruption
/// detector; the reader itself draws no conclusions about severity.
pub(crate) struct ZipParse {
    /// Offset of the EOCD record, or `None` if its signature was not found.
    pub eocd_offset: Option<u64>,
    /// Total entry count declared in the EOCD.
    pub declared_entries: u16,
    /// Central-directory offset declared in the EOCD.
    pub cd_offset: u32,
    /// Whether a valid central-directory signature was found at `cd_offset`.
    pub cd_present: bool,
    /// Whether every entry's local file header signature was found.
    pub local_headers_ok: bool,
    /// Members parsed from the central directory.
    pub entries: Vec<ArchiveEntry>,
    /// Compression method per entry, parallel to `entries` (0 = stored).
    pub methods: Vec<u16>,
}

/// Reader for the ZIP format.
pub struct ZipReader;

impl ZipReader {
    /// Parse the ZIP structure defensively. Never panics on malformed input.
    pub(crate) fn parse(&self, source: &DataSource) -> ZipParse {
        let mut parse = ZipParse {
            eocd_offset: None,
            declared_entries: 0,
            cd_offset: 0,
            cd_present: false,
            local_headers_ok: true,
            entries: Vec::new(),
            methods: Vec::new(),
        };

        let len = source.len();
        if len < EOCD_MIN_LEN as u64 {
            return parse;
        }

        // Scan backward for the EOCD signature within the comment window.
        let window = EOCD_SCAN_WINDOW.min(len);
        let start = len - window;
        let buf = match source.read_exact_at(start, window as usize) {
            Ok(b) => b,
            Err(_) => return parse,
        };

        let Some(rel) = find_eocd(&buf) else {
            return parse;
        };
        let eocd_abs = start + rel as u64;
        parse.eocd_offset = Some(eocd_abs);

        let eocd = &buf[rel..];
        if eocd.len() < EOCD_MIN_LEN {
            return parse;
        }
        parse.declared_entries = u16_le(&eocd[10..12]);
        let cd_size = u32_le(&eocd[12..16]);
        parse.cd_offset = u32_le(&eocd[16..20]);

        // Read and walk the central directory.
        if (parse.cd_offset as u64) < len {
            if let Ok(cd) = source.read_exact_at(parse.cd_offset as u64, cd_size as usize) {
                parse.cd_present = cd.len() >= 4 && u32_le(&cd[0..4]) == CDFH_SIG;
                let (entries, methods) = parse_central_directory(&cd);
                parse.entries = entries;
                parse.methods = methods;
            }
        }

        // Spot-check that local file headers exist where the CD points.
        for entry in &parse.entries {
            let mut sig = [0u8; 4];
            if source.read_at(entry.offset, &mut sig).unwrap_or(0) < 4 || u32_le(&sig) != LFH_SIG {
                parse.local_headers_ok = false;
                break;
            }
        }

        parse
    }
}

impl ArchiveReader for ZipReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Zip
    }

    fn entries(&self, source: &DataSource) -> Result<Vec<ArchiveEntry>, EngineError> {
        let parse = self.parse(source);
        if parse.eocd_offset.is_none() {
            // No EOCD: the directory is unrecoverable by enumeration. Report a
            // best-effort empty list; the detector flags the structural damage.
            return Ok(Vec::new());
        }
        Ok(parse.entries)
    }
}

/// Locate the EOCD signature scanning from the end of `buf`. Returns the
/// relative index of the signature's first byte.
fn find_eocd(buf: &[u8]) -> Option<usize> {
    if buf.len() < EOCD_MIN_LEN {
        return None;
    }
    // Latest valid EOCD wins; iterate from the back.
    (0..=buf.len() - 4)
        .rev()
        .find(|&i| u32_le(&buf[i..i + 4]) == EOCD_SIG)
}

/// Parse central-directory file headers into entries and their compression
/// methods (parallel vectors). Stops on the first malformed header.
fn parse_central_directory(cd: &[u8]) -> (Vec<ArchiveEntry>, Vec<u16>) {
    let mut entries = Vec::new();
    let mut methods = Vec::new();
    let mut pos = 0usize;
    while pos + 46 <= cd.len() {
        if u32_le(&cd[pos..pos + 4]) != CDFH_SIG {
            break;
        }
        let flags = u16_le(&cd[pos + 8..pos + 10]);
        let method = u16_le(&cd[pos + 10..pos + 12]);
        let crc = u32_le(&cd[pos + 16..pos + 20]);
        let comp_size = u32_le(&cd[pos + 20..pos + 24]);
        let uncomp_size = u32_le(&cd[pos + 24..pos + 28]);
        let name_len = u16_le(&cd[pos + 28..pos + 30]) as usize;
        let extra_len = u16_le(&cd[pos + 30..pos + 32]) as usize;
        let comment_len = u16_le(&cd[pos + 32..pos + 34]) as usize;
        let external_attrs = u32_le(&cd[pos + 38..pos + 42]);
        let lfh_offset = u32_le(&cd[pos + 42..pos + 46]);

        let name_start = pos + 46;
        let name_end = name_start + name_len;
        if name_end > cd.len() {
            break;
        }
        let name = String::from_utf8_lossy(&cd[name_start..name_end]).into_owned();

        // Unix symlinks carry mode S_IFLNK (0o120000) in the high 16 bits of
        // the external attributes; the entry data is the link target.
        let unix_mode = (external_attrs >> 16) & 0xFFFF;
        let is_link = unix_mode & 0xF000 == 0xA000;

        entries.push(ArchiveEntry {
            path: PathBuf::from(name),
            size: uncomp_size as u64,
            compressed_size: comp_size as u64,
            offset: lfh_offset as u64,
            // GP flag bit 0 (traditional) OR bit 6 (strong encryption). This is
            // the single authoritative "is encrypted" predicate shared with
            // phx_safety and phx_inspect — previously bit-0-only, which disagreed
            // with the safety scanner on AES/strong-encrypted ZIPs.
            encrypted: flags & 0x0001 != 0 || flags & 0x0040 != 0,
            stored_crc32: Some(crc),
            is_link,
            link_target: None,
        });
        methods.push(method);

        pos = name_end + extra_len + comment_len;
    }
    (entries, methods)
}

#[inline]
fn u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

#[inline]
fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal empty ZIP: just an EOCD with zero entries.
    fn empty_zip() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&EOCD_SIG.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // disk
        v.extend_from_slice(&0u16.to_le_bytes()); // disk w/ cd
        v.extend_from_slice(&0u16.to_le_bytes()); // entries this disk
        v.extend_from_slice(&0u16.to_le_bytes()); // total entries
        v.extend_from_slice(&0u32.to_le_bytes()); // cd size
        v.extend_from_slice(&0u32.to_le_bytes()); // cd offset
        v.extend_from_slice(&0u16.to_le_bytes()); // comment len
        v
    }

    #[test]
    fn finds_eocd_in_empty_zip() {
        let src = DataSource::from_bytes("z.zip", empty_zip());
        let parse = ZipReader.parse(&src);
        assert!(parse.eocd_offset.is_some());
        assert_eq!(parse.declared_entries, 0);
    }

    #[test]
    fn missing_eocd_yields_none() {
        let src = DataSource::from_bytes("z.zip", vec![0u8; 64]);
        let parse = ZipReader.parse(&src);
        assert!(parse.eocd_offset.is_none());
    }
}
