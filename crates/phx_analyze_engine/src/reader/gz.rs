//! GZIP reader (Phase 6).
//!
//! GZIP wraps a single DEFLATE stream. This reader reports one logical member
//! without decompressing it — the corruption detector handles the structural
//! checks (magic, CM, CRC32, ISIZE) directly from the raw bytes.

use crate::error::EngineError;
use crate::model::ArchiveFormat;
use crate::reader::{ArchiveEntry, ArchiveReader, DataSource};

/// Minimal GZIP reader — reports the single decompressed-content member.
pub struct GzipReader;

impl ArchiveReader for GzipReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Gzip
    }

    fn entries(&self, source: &DataSource) -> Result<Vec<ArchiveEntry>, EngineError> {
        // GZIP: read the optional original filename from the header (FNAME flag).
        let name = gz_original_name(source).unwrap_or_else(|| "content".to_string());
        Ok(vec![ArchiveEntry {
            path: name.into(),
            size: 0, // unknown without decompressing
            compressed_size: source.len().saturating_sub(18),
            offset: 10,
            encrypted: false,
            stored_crc32: None,
            is_link: false,
            link_target: None,
        }])
    }
}

/// Read the optional original filename (FNAME flag, byte 3 bit 3).
fn gz_original_name(source: &DataSource) -> Option<String> {
    let head = source.read_exact_at(0, 10).ok()?;
    if head.len() < 10 || head[0] != 0x1F || head[1] != 0x8B {
        return None;
    }
    let flags = head[3];
    let fextra = flags & 0x04 != 0;
    let fname = flags & 0x08 != 0;
    if !fname {
        return None;
    }

    let mut pos: u64 = 10;
    if fextra {
        let xlen_bytes = source.read_exact_at(pos, 2).ok()?;
        let xlen = u16::from_le_bytes([xlen_bytes[0], xlen_bytes[1]]) as u64;
        pos += 2 + xlen;
    }

    // FNAME is a null-terminated ISO 8859-1 string.
    let mut name = Vec::new();
    loop {
        let b = source.read_exact_at(pos, 1).ok()?;
        if b[0] == 0 {
            break;
        }
        name.push(b[0]);
        pos += 1;
        if name.len() > 255 {
            break;
        }
    }
    if name.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&name).into_owned())
    }
}
