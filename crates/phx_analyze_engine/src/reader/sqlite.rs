//! Read-only SQLite reader.
//!
//! Parses the 100-byte database header, walks b-tree page headers for pages 1–N
//! (capped to avoid DoS on giant files), and probes the companion WAL file when
//! one is present alongside the database.  Never decompresses or decrypts data.
//!
//! SQLite 3 file format reference:
//!   https://www.sqlite.org/fileformat.html

use std::path::Path;

use crate::error::EngineError;
use crate::model::ArchiveFormat;

use super::{ArchiveEntry, ArchiveReader, DataSource};

/// The exact 16-byte header magic for every SQLite 3 file.
pub(crate) const SQ_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Max pages to walk when checking b-tree headers (DoS guard).
const MAX_PAGES_WALK: u32 = 512;

/// WAL magic constants (read as a big-endian u32). The suffix names the
/// *checksum word order* the magic selects: `0x377f0683` means big-endian
/// checksums, `0x377f0682` little-endian. Detection accepts either.
const WAL_MAGIC_LE: u32 = 0x377f_0682;
const WAL_MAGIC_BE: u32 = 0x377f_0683;

/// Per-page b-tree error kinds recorded during the page walk.
#[derive(Debug, Clone)]
pub(crate) enum BtreeErrorKind {
    InvalidPageType(u8),
    CellCountExceedsCapacity { count: u16, page_size: u32 },
    CellPtrOutOfBounds { ptr: u16, page_size: u32 },
}

/// One b-tree page anomaly.
#[derive(Debug, Clone)]
pub(crate) struct BtreePageError {
    pub page_num: u32,
    pub page_offset: u64,
    pub kind: BtreeErrorKind,
}

/// Structural facts extracted from a SQLite file.
pub(crate) struct SqliteParse {
    /// Header magic bytes matched `"SQLite format 3\0"`.
    pub magic_ok: bool,
    /// Raw page-size field value from header[16..18] (1 means 65536).
    pub page_size_raw: u16,
    /// Resolved page size in bytes (0 if the raw value is invalid).
    pub page_size: u32,
    /// page_size is a valid power of 2 in [512, 65536].
    pub page_size_valid: bool,
    /// Declared page count (header[28..32]).
    pub declared_pages: u32,
    /// Actual page count inferred from file length and page_size.
    /// `None` when page_size is invalid.
    pub actual_pages: Option<u64>,
    /// File length is an exact multiple of page_size.
    pub ends_on_page_boundary: bool,
    /// File is too short to contain a second page (severe truncation).
    pub truncated_before_page2: bool,
    /// Declared page count matches actual count derived from file size.
    pub page_count_matches: bool,
    /// First freelist trunk page number (header[32..36]).
    pub freelist_trunk: u32,
    /// Total freelist page count (header[36..40]).
    pub freelist_count: u32,
    /// Freelist trunk page number ≤ actual_pages (0 = no freelist, always valid).
    pub freelist_trunk_valid: bool,
    /// Freelist count ≤ actual_pages.
    pub freelist_count_valid: bool,
    /// File-change counter (header[24..28]).
    pub file_change_counter: u32,
    /// Version-valid-for number (header[92..96]); must equal file_change_counter
    /// in rollback-journal mode.
    pub version_valid_for: u32,
    /// Write version byte (1 = legacy, 2 = WAL).
    pub write_version: u8,
    /// Read version byte (should equal write_version).
    pub read_version: u8,
    /// B-tree page header anomalies found during the page walk.
    pub btree_errors: Vec<BtreePageError>,
    /// A companion `.db-wal` / `-wal` file was found alongside the database.
    pub wal_present: bool,
    /// WAL magic bytes are valid (only meaningful when wal_present).
    pub wal_magic_ok: bool,
    /// WAL salt-1 matches the database salt at header[92..96] (i.e. same session).
    pub wal_salt_matches: bool,
}

/// Reader for the SQLite format.
pub struct SqliteReader;

impl SqliteReader {
    /// Parse the SQLite file.  Never panics on malformed input.
    pub(crate) fn parse(&self, source: &DataSource) -> SqliteParse {
        let mut out = SqliteParse {
            magic_ok: false,
            page_size_raw: 0,
            page_size: 0,
            page_size_valid: false,
            declared_pages: 0,
            actual_pages: None,
            ends_on_page_boundary: false,
            truncated_before_page2: false,
            page_count_matches: false,
            freelist_trunk: 0,
            freelist_count: 0,
            freelist_trunk_valid: true,
            freelist_count_valid: true,
            file_change_counter: 0,
            version_valid_for: 0,
            write_version: 0,
            read_version: 0,
            btree_errors: Vec::new(),
            wal_present: false,
            wal_magic_ok: false,
            wal_salt_matches: false,
        };

        let file_len = source.len();

        // Need at least 100 bytes for the header.
        let Ok(hdr) = source.read_exact_at(0, 100) else {
            out.truncated_before_page2 = true;
            return out;
        };

        // Magic check.
        out.magic_ok = &hdr[..16] == SQ_MAGIC;

        // Page size: raw u16 at [16..18]; value 1 encodes 65536.
        let raw = u16::from_be_bytes([hdr[16], hdr[17]]);
        out.page_size_raw = raw;
        out.page_size = if raw == 1 { 65536 } else { raw as u32 };
        out.page_size_valid = is_valid_page_size(out.page_size);

        out.write_version = hdr[18];
        out.read_version = hdr[19];

        out.file_change_counter = u32_be(&hdr[24..28]);
        out.declared_pages = u32_be(&hdr[28..32]);
        out.freelist_trunk = u32_be(&hdr[32..36]);
        out.freelist_count = u32_be(&hdr[36..40]);
        out.version_valid_for = u32_be(&hdr[92..96]);

        if out.page_size_valid && out.page_size > 0 {
            let ps = out.page_size as u64;
            let actual = file_len / ps;
            out.actual_pages = Some(actual);
            out.ends_on_page_boundary = file_len % ps == 0;
            out.truncated_before_page2 = file_len < ps * 2;
            out.page_count_matches = out.declared_pages > 0 && out.declared_pages as u64 == actual;

            let ap = actual;
            out.freelist_trunk_valid = out.freelist_trunk == 0 || out.freelist_trunk as u64 <= ap;
            out.freelist_count_valid = out.freelist_count as u64 <= ap;

            // Walk page headers.
            let walk_count = (actual as u32).min(MAX_PAGES_WALK);
            out.btree_errors = walk_btree_pages(source, out.page_size, walk_count);
        } else {
            out.truncated_before_page2 = file_len < 2048; // can't know without valid page_size
        }

        // Probe WAL file alongside the database.
        let wal_path = wal_path_for(source.path());
        if let Some(wp) = wal_path {
            if wp.exists() {
                out.wal_present = true;
                if let Some(wal_bytes) = std::fs::read(&wp).ok().filter(|b| b.len() >= 32) {
                    let magic = u32::from_be_bytes([
                        wal_bytes[0],
                        wal_bytes[1],
                        wal_bytes[2],
                        wal_bytes[3],
                    ]);
                    out.wal_magic_ok = magic == WAL_MAGIC_LE || magic == WAL_MAGIC_BE;
                    // WAL salt-1 at [16..20] should match the db version-valid-for in WAL mode.
                    let wal_salt1 = u32::from_be_bytes([
                        wal_bytes[16],
                        wal_bytes[17],
                        wal_bytes[18],
                        wal_bytes[19],
                    ]);
                    out.wal_salt_matches =
                        wal_salt1 == out.version_valid_for || wal_salt1 == out.file_change_counter;
                }
            }
        }

        out
    }
}

impl ArchiveReader for SqliteReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Sqlite
    }

    fn entries(&self, _source: &DataSource) -> Result<Vec<ArchiveEntry>, EngineError> {
        // SQLite doesn't expose logical file members the way archives do.
        Ok(Vec::new())
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn is_valid_page_size(ps: u32) -> bool {
    if !(512..=65536).contains(&ps) {
        return false;
    }
    ps.is_power_of_two()
}

/// Walk up to `page_count` b-tree page headers and collect structural errors.
fn walk_btree_pages(source: &DataSource, page_size: u32, page_count: u32) -> Vec<BtreePageError> {
    let mut errors = Vec::new();
    let ps = page_size as u64;

    for page_num in 1..=page_count {
        let page_offset = (page_num as u64 - 1) * ps;
        // Page 1 has the 100-byte file header before the b-tree header.
        let btree_hdr_offset = if page_num == 1 {
            page_offset + 100
        } else {
            page_offset
        };

        // Read 12 bytes — enough for the full b-tree page header (incl. right-pointer).
        let Ok(hdr) = source.read_exact_at(btree_hdr_offset, 12) else {
            break;
        };

        let page_type = hdr[0];
        let valid_type = matches!(page_type, 2 | 5 | 10 | 13);
        if !valid_type {
            errors.push(BtreePageError {
                page_num,
                page_offset,
                kind: BtreeErrorKind::InvalidPageType(page_type),
            });
            // Don't walk cell pointers if the type is garbage.
            continue;
        }

        let cell_count = u16::from_be_bytes([hdr[3], hdr[4]]);
        // Maximum cells that can fit: each cell pointer is 2 bytes; usable space
        // ≈ page_size - header (8 or 12 bytes). Use a generous ceiling.
        let max_cells = (page_size.saturating_sub(12) / 2) as u16;
        if cell_count > max_cells {
            errors.push(BtreePageError {
                page_num,
                page_offset,
                kind: BtreeErrorKind::CellCountExceedsCapacity {
                    count: cell_count,
                    page_size,
                },
            });
            continue;
        }

        // Check a sample of cell pointers (first 8) for out-of-bounds.
        let ptr_array_offset = if matches!(page_type, 2 | 5) {
            12u64
        } else {
            8u64
        };
        let check_cells = cell_count.min(8);
        for i in 0..check_cells {
            let ptr_off = btree_hdr_offset + ptr_array_offset + i as u64 * 2;
            let Ok(ptr_bytes) = source.read_exact_at(ptr_off, 2) else {
                break;
            };
            let ptr = u16::from_be_bytes([ptr_bytes[0], ptr_bytes[1]]);
            // Cell pointer must point within the page (non-zero, < page_size).
            if ptr == 0 || ptr as u32 >= page_size {
                errors.push(BtreePageError {
                    page_num,
                    page_offset,
                    kind: BtreeErrorKind::CellPtrOutOfBounds { ptr, page_size },
                });
                break; // One per page is enough.
            }
        }
    }

    errors
}

/// Return the WAL file path for a given database path, if determinable.
/// SQLite appends "-wal" to the database path: `foo.db` → `foo.db-wal`.
fn wal_path_for(db_path: &Path) -> Option<std::path::PathBuf> {
    let s = db_path.to_str()?;
    Some(std::path::PathBuf::from(format!("{s}-wal")))
}

#[inline]
fn u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
