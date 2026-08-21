//! Read-only format readers.
//!
//! The reader layer **never modifies data**. Each reader enumerates the
//! logical members of a container and exposes the structural facts the
//! corruption detector needs (e.g. whether a ZIP end-of-central-directory was
//! found). Detection/classification of *meaning* happens in
//! [`crate::corruption`]; this layer only parses.
//!
//! Adding a new format means implementing [`ArchiveReader`] — no engine change.

mod data_source;
pub mod field_map;
mod gz;
mod iso;
mod raw;
mod sqlite;
mod tar;
mod zip;

use std::path::PathBuf;

use crate::error::EngineError;
use crate::model::ArchiveFormat;

pub use data_source::{DataSource, STREAM_BUFFER_BYTES};
pub use gz::GzipReader;
pub use iso::IsoReader;
pub use raw::RawReader;
pub use sqlite::SqliteReader;
pub use tar::TarReader;
pub use zip::ZipReader;

// Structural parse outputs consumed by the corruption detector (same crate).
pub(crate) use iso::IsoParse;
pub(crate) use sqlite::{BtreeErrorKind, SqliteParse};
pub(crate) use tar::TarParse;
pub(crate) use zip::ZipParse;

/// A logical member of an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    /// Member path as recorded in the archive.
    pub path: PathBuf,
    /// Uncompressed size in bytes, when known.
    pub size: u64,
    /// Stored (possibly compressed) size in bytes, when known.
    pub compressed_size: u64,
    /// Absolute offset of the member's local header / data within the source.
    pub offset: u64,
    /// `true` if the member is encrypted (detected, never decrypted here).
    pub encrypted: bool,
    /// Embedded CRC-32 if the format carries one (ZIP).
    pub stored_crc32: Option<u32>,
    /// `true` if the member is a symlink or hardlink (detected, never followed
    /// or materialized — the sandbox treats it as a security finding).
    pub is_link: bool,
    /// Link target path when the format records it inline (e.g. TAR linkname).
    pub link_target: Option<String>,
}

/// Read-only enumeration of an archive's members.
pub trait ArchiveReader {
    /// Format this reader handles.
    fn format(&self) -> ArchiveFormat;

    /// Enumerate members. Must not modify the source and must not panic on
    /// malformed input — return [`EngineError`] or a best-effort partial list.
    fn entries(&self, source: &DataSource) -> Result<Vec<ArchiveEntry>, EngineError>;
}

/// Return the reader for a detected format.
pub fn reader_for(format: ArchiveFormat) -> Box<dyn ArchiveReader> {
    match format {
        ArchiveFormat::Raw => Box::new(RawReader),
        ArchiveFormat::Zip => Box::new(ZipReader),
        ArchiveFormat::Tar => Box::new(TarReader),
        ArchiveFormat::Iso9660 => Box::new(IsoReader),
        ArchiveFormat::Gzip => Box::new(GzipReader),
        ArchiveFormat::Sqlite => Box::new(SqliteReader),
        // 7z/RAR: signature-level analysis only (no member enumeration yet) —
        // no entries, like a stream format.
        ArchiveFormat::SevenZ
        | ArchiveFormat::Rar
        | ArchiveFormat::Pdf
        | ArchiveFormat::Bzip2
        | ArchiveFormat::Xz
        | ArchiveFormat::Zstd
        | ArchiveFormat::Lz4 => Box::new(RawReader),
    }
}
