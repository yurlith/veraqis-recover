//! Raw byte-stream reader: a single opaque member covering the whole source.

use crate::error::EngineError;
use crate::model::ArchiveFormat;

use super::{ArchiveEntry, ArchiveReader, DataSource};

/// Reader for unstructured byte streams (the fallback format).
pub struct RawReader;

impl ArchiveReader for RawReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Raw
    }

    fn entries(&self, source: &DataSource) -> Result<Vec<ArchiveEntry>, EngineError> {
        // A raw stream has no internal members; represent it as one entry so
        // downstream code can treat all formats uniformly.
        Ok(vec![ArchiveEntry {
            path: source.path().to_path_buf(),
            size: source.len(),
            compressed_size: source.len(),
            offset: 0,
            encrypted: false,
            stored_crc32: None,
            is_link: false,
            link_target: None,
        }])
    }
}
