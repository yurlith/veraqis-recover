//! Stage 1 — Discovery. Open the target read-only and record its size.
//! Fails fast with [`EngineError::Io`] if the target cannot be opened.

use std::path::Path;

use crate::error::EngineError;
use crate::reader::DataSource;

/// Open `path` as a read-only [`DataSource`].
pub fn run(path: &Path) -> Result<DataSource, EngineError> {
    DataSource::open(path).map_err(|e| EngineError::io(path, e))
}
