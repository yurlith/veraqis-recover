//! [`DataSource`] — the single read-only abstraction over the bytes being
//! analyzed. Backed by either a file on disk or an in-memory buffer (used by
//! tests and by per-file archive analysis).
//!
//! Read-only by contract: there is no method that writes back to the source.

use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Default streaming buffer size (64 KiB), per the single-pass I/O rule.
pub const STREAM_BUFFER_BYTES: usize = 64 * 1024;

/// A read-only, seekable source of bytes with a known length.
pub struct DataSource {
    path: PathBuf,
    backing: Backing,
    len: u64,
}

enum Backing {
    /// On-disk file. Each `stream`/`read_at` opens its own handle so callers
    /// never interfere with one another's cursor.
    File,
    /// In-memory bytes (tests, archive members).
    Memory(Vec<u8>),
}

impl DataSource {
    /// Open a file read-only and record its length.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let meta = std::fs::metadata(&path)?;
        Ok(DataSource {
            path,
            backing: Backing::File,
            len: meta.len(),
        })
    }

    /// Build an in-memory source. `name` is a logical label only.
    pub fn from_bytes(name: impl Into<PathBuf>, bytes: Vec<u8>) -> Self {
        let len = bytes.len() as u64;
        DataSource {
            path: name.into(),
            backing: Backing::Memory(bytes),
            len,
        }
    }

    /// Logical path / name of the source.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Total length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the source is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Open a buffered streaming reader positioned at offset 0.
    ///
    /// Always a fresh stream — safe to call repeatedly. This is the entry
    /// point the integrity hasher uses for its single forward pass.
    pub fn stream(&self) -> io::Result<BufReader<Box<dyn Read + Send>>> {
        let inner: Box<dyn Read + Send> = match &self.backing {
            Backing::File => Box::new(File::open(&self.path)?),
            // Clone is unavoidable for an owned Read; memory sources are small
            // (tests / archive members), so this is acceptable.
            Backing::Memory(bytes) => Box::new(Cursor::new(bytes.clone())),
        };
        Ok(BufReader::with_capacity(STREAM_BUFFER_BYTES, inner))
    }

    /// Read up to `buf.len()` bytes starting at absolute `offset`.
    ///
    /// Returns the number of bytes actually read (may be short near EOF).
    /// Used by format detection (magic bytes) and corruption probing.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        match &self.backing {
            Backing::File => {
                let mut f = File::open(&self.path)?;
                f.seek(SeekFrom::Start(offset))?;
                read_up_to(&mut f, buf)
            }
            Backing::Memory(bytes) => {
                let start = offset as usize;
                let avail = &bytes[start..];
                let n = avail.len().min(buf.len());
                buf[..n].copy_from_slice(&avail[..n]);
                Ok(n)
            }
        }
    }

    /// Read an exact-length region, erroring on short reads. Convenience over
    /// [`DataSource::read_at`] for fixed-size structures (e.g. ZIP EOCD).
    pub fn read_exact_at(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.read_at(offset, &mut buf)?;
        if n < len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("wanted {len} bytes at offset {offset}, got {n}"),
            ));
        }
        Ok(buf)
    }
}

/// Read into `buf` until it is full or EOF, tolerating partial reads.
fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_source_reports_len_and_reads_at_offset() {
        let src = DataSource::from_bytes("mem", (0u8..=255).collect());
        assert_eq!(src.len(), 256);
        let mut buf = [0u8; 4];
        let n = src.read_at(10, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [10, 11, 12, 13]);
    }

    #[test]
    fn read_at_past_eof_returns_zero() {
        let src = DataSource::from_bytes("mem", vec![1, 2, 3]);
        let mut buf = [0u8; 4];
        assert_eq!(src.read_at(100, &mut buf).unwrap(), 0);
    }

    #[test]
    fn read_exact_at_short_read_errors() {
        let src = DataSource::from_bytes("mem", vec![1, 2, 3]);
        assert!(src.read_exact_at(0, 8).is_err());
    }

    #[test]
    fn stream_reads_full_contents() {
        let data: Vec<u8> = (0u8..100).collect();
        let src = DataSource::from_bytes("mem", data.clone());
        let mut out = Vec::new();
        src.stream().unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }
}
