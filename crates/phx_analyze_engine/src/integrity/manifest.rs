//! coreutils-compatible hash manifest parsing.
//!
//! A manifest is a `.sha256` or `.sha3_512` file listing `hash  name` pairs.
//! Names are relative to the manifest's own location. UTF-8 without BOM; empty
//! lines are ignored; one or two spaces (optionally `*` for binary mode)
//! separate the hash from the name.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::EngineError;
use crate::model::HashType;

/// Parsed manifest: a map of relative name → expected hex hash.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub path: PathBuf,
    entries: HashMap<String, String>,
}

impl Manifest {
    /// Parse manifest text. Malformed lines are skipped silently except that a
    /// completely unparseable file yields an empty manifest (not an error).
    pub fn parse(path: impl Into<PathBuf>, text: &str) -> Self {
        let mut entries = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((hash, name)) = split_entry(line) {
                entries.insert(name, hash);
            }
        }
        Manifest {
            path: path.into(),
            entries,
        }
    }

    /// Load and parse a manifest from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, EngineError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|e| EngineError::Manifest {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        Ok(Manifest::parse(path.to_path_buf(), &text))
    }

    /// Look up the expected hash for a name relative to the manifest.
    pub fn lookup(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(String::as_str)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the manifest has no usable entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Split a manifest line into `(hash, name)`. Returns `None` if it has no name.
fn split_entry(line: &str) -> Option<(String, String)> {
    let mut parts = line.splitn(2, char::is_whitespace);
    let hash = parts.next()?.to_ascii_lowercase();
    let rest = parts.next()?.trim_start();
    // coreutils binary-mode marker.
    let name = rest.strip_prefix('*').unwrap_or(rest);
    if hash.is_empty() || name.is_empty() {
        return None;
    }
    Some((hash, name.to_string()))
}

/// Find the sidecar manifest for `target`, if present. Looks for
/// `target.<ext>` where `<ext>` matches the hash type (e.g. `archive.zip` →
/// `archive.zip.sha256`).
pub fn find_sidecar(target: &Path, hash_type: HashType) -> Option<PathBuf> {
    let mut name = target.as_os_str().to_os_string();
    name.push(".");
    name.push(hash_type.manifest_extension());
    let candidate = PathBuf::from(name);
    candidate.exists().then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_double_space_and_binary_marker() {
        let text = "a1b2  file.dat\nd4e5 *bin.dat\n\n  \nzz99  sub/x.bin\n";
        let m = Manifest::parse("m.sha256", text);
        assert_eq!(m.len(), 3);
        assert_eq!(m.lookup("file.dat"), Some("a1b2"));
        assert_eq!(m.lookup("bin.dat"), Some("d4e5"));
        assert_eq!(m.lookup("sub/x.bin"), Some("zz99"));
    }

    #[test]
    fn lowercases_hashes() {
        let m = Manifest::parse("m.sha256", "ABCDEF  f");
        assert_eq!(m.lookup("f"), Some("abcdef"));
    }

    #[test]
    fn missing_name_is_skipped() {
        let m = Manifest::parse("m.sha256", "deadbeef\n");
        assert!(m.is_empty());
    }
}
