//! Filesystem fixtures: temporary files and sidecar manifests for end-to-end
//! tests that need a real path on disk.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// A self-deleting temporary directory under the system temp dir.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a uniquely named temp directory.
    pub fn new(tag: &str) -> std::io::Result<Self> {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "phx-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(unique);
        std::fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write `bytes` to `name` inside the temp dir and return its path.
    pub fn write_file(&self, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
        let p = self.path.join(name);
        std::fs::write(&p, bytes)?;
        Ok(p)
    }

    /// Write a coreutils-style `.sha256` sidecar manifest for `target` that
    /// records the real SHA-256 of `bytes`.
    pub fn write_sha256_manifest(&self, target: &Path, bytes: &[u8]) -> std::io::Result<PathBuf> {
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let digest = Sha256::digest(bytes);
        let hex = to_hex(&digest);
        let manifest = format!("{hex}  {name}\n");

        let mut manifest_path = target.as_os_str().to_os_string();
        manifest_path.push(".sha256");
        let manifest_path = PathBuf::from(manifest_path);
        std::fs::write(&manifest_path, manifest)?;
        Ok(manifest_path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
