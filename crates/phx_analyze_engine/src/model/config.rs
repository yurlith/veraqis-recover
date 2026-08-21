//! Analysis configuration.
//!
//! `AnalysisConfig` is *not* serializable: it carries runtime hook handles
//! (Protection, OEM) as trait objects. The serializable, auditable output is
//! [`super::analysis_result::AnalysisResult`].

use std::fmt;
use std::sync::Arc;

use crate::hooks::{OemHook, ProtectionHook};

use super::integrity::HashType;

/// Default cap on reported corruptions before the scan stops and warns.
pub const DEFAULT_MAX_CORRUPTIONS: usize = 1_000;

/// Tuning knobs for a single analysis run.
#[derive(Clone)]
pub struct AnalysisConfig {
    /// Hash algorithm for the integrity scan.
    pub hash_type: HashType,

    /// If set, per-block hashes of this size (bytes) are computed in the same
    /// single pass as the global hash.
    pub block_size_bytes: Option<u64>,

    /// Verify embedded checksums (e.g. ZIP CRC-32) when available.
    pub verify_embedded_checksums: bool,

    /// Stop the corruption scan after this many findings; emit a warning.
    pub max_corruptions_reported: usize,

    /// Treat any detected corruption as a hard failure for exit-code purposes.
    pub strict: bool,

    /// Reserved extension point. **Ignored in V1** (single-threaded).
    pub parallelism: usize,

    /// Optional known-good reference file. When set, the engine additionally
    /// diffs the target against it to pinpoint truncation/bitflip/missing-data
    /// corruptions (reference-diff detection).
    pub reference: Option<std::path::PathBuf>,

    /// Optional bridge to Protection (Module 6). Trait object — the engine
    /// never imports `phx_protect`.
    pub protection_hook: Option<Arc<dyn ProtectionHook>>,

    /// Optional bridge to OEM feature gating (Module 7).
    pub oem_hook: Option<Arc<dyn OemHook>>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        AnalysisConfig {
            hash_type: HashType::default(),
            block_size_bytes: None,
            verify_embedded_checksums: true,
            max_corruptions_reported: DEFAULT_MAX_CORRUPTIONS,
            strict: false,
            parallelism: 1,
            reference: None,
            protection_hook: None,
            oem_hook: None,
        }
    }
}

impl AnalysisConfig {
    /// Builder-style override of the hash algorithm.
    pub fn with_hash(mut self, hash_type: HashType) -> Self {
        self.hash_type = hash_type;
        self
    }

    /// Builder-style override of the block size.
    pub fn with_block_size(mut self, block_size_bytes: u64) -> Self {
        self.block_size_bytes = Some(block_size_bytes);
        self
    }

    /// Consult the OEM hook for a feature flag, falling back to `default`
    /// when no hook is registered.
    pub fn feature_enabled(&self, flag: &str, default: bool) -> bool {
        match &self.oem_hook {
            Some(hook) => hook.feature_enabled(flag, default),
            None => default,
        }
    }
}

impl fmt::Debug for AnalysisConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnalysisConfig")
            .field("hash_type", &self.hash_type)
            .field("block_size_bytes", &self.block_size_bytes)
            .field("verify_embedded_checksums", &self.verify_embedded_checksums)
            .field("max_corruptions_reported", &self.max_corruptions_reported)
            .field("strict", &self.strict)
            .field("parallelism", &self.parallelism)
            .field("reference", &self.reference)
            .field("protection_hook", &self.protection_hook.is_some())
            .field("oem_hook", &self.oem_hook.is_some())
            .finish()
    }
}
