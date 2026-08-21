//! Protection-hook trait. **Trait only** — this module must never import
//! `phx_protect`. The engine calls into Protection (Module 6) exclusively
//! through this interface, preserving the "lower layers never call upward"
//! rule.

use crate::error::HookError;
use crate::reader::DataSource;

/// Bridge from Analysis to Protection.
///
/// Registered via [`crate::model::config::AnalysisConfig::protection_hook`].
/// When present, the integrity stage calls [`ProtectionHook::verify_signature`]
/// and the discovery stage may call [`ProtectionHook::pre_scan`].
pub trait ProtectionHook: Send + Sync {
    /// Run any pre-analysis check Protection requires on the raw source.
    fn pre_scan(&self, source: &DataSource) -> Result<(), HookError>;

    /// Verify an embedded signature over `data`. Returns `true` if valid.
    fn verify_signature(&self, data: &[u8]) -> Result<bool, HookError>;

    /// Optional algorithm label used to enrich the integrity result.
    /// Defaults to `"unknown"`.
    fn signature_algorithm(&self) -> &str {
        "unknown"
    }

    /// Optional key fingerprint (never raw key material) for the report.
    fn key_id(&self) -> Option<String> {
        None
    }
}
