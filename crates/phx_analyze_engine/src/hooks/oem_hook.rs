//! OEM-hook trait. **Trait only** — this module must never import `phx_oem`.
//!
//! The engine exposes feature gating to the OEM layer (Module 7) through this
//! interface so that, e.g., `recovery_enabled = false` can be enforced without
//! the engine depending on `phx_oem`.

/// Minimal feature-gate surface the engine consults during analysis.
///
/// `phx_oem::OemConfig` implements this trait; the CLI registers it into
/// [`crate::model::config::AnalysisConfig::oem_hook`].
pub trait OemHook: Send + Sync {
    /// Whether a named feature flag is enabled. Unknown flags default to the
    /// `default_value` provided by the caller.
    fn feature_enabled(&self, flag: &str, default_value: bool) -> bool;

    /// Vendor/product name for branding the analysis warnings, if any.
    fn vendor_name(&self) -> Option<&str> {
        None
    }
}
