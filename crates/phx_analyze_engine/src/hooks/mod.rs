//! Upward-facing hook traits. Each submodule is **trait only**: the engine
//! never imports `phx_protect` or `phx_oem`. Implementations live in those
//! crates and are registered at runtime via `AnalysisConfig`.

mod oem_hook;
mod protection_hook;

pub use oem_hook::OemHook;
pub use protection_hook::ProtectionHook;
