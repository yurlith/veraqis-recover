//! Error types for the analysis engine.

use std::path::PathBuf;

use thiserror::Error;

/// Errors produced anywhere in the analysis pipeline.
#[derive(Debug, Error)]
pub enum EngineError {
    /// Failed to open or read the target.
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The format could not be determined or parsed safely.
    #[error("format detection failed: {0}")]
    Format(String),

    /// An encrypted container was encountered (detected, not parsed).
    #[error("input is encrypted and cannot be analyzed: {0}")]
    Encrypted(String),

    /// A manifest file was found but could not be parsed.
    #[error("manifest parse error in {path}: {reason}")]
    Manifest { path: PathBuf, reason: String },

    /// A registered hook (Protection / OEM) reported a failure.
    #[error("hook error: {0}")]
    Hook(#[from] HookError),

    /// Catch-all for invariant violations that should never occur.
    #[error("internal invariant violated: {0}")]
    Internal(String),
}

impl EngineError {
    /// Build an [`EngineError::Io`] from a path and the underlying error.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        EngineError::Io {
            path: path.into(),
            source,
        }
    }
}

/// Error surfaced by a registered hook.
///
/// The hook traits live in the engine ("trait only — no phx_protect import"),
/// so they cannot reference `phx_protect::ProtectionError` directly. Hook
/// implementations map their own errors into this opaque type.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct HookError(pub String);

impl HookError {
    pub fn new(msg: impl Into<String>) -> Self {
        HookError(msg.into())
    }
}
