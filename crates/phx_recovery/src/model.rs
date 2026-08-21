//! Recovery data model: errors, the writable staging sink, and the report
//! types surfaced to callers and to `phx_report`.

use std::path::PathBuf;

use phx_analyze_engine::model::IntegrityResult;
use serde::Serialize;
use thiserror::Error;

/// Errors raised during recovery.
#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Output path equals the source path — forbidden invariant.
    #[error("recovery output path must differ from the source path")]
    OutputEqualsSource,

    /// No registered strategy could apply to the given analysis.
    #[error("no applicable recovery strategy for this damage")]
    NoApplicableStrategy,

    /// A strategy failed irrecoverably.
    #[error("strategy '{strategy}' failed: {reason}")]
    Strategy { strategy: String, reason: String },
}

impl RecoveryError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        RecoveryError::Io {
            path: path.into(),
            source,
        }
    }
}

/// A writable staging buffer. Recovery never writes directly to the final
/// destination: strategies fill a `DataSink`, the engine verifies it, then
/// commits it to the output path.
#[derive(Debug, Default)]
pub struct DataSink {
    buf: Vec<u8>,
}

impl DataSink {
    pub fn new() -> Self {
        DataSink { buf: Vec::new() }
    }

    /// Append bytes to the staging buffer.
    pub fn write(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes staged so far.
    pub fn len(&self) -> u64 {
        self.buf.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Borrow the staged bytes (used for verification before commit).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consume and return the staged bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Reset the staging buffer (used when a strategy is abandoned).
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

/// Serializable recovery summary.
///
/// A single `RecoveryReport` is produced by each strategy's `apply` and the
/// engine merges them into the final report it returns. This same type is
/// embedded in `phx_report::PlatformReport`. `RecoveryResult` is a type alias
/// kept for spec parity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryReport {
    pub success: bool,
    pub output_path: PathBuf,
    pub bytes_recovered: u64,
    pub bytes_lost: u64,
    pub files_recovered: Vec<PathBuf>,
    pub files_failed: Vec<PathBuf>,
    pub strategies_applied: Vec<String>,
    pub post_recovery_integrity: Option<IntegrityResult>,
    /// Overall health of the source before recovery (Phase 6 rollback gate).
    pub health_before: Option<u8>,
    /// Overall health of the committed output after recovery.
    pub health_after: Option<u8>,
    /// Strategies whose staged output was rolled back because it did not
    /// improve (or would regress) health — the "zero non-rolled-back health
    /// regressions" guarantee made auditable.
    pub rolled_back: Vec<String>,
    /// Path to the signed repair manifest sidecar, when one was written.
    pub manifest_path: Option<PathBuf>,
    pub warnings: Vec<String>,
}

/// Spec-named alias for [`RecoveryReport`]; the platform unifies the two.
pub type RecoveryResult = RecoveryReport;

impl RecoveryReport {
    /// An empty report for the given output path.
    pub fn empty(output_path: PathBuf) -> Self {
        RecoveryReport {
            success: false,
            output_path,
            bytes_recovered: 0,
            bytes_lost: 0,
            files_recovered: Vec::new(),
            files_failed: Vec::new(),
            strategies_applied: Vec::new(),
            post_recovery_integrity: None,
            health_before: None,
            health_after: None,
            rolled_back: Vec::new(),
            manifest_path: None,
            warnings: Vec::new(),
        }
    }

    /// Fold another strategy's report into this aggregate.
    pub fn merge(&mut self, other: RecoveryReport) {
        self.bytes_recovered = self.bytes_recovered.max(other.bytes_recovered);
        self.bytes_lost = other.bytes_lost;
        for f in other.files_recovered {
            if !self.files_recovered.contains(&f) {
                self.files_recovered.push(f);
            }
        }
        for f in other.files_failed {
            if !self.files_failed.contains(&f) {
                self.files_failed.push(f);
            }
        }
        self.strategies_applied.extend(other.strategies_applied);
        self.rolled_back.extend(other.rolled_back);
        if other.health_after.is_some() {
            self.health_after = other.health_after;
        }
        self.warnings.extend(other.warnings);
        self.success = self.success || other.success;
    }
}
