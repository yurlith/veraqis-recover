//! Shared data model for the entire PHX platform.
//!
//! Every type here implements `Serialize`, `Clone` and `Debug` (the sole
//! exception is [`config::AnalysisConfig`], which holds runtime trait objects
//! and is therefore not serializable). Downstream crates — `phx_report`,
//! `phx_recovery`, `phx_protect`, `phx_oem` — consume these types and never
//! redefine them.

pub mod analysis_result;
pub mod config;
pub mod corruption;
pub mod evidence;
pub mod health;
pub mod integrity;
pub mod recoverability;

pub use analysis_result::{AnalysisResult, ArchiveFormat, EvidenceBreakdown, FileResult};
pub use config::{AnalysisConfig, DEFAULT_MAX_CORRUPTIONS};
pub use corruption::{ByteRange, Corruption, CorruptionCategory, CorruptionLocation, Severity};
pub use evidence::{
    ChainOfEvidence, Evidence, EvidenceType, MAX_EVIDENCE_BYTES, MIN_EMIT_CONFIDENCE,
};
pub use health::HealthScore;
pub use integrity::{BlockVerification, HashType, IntegrityResult, SignatureVerificationResult};
pub use recoverability::{RecoverabilityClass, RecoverabilityScore, RecoveryFactor};
