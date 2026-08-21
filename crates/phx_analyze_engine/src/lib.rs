//! # phx_analyze_engine — Modules 1, 2, 3
//!
//! Analysis, Health Assessment and Integrity Verification for the PHX
//! platform. This crate is the foundation of the stack: it defines the shared
//! data model ([`model`]) consumed by every other crate and performs read-only
//! analysis of archives and file containers.
//!
//! ## Layer boundaries (never violate)
//!
//! - No `clap`, no stdout writes — only `tracing` logging.
//! - The reader layer is read-only and never modifies data.
//! - The integrity layer reports match/mismatch only.
//! - The corruption layer classifies only; it does not score health.
//! - The health layer consumes corruption + integrity.
//! - The recoverability layer consumes health + damage (no repair).
//! - Reporting/serialization lives in `phx_report`, not here.
//! - Protection (Module 6) is reached only through [`hooks::ProtectionHook`].
//!
//! ## Example
//!
//! ```no_run
//! use phx_analyze_engine::{Engine, model::AnalysisConfig};
//! use std::path::Path;
//!
//! let engine = Engine::new();
//! let result = engine.analyze(Path::new("archive.zip"), AnalysisConfig::default())?;
//! println!("health = {}", result.health_score.overall);
//! # Ok::<(), phx_analyze_engine::EngineError>(())
//! ```

pub mod corruption;
pub mod engine;
pub mod error;
pub mod health;
pub mod hooks;
pub mod integrity;
pub mod model;
pub mod pipeline;
pub mod reader;
pub mod recoverability;

pub use engine::Engine;
pub use error::{EngineError, HookError};

// Re-export the most commonly used model types at the crate root for ergonomic
// downstream use (`phx_analyze_engine::AnalysisResult`, etc.).
pub use model::{
    AnalysisConfig, AnalysisResult, ArchiveFormat, BlockVerification, ByteRange, ChainOfEvidence,
    Corruption, CorruptionCategory, CorruptionLocation, Evidence, EvidenceType, FileResult,
    HashType, HealthScore, IntegrityResult, RecoverabilityScore, RecoveryFactor, Severity,
    SignatureVerificationResult,
};
