//! # phx_recovery — open structural recovery core
//!
//! Data reconstruction and repair for damaged ZIP, gzip, tar, RAR5, and 7z
//! containers. Consumes an
//! [`AnalysisResult`](phx_analyze_engine::model::AnalysisResult), selects
//! applicable strategies, and produces a verified [`RecoveryReport`].
//!
//! Recovery **always** writes to a separate output path and never modifies the
//! source. It must not be invoked before analysis completes.
//!
//! This is the open subset of a larger engine: base structural repair only,
//! independently CRC/SHA-verified against surviving bytes. It never invents
//! data — an unrecoverable region is reported as such, never guessed at.

pub mod crc;
pub mod engine;
pub mod evidence;
pub mod manifest;
pub mod model;
pub mod plan;
pub mod rar;
pub mod resync;
pub mod sevenz;
pub mod strategies;

// Re-exported from `phx_zip_core` (evidence-only ZIP core) at the original
// paths — no logic changed, no call site needed to change.
pub use phx_zip_core::{
    android_backup_container, cd_scan, mobile_zip, verdict, zip_container, zip_index,
    zip_offset_map, zip_policy,
};

pub use crc::catalog::{CRC32_BZIP2, CRC32_ISO_HDLC, CRC64_XZ};
pub use crc::CrcParams;
pub use evidence::{Axis, EvidenceClass, EvidenceError, EvidenceRecord, SolvedAgainst, Verifier};

pub use engine::{RecoveryEngine, RecoveryOptions};
pub use manifest::{Guarantee, GuaranteeTriad, RepairManifest, RepairRecord};
pub use model::{DataSink, RecoveryError, RecoveryReport, RecoveryResult};
pub use plan::{RepairPlan, RepairRisk};
pub use sevenz::{repair_signature as sevenz_repair_signature, Inspect as SevenZInspect};
pub use strategies::{all_strategies, strategy_by_name, RecoveryStrategy};
