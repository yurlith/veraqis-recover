//! The sequential analysis pipeline.
//!
//! ```text
//! [Discovery] → [Format Detection] → [Integrity Scan] → [Corruption Scan]
//!                                                              │
//!                                        [Health Assessment] ◄┘
//!                                                │
//!                                        [Recoverability Scoring]
//!                                                │
//!                                        [Report Assembly] → AnalysisResult
//! ```
//!
//! Stages are sequential, single-threaded and deterministic. Each stage lives
//! in its own module; orchestration happens in [`crate::engine`].

pub mod corruption_scan;
pub mod discovery;
pub mod format_detection;
pub mod health_assessment;
pub mod integrity_scan;
pub mod recoverability_scoring;
pub mod report_assembly;
