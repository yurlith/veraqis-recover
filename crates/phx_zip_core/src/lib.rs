//! # phx_zip_core
//!
//! The wasm32-eligible subset of `phx_recovery`'s ZIP evidence model: central-directory
//! scan, local-header walk, the OPC-recovery ZIP reader, and the verdict/provenance
//! types they share. Moved verbatim out of `phx_recovery` (no logic rewritten) so it can
//! be built for `wasm32-unknown-unknown` independently of the rest of the recovery
//! engine, which pulls in `reed-solomon-simd`, `ed25519-dalek`, `rand`, and other
//! dependencies that are not part of this evidence-only surface.
//!
//! `phx_recovery` re-exports most modules here at their original path
//! (`phx_recovery::cd_scan`, `phx_recovery::verdict`, …), so most downstream call
//! sites don't change. `opc_zip` is the one exception: it's used directly as
//! `phx_zip_core::opc_zip` rather than through any `phx_recovery` re-export, so
//! that one path is stable across every `phx_recovery` build configuration,
//! including ones that don't compile the modules that used to alias it.

pub mod android_backup_container;
pub mod cd_scan;
pub mod mobile_zip;
pub mod opc_zip;
pub mod verdict;
pub mod zip_container;
pub mod zip_index;
pub mod zip_offset_map;
pub mod zip_policy;

pub mod build;
