//! # phx_zip_core
//!
//! The wasm32-eligible subset of `phx_recovery`'s ZIP evidence model: central-directory
//! scan, local-header walk, the OPC-recovery ZIP reader, and the verdict/provenance
//! types they share. Moved verbatim out of `phx_recovery` (no logic rewritten) so it can
//! be built for `wasm32-unknown-unknown` independently of the rest of the recovery
//! engine, which pulls in `reed-solomon-simd`, `ed25519-dalek`, `rand`, and other
//! dependencies that are not part of this evidence-only surface.
//!
//! `phx_recovery` re-exports every module here at its original path
//! (`phx_recovery::cd_scan`, `phx_recovery::verdict`, `phx_recovery::semantic::opc::zip`,
//! …), so no downstream call site changes. See `docs/web-studio/WASM_FEASIBILITY.md`,
//! Phase G / G0.

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
