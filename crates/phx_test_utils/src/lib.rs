//! Shared test helpers for the PHX workspace. **Dev-dependency only** — never
//! depend on this crate outside `[dev-dependencies]`.

pub mod assertions;
pub mod corpus;
mod corpus_generator;
pub mod fixtures;
pub mod generators;

pub use assertions::{
    assert_health_invariants, assert_recoverability_invariants, assert_result_invariants,
};
pub use corpus::{
    CleanFile, CorpusEntry, CorpusIndex, ExpectedCorruption, FormatMetadata, FormatSummary,
    GroundTruth, SplitMix64,
};
pub use fixtures::TempDir;
