//! Recoverability scoring (Module 5 heuristic, computed during analysis).

pub mod estimator;
pub mod weights;

pub use estimator::{estimate, Inputs};
