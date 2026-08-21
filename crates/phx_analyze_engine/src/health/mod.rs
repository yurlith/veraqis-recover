//! Module 2 — Health Assessment. See [`scorer`] for the formula and routing.

pub mod scorer;
pub mod weights;

pub use scorer::score;
pub use weights::{penalty_for, RulePenalty};
