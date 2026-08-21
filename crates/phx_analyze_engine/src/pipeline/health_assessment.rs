//! Stage 5 — Health assessment. Thin wrapper over [`crate::health::score`].

use crate::health;
use crate::model::{Corruption, HealthScore};

/// Score health from the container's corruptions.
pub fn run(corruptions: &[Corruption]) -> HealthScore {
    health::score(corruptions)
}
