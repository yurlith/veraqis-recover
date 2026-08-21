//! Health-score model types (Module 2 output).

use serde::{Deserialize, Serialize};

/// Component and overall health, all integers in `0..=100`.
///
/// `overall` is derived from the three subscores via the Module 2 formula:
/// `overall = structural*0.4 + data*0.4 + metadata*0.2`, rounded to nearest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthScore {
    pub overall: u8,
    pub structural_health: u8,
    pub data_health: u8,
    pub metadata_health: u8,
}

impl HealthScore {
    /// A perfect score (no detected issues).
    pub fn perfect() -> Self {
        HealthScore {
            overall: 100,
            structural_health: 100,
            data_health: 100,
            metadata_health: 100,
        }
    }

    /// Compute `overall` from the three subscores using the Module 2 weights.
    ///
    /// Subscores are clamped to `0..=100` first; the weighted sum is rounded
    /// to the nearest integer and the overall floor is 0.
    pub fn from_subscores(structural: u8, data: u8, metadata: u8) -> Self {
        let structural = structural.min(100);
        let data = data.min(100);
        let metadata = metadata.min(100);
        let overall = (structural as f64 * 0.4 + data as f64 * 0.4 + metadata as f64 * 0.2)
            .round()
            .clamp(0.0, 100.0) as u8;
        HealthScore {
            overall,
            structural_health: structural,
            data_health: data,
            metadata_health: metadata,
        }
    }

    /// Human-readable interpretation band (Module 2 table).
    pub fn interpretation(&self) -> &'static str {
        match self.overall {
            100 => "Perfect",
            80..=99 => "Minor issues, fully usable",
            50..=79 => "Significant damage, partial loss",
            20..=49 => "Severe damage",
            _ => "Catastrophic",
        }
    }
}
