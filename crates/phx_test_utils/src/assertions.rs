//! Shared assertion helpers for invariants the platform must always uphold.

use phx_analyze_engine::model::{AnalysisResult, HealthScore, RecoverabilityScore};

/// Assert the documented invariants on a [`HealthScore`].
pub fn assert_health_invariants(h: &HealthScore) {
    assert!(h.overall <= 100, "overall {} > 100", h.overall);
    assert!(h.structural_health <= 100);
    assert!(h.data_health <= 100);
    assert!(h.metadata_health <= 100);
}

/// Assert the documented invariants on a [`RecoverabilityScore`].
pub fn assert_recoverability_invariants(r: &RecoverabilityScore) {
    assert!(
        (0.0..=1.0).contains(&r.probability),
        "probability {} out of range",
        r.probability
    );
    assert!(
        (0.0..=1.0).contains(&r.confidence),
        "confidence {} out of range",
        r.confidence
    );
}

/// Assert every invariant on a full [`AnalysisResult`], including byte-range
/// ordering and per-file scores.
pub fn assert_result_invariants(result: &AnalysisResult) {
    assert_health_invariants(&result.health_score);
    assert_recoverability_invariants(&result.recoverability_score);
    for c in &result.corruptions {
        assert!(
            c.location.offset_end >= c.location.offset_start,
            "corruption offset_end < offset_start"
        );
    }
    for f in &result.per_file_results {
        assert_health_invariants(&f.health_score);
        assert_recoverability_invariants(&f.recoverability_score);
    }
}
