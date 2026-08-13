//! Health engine: bounded history + EWMA aggregates.

use kvn_core::health::{FailureCategory, HealthHistory, HealthSample};

#[test]
fn history_is_bounded() {
    let mut h = HealthHistory::new(3, 0.5);
    for ts in 0..10 {
        h.record(HealthSample::reachable(ts, 50.0));
    }
    assert_eq!(
        h.snapshot().sample_count,
        3,
        "history must not grow unbounded"
    );
}

#[test]
fn ewma_smooths_latency() {
    let mut h = HealthHistory::new(16, 0.5);
    h.record(HealthSample::reachable(0, 100.0));
    assert_eq!(h.snapshot().ewma_latency_ms, Some(100.0)); // seeded by first
    h.record(HealthSample::reachable(1, 200.0));
    // 0.5*200 + 0.5*100 = 150
    assert_eq!(h.snapshot().ewma_latency_ms, Some(150.0));
}

#[test]
fn availability_and_failures_are_tracked() {
    let mut h = HealthHistory::new(16, 0.3);
    h.record(HealthSample::reachable(0, 40.0));
    h.record(HealthSample::unreachable(1, FailureCategory::Timeout));
    h.record(HealthSample::unreachable(2, FailureCategory::Network));

    let snap = h.snapshot();
    assert_eq!(snap.sample_count, 3);
    assert_eq!(snap.recent_failures, 2);
    assert_eq!(snap.consecutive_failures, 2);
    assert!(!snap.reachable);
    assert!((snap.availability_ratio - (1.0 / 3.0)).abs() < 1e-9);

    // A success resets the consecutive-failure streak.
    h.record(HealthSample::reachable(3, 30.0));
    assert_eq!(h.snapshot().consecutive_failures, 0);
    assert!(h.snapshot().reachable);
}

#[test]
fn snapshot_age_is_relative_to_now() {
    let mut h = HealthHistory::new(4, 0.3);
    h.record(HealthSample::reachable(1_000, 40.0));
    assert_eq!(h.snapshot().age_ms(6_000), Some(5_000));
    // Clock skew saturates at 0 rather than underflowing.
    assert_eq!(h.snapshot().age_ms(500), Some(0));
}
