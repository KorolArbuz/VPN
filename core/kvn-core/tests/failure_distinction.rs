//! Regression: a failed health probe is passive telemetry and must NOT trip
//! the backend connection circuit breaker unless a policy explicitly opts in.
//! Only `report_connection_failure` (an actual VPN/backend failure) does.

mod common;

use common::*;
use kvn_core::health::{FailureCategory, HealthSample};
use kvn_core::model::CandidateState;
use kvn_core::KvnCore;

// Default policy: many unreachable health probes never trip the breaker.
#[test]
fn health_probe_failures_do_not_trip_backend_breaker_by_default() {
    let mut core = KvnCore::default(); // failure_threshold = 3

    register_simple(&mut core, "probe");
    // Far more unreachable probes than the breaker's failure threshold.
    for ts in 0..10 {
        core.update_health(
            &cid("probe"),
            HealthSample::unreachable(ts, FailureCategory::Timeout),
        )
        .unwrap();
    }

    // The candidate is Unavailable because its last probe was unreachable — but
    // NOT in Cooldown, because the backend breaker was never fed.
    assert_eq!(
        core.candidate_state(&cid("probe"), 1_000),
        Some(CandidateState::Unavailable)
    );

    // A single reachable probe restores it immediately: no breaker cooldown is
    // holding it down.
    feed(&mut core, "probe", 2_000, 40.0, 0.0);
    assert_ne!(
        core.candidate_state(&cid("probe"), 2_000),
        Some(CandidateState::Cooldown)
    );
    assert_eq!(core.select_best(2_000).selected, Some(cid("probe")));

    // Contrast: explicit backend failures DO trip the breaker into cooldown.
    register_simple(&mut core, "backend");
    feed(&mut core, "backend", 0, 40.0, 0.0);
    for _ in 0..3 {
        core.report_connection_failure(&cid("backend"), 0).unwrap();
    }
    assert_eq!(
        core.candidate_state(&cid("backend"), 1_000),
        Some(CandidateState::Cooldown)
    );
}

// Opt-in policy: health failures may be configured to feed the breaker.
#[test]
fn health_probe_failures_trip_breaker_when_opted_in() {
    let mut config = kvn_core::CoreConfiguration::default();
    config.circuit_breaker.health_failures_trip_breaker = true;
    let mut core = KvnCore::new(config);

    register_simple(&mut core, "probe");
    for ts in 0..3 {
        core.update_health(
            &cid("probe"),
            HealthSample::unreachable(ts, FailureCategory::Timeout),
        )
        .unwrap();
    }

    // With the opt-in flag, the breaker is now tripped into cooldown.
    assert_eq!(
        core.candidate_state(&cid("probe"), 1_000),
        Some(CandidateState::Cooldown)
    );
}
