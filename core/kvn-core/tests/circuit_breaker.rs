//! Circuit breaker / cooldown behavior (spec tests 9, 10).

mod common;

use common::*;
use kvn_core::model::CandidateState;
use kvn_core::selector::SelectionReason;
use kvn_core::KvnCore;

// 9. Reaching the failure threshold trips the breaker into cooldown.
#[test]
fn failure_threshold_triggers_cooldown() {
    let mut core = KvnCore::default(); // failure_threshold = 3, cooldown = 30s
    register_simple(&mut core, "a");
    feed(&mut core, "a", 0, 40.0, 0.0);
    assert_eq!(
        core.candidate_state(&cid("a"), 0),
        Some(CandidateState::Healthy)
    );

    for _ in 0..3 {
        core.report_connection_failure(&cid("a"), 0).unwrap();
    }

    // During cooldown the candidate is unavailable for selection.
    assert_eq!(
        core.candidate_state(&cid("a"), 1_000),
        Some(CandidateState::Cooldown)
    );
    let decision = core.select_best(1_000);
    assert_eq!(decision.selected, None);
    assert_eq!(decision.reason, SelectionReason::NoHealthyCandidates);
}

// 10. After cooldown, recovery probes restore the candidate.
#[test]
fn candidate_recovers_after_cooldown() {
    let mut core = KvnCore::default(); // recovery_threshold = 2, cooldown = 30s
    register_simple(&mut core, "a");
    feed(&mut core, "a", 0, 40.0, 0.0);
    for _ in 0..3 {
        core.report_connection_failure(&cid("a"), 0).unwrap();
    }
    assert_eq!(
        core.candidate_state(&cid("a"), 1_000),
        Some(CandidateState::Cooldown)
    );

    // Before the cooldown elapses, a success does not recover it.
    core.report_connection_success(&cid("a"), 10_000).unwrap();
    assert_eq!(
        core.candidate_state(&cid("a"), 10_000),
        Some(CandidateState::Cooldown)
    );

    // After cooldown, two successful probes fully recover it.
    let after = 40_000;
    core.report_connection_success(&cid("a"), after).unwrap();
    core.report_connection_success(&cid("a"), after).unwrap();
    feed(&mut core, "a", after, 40.0, 0.0);
    assert_eq!(
        core.candidate_state(&cid("a"), after),
        Some(CandidateState::Healthy)
    );
    assert_eq!(core.select_best(after).selected, Some(cid("a")));
}
