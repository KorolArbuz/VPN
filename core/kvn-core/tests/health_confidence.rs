//! Health confidence / incomplete-telemetry hardening.
//!
//! A candidate with one excellent metric but no other telemetry must not
//! outscore a candidate with slightly worse but complete, trustworthy metrics.

mod common;

use common::*;
use kvn_core::health::HealthSample;
use kvn_core::model::CandidateState;
use kvn_core::selector::SelectionReason;
use kvn_core::KvnCore;

const NOW: u64 = 100_000;

fn full_sample(ts: u64, latency: f64) -> HealthSample {
    let mut s = HealthSample::reachable(ts, latency);
    s.jitter_ms = Some(8.0);
    s.packet_loss_percent = Some(0.5);
    s.handshake_ms = Some(120.0);
    s.download_bps = Some(40_000_000.0);
    s
}

// A) Excellent latency but almost no other telemetry -> low confidence, and a
//    score that is not unrealistically high.
#[test]
fn sparse_telemetry_is_not_overconfident() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "sparse");
    // One reachable sample carrying ONLY latency.
    core.update_health(&cid("sparse"), HealthSample::reachable(NOW, 10.0))
        .unwrap();

    let b = core.score(&cid("sparse"), NOW).unwrap();
    // Latency is excellent but confidence is low (only latency + a single-sample
    // reliability fraction back the score).
    assert!(b.confidence < 0.5, "confidence={}", b.confidence);
    // The total must not approach a "perfect" score on one metric alone.
    assert!(b.total < 55.0, "total={}", b.total);
    // Still selectable — sparse telemetry does not exclude a candidate.
    assert_eq!(
        core.candidate_state(&cid("sparse"), NOW),
        Some(CandidateState::Healthy)
    );
}

// B) A candidate with slightly worse latency but complete, reliable telemetry
//    beats the sparse-but-fast one.
#[test]
fn complete_telemetry_beats_sparse_fast() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "sparse_fast");
    register_simple(&mut core, "complete");

    core.update_health(&cid("sparse_fast"), HealthSample::reachable(NOW, 10.0))
        .unwrap();
    // Complete candidate: worse latency, but full metrics over enough history.
    for ts in [NOW - 2, NOW - 1, NOW] {
        core.update_health(&cid("complete"), full_sample(ts, 60.0))
            .unwrap();
    }

    let sparse = core.score(&cid("sparse_fast"), NOW).unwrap();
    let complete = core.score(&cid("complete"), NOW).unwrap();
    assert!(complete.confidence > sparse.confidence);
    assert!(
        complete.total > sparse.total,
        "complete={} sparse={}",
        complete.total,
        sparse.total
    );

    assert_eq!(core.select_best(NOW).selected, Some(cid("complete")));
}

// C) Cold start: a brand-new candidate with a single reachable sample is
//    immediately selectable and chosen when it is the only option.
#[test]
fn new_candidate_cold_start_is_selectable() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "newbie");
    core.update_health(&cid("newbie"), HealthSample::reachable(NOW, 45.0))
        .unwrap();

    assert_eq!(
        core.candidate_state(&cid("newbie"), NOW),
        Some(CandidateState::Healthy)
    );
    let decision = core.select_best(NOW);
    assert_eq!(decision.selected, Some(cid("newbie")));
    assert_eq!(decision.reason, SelectionReason::InitialSelection);

    // Confidence starts low and grows as history accumulates.
    let cold = core.score(&cid("newbie"), NOW).unwrap().confidence;
    for ts in 1..6 {
        core.update_health(&cid("newbie"), full_sample(NOW + ts, 45.0))
            .unwrap();
    }
    let warm = core.score(&cid("newbie"), NOW + 6).unwrap().confidence;
    assert!(warm > cold, "warm={warm} cold={cold}");
}
