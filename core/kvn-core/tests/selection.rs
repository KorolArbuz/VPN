//! Selection / anti-flapping behavior (spec tests 1, 2, 4, 5, 6, 7, 8).

mod common;

use common::*;
use kvn_core::backend::BackendCapabilities;
use kvn_core::model::{BackendKind, ProtocolKind};
use kvn_core::selector::SelectionReason;
use kvn_core::KvnCore;

const NOW: u64 = 100_000;

// 1. A single healthy candidate is selected.
#[test]
fn single_healthy_candidate_is_selected() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "a");
    feed(&mut core, "a", NOW, 40.0, 0.0);

    let decision = core.select_best(NOW);
    assert_eq!(decision.selected, Some(cid("a")));
    assert!(decision.should_switch);
    assert_eq!(decision.reason, SelectionReason::InitialSelection);
}

// 2. The better of two candidates is selected.
#[test]
fn best_of_two_is_selected() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "slow");
    register_simple(&mut core, "fast");
    feed(&mut core, "slow", NOW, 300.0, 0.0);
    feed(&mut core, "fast", NOW, 20.0, 0.0);

    let decision = core.select_best(NOW);
    assert_eq!(decision.selected, Some(cid("fast")));
}

// 4. A small improvement does not trigger a switch.
#[test]
fn small_improvement_does_not_switch() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "current");
    register_simple(&mut core, "other");
    // Current selected long ago so hold/cooldown are satisfied.
    core.set_current_candidate(Some(cid("current")), 0).unwrap();
    feed(&mut core, "current", NOW, 150.0, 0.0);
    feed(&mut core, "other", NOW, 120.0, 0.0); // only ~2 points better

    let decision = core.select_best(NOW);
    assert!(!decision.should_switch);
    assert_eq!(decision.reason, SelectionReason::NoChange);
    let improvement = decision.selected_score.unwrap() - decision.current_score.unwrap();
    assert!(improvement < 8.0, "improvement was {improvement}");
}

// 5. A significant improvement produces a switch recommendation.
#[test]
fn significant_improvement_recommends_switch() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "current");
    register_simple(&mut core, "other");
    core.set_current_candidate(Some(cid("current")), 0).unwrap();
    feed(&mut core, "current", NOW, 450.0, 0.0);
    feed(&mut core, "other", NOW, 20.0, 0.0);

    let decision = core.select_best(NOW);
    assert!(decision.should_switch);
    assert_eq!(decision.selected, Some(cid("other")));
    assert_eq!(decision.reason, SelectionReason::SignificantlyBetter);
}

// 6. An unreachable candidate is not selected.
#[test]
fn unreachable_is_not_selected() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "reachable");
    register_simple(&mut core, "down");
    feed(&mut core, "reachable", NOW, 80.0, 0.0);
    core.update_health(
        &cid("down"),
        kvn_core::health::HealthSample::unreachable(
            NOW,
            kvn_core::health::FailureCategory::Timeout,
        ),
    )
    .unwrap();

    let decision = core.select_best(NOW);
    assert_eq!(decision.selected, Some(cid("reachable")));

    // With only the unreachable candidate, nothing is selectable.
    core.remove_candidate(&cid("reachable")).unwrap();
    let decision = core.select_best(NOW);
    assert_eq!(decision.selected, None);
    assert_eq!(decision.reason, SelectionReason::NoHealthyCandidates);
}

// 7. A disabled candidate is not selected.
#[test]
fn disabled_is_not_selected() {
    let mut core = KvnCore::default();
    register(
        &mut core,
        "on",
        ProtocolKind::Vless,
        BackendKind::Xray,
        0,
        true,
    );
    register(
        &mut core,
        "off",
        ProtocolKind::Vless,
        BackendKind::Xray,
        100,
        false,
    );
    feed(&mut core, "on", NOW, 100.0, 0.0);
    feed(&mut core, "off", NOW, 1.0, 0.0); // great metrics but disabled

    let decision = core.select_best(NOW);
    assert_eq!(decision.selected, Some(cid("on")));
}

// 8. A candidate whose backend cannot carry its protocol is not selected.
#[test]
fn incompatible_backend_is_not_selected() {
    let mut core = KvnCore::default();
    // Xray only advertises vless support.
    core.set_backend_capabilities(
        BackendKind::Xray,
        BackendCapabilities::new(vec![ProtocolKind::Vless]),
    );
    core.set_backend_capabilities(
        BackendKind::Wireguard,
        BackendCapabilities::new(vec![ProtocolKind::Wireguard]),
    );

    // wireguard-on-xray is incompatible; vless-on-xray is fine.
    register(
        &mut core,
        "ok",
        ProtocolKind::Vless,
        BackendKind::Xray,
        0,
        true,
    );
    register(
        &mut core,
        "bad",
        ProtocolKind::Wireguard,
        BackendKind::Xray,
        100,
        true,
    );
    feed(&mut core, "ok", NOW, 120.0, 0.0);
    feed(&mut core, "bad", NOW, 1.0, 0.0);

    let decision = core.select_best(NOW);
    assert_eq!(decision.selected, Some(cid("ok")));
}
