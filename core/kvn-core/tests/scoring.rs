//! Scoring behavior (spec tests 3, 11, 12, 13, 14, 15, 16).

mod common;

use common::*;
use kvn_core::model::{BackendKind, NetworkType, ProtocolKind};
use kvn_core::policy::ProtocolPreference;
use kvn_core::KvnCore;

const NOW: u64 = 100_000;

// 3. Low latency but high packet loss does not automatically win.
#[test]
fn low_latency_high_loss_does_not_win() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "fast_lossy");
    register_simple(&mut core, "moderate_clean");
    feed(&mut core, "fast_lossy", NOW, 20.0, 9.0); // near loss ceiling
    feed(&mut core, "moderate_clean", NOW, 120.0, 0.0);

    let fast = core.score(&cid("fast_lossy"), NOW).unwrap().total;
    let clean = core.score(&cid("moderate_clean"), NOW).unwrap().total;
    assert!(clean > fast, "clean={clean} fast={fast}");

    let decision = core.select_best(NOW);
    assert_eq!(decision.selected, Some(cid("moderate_clean")));
}

// 11. A stale sample receives a freshness penalty.
#[test]
fn stale_sample_is_penalized() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "a");
    feed(&mut core, "a", 0, 40.0, 0.0);

    let fresh = core.score(&cid("a"), 0).unwrap();
    // Well beyond the default 30s stale timeout.
    let stale = core.score(&cid("a"), 90_000).unwrap();

    assert_eq!(fresh.penalties, 0.0);
    assert!(stale.penalties > 0.0);
    assert!(stale.total < fresh.total);
}

// 12. Manual priority is taken into account.
#[test]
fn priority_is_taken_into_account() {
    let mut core = KvnCore::default();
    register(
        &mut core,
        "plain",
        ProtocolKind::Vless,
        BackendKind::Xray,
        0,
        true,
    );
    register(
        &mut core,
        "prioritized",
        ProtocolKind::Vless,
        BackendKind::Xray,
        5,
        true,
    );
    // Identical health.
    feed(&mut core, "plain", NOW, 100.0, 0.0);
    feed(&mut core, "prioritized", NOW, 100.0, 0.0);

    let plain = core.score(&cid("plain"), NOW).unwrap();
    let prioritized = core.score(&cid("prioritized"), NOW).unwrap();
    assert_eq!(plain.priority, 0.0);
    assert_eq!(prioritized.priority, 5.0);
    assert!(prioritized.total > plain.total);

    assert_eq!(core.select_best(NOW).selected, Some(cid("prioritized")));
}

// 13. Wi-Fi protocol preference is deterministic.
#[test]
fn wifi_preference_is_deterministic() {
    let preference =
        ProtocolPreference::default().with_network(NetworkType::Wifi, ProtocolKind::Vless, 10.0);
    let config = kvn_core::CoreConfiguration {
        preference,
        ..Default::default()
    };
    let mut core = KvnCore::new(config);
    core.set_network_type(NetworkType::Wifi);

    register(
        &mut core,
        "vless",
        ProtocolKind::Vless,
        BackendKind::Xray,
        0,
        true,
    );
    register(
        &mut core,
        "trojan",
        ProtocolKind::Trojan,
        BackendKind::Xray,
        0,
        true,
    );
    feed(&mut core, "vless", NOW, 100.0, 0.0);
    feed(&mut core, "trojan", NOW, 100.0, 0.0);

    let first = core.select_best(NOW);
    let second = core.select_best(NOW);
    assert_eq!(first.selected, Some(cid("vless")));
    assert_eq!(first.selected, second.selected); // deterministic
    assert_eq!(
        core.score(&cid("vless"), NOW).unwrap().protocol_preference,
        10.0
    );
}

// 14. Cellular protocol preference is deterministic and network-scoped.
#[test]
fn cellular_preference_is_deterministic() {
    let preference = ProtocolPreference::default().with_network(
        NetworkType::Cellular,
        ProtocolKind::Hysteria2,
        10.0,
    );
    let config = kvn_core::CoreConfiguration {
        preference,
        ..Default::default()
    };
    let mut core = KvnCore::new(config);

    register(
        &mut core,
        "vless",
        ProtocolKind::Vless,
        BackendKind::Xray,
        0,
        true,
    );
    register(
        &mut core,
        "hy2",
        ProtocolKind::Hysteria2,
        BackendKind::Hysteria,
        0,
        true,
    );
    feed(&mut core, "vless", NOW, 100.0, 0.0);
    feed(&mut core, "hy2", NOW, 100.0, 0.0);

    // On cellular, Hysteria2 gets the bonus.
    core.set_network_type(NetworkType::Cellular);
    assert_eq!(core.select_best(NOW).selected, Some(cid("hy2")));
    assert_eq!(
        core.score(&cid("hy2"), NOW).unwrap().protocol_preference,
        10.0
    );

    // On Wi-Fi there is no such preference, so the tie breaks elsewhere.
    core.set_network_type(NetworkType::Wifi);
    assert_eq!(
        core.score(&cid("hy2"), NOW).unwrap().protocol_preference,
        0.0
    );
}

// 15. The score always stays within 0..=100.
#[test]
fn score_stays_within_bounds() {
    let mut core = KvnCore::default();

    // Terrible metrics -> clamped at >= 0.
    register(
        &mut core,
        "awful",
        ProtocolKind::Vless,
        BackendKind::Xray,
        -1000,
        true,
    );
    let mut bad = kvn_core::health::HealthSample::reachable(NOW, 100_000.0);
    bad.packet_loss_percent = Some(100.0);
    bad.jitter_ms = Some(100_000.0);
    core.update_health(&cid("awful"), bad).unwrap();
    let awful = core.score(&cid("awful"), NOW).unwrap().total;
    assert!((0.0..=100.0).contains(&awful), "awful={awful}");

    // Excellent metrics plus huge bonuses -> clamped at <= 100.
    let preference = ProtocolPreference::default().with_base(ProtocolKind::Vless, 1000.0);
    let config = kvn_core::CoreConfiguration {
        preference,
        ..Default::default()
    };
    let mut core = KvnCore::new(config);
    register(
        &mut core,
        "great",
        ProtocolKind::Vless,
        BackendKind::Xray,
        1000,
        true,
    );
    let mut good = kvn_core::health::HealthSample::reachable(NOW, 1.0);
    good.packet_loss_percent = Some(0.0);
    good.download_bps = Some(1_000_000_000.0);
    core.update_health(&cid("great"), good).unwrap();
    let great = core.score(&cid("great"), NOW).unwrap().total;
    assert!((0.0..=100.0).contains(&great), "great={great}");
    assert_eq!(great, 100.0);
}

// 16. The score breakdown reconciles with the clamped total.
#[test]
fn breakdown_matches_total() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "a");
    let mut s = kvn_core::health::HealthSample::reachable(NOW, 60.0);
    s.jitter_ms = Some(15.0);
    s.packet_loss_percent = Some(2.0);
    s.handshake_ms = Some(120.0);
    s.download_bps = Some(20_000_000.0);
    core.update_health(&cid("a"), s).unwrap();

    let b = core.score(&cid("a"), NOW).unwrap();
    let expected = b.raw_total().clamp(0.0, 100.0);
    assert!(
        (b.total - expected).abs() < 1e-9,
        "total={} raw={}",
        b.total,
        b.raw_total()
    );
}
