//! Versioning and security invariants (spec tests 27, 28).

mod common;

use common::*;
use kvn_core::KvnCore;

// 27. The API version is reported correctly.
#[test]
fn api_version_is_reported() {
    assert!(!kvn_core::version().is_empty());
    assert_eq!(kvn_core::version(), env!("CARGO_PKG_VERSION"));
    assert_eq!(kvn_core::schema_version(), kvn_core::SCHEMA_VERSION);
    assert_eq!(kvn_core::schema_version(), 1);
}

// 28. Serialized responses never contain credentials.
//
// The core is never handed secrets, so serialized outputs cannot leak them.
// This test also guards against a future field accidentally carrying one.
#[test]
fn serialized_responses_contain_no_credentials() {
    let mut core = KvnCore::default();
    register_simple(&mut core, "candidate-1");
    feed(&mut core, "candidate-1", 100, 42.0, 0.5);
    core.set_current_candidate(Some(cid("candidate-1")), 0)
        .unwrap();

    let decision = core.select_best(100);
    let stats = core.get_statistics(100);

    let decision_json = serde_json::to_string(&decision).unwrap();
    let stats_json = serde_json::to_string(&stats).unwrap();

    // Forbidden markers per the security rules.
    const FORBIDDEN: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "private_key",
        "privatekey",
        "token",
        "uuid",
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "credential",
    ];
    for haystack in [&decision_json, &stats_json] {
        let lower = haystack.to_lowercase();
        for needle in FORBIDDEN {
            assert!(
                !lower.contains(needle),
                "serialized output leaked '{needle}': {haystack}"
            );
        }
    }

    // Sanity: the opaque candidate id is present (proves we serialized content).
    assert!(decision_json.contains("candidate-1"));
}
