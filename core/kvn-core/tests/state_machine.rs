//! Connection state machine (spec tests 22, 23).

use kvn_core::state::{ConnectionEvent as E, ConnectionState as S, ConnectionStateMachine};
use kvn_core::KvnCore;

// 22. The full happy-path transitions are valid.
#[test]
fn valid_transitions_follow_lifecycle() {
    let mut m = ConnectionStateMachine::new();
    assert_eq!(m.state(), S::Idle);
    assert_eq!(m.handle(E::ManualConnect).unwrap(), S::Selecting);
    assert_eq!(m.handle(E::HealthUpdated).unwrap(), S::Preparing);
    assert_eq!(m.handle(E::BackendStarted).unwrap(), S::Connecting);
    assert_eq!(m.handle(E::HealthUpdated).unwrap(), S::Connected);
    // Reconnect cycle.
    assert_eq!(m.handle(E::NetworkChanged).unwrap(), S::Reconnecting);
    assert_eq!(m.handle(E::BackendStarted).unwrap(), S::Connected);
    // Teardown.
    assert_eq!(m.handle(E::ManualDisconnect).unwrap(), S::Disconnecting);
    assert_eq!(m.handle(E::BackendStopped).unwrap(), S::Idle);
}

// 23. Invalid transitions are rejected without mutating state.
#[test]
fn invalid_transitions_are_rejected() {
    let mut m = ConnectionStateMachine::new();
    // Cannot start a backend from Idle.
    assert!(m.handle(E::BackendStarted).is_err());
    assert_eq!(m.state(), S::Idle, "state must not change on rejection");
    // Cannot stop a backend from Idle.
    assert!(m.handle(E::BackendStopped).is_err());
    assert_eq!(m.state(), S::Idle);

    // From Connected, ManualConnect is not a legal event.
    m.handle(E::ManualConnect).unwrap();
    m.handle(E::HealthUpdated).unwrap();
    m.handle(E::BackendStarted).unwrap();
    m.handle(E::HealthUpdated).unwrap();
    assert_eq!(m.state(), S::Connected);
    assert!(m.handle(E::ManualConnect).is_err());
    assert_eq!(m.state(), S::Connected);
}

// The engine wrapper counts reconnects and tracks connected_since.
#[test]
fn engine_tracks_reconnects_and_connected_since() {
    let mut core = KvnCore::default();
    core.handle_event(E::ManualConnect, 0).unwrap();
    core.handle_event(E::HealthUpdated, 0).unwrap();
    core.handle_event(E::BackendStarted, 0).unwrap();
    core.handle_event(E::HealthUpdated, 5_000).unwrap();
    assert_eq!(core.get_state(), S::Connected);
    assert_eq!(core.get_statistics(6_000).connected_since_ms, Some(5_000));

    core.handle_event(E::NetworkChanged, 7_000).unwrap();
    core.handle_event(E::BackendStarted, 8_000).unwrap();
    assert_eq!(core.get_statistics(9_000).reconnect_count, 1);
}
