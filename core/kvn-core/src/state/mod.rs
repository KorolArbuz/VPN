//! Explicit, event-driven connection state machine.
//!
//! Every transition is enumerated; anything not listed is rejected with
//! [`CoreError::InvalidStateTransition`]. Semantics of the two "advance" uses of
//! `HealthUpdated`:
//!   * `Selecting -> Preparing`: a selection result is available.
//!   * `Connecting -> Connected`: tunnel health has been confirmed.
//!   * While `Connected`, `HealthUpdated` is a no-op self-loop.

use crate::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};

/// The lifecycle state of the overall connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Idle,
    Selecting,
    Preparing,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Failed,
}

impl ConnectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionState::Idle => "idle",
            ConnectionState::Selecting => "selecting",
            ConnectionState::Preparing => "preparing",
            ConnectionState::Connecting => "connecting",
            ConnectionState::Connected => "connected",
            ConnectionState::Reconnecting => "reconnecting",
            ConnectionState::Disconnecting => "disconnecting",
            ConnectionState::Failed => "failed",
        }
    }
}

/// Events supplied by the platform coordinator to drive the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionEvent {
    ManualConnect,
    ManualDisconnect,
    NetworkChanged,
    HealthUpdated,
    BackendStarted,
    BackendFailed,
    BackendStopped,
}

impl ConnectionEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionEvent::ManualConnect => "manual_connect",
            ConnectionEvent::ManualDisconnect => "manual_disconnect",
            ConnectionEvent::NetworkChanged => "network_changed",
            ConnectionEvent::HealthUpdated => "health_updated",
            ConnectionEvent::BackendStarted => "backend_started",
            ConnectionEvent::BackendFailed => "backend_failed",
            ConnectionEvent::BackendStopped => "backend_stopped",
        }
    }
}

/// A minimal, deterministic state machine.
#[derive(Debug, Clone)]
pub struct ConnectionStateMachine {
    state: ConnectionState,
    /// Set on the transition that enters `Reconnecting`, so the engine can
    /// count reconnects.
    entered_reconnecting: bool,
}

impl Default for ConnectionStateMachine {
    fn default() -> Self {
        Self {
            state: ConnectionState::Idle,
            entered_reconnecting: false,
        }
    }
}

impl ConnectionStateMachine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Computes the target state for `(current, event)` without mutating.
    /// Returns `None` for a rejected transition.
    pub fn next_state(state: ConnectionState, event: ConnectionEvent) -> Option<ConnectionState> {
        use ConnectionEvent::*;
        use ConnectionState::*;
        let next = match (state, event) {
            (Idle, ManualConnect) => Selecting,
            (Failed, ManualConnect) => Selecting,
            (Failed, ManualDisconnect) => Idle,

            (Selecting, HealthUpdated) => Preparing,
            (Selecting, BackendFailed) => Failed,
            (Selecting, ManualDisconnect) => Disconnecting,

            (Preparing, BackendStarted) => Connecting,
            (Preparing, BackendFailed) => Failed,
            (Preparing, ManualDisconnect) => Disconnecting,

            (Connecting, HealthUpdated) => Connected,
            (Connecting, BackendFailed) => Failed,
            (Connecting, ManualDisconnect) => Disconnecting,

            (Connected, HealthUpdated) => Connected,
            (Connected, NetworkChanged) => Reconnecting,
            (Connected, BackendFailed) => Reconnecting,
            (Connected, ManualDisconnect) => Disconnecting,

            (Reconnecting, BackendStarted) => Connected,
            (Reconnecting, BackendFailed) => Failed,
            (Reconnecting, ManualDisconnect) => Disconnecting,

            (Disconnecting, BackendStopped) => Idle,

            _ => return None,
        };
        Some(next)
    }

    /// True when `event` is accepted in the current state.
    pub fn can_handle(&self, event: ConnectionEvent) -> bool {
        Self::next_state(self.state, event).is_some()
    }

    /// Applies `event`, returning the new state or an error for an invalid
    /// transition. Self-loops (e.g. `Connected + HealthUpdated`) are accepted.
    pub fn handle(&mut self, event: ConnectionEvent) -> CoreResult<ConnectionState> {
        match Self::next_state(self.state, event) {
            Some(next) => {
                self.entered_reconnecting = next == ConnectionState::Reconnecting
                    && self.state != ConnectionState::Reconnecting;
                self.state = next;
                Ok(next)
            }
            None => Err(CoreError::InvalidStateTransition {
                from: self.state.as_str().to_string(),
                event: event.as_str().to_string(),
            }),
        }
    }

    /// Whether the last handled event entered the `Reconnecting` state.
    pub fn just_entered_reconnecting(&self) -> bool {
        self.entered_reconnecting
    }
}
