//! Portable domain model shared across all platforms.
//!
//! IMPORTANT: this module intentionally contains **no secrets**. Credentials
//! (UUIDs, passwords, private keys, tokens, raw URIs, subscription URLs) never
//! enter the control-plane core; only opaque identities and connectivity
//! metadata do.

use serde::{Deserialize, Serialize};

/// Application-layer / transport protocol of a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolKind {
    Vless,
    Trojan,
    Vmess,
    Hysteria2,
    Wireguard,
    Shadowsocks,
    Tuic,
    Ikev2,
    Unknown,
}

/// The data-plane engine that would carry traffic for a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Xray,
    Hysteria,
    Wireguard,
    System,
    Custom,
}

/// Physical network the device is currently attached to.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum NetworkType {
    Wifi,
    Cellular,
    Ethernet,
    #[default]
    Unknown,
}

/// Runtime health classification of a candidate, derived on demand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateState {
    Healthy,
    Degraded,
    Unavailable,
    Cooldown,
}

/// Opaque, stable identifier for a source profile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(pub String);

impl ProfileId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque, stable identifier for a selectable candidate (profile x endpoint).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CandidateId(pub String);

impl CandidateId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Non-secret description of where and how a candidate connects.
///
/// Host/port are connectivity metadata (not secrets). Credentials are resolved
/// on the platform/backend side via a reference the core never sees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub protocol: ProtocolKind,
    pub backend: BackendKind,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    /// Operator hint: higher means "prefer this candidate", 0 is neutral.
    #[serde(default)]
    pub manual_priority: i32,
}

fn default_true() -> bool {
    true
}

impl Endpoint {
    /// Builder-style constructor for the common case.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        protocol: ProtocolKind,
        backend: BackendKind,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            protocol,
            backend,
            enabled: true,
            tags: Vec::new(),
            region: None,
            country: None,
            manual_priority: 0,
        }
    }
}
