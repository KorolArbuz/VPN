//! Tunable policies. All weights and thresholds live here so scoring and
//! selection stay free of magic numbers and remain deterministic.

use crate::model::{NetworkType, ProtocolKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Weights and normalization references for [`crate::selector::ConnectionScorer`].
///
/// The six "quality" weights define the maximum point contribution of each
/// base metric; they are renormalized over whichever metrics are present so
/// the base score always lands in `0..=100`. Preference and priority are
/// additive bonuses; freshness and failures are subtractive penalties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoringPolicy {
    // Quality weights (relative; renormalized over present metrics).
    pub weight_latency: f64,
    pub weight_loss: f64,
    pub weight_reliability: f64,
    pub weight_jitter: f64,
    pub weight_handshake: f64,
    pub weight_throughput: f64,

    // Normalization references: the value at which a metric scores 0.
    pub latency_max_ms: f64,
    pub jitter_max_ms: f64,
    pub loss_max_percent: f64,
    pub handshake_max_ms: f64,
    pub throughput_reference_bps: f64,

    /// Number of samples at which reliability earns full weight. Below this the
    /// reliability contribution is ramped down (cold-start damping). Clamped to
    /// at least 1.
    pub min_samples_for_reliability: usize,

    // Bonuses.
    pub priority_points_per_unit: f64,
    pub priority_points_cap: f64,

    // Penalties.
    pub freshness_penalty: f64,
    pub failure_penalty_per: f64,
    pub failure_penalty_cap: f64,
    /// Age beyond which a sample is considered stale and penalized (ms).
    pub stale_sample_timeout_ms: u64,
}

impl Default for ScoringPolicy {
    fn default() -> Self {
        Self {
            weight_latency: 30.0,
            weight_loss: 25.0,
            weight_reliability: 20.0,
            weight_jitter: 10.0,
            weight_handshake: 8.0,
            weight_throughput: 7.0,

            latency_max_ms: 500.0,
            jitter_max_ms: 100.0,
            loss_max_percent: 10.0,
            handshake_max_ms: 800.0,
            throughput_reference_bps: 50_000_000.0,
            min_samples_for_reliability: 3,

            priority_points_per_unit: 1.0,
            priority_points_cap: 10.0,

            freshness_penalty: 25.0,
            failure_penalty_per: 5.0,
            failure_penalty_cap: 30.0,
            stale_sample_timeout_ms: 30_000,
        }
    }
}

/// Hysteresis / anti-flapping policy governing when a switch is recommended.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectionPolicy {
    /// Minimum score advantage (points) required to leave a healthy current.
    pub minimum_score_improvement: f64,
    /// A candidate must be held at least this long before switching away (ms).
    pub minimum_hold_duration_ms: u64,
    /// Additional cooldown after a switch before another is allowed (ms).
    pub switch_cooldown_ms: u64,
    /// Consecutive failures on the current candidate that force a switch.
    pub failure_threshold: u32,
    /// Consecutive successes needed to consider a candidate recovered.
    pub recovery_threshold: u32,
    /// Sample age beyond which selection treats health as stale (ms).
    pub stale_sample_timeout_ms: u64,
}

impl Default for SelectionPolicy {
    fn default() -> Self {
        Self {
            minimum_score_improvement: 8.0,
            minimum_hold_duration_ms: 15_000,
            switch_cooldown_ms: 10_000,
            failure_threshold: 3,
            recovery_threshold: 2,
            stale_sample_timeout_ms: 30_000,
        }
    }
}

/// Circuit-breaker policy for tripping a candidate into cooldown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CircuitBreakerPolicy {
    /// Consecutive failures that trip the breaker.
    pub failure_threshold: u32,
    /// Cooldown duration once tripped (ms).
    pub cooldown_ms: u64,
    /// Consecutive successes (after cooldown elapses) needed to fully recover.
    pub recovery_threshold: u32,
    /// When `true`, an unreachable/failed **health probe** also feeds the
    /// backend connection breaker (unreachable => failure, reachable =>
    /// success). Defaults to `false`: a failed probe is passive telemetry and
    /// must NOT trip the backend breaker unless explicitly opted in. Only
    /// `report_connection_failure` / `report_connection_success` (actual
    /// VPN/backend outcomes) drive the breaker by default.
    #[serde(default)]
    pub health_failures_trip_breaker: bool,
}

impl Default for CircuitBreakerPolicy {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            cooldown_ms: 30_000,
            recovery_threshold: 2,
            health_failures_trip_breaker: false,
        }
    }
}

/// Configurable, network-aware protocol bonuses. Nothing is hardcoded: an empty
/// preference contributes zero points everywhere.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProtocolPreference {
    /// Baseline bonus points per protocol, regardless of network.
    #[serde(default)]
    pub base: BTreeMap<ProtocolKind, f64>,
    /// Per-network overrides; when present, replaces the base for that network.
    #[serde(default)]
    pub per_network: BTreeMap<NetworkType, BTreeMap<ProtocolKind, f64>>,
}

impl ProtocolPreference {
    /// Bonus points for a protocol on the given network. A per-network override
    /// takes precedence over the base value; missing entries yield 0.
    pub fn bonus(&self, network: NetworkType, protocol: ProtocolKind) -> f64 {
        if let Some(map) = self.per_network.get(&network) {
            if let Some(points) = map.get(&protocol) {
                return *points;
            }
        }
        self.base.get(&protocol).copied().unwrap_or(0.0)
    }

    /// Sets the baseline bonus for a protocol (builder-style).
    pub fn with_base(mut self, protocol: ProtocolKind, points: f64) -> Self {
        self.base.insert(protocol, points);
        self
    }

    /// Sets a per-network bonus for a protocol (builder-style).
    pub fn with_network(
        mut self,
        network: NetworkType,
        protocol: ProtocolKind,
        points: f64,
    ) -> Self {
        self.per_network
            .entry(network)
            .or_default()
            .insert(protocol, points);
        self
    }
}
