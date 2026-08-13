//! Connection scoring and selection decisions.
//!
//! Scoring is deterministic: given the same inputs and `now_ms` it always
//! yields the same breakdown. The core never reads the wall clock itself.

use crate::health::HealthSnapshot;
use crate::model::{CandidateId, Endpoint, NetworkType};
use crate::policy::{ProtocolPreference, ScoringPolicy};
use serde::{Deserialize, Serialize};

/// Per-component point contributions to a candidate's score, for
/// explainability. `total` is the clamped `0..=100` result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateScoreBreakdown {
    pub total: f64,
    pub latency: f64,
    pub jitter: f64,
    pub loss: f64,
    pub handshake: f64,
    pub reliability: f64,
    pub throughput: f64,
    pub protocol_preference: f64,
    pub priority: f64,
    /// Positive number subtracted from the sum (freshness + failures).
    pub penalties: f64,
    /// Telemetry confidence in `0..=1`: the share of scoring weight actually
    /// backed by present, trustworthy metrics. Explanatory only — the
    /// per-metric effects are already reflected in the components above.
    pub confidence: f64,
}

impl CandidateScoreBreakdown {
    /// Sum of components before clamping. `total == clamp(raw_total(), 0, 100)`.
    pub fn raw_total(&self) -> f64 {
        self.latency
            + self.jitter
            + self.loss
            + self.handshake
            + self.reliability
            + self.throughput
            + self.protocol_preference
            + self.priority
            - self.penalties
    }
}

/// Stateless deterministic scorer.
pub struct ConnectionScorer<'a> {
    policy: &'a ScoringPolicy,
    preference: &'a ProtocolPreference,
}

impl<'a> ConnectionScorer<'a> {
    pub fn new(policy: &'a ScoringPolicy, preference: &'a ProtocolPreference) -> Self {
        Self { policy, preference }
    }

    /// Scores a candidate. Base quality metrics are renormalized over whichever
    /// metrics are present, so the base always lands in `0..=100` before
    /// bonuses/penalties. Result is clamped to `0..=100`.
    pub fn score(
        &self,
        endpoint: &Endpoint,
        snapshot: &HealthSnapshot,
        network: NetworkType,
        now_ms: u64,
    ) -> CandidateScoreBreakdown {
        let p = self.policy;

        // (weight, present, subscore in 0..=1)
        let latency_sub = snapshot
            .ewma_latency_ms
            .map(|v| inverse_norm(v, p.latency_max_ms));
        let jitter_sub = snapshot
            .ewma_jitter_ms
            .map(|v| inverse_norm(v, p.jitter_max_ms));
        let loss_sub = snapshot
            .ewma_loss_percent
            .map(|v| inverse_norm(v, p.loss_max_percent));
        let handshake_sub = snapshot
            .ewma_handshake_ms
            .map(|v| inverse_norm(v, p.handshake_max_ms));
        let throughput_sub = snapshot
            .ewma_download_bps
            .map(|v| clamp01(v / p.throughput_reference_bps));
        // Reliability is available whenever we have any samples.
        let reliability_sub = if snapshot.sample_count > 0 {
            Some(clamp01(snapshot.availability_ratio))
        } else {
            None
        };

        let total_weight = p.weight_latency
            + p.weight_jitter
            + p.weight_loss
            + p.weight_handshake
            + p.weight_reliability
            + p.weight_throughput;

        // Scale relative weights into absolute points. Crucially we divide by
        // the TOTAL weight, not just the present ones: a missing metric earns
        // zero points and is NOT redistributed, so a candidate cannot look
        // excellent on the strength of one known metric while the rest of its
        // telemetry is unknown.
        let scale = if total_weight > 0.0 {
            100.0 / total_weight
        } else {
            0.0
        };

        let component = |weight: f64, sub: Option<f64>| -> f64 {
            match sub {
                Some(s) => weight * scale * s,
                None => 0.0,
            }
        };

        // Reliability confidence ramps up with accumulated history, so a single
        // reachable sample does not grant full reliability credit (cold-start
        // damping). With enough samples it reaches 1.0.
        let reliability_confidence = if snapshot.sample_count == 0 {
            0.0
        } else {
            clamp01(snapshot.sample_count as f64 / p.min_samples_for_reliability.max(1) as f64)
        };

        let latency = component(p.weight_latency, latency_sub);
        let jitter = component(p.weight_jitter, jitter_sub);
        let loss = component(p.weight_loss, loss_sub);
        let handshake = component(p.weight_handshake, handshake_sub);
        let reliability = component(p.weight_reliability, reliability_sub) * reliability_confidence;
        let throughput = component(p.weight_throughput, throughput_sub);

        // Telemetry confidence: share of total scoring weight backed by present,
        // trustworthy metrics (reliability counted fractionally by its ramp).
        let present_weight = latency_sub.map_or(0.0, |_| p.weight_latency)
            + jitter_sub.map_or(0.0, |_| p.weight_jitter)
            + loss_sub.map_or(0.0, |_| p.weight_loss)
            + handshake_sub.map_or(0.0, |_| p.weight_handshake)
            + throughput_sub.map_or(0.0, |_| p.weight_throughput)
            + p.weight_reliability * reliability_confidence;
        let confidence = if total_weight > 0.0 {
            clamp01(present_weight / total_weight)
        } else {
            0.0
        };

        // Bonuses.
        let protocol_preference = self.preference.bonus(network, endpoint.protocol);
        let priority = (endpoint.manual_priority as f64 * p.priority_points_per_unit)
            .clamp(-p.priority_points_cap, p.priority_points_cap);

        // Penalties.
        let freshness_penalty = freshness_penalty(snapshot, now_ms, p);
        let failure_penalty =
            (snapshot.recent_failures as f64 * p.failure_penalty_per).min(p.failure_penalty_cap);
        let penalties = freshness_penalty + failure_penalty;

        let raw = latency
            + jitter
            + loss
            + handshake
            + reliability
            + throughput
            + protocol_preference
            + priority
            - penalties;

        CandidateScoreBreakdown {
            total: raw.clamp(0.0, 100.0),
            latency,
            jitter,
            loss,
            handshake,
            reliability,
            throughput,
            protocol_preference,
            priority,
            penalties,
            confidence,
        }
    }
}

/// 1.0 at value 0, linearly down to 0.0 at `max`, clamped.
fn inverse_norm(value: f64, max: f64) -> f64 {
    if max <= 0.0 {
        return 0.0;
    }
    clamp01(1.0 - value / max)
}

fn clamp01(v: f64) -> f64 {
    v.clamp(0.0, 1.0)
}

fn freshness_penalty(snapshot: &HealthSnapshot, now_ms: u64, policy: &ScoringPolicy) -> f64 {
    let Some(age) = snapshot.age_ms(now_ms) else {
        return 0.0;
    };
    let stale = policy.stale_sample_timeout_ms;
    if stale == 0 || age <= stale {
        return 0.0;
    }
    // Scale penalty from 0 at the threshold up to the full penalty one window
    // later.
    let over = (age - stale) as f64 / stale as f64;
    policy.freshness_penalty * over.clamp(0.0, 1.0)
}

/// Why a selection decision reached its conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionReason {
    InitialSelection,
    CurrentUnavailable,
    SignificantlyBetter,
    FailureThresholdReached,
    ManualOverride,
    PolicyChange,
    NoChange,
    NoHealthyCandidates,
}

/// The recommendation produced by `select_best`. The core never acts on this;
/// the platform coordinator performs any actual reconnect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectionDecision {
    pub selected: Option<CandidateId>,
    pub current: Option<CandidateId>,
    pub should_switch: bool,
    pub current_score: Option<f64>,
    pub selected_score: Option<f64>,
    pub reason: SelectionReason,
    pub timestamp_ms: u64,
    pub breakdown: Option<CandidateScoreBreakdown>,
}
