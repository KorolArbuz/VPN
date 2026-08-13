//! `KvnCore`: the portable control-plane engine. Owns candidates, health,
//! selection, routing, state, and statistics. It performs no I/O, reads no
//! clock (callers pass `now_ms`), and holds no secrets.

use crate::backend::BackendCapabilities;
use crate::config::CoreConfiguration;
use crate::error::{CoreError, CoreResult};
use crate::health::{HealthHistory, HealthSample, HealthSnapshot};
use crate::model::{BackendKind, CandidateId, CandidateState, Endpoint, NetworkType, ProfileId};
use crate::policy::CircuitBreakerPolicy;
use crate::routing::{RouteAction, RouteQuery, RouteRule, RoutingTable};
use crate::selector::{
    CandidateScoreBreakdown, ConnectionScorer, SelectionDecision, SelectionReason,
};
use crate::state::{ConnectionEvent, ConnectionState, ConnectionStateMachine};
use crate::stats::CoreStatistics;
use std::collections::BTreeMap;

/// Per-candidate circuit breaker state.
#[derive(Debug, Clone, Default)]
struct CircuitBreaker {
    failures: u32,
    successes: u32,
    tripped: bool,
    cooldown_until: Option<u64>,
}

impl CircuitBreaker {
    fn record_failure(&mut self, now_ms: u64, policy: &CircuitBreakerPolicy) {
        self.failures = self.failures.saturating_add(1);
        self.successes = 0;
        if self.failures >= policy.failure_threshold {
            self.tripped = true;
            self.cooldown_until = Some(now_ms.saturating_add(policy.cooldown_ms));
        }
    }

    fn record_success(&mut self, now_ms: u64, policy: &CircuitBreakerPolicy) {
        if self.tripped {
            // Half-open: only count recovery probes once the cooldown elapsed.
            if self.cooldown_elapsed(now_ms) {
                self.successes = self.successes.saturating_add(1);
                if self.successes >= policy.recovery_threshold {
                    self.tripped = false;
                    self.cooldown_until = None;
                    self.failures = 0;
                    self.successes = 0;
                }
            }
        } else {
            self.failures = 0;
            self.successes = 0;
        }
    }

    fn in_cooldown(&self, now_ms: u64) -> bool {
        self.tripped && self.cooldown_until.is_some_and(|u| now_ms < u)
    }

    fn cooldown_elapsed(&self, now_ms: u64) -> bool {
        self.cooldown_until.is_none_or(|u| now_ms >= u)
    }
}

/// A registered candidate: identity + connectivity metadata + runtime health.
struct Candidate {
    profile_id: ProfileId,
    endpoint: Endpoint,
    history: HealthHistory,
    breaker: CircuitBreaker,
}

/// The control-plane engine.
pub struct KvnCore {
    config: CoreConfiguration,
    candidates: BTreeMap<CandidateId, Candidate>,
    current: Option<CandidateId>,
    network_type: NetworkType,
    state: ConnectionStateMachine,
    routing: RoutingTable,
    last_switch_ms: u64,
    total_switches: u64,
    reconnect_count: u64,
    connected_since_ms: Option<u64>,
    bytes_sent: u64,
    bytes_received: u64,
}

impl Default for KvnCore {
    fn default() -> Self {
        Self::new(CoreConfiguration::default())
    }
}

impl KvnCore {
    pub fn new(config: CoreConfiguration) -> Self {
        Self {
            config,
            candidates: BTreeMap::new(),
            current: None,
            network_type: NetworkType::Unknown,
            state: ConnectionStateMachine::new(),
            routing: RoutingTable::new(),
            last_switch_ms: 0,
            total_switches: 0,
            reconnect_count: 0,
            connected_since_ms: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    // --- configuration -----------------------------------------------------

    /// Validates and applies a new configuration. Existing candidates keep the
    /// history capacity/alpha they were created with; policies are read live.
    pub fn set_configuration(&mut self, config: CoreConfiguration) -> CoreResult<()> {
        if config.health_capacity == 0 {
            return Err(CoreError::InvalidConfiguration(
                "health_capacity must be >= 1".into(),
            ));
        }
        if !(config.ewma_alpha > 0.0 && config.ewma_alpha <= 1.0) {
            return Err(CoreError::InvalidConfiguration(
                "ewma_alpha must be in (0, 1]".into(),
            ));
        }
        self.config = config;
        Ok(())
    }

    pub fn configuration(&self) -> &CoreConfiguration {
        &self.config
    }

    // --- candidate lifecycle ----------------------------------------------

    pub fn register_candidate(
        &mut self,
        id: CandidateId,
        profile_id: ProfileId,
        endpoint: Endpoint,
    ) -> CoreResult<()> {
        if self.candidates.contains_key(&id) {
            return Err(CoreError::DuplicateCandidate(id.0));
        }
        let history = HealthHistory::new(self.config.health_capacity, self.config.ewma_alpha);
        self.candidates.insert(
            id,
            Candidate {
                profile_id,
                endpoint,
                history,
                breaker: CircuitBreaker::default(),
            },
        );
        Ok(())
    }

    pub fn remove_candidate(&mut self, id: &CandidateId) -> CoreResult<()> {
        if self.candidates.remove(id).is_none() {
            return Err(CoreError::UnknownCandidate(id.0.clone()));
        }
        if self.current.as_ref() == Some(id) {
            self.current = None;
            self.connected_since_ms = None;
        }
        Ok(())
    }

    /// Replaces the endpoint metadata of an existing candidate, preserving its
    /// health history and breaker state.
    pub fn update_candidate(&mut self, id: &CandidateId, endpoint: Endpoint) -> CoreResult<()> {
        let candidate = self
            .candidates
            .get_mut(id)
            .ok_or_else(|| CoreError::UnknownCandidate(id.0.clone()))?;
        candidate.endpoint = endpoint;
        Ok(())
    }

    pub fn candidate_ids(&self) -> Vec<CandidateId> {
        self.candidates.keys().cloned().collect()
    }

    pub fn profile_id(&self, id: &CandidateId) -> Option<&ProfileId> {
        self.candidates.get(id).map(|c| &c.profile_id)
    }

    // --- health & signals --------------------------------------------------

    pub fn update_health(&mut self, id: &CandidateId, sample: HealthSample) -> CoreResult<()> {
        let policy = self.config.circuit_breaker.clone();
        let candidate = self
            .candidates
            .get_mut(id)
            .ok_or_else(|| CoreError::UnknownCandidate(id.0.clone()))?;
        let ts = sample.timestamp_ms;
        let reachable = sample.reachable;
        candidate.history.record(sample);

        // By default a health probe is PASSIVE telemetry: it updates history and
        // the reliability signal, but never the backend connection breaker. Only
        // explicit `report_connection_*` calls do — unless a policy opts in.
        if policy.health_failures_trip_breaker {
            if reachable {
                candidate.breaker.record_success(ts, &policy);
            } else {
                candidate.breaker.record_failure(ts, &policy);
            }
        }
        Ok(())
    }

    pub fn set_network_type(&mut self, network: NetworkType) {
        self.network_type = network;
    }

    pub fn network_type(&self) -> NetworkType {
        self.network_type
    }

    /// Records the candidate the platform actually connected to. Updates
    /// hysteresis timing and the switch counter when the identity changes.
    pub fn set_current_candidate(
        &mut self,
        id: Option<CandidateId>,
        now_ms: u64,
    ) -> CoreResult<()> {
        if let Some(ref candidate_id) = id {
            if !self.candidates.contains_key(candidate_id) {
                return Err(CoreError::UnknownCandidate(candidate_id.0.clone()));
            }
        }
        if id != self.current {
            if id.is_some() {
                self.total_switches = self.total_switches.saturating_add(1);
            }
            self.last_switch_ms = now_ms;
            self.current = id;
        }
        Ok(())
    }

    pub fn current_candidate(&self) -> Option<&CandidateId> {
        self.current.as_ref()
    }

    pub fn report_connection_success(&mut self, id: &CandidateId, now_ms: u64) -> CoreResult<()> {
        let policy = self.config.circuit_breaker.clone();
        let candidate = self
            .candidates
            .get_mut(id)
            .ok_or_else(|| CoreError::UnknownCandidate(id.0.clone()))?;
        candidate.breaker.record_success(now_ms, &policy);
        Ok(())
    }

    pub fn report_connection_failure(&mut self, id: &CandidateId, now_ms: u64) -> CoreResult<()> {
        let policy = self.config.circuit_breaker.clone();
        let candidate = self
            .candidates
            .get_mut(id)
            .ok_or_else(|| CoreError::UnknownCandidate(id.0.clone()))?;
        candidate.breaker.record_failure(now_ms, &policy);
        Ok(())
    }

    // --- derived views -----------------------------------------------------

    pub fn candidate_state(&self, id: &CandidateId, now_ms: u64) -> Option<CandidateState> {
        self.candidates.get(id).map(|c| self.state_of(c, now_ms))
    }

    fn state_of(&self, candidate: &Candidate, now_ms: u64) -> CandidateState {
        if !candidate.endpoint.enabled {
            return CandidateState::Unavailable;
        }
        if !self.backend_compatible(&candidate.endpoint) {
            return CandidateState::Unavailable;
        }
        if candidate.breaker.in_cooldown(now_ms) {
            return CandidateState::Cooldown;
        }
        let snap = candidate.history.snapshot();
        if snap.sample_count == 0 || !snap.reachable {
            return CandidateState::Unavailable;
        }
        if snap.recent_failures > 0 || candidate.breaker.failures > 0 {
            return CandidateState::Degraded;
        }
        CandidateState::Healthy
    }

    /// Empty capability map => filtering disabled (all compatible).
    fn backend_compatible(&self, endpoint: &Endpoint) -> bool {
        if self.config.backends.is_empty() {
            return true;
        }
        self.config
            .backends
            .get(&endpoint.backend)
            .is_some_and(|caps| caps.supports(endpoint.protocol))
    }

    fn is_selectable(&self, candidate: &Candidate, now_ms: u64) -> bool {
        matches!(
            self.state_of(candidate, now_ms),
            CandidateState::Healthy | CandidateState::Degraded
        )
    }

    /// Deterministic score for a candidate, or `None` if unknown.
    pub fn score(&self, id: &CandidateId, now_ms: u64) -> Option<CandidateScoreBreakdown> {
        self.candidates.get(id).map(|c| self.score_of(c, now_ms))
    }

    fn score_of(&self, candidate: &Candidate, now_ms: u64) -> CandidateScoreBreakdown {
        let scorer = ConnectionScorer::new(&self.config.scoring, &self.config.preference);
        let snapshot: HealthSnapshot = candidate.history.snapshot();
        scorer.score(&candidate.endpoint, &snapshot, self.network_type, now_ms)
    }

    // --- selection ---------------------------------------------------------

    /// Produces a switch recommendation without mutating selection state. The
    /// platform decides whether to act, then calls `set_current_candidate`.
    pub fn select_best(&self, now_ms: u64) -> SelectionDecision {
        // Score every selectable candidate.
        let mut scored: Vec<(CandidateId, CandidateScoreBreakdown, i32)> = self
            .candidates
            .iter()
            .filter(|(_, c)| self.is_selectable(c, now_ms))
            .map(|(id, c)| {
                (
                    id.clone(),
                    self.score_of(c, now_ms),
                    c.endpoint.manual_priority,
                )
            })
            .collect();

        // Deterministic ordering: score desc, priority desc, id asc.
        scored.sort_by(|a, b| {
            b.1.total
                .partial_cmp(&a.1.total)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.2.cmp(&a.2))
                .then(a.0.cmp(&b.0))
        });

        let current = self.current.clone();
        let current_score = current
            .as_ref()
            .and_then(|id| self.score(id, now_ms))
            .map(|b| b.total);

        let Some((best_id, best_breakdown, _)) = scored.into_iter().next() else {
            return SelectionDecision {
                selected: None,
                current,
                should_switch: false,
                current_score,
                selected_score: None,
                reason: SelectionReason::NoHealthyCandidates,
                timestamp_ms: now_ms,
                breakdown: None,
            };
        };

        let best_score = best_breakdown.total;

        // No prior selection.
        let Some(current_id) = current.clone() else {
            return self.decision(
                &current,
                best_id,
                best_breakdown,
                current_score,
                true,
                SelectionReason::InitialSelection,
                now_ms,
            );
        };

        // Current not registered or not selectable.
        let current_selectable = self
            .candidates
            .get(&current_id)
            .is_some_and(|c| self.is_selectable(c, now_ms));
        if !current_selectable {
            let switch = best_id != current_id;
            return self.decision(
                &current,
                best_id,
                best_breakdown,
                current_score,
                switch,
                SelectionReason::CurrentUnavailable,
                now_ms,
            );
        }

        // Current is failing per selection failure threshold.
        let current_failures = self
            .candidates
            .get(&current_id)
            .map(|c| c.history.snapshot().consecutive_failures)
            .unwrap_or(0);
        if current_failures >= self.config.selection.failure_threshold {
            let switch = best_id != current_id;
            return self.decision(
                &current,
                best_id,
                best_breakdown,
                current_score,
                switch,
                SelectionReason::FailureThresholdReached,
                now_ms,
            );
        }

        // Best already is the current candidate.
        if best_id == current_id {
            return self.decision(
                &current,
                best_id,
                best_breakdown,
                current_score,
                false,
                SelectionReason::NoChange,
                now_ms,
            );
        }

        // Hysteresis: require a real improvement, hold and cooldown satisfied.
        let improvement = best_score - current_score.unwrap_or(0.0);
        let elapsed = now_ms.saturating_sub(self.last_switch_ms);
        let held = elapsed >= self.config.selection.minimum_hold_duration_ms;
        let cooled = elapsed >= self.config.selection.switch_cooldown_ms;

        if improvement >= self.config.selection.minimum_score_improvement && held && cooled {
            self.decision(
                &current,
                best_id,
                best_breakdown,
                current_score,
                true,
                SelectionReason::SignificantlyBetter,
                now_ms,
            )
        } else {
            self.decision(
                &current,
                best_id,
                best_breakdown,
                current_score,
                false,
                SelectionReason::NoChange,
                now_ms,
            )
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decision(
        &self,
        current: &Option<CandidateId>,
        selected_id: CandidateId,
        breakdown: CandidateScoreBreakdown,
        current_score: Option<f64>,
        should_switch: bool,
        reason: SelectionReason,
        now_ms: u64,
    ) -> SelectionDecision {
        SelectionDecision {
            selected: Some(selected_id),
            current: current.clone(),
            should_switch,
            current_score,
            selected_score: Some(breakdown.total),
            reason,
            timestamp_ms: now_ms,
            breakdown: Some(breakdown),
        }
    }

    // --- state machine -----------------------------------------------------

    /// Drives the connection state machine and maintains derived counters.
    pub fn handle_event(
        &mut self,
        event: ConnectionEvent,
        now_ms: u64,
    ) -> CoreResult<ConnectionState> {
        let next = self.state.handle(event)?;
        match next {
            ConnectionState::Connected => {
                if self.connected_since_ms.is_none() {
                    self.connected_since_ms = Some(now_ms);
                }
            }
            ConnectionState::Idle | ConnectionState::Failed | ConnectionState::Disconnecting => {
                self.connected_since_ms = None;
            }
            _ => {}
        }
        if self.state.just_entered_reconnecting() {
            self.reconnect_count = self.reconnect_count.saturating_add(1);
        }
        Ok(next)
    }

    pub fn get_state(&self) -> ConnectionState {
        self.state.state()
    }

    // --- routing -----------------------------------------------------------

    pub fn set_routing_rules(&mut self, rules: Vec<RouteRule>) {
        self.routing.set_rules(rules);
    }

    pub fn resolve_route(&self, query: &RouteQuery) -> Option<RouteAction> {
        self.routing.resolve(query)
    }

    // --- statistics --------------------------------------------------------

    pub fn set_traffic_counters(&mut self, bytes_sent: u64, bytes_received: u64) {
        self.bytes_sent = bytes_sent;
        self.bytes_received = bytes_received;
    }

    pub fn get_statistics(&self, now_ms: u64) -> CoreStatistics {
        let current = self.current.clone();
        let snapshot = current
            .as_ref()
            .and_then(|id| self.candidates.get(id))
            .map(|c| c.history.snapshot());
        let current_score = current
            .as_ref()
            .and_then(|id| self.score(id, now_ms))
            .map(|b| b.total);

        CoreStatistics {
            current_candidate: current,
            current_score,
            connected_since_ms: self.connected_since_ms,
            total_switches: self.total_switches,
            reconnect_count: self.reconnect_count,
            latency_ms: snapshot.as_ref().and_then(|s| s.ewma_latency_ms),
            jitter_ms: snapshot.as_ref().and_then(|s| s.ewma_jitter_ms),
            loss_percent: snapshot.as_ref().and_then(|s| s.ewma_loss_percent),
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            network_type: self.network_type,
        }
    }

    // --- introspection for callers/tests -----------------------------------

    /// Registers or replaces a backend's declared capabilities.
    pub fn set_backend_capabilities(
        &mut self,
        backend: BackendKind,
        capabilities: BackendCapabilities,
    ) {
        self.config.backends.insert(backend, capabilities);
    }
}
