//! Shared test helpers.
//!
//! Each integration-test binary compiles this module independently and uses a
//! different subset, so unused helpers are expected per binary.
#![allow(dead_code)]

use kvn_core::health::HealthSample;
use kvn_core::model::{BackendKind, CandidateId, Endpoint, ProfileId, ProtocolKind};
use kvn_core::KvnCore;

pub fn cid(s: &str) -> CandidateId {
    CandidateId::new(s)
}

/// Registers a candidate with the given identity and endpoint knobs.
#[allow(clippy::too_many_arguments)]
pub fn register(
    core: &mut KvnCore,
    id: &str,
    protocol: ProtocolKind,
    backend: BackendKind,
    priority: i32,
    enabled: bool,
) {
    let mut endpoint = Endpoint::new(format!("{id}.example.com"), 443, protocol, backend);
    endpoint.manual_priority = priority;
    endpoint.enabled = enabled;
    core.register_candidate(cid(id), ProfileId::new("profile"), endpoint)
        .expect("register");
}

/// A simple vless/xray candidate.
pub fn register_simple(core: &mut KvnCore, id: &str) {
    register(core, id, ProtocolKind::Vless, BackendKind::Xray, 0, true);
}

/// Builds a reachable sample with latency and packet loss.
pub fn sample(ts: u64, latency_ms: f64, loss_percent: f64) -> HealthSample {
    let mut s = HealthSample::reachable(ts, latency_ms);
    s.packet_loss_percent = Some(loss_percent);
    s
}

/// Records a reachable sample for a candidate.
pub fn feed(core: &mut KvnCore, id: &str, ts: u64, latency_ms: f64, loss_percent: f64) {
    core.update_health(&cid(id), sample(ts, latency_ms, loss_percent))
        .expect("update_health");
}
