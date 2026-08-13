//! Aggregated, non-secret statistics snapshot.

use crate::model::{CandidateId, NetworkType};
use serde::{Deserialize, Serialize};

/// A point-in-time view of core statistics. Byte counters originate on the
/// platform and are passed in; the core aggregates the rest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreStatistics {
    pub current_candidate: Option<CandidateId>,
    pub current_score: Option<f64>,
    pub connected_since_ms: Option<u64>,
    pub total_switches: u64,
    pub reconnect_count: u64,
    pub latency_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_percent: Option<f64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub network_type: NetworkType,
}

impl Default for CoreStatistics {
    fn default() -> Self {
        Self {
            current_candidate: None,
            current_score: None,
            connected_since_ms: None,
            total_switches: 0,
            reconnect_count: 0,
            latency_ms: None,
            jitter_ms: None,
            loss_percent: None,
            bytes_sent: 0,
            bytes_received: 0,
            network_type: NetworkType::Unknown,
        }
    }
}
