//! Health engine: ingests externally-measured samples and maintains bounded
//! history plus EWMA aggregates. The core does not perform any I/O or probing
//! itself; the platform supplies [`HealthSample`]s.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Coarse failure category. Never contains addresses, secrets, or raw errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    Timeout,
    Refused,
    Dns,
    Tls,
    Handshake,
    Network,
    Unknown,
}

/// A single measurement point supplied by the platform/backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthSample {
    /// Monotonic-ish milliseconds timestamp, supplied by the caller.
    pub timestamp_ms: u64,
    pub reachable: bool,
    #[serde(default)]
    pub latency_ms: Option<f64>,
    #[serde(default)]
    pub jitter_ms: Option<f64>,
    #[serde(default)]
    pub packet_loss_percent: Option<f64>,
    #[serde(default)]
    pub handshake_ms: Option<f64>,
    #[serde(default)]
    pub download_bps: Option<f64>,
    #[serde(default)]
    pub upload_bps: Option<f64>,
    #[serde(default)]
    pub failure: Option<FailureCategory>,
}

impl HealthSample {
    /// Convenience constructor for a successful reachability sample.
    pub fn reachable(timestamp_ms: u64, latency_ms: f64) -> Self {
        Self {
            timestamp_ms,
            reachable: true,
            latency_ms: Some(latency_ms),
            jitter_ms: None,
            packet_loss_percent: None,
            handshake_ms: None,
            download_bps: None,
            upload_bps: None,
            failure: None,
        }
    }

    /// Convenience constructor for an unreachable sample.
    pub fn unreachable(timestamp_ms: u64, failure: FailureCategory) -> Self {
        Self {
            timestamp_ms,
            reachable: false,
            latency_ms: None,
            jitter_ms: None,
            packet_loss_percent: None,
            handshake_ms: None,
            download_bps: None,
            upload_bps: None,
            failure: Some(failure),
        }
    }
}

/// Read-only aggregated view derived from history; consumed by the scorer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub sample_count: usize,
    pub last_sample_ms: Option<u64>,
    pub last_success_ms: Option<u64>,
    pub last_failure_ms: Option<u64>,
    /// Reachability of the most recent sample.
    pub reachable: bool,
    pub ewma_latency_ms: Option<f64>,
    pub ewma_jitter_ms: Option<f64>,
    pub ewma_loss_percent: Option<f64>,
    pub ewma_handshake_ms: Option<f64>,
    pub ewma_download_bps: Option<f64>,
    pub ewma_upload_bps: Option<f64>,
    /// Fraction of samples in the window that were reachable (0.0..=1.0).
    pub availability_ratio: f64,
    /// Trailing count of consecutive unreachable samples.
    pub consecutive_failures: u32,
    /// Count of unreachable samples currently in the window.
    pub recent_failures: u32,
}

impl HealthSnapshot {
    /// Age in milliseconds of the most recent sample relative to `now_ms`.
    /// Returns `None` when there are no samples. Saturates at 0 for future
    /// timestamps (clock skew).
    pub fn age_ms(&self, now_ms: u64) -> Option<u64> {
        self.last_sample_ms.map(|t| now_ms.saturating_sub(t))
    }
}

/// Bounded EWMA-backed health history for a single candidate.
#[derive(Debug, Clone)]
pub struct HealthHistory {
    capacity: usize,
    alpha: f64,
    samples: VecDeque<HealthSample>,
    ewma_latency: Option<f64>,
    ewma_jitter: Option<f64>,
    ewma_loss: Option<f64>,
    ewma_handshake: Option<f64>,
    ewma_download: Option<f64>,
    ewma_upload: Option<f64>,
    last_sample_ms: Option<u64>,
    last_success_ms: Option<u64>,
    last_failure_ms: Option<u64>,
    last_reachable: bool,
    consecutive_failures: u32,
}

impl HealthHistory {
    /// Creates a bounded history. `capacity` is clamped to at least 1 and
    /// `alpha` to the open interval (0, 1].
    pub fn new(capacity: usize, alpha: f64) -> Self {
        let capacity = capacity.max(1);
        let alpha = alpha.clamp(f64::MIN_POSITIVE, 1.0);
        Self {
            capacity,
            alpha,
            samples: VecDeque::with_capacity(capacity),
            ewma_latency: None,
            ewma_jitter: None,
            ewma_loss: None,
            ewma_handshake: None,
            ewma_download: None,
            ewma_upload: None,
            last_sample_ms: None,
            last_success_ms: None,
            last_failure_ms: None,
            last_reachable: false,
            consecutive_failures: 0,
        }
    }

    /// Ingests a sample, evicting the oldest when at capacity (never grows
    /// without bound).
    pub fn record(&mut self, sample: HealthSample) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }

        self.last_sample_ms = Some(sample.timestamp_ms);
        self.last_reachable = sample.reachable;
        if sample.reachable {
            self.last_success_ms = Some(sample.timestamp_ms);
            self.consecutive_failures = 0;
        } else {
            self.last_failure_ms = Some(sample.timestamp_ms);
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }

        Self::update_ewma(&mut self.ewma_latency, sample.latency_ms, self.alpha);
        Self::update_ewma(&mut self.ewma_jitter, sample.jitter_ms, self.alpha);
        Self::update_ewma(&mut self.ewma_loss, sample.packet_loss_percent, self.alpha);
        Self::update_ewma(&mut self.ewma_handshake, sample.handshake_ms, self.alpha);
        Self::update_ewma(&mut self.ewma_download, sample.download_bps, self.alpha);
        Self::update_ewma(&mut self.ewma_upload, sample.upload_bps, self.alpha);

        self.samples.push_back(sample);
    }

    fn update_ewma(current: &mut Option<f64>, value: Option<f64>, alpha: f64) {
        if let Some(v) = value {
            *current = Some(match *current {
                Some(prev) => alpha * v + (1.0 - alpha) * prev,
                None => v,
            });
        }
    }

    /// Produces the aggregated snapshot used by scoring and selection.
    pub fn snapshot(&self) -> HealthSnapshot {
        let sample_count = self.samples.len();
        let recent_failures = self.samples.iter().filter(|s| !s.reachable).count() as u32;
        let reachable_count = sample_count as u32 - recent_failures;
        let availability_ratio = if sample_count == 0 {
            0.0
        } else {
            reachable_count as f64 / sample_count as f64
        };

        HealthSnapshot {
            sample_count,
            last_sample_ms: self.last_sample_ms,
            last_success_ms: self.last_success_ms,
            last_failure_ms: self.last_failure_ms,
            reachable: self.last_reachable,
            ewma_latency_ms: self.ewma_latency,
            ewma_jitter_ms: self.ewma_jitter,
            ewma_loss_percent: self.ewma_loss,
            ewma_handshake_ms: self.ewma_handshake,
            ewma_download_bps: self.ewma_download,
            ewma_upload_bps: self.ewma_upload,
            availability_ratio,
            consecutive_failures: self.consecutive_failures,
            recent_failures,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}
