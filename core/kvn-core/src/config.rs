//! Aggregate, serializable configuration for the control-plane core.

use crate::backend::BackendCapabilities;
use crate::model::BackendKind;
use crate::policy::{CircuitBreakerPolicy, ProtocolPreference, ScoringPolicy, SelectionPolicy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema version for any JSON crossing an ABI/IPC boundary.
pub const SCHEMA_VERSION: u32 = 1;

/// Complete tunable configuration. Applied via `set_configuration`; policies are
/// read live at scoring/selection time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreConfiguration {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Bounded per-candidate health history length.
    pub health_capacity: usize,
    /// EWMA smoothing factor in (0, 1].
    pub ewma_alpha: f64,
    pub scoring: ScoringPolicy,
    pub selection: SelectionPolicy,
    pub circuit_breaker: CircuitBreakerPolicy,
    pub preference: ProtocolPreference,
    /// Declared backend capabilities. When empty, compatibility filtering is
    /// skipped (all backends assumed capable). When non-empty, a candidate is
    /// only selectable if its backend is present and supports its protocol.
    #[serde(default)]
    pub backends: BTreeMap<BackendKind, BackendCapabilities>,
}

fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

impl Default for CoreConfiguration {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            health_capacity: 32,
            ewma_alpha: 0.3,
            scoring: ScoringPolicy::default(),
            selection: SelectionPolicy::default(),
            circuit_breaker: CircuitBreakerPolicy::default(),
            preference: ProtocolPreference::default(),
            backends: BTreeMap::new(),
        }
    }
}
