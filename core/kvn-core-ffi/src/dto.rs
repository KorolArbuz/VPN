//! Wire (JSON) request shapes for the C ABI.
//!
//! These deliberately reuse the pure-core serde types (`Endpoint`,
//! `HealthSample`, `RouteRule`, ...). None of those types has a field capable
//! of carrying a secret (no password/UUID/token/URI/metadata-map), so a
//! malicious or accidental secret in a request payload has nowhere to land and
//! cannot be echoed back in any response.
//!
//! Unknown JSON fields are ignored (serde default) for forward compatibility;
//! the mandatory `schema_version` is validated by the boundary before these
//! structs are constructed.

use kvn_core::config::CoreConfiguration;
use kvn_core::health::HealthSample;
use kvn_core::model::{Endpoint, NetworkType};
use kvn_core::routing::{RouteQuery, RouteRule};
use kvn_core::state::ConnectionEvent;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SetConfigurationRequest {
    pub config: CoreConfiguration,
}

#[derive(Debug, Deserialize)]
pub struct RegisterCandidateRequest {
    pub candidate_id: String,
    pub profile_id: String,
    pub endpoint: Endpoint,
}

#[derive(Debug, Deserialize)]
pub struct CandidateIdRequest {
    pub candidate_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCandidateRequest {
    pub candidate_id: String,
    pub endpoint: Endpoint,
}

#[derive(Debug, Deserialize)]
pub struct UpdateHealthRequest {
    pub candidate_id: String,
    pub sample: HealthSample,
}

#[derive(Debug, Deserialize)]
pub struct SetNetworkTypeRequest {
    pub network_type: NetworkType,
}

#[derive(Debug, Deserialize)]
pub struct SetCurrentCandidateRequest {
    /// `null` clears the current candidate.
    #[serde(default)]
    pub candidate_id: Option<String>,
    pub now_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct CandidateReportRequest {
    pub candidate_id: String,
    pub now_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct NowRequest {
    pub now_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct HandleEventRequest {
    pub event: ConnectionEvent,
    pub now_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct SetRoutingRulesRequest {
    pub rules: Vec<RouteRule>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveRouteRequest {
    pub query: RouteQuery,
}

#[derive(Debug, Deserialize)]
pub struct SetTrafficCountersRequest {
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
