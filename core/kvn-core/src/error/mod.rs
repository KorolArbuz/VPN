//! Typed, sanitized errors for the control-plane core.
//!
//! Error messages never contain secrets (UUIDs, passwords, keys, tokens, raw
//! URIs). Only opaque candidate identifiers and coarse categories are allowed.

use thiserror::Error;

/// Result alias used across the core.
pub type CoreResult<T> = Result<T, CoreError>;

/// All fallible operations in the control plane surface one of these.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreError {
    /// A candidate identifier was referenced but is not registered.
    #[error("unknown candidate: {0}")]
    UnknownCandidate(String),

    /// Attempted to register a candidate identifier that already exists.
    #[error("duplicate candidate: {0}")]
    DuplicateCandidate(String),

    /// No candidate is currently selectable (all disabled/unavailable/cooldown).
    #[error("no healthy candidates")]
    NoHealthyCandidates,

    /// The requested connection state transition is not allowed.
    #[error("invalid state transition from {from} on event {event}")]
    InvalidStateTransition { from: String, event: String },

    /// Provided configuration is structurally invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// A JSON payload crossing a boundary could not be (de)serialized.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A structurally valid but semantically rejected input.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
