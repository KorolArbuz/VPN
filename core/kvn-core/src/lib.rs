//! # kvn-core
//!
//! Portable, platform-agnostic **control plane** for a multi-protocol VPN
//! client. It decides *which* candidate to connect to and *when* to switch;
//! it never carries traffic and never launches a backend (that is the data
//! plane's job, on the platform side).
//!
//! ## Design invariants
//! * **No secrets.** UUIDs, passwords, keys, tokens, raw URIs and subscription
//!   URLs never enter this crate. Only opaque identities + connectivity
//!   metadata do.
//! * **No I/O, no clock.** The core performs no networking and never reads the
//!   wall clock; callers pass `now_ms`. This makes every decision deterministic
//!   and unit-testable.
//! * **Recommendations only.** [`KvnCore::select_best`] returns a
//!   [`SelectionDecision`]; the platform coordinator performs any real switch.
//! * **Safe Rust.** No `unsafe` in this crate; the FFI layer (Phase C) is the
//!   only place `unsafe` is allowed.

pub mod backend;
pub mod config;
pub mod error;
pub mod health;
pub mod model;
pub mod policy;
pub mod routing;
pub mod selector;
pub mod state;
pub mod stats;

mod engine;

pub use config::{CoreConfiguration, SCHEMA_VERSION};
pub use engine::KvnCore;
pub use error::{CoreError, CoreResult};

/// Crate version string (from Cargo).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the semantic version of the core.
pub fn version() -> &'static str {
    VERSION
}

/// Returns the schema version used for JSON crossing ABI/IPC boundaries.
pub fn schema_version() -> u32 {
    SCHEMA_VERSION
}
