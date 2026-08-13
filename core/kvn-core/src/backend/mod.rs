//! Portable backend capability descriptors.
//!
//! The core never launches a backend; it only reasons about what a backend
//! *can* do so incompatible candidates are excluded from selection.

use crate::model::ProtocolKind;
use serde::{Deserialize, Serialize};

/// What a data-plane backend supports. Used to filter out candidates whose
/// protocol cannot be carried by their declared backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub tcp: bool,
    pub udp: bool,
    pub ipv6: bool,
    pub multiplexing: bool,
    pub supported_protocols: Vec<ProtocolKind>,
    #[serde(default)]
    pub features: Vec<String>,
}

impl BackendCapabilities {
    pub fn new(supported_protocols: Vec<ProtocolKind>) -> Self {
        Self {
            tcp: true,
            udp: true,
            ipv6: true,
            multiplexing: false,
            supported_protocols,
            features: Vec::new(),
        }
    }

    /// Whether this backend can carry the given protocol.
    pub fn supports(&self, protocol: ProtocolKind) -> bool {
        self.supported_protocols.contains(&protocol)
    }
}
