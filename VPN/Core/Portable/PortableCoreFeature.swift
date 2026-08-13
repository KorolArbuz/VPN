//
//  PortableCoreFeature.swift
//  VPN
//
//  Feature flag gating the passive portable-core integration. Defaults to
//  FALSE: when disabled, the Rust control plane has ZERO effect on connection
//  selection or the live VPN flow.
//

import Foundation

nonisolated struct PortableCoreFeature: Sendable, Equatable {
    /// UserDefaults key for the flag. Not surfaced in production settings UI yet.
    static let storageKey = "portable.core.selection.enabled"

    var isEnabled: Bool

    init(isEnabled: Bool = false) {
        self.isEnabled = isEnabled
    }

    /// Reads the flag from UserDefaults (absent key => disabled).
    static func fromDefaults(_ defaults: UserDefaults = .standard) -> PortableCoreFeature {
        PortableCoreFeature(isEnabled: defaults.bool(forKey: storageKey))
    }

    static let disabled = PortableCoreFeature(isEnabled: false)
}
