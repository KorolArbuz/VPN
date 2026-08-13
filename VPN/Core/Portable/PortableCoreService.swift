//
//  PortableCoreService.swift
//  VPN
//
//  Single application-level owner of the KVNCore control-plane bridge. It is an
//  actor: all core access is serialized here (the C layer also has its own
//  mutex). SwiftUI views never create their own bridge/handle.
//
//  PASSIVE ONLY (Phase E): this service can register candidates, feed health,
//  and compute recommendations, but it NEVER performs a real VPN reconnect. The
//  existing Swift connection manager remains the authority for actual VPN state.
//  See docs/KVNCoreArchitecture.md.
//

import Foundation

actor PortableCoreService {
    private let bridge: KVNCoreBridge
    private var feature: PortableCoreFeature
    /// Candidate IDs currently registered in the core (control-plane runtime
    /// state only — NOT a second profile database).
    private var registeredCandidateIDs: Set<String> = []

    init(feature: PortableCoreFeature = .fromDefaults()) throws {
        self.bridge = try KVNCoreBridge()
        self.feature = feature
    }

    // MARK: - Diagnostics / configuration

    var coreVersion: String { bridge.coreVersion }
    var abiVersion: UInt32 { bridge.abiVersion }
    var schemaVersion: UInt32 { bridge.schemaVersion }
    var isFeatureEnabled: Bool { feature.isEnabled }

    func setFeature(_ feature: PortableCoreFeature) {
        self.feature = feature
    }

    // MARK: - Candidate synchronization (add / update / remove)

    /// Reconciles the core's candidate set with the given profiles. The Swift
    /// repository remains the source of truth; this only mirrors identity +
    /// connectivity metadata into the control plane.
    func syncCandidates(from profiles: [VPNProfile]) throws {
        var desired: [String: VPNProfile] = [:]
        for profile in profiles {
            desired[profile.id.uuidString] = profile
        }

        // Remove candidates no longer present.
        for staleID in registeredCandidateIDs.subtracting(desired.keys) {
            try bridge.removeCandidate(id: staleID)
            registeredCandidateIDs.remove(staleID)
        }

        // Add or update the rest.
        for (id, profile) in desired {
            let candidate = KVNCoreMapper.candidate(from: profile)
            if registeredCandidateIDs.contains(id) {
                try bridge.updateCandidate(candidate)
            } else {
                try bridge.registerCandidate(candidate)
                registeredCandidateIDs.insert(id)
            }
        }
    }

    func registeredCandidateCount() -> Int {
        registeredCandidateIDs.count
    }

    // MARK: - Signals

    func updateHealth(candidateID: String, sample: KVNHealthSampleDTO) throws {
        try bridge.updateHealth(candidateID: candidateID, sample: sample)
    }

    func setNetworkType(_ type: KVNNetworkType) throws {
        try bridge.setNetworkType(type)
    }

    /// Marks the candidate the platform believes is actually active/connected.
    /// Callers must only invoke this AFTER a real switch has occurred.
    func setCurrentCandidate(id: String?, now: Date = Date()) throws {
        try bridge.setCurrentCandidate(id: id, nowMs: Self.milliseconds(now))
    }

    // MARK: - Recommendations (passive)

    /// Returns a recommendation only when the feature flag is enabled; otherwise
    /// `nil` so production selection is completely unaffected. NEVER triggers a
    /// reconnect — the caller decides what (if anything) to do with it.
    func recommendation(now: Date = Date()) throws -> KVNSelectionDecisionDTO? {
        guard feature.isEnabled else { return nil }
        return try bridge.selectBest(nowMs: Self.milliseconds(now))
    }

    /// Flag-independent recommendation, for diagnostics/tests only.
    func selectBest(now: Date = Date()) throws -> KVNSelectionDecisionDTO {
        try bridge.selectBest(nowMs: Self.milliseconds(now))
    }

    func statistics(now: Date = Date()) throws -> KVNCoreStatisticsDTO {
        try bridge.statistics(nowMs: Self.milliseconds(now))
    }

    func controlPlaneState() throws -> KVNConnectionStateDTO {
        try bridge.state()
    }

    // MARK: - Routing

    func setRoutingRules(_ rules: [KVNRouteRuleDTO]) throws {
        try bridge.setRoutingRules(rules)
    }

    func resolveRoute(_ query: KVNRouteQueryDTO) throws -> KVNRouteActionDTO? {
        try bridge.resolveRoute(query)
    }

    // MARK: - Helpers

    private static func milliseconds(_ date: Date) -> UInt64 {
        let interval = date.timeIntervalSince1970
        guard interval > 0 else { return 0 }
        return UInt64(interval * 1000)
    }
}
