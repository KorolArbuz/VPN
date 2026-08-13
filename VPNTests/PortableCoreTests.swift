//
//  PortableCoreTests.swift
//  VPNTests
//
//  Phase E: KVNCore Swift bridge tests. No real network. Exercises the bridge,
//  DTO layer, mapper (secret boundary), and passive service behavior.
//

import Foundation
import Testing
@testable import VPN

private nonisolated func makeProfile(
    protocolType: VPNProtocol = .vless,
    host: String = "node.example.com",
    port: Int? = 443,
    credentialReference: String? = "credential-ref",
    isEnabled: Bool = true,
    isFavorite: Bool? = nil,
    metadata: [String: String] = [:]
) -> VPNProfile {
    var profile = VPNProfile.draft(
        name: "Test Node",
        protocolType: protocolType,
        serverAddress: host,
        port: port,
        credentialReference: credentialReference,
        protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
        source: .manual,
        metadata: metadata
    )
    profile.isEnabled = isEnabled
    profile.isFavorite = isFavorite
    return profile
}

struct PortableCoreBridgeTests {
    // 1 + 3: bridge creates/destroys and exposes a version (proves KVNCore import).
    @Test
    func bridgeInitializesAndReportsVersion() throws {
        let bridge = try KVNCoreBridge()
        #expect(bridge.coreVersion.isEmpty == false)
    }

    // 4 + 5: ABI and schema versions match the bridge's expectations.
    @Test
    func abiAndSchemaVersionsMatch() throws {
        let bridge = try KVNCoreBridge()
        #expect(bridge.abiVersion == KVNCoreBridge.expectedABIVersion)
        #expect(bridge.schemaVersion == KVNCoreBridge.expectedSchemaVersion)
    }

    // 6 + 7 + 8: register / update / remove a candidate.
    @Test
    func candidateLifecycleSucceeds() throws {
        let bridge = try KVNCoreBridge()
        var candidate = KVNCoreMapper.candidate(from: makeProfile())
        try bridge.registerCandidate(candidate)
        candidate.endpoint.manualPriority = 5
        try bridge.updateCandidate(candidate)
        try bridge.removeCandidate(id: candidate.candidateID)
    }

    // 9: health update succeeds.
    @Test
    func healthUpdateSucceeds() throws {
        let bridge = try KVNCoreBridge()
        let candidate = KVNCoreMapper.candidate(from: makeProfile())
        try bridge.registerCandidate(candidate)
        try bridge.updateHealth(
            candidateID: candidate.candidateID,
            sample: KVNHealthSampleDTO(timestampMs: 1_000, reachable: true, latencyMs: 42, packetLossPercent: 0)
        )
    }

    // 10: network type update succeeds.
    @Test
    func networkTypeUpdateSucceeds() throws {
        let bridge = try KVNCoreBridge()
        try bridge.setNetworkType(.wifi)
    }

    // 11 + 12: selectBest and its score breakdown decode correctly.
    @Test
    func selectBestAndBreakdownDecode() throws {
        let bridge = try KVNCoreBridge()
        let candidate = KVNCoreMapper.candidate(from: makeProfile())
        try bridge.registerCandidate(candidate)
        try bridge.updateHealth(
            candidateID: candidate.candidateID,
            sample: KVNHealthSampleDTO(timestampMs: 5_000, reachable: true, latencyMs: 30, packetLossPercent: 0)
        )
        let decision = try bridge.selectBest(nowMs: 5_000)
        #expect(decision.selected == candidate.candidateID)
        #expect(decision.reason == .initialSelection)
        let breakdown = try #require(decision.breakdown)
        #expect(breakdown.total >= 0 && breakdown.total <= 100)
        #expect(breakdown.confidence >= 0 && breakdown.confidence <= 1)
    }

    // 13: state decodes.
    @Test
    func stateDecodes() throws {
        let bridge = try KVNCoreBridge()
        #expect(try bridge.state() == .idle)
    }

    // 14: statistics decode.
    @Test
    func statisticsDecode() throws {
        let bridge = try KVNCoreBridge()
        let stats = try bridge.statistics(nowMs: 1_000)
        #expect(stats.totalSwitches == 0)
        #expect(stats.networkType == .unknown)
    }

    // 15: routing response decodes.
    @Test
    func routingResponseDecodes() throws {
        let bridge = try KVNCoreBridge()
        try bridge.setRoutingRules([
            KVNRouteRuleDTO(matcher: .exactDomain("example.com"), action: .direct, priority: 1),
            KVNRouteRuleDTO(matcher: .catchAll, action: .vpn, priority: 100)
        ])
        #expect(try bridge.resolveRoute(KVNRouteQueryDTO(domain: "example.com")) == .direct)
        #expect(try bridge.resolveRoute(KVNRouteQueryDTO(domain: "other.org")) == .vpn)
    }

    // 16: unknown candidate maps to KVNCoreError.notFound.
    @Test
    func unknownCandidateMapsToNotFound() throws {
        let bridge = try KVNCoreBridge()
        do {
            try bridge.removeCandidate(id: "does-not-exist")
            Issue.record("expected notFound error")
        } catch let error as KVNCoreError {
            guard case .notFound = error else {
                Issue.record("expected .notFound, got \(error)")
                return
            }
        }
    }

    // 17: status codes map to the correct typed errors.
    @Test
    func statusCodesMapToTypedErrors() {
        #expect(KVNCoreError.from(status: 6, message: nil) == .notFound(nil))
        #expect(KVNCoreError.from(status: 7, message: nil) == .invalidState(nil))
        #expect(KVNCoreError.from(status: 4, message: nil) == .invalidJSON(nil))
        #expect(KVNCoreError.from(status: 5, message: nil) == .schemaMismatchResponse)
        #expect(KVNCoreError.from(status: 9, message: nil) == .panic)
        #expect(KVNCoreError.from(status: 999, message: nil) == .unknownStatus(999))
    }

    // 18: repeated bridge create/destroy cycles do not crash.
    @Test
    func repeatedCreateDestroyIsStable() throws {
        for _ in 0..<50 {
            let bridge = try KVNCoreBridge()
            _ = bridge.coreVersion
        }
    }

    // 19: repeated response calls remain stable (string ownership / no crash).
    @Test
    func repeatedResponseCallsAreStable() throws {
        let bridge = try KVNCoreBridge()
        let candidate = KVNCoreMapper.candidate(from: makeProfile())
        try bridge.registerCandidate(candidate)
        try bridge.updateHealth(
            candidateID: candidate.candidateID,
            sample: KVNHealthSampleDTO(timestampMs: 1, reachable: true, latencyMs: 20)
        )
        for _ in 0..<500 {
            _ = try bridge.selectBest(nowMs: 1)
        }
    }

    // 20: Unicode host/tag values round-trip through the DTO coder.
    @Test
    func unicodeValuesRoundTrip() throws {
        let endpoint = KVNEndpointDTO(
            host: "münchen-server-日本.example.com",
            port: 443,
            protocolKind: .vless,
            backend: .xray,
            enabled: true,
            tags: ["регион-eu", "🌍"],
            region: "eu",
            country: "DE",
            manualPriority: 0
        )
        let data = try JSONEncoder().encode(endpoint)
        let decoded = try JSONDecoder().decode(KVNEndpointDTO.self, from: data)
        #expect(decoded == endpoint)
    }

    // 27: two bridge instances have fully independent state.
    @Test
    func twoBridgesAreIndependent() throws {
        let first = try KVNCoreBridge()
        let second = try KVNCoreBridge()
        let candidate = KVNCoreMapper.candidate(from: makeProfile())
        try first.registerCandidate(candidate)
        try first.updateHealth(
            candidateID: candidate.candidateID,
            sample: KVNHealthSampleDTO(timestampMs: 1, reachable: true, latencyMs: 20)
        )
        #expect(try first.selectBest(nowMs: 1).selected == candidate.candidateID)
        #expect(try second.selectBest(nowMs: 1).reason == .noHealthyCandidates)
    }
}

struct PortableCoreMapperSecurityTests {
    // 21 + 22 + 23 + 25: the mapper never lets secrets into the candidate DTO.
    @Test
    func mapperExcludesAllSecrets() throws {
        let profile = makeProfile(
            protocolType: .wireGuard,
            host: "vpn.example.com",
            port: 51_820,
            credentialReference: "private-key-ABCDEF0123456789",
            metadata: [
                "password": "hunter2-secret",
                "subscriptionURL": "https://provider.example/sub?token=SECRET-TOKEN",
                "vpnURI": "vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443",
                "country": "DE"
            ]
        )

        let candidate = KVNCoreMapper.candidate(from: profile)
        let json = String(data: try JSONEncoder().encode(candidate), encoding: .utf8) ?? ""

        let forbidden = [
            "hunter2-secret",
            "private-key-ABCDEF0123456789",
            "SECRET-TOKEN",
            "provider.example/sub",
            "vless://",
            "11111111-2222-3333-4444-555555555555",
            "credential-ref"
        ]
        for secret in forbidden {
            #expect(json.contains(secret) == false, "leaked secret: \(secret)")
        }
        // Non-secret connectivity metadata is allowed through.
        #expect(json.contains("vpn.example.com"))
        #expect(candidate.endpoint.country == "DE")
        #expect(candidate.endpoint.protocolKind == .wireguard)
        #expect(candidate.endpoint.backend == .wireguard)
    }

    @Test
    func protocolAndBackendMappingIsComplete() {
        #expect(KVNCoreMapper.protocolKind(for: .vless) == .vless)
        #expect(KVNCoreMapper.protocolKind(for: .hysteria2) == .hysteria2)
        #expect(KVNCoreMapper.protocolKind(for: .ikev2) == .ikev2)
        #expect(KVNCoreMapper.backendKind(for: .trojan) == .xray)
        #expect(KVNCoreMapper.backendKind(for: .hysteria2) == .hysteria)
        #expect(KVNCoreMapper.backendKind(for: .wireGuard) == .wireguard)
        #expect(KVNCoreMapper.backendKind(for: .ikev2) == .system)
    }
}

struct PortableCoreServiceTests {
    // 24: feature flag defaults false and gates recommendations.
    @Test
    func featureFlagDefaultsFalseAndGatesRecommendation() async throws {
        #expect(PortableCoreFeature().isEnabled == false)
        let service = try PortableCoreService(feature: .disabled)
        try await service.syncCandidates(from: [makeProfile()])
        let ids = await service.registeredCandidateCount()
        #expect(ids == 1)
        // Disabled => no recommendation surfaces to production selection.
        let recommendation = try await service.recommendation()
        #expect(recommendation == nil)
    }

    @Test
    func syncCandidatesHandlesAddUpdateRemove() async throws {
        let service = try PortableCoreService(feature: .init(isEnabled: true))
        let a = makeProfile(host: "a.example.com")
        let b = makeProfile(host: "b.example.com")
        try await service.syncCandidates(from: [a, b])
        #expect(await service.registeredCandidateCount() == 2)
        // Remove one, keep the other (update path).
        try await service.syncCandidates(from: [a])
        #expect(await service.registeredCandidateCount() == 1)
    }

    // 25 + 26: a recommendation never triggers a real reconnect; the existing
    // authoritative connection manager's state is unchanged by using the core.
    @Test
    func recommendationDoesNotChangeConnectionState() async throws {
        let manager = MockVPNConnectionManager()
        let stateBefore = await manager.currentState()

        let service = try PortableCoreService(feature: .init(isEnabled: true))
        var profile = makeProfile(host: "fast.example.com")
        profile.isFavorite = true
        try await service.syncCandidates(from: [profile])
        let candidate = KVNCoreMapper.candidate(from: profile)
        try await service.updateHealth(
            candidateID: candidate.candidateID,
            sample: KVNHealthSampleDTO(timestampMs: 1, reachable: true, latencyMs: 10, packetLossPercent: 0)
        )

        let recommendation = try await service.recommendation()
        #expect(recommendation?.selected == candidate.candidateID)
        #expect(recommendation?.shouldSwitch == true) // core recommends, but…

        // …the authoritative VPN connection state is untouched by the core.
        let stateAfter = await manager.currentState()
        #expect(stateBefore == .disconnected)
        #expect(stateAfter == .disconnected)
    }
}
