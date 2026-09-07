//
//  NetworkContextV2Tests.swift
//  VPNTests
//
//  Deterministic Build-9 NetworkContext V2 foundation regressions.
//

import Foundation
import Testing
@testable import VPN

@Suite(.serialized)
struct NetworkContextV2CompatibilityTests {
    @Test
    func build8V1ContextAndSnapshotRemainDecodable() throws {
        let contextJSON = """
        {
          "schemaVersion": 1,
          "interfaceClass": "wifi",
          "isExpensive": false,
          "isConstrained": true,
          "supportsIPv4": true,
          "supportsIPv6": false
        }
        """
        let context = try JSONDecoder().decode(
            NetworkContext.self,
            from: Data(contextJSON.utf8)
        )

        #expect(context.schemaVersion == 1)
        #expect(context.identitySource == .coarseOnly)
        #expect(context.environmentIdentity == .empty)
        #expect(
            context.stableKey
                == "v1|wifi|not-expensive|constrained|ipv4|no-ipv6"
        )

        let snapshotJSON = """
        {
          "schemaVersion": 1,
          "contextProfileRecords": [],
          "profileRecords": [],
          "protocolRecords": []
        }
        """
        let snapshot = try JSONDecoder().decode(
            SmartConnectionLearningSnapshot.self,
            from: Data(snapshotJSON.utf8)
        )

        #expect(snapshot.schemaVersion == 1)
        #expect(snapshot.contextProfileRecords.isEmpty)
        #expect(snapshot.lastSafelyKnownEnvironmentObservation == nil)
        #expect(SmartConnectionLearningLocation.fileName == "smart-connection-learning-v1.json")
    }

    @Test
    func twoObservedIdentitiesProduceDifferentExactContexts() {
        let first = makeV2Context(underlyingASN: 64_512)
        let second = makeV2Context(underlyingASN: 64_513)

        #expect(first.schemaVersion == 2)
        #expect(second.schemaVersion == 2)
        #expect(first.hasExactEnvironmentIdentity)
        #expect(second.hasExactEnvironmentIdentity)
        #expect(first.physicalEnvironmentKey != second.physicalEnvironmentKey)
        #expect(first.stableKey != second.stableKey)
        #expect(first != second)
        #expect(first.matchingCoarseContext == second.matchingCoarseContext)
    }

    @Test
    func unavailableASNFallsBackToRealV1Context() async {
        let client = CountingOwnedMetadataClient(underlyingASN: nil)
        let enricher = SmartConnectionNetworkContextEnricher(
            resolver: OwnedASNNetworkEnvironmentResolver(client: client)
        )

        let result = await enricher.resolve(
            coarseContext: testWiFiContext,
            authoritativeConnection: testAuthority(status: .disconnected),
            observedAt: testNow
        )

        #expect(result.disposition == .unavailable)
        #expect(result.context == testWiFiContext)
        #expect(result.context.schemaVersion == 1)
        #expect(result.safeObservation == nil)
        #expect(await client.callCount() == 1)
    }

    @Test
    func ownedBackendResponseContractCarriesOnlyVersionAndASN() throws {
        let response = SmartConnectionOwnedNetworkMetadata(
            underlyingASN: 64_512
        )
        let data = try JSONEncoder().encode(response)
        let object = try #require(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )

        #expect(Set(object.keys) == ["schemaVersion", "underlyingASN"])
        #expect(object["schemaVersion"] as? Int == 1)
        #expect(object["underlyingASN"] as? Int == 64_512)
    }

    @Test
    func localSSIDTaggingIsRejectedByCurrentCapabilityContract() {
        #expect(
            SmartConnectionNetworkEnvironmentCapabilityContract
                .currentSSIDAvailable == false
        )
        #expect(
            SmartConnectionNetworkEnvironmentCapabilityContract
                .currentBSSIDAvailable == false
        )
        #expect(
            SmartConnectionNetworkEnvironmentCapabilityContract
                .localNetworkTaggingEnabled == false
        )
        #expect(
            SmartConnectionNetworkEnvironmentCapabilityContract
                .ownedUnderlyingASNEndpointAvailable == false
        )
        #expect(
            SmartConnectionNetworkEnvironmentCapabilityContract
                .permitsPublicThirdPartyASNService == false
        )
    }
}

@Suite(.serialized)
struct NetworkContextV2PrivacyAndStorageTests {
    @Test
    func persistedJSONContainsOnlyOpaqueIdentityAndNeverRawInputsOrSecret() throws {
        let rawNetworkName = "Build9 Raw Office SSID"
        let hmacSecret = "build9-test-hmac-secret-must-never-persist"
        let tag = makeLocalNetworkTag(
            "0123456789abcdef0123456789abcdef"
        )
        let identity = SmartConnectionEnvironmentIdentity(
            localNetworkTag: tag,
            underlyingASN: 64_512
        )
        let exactContext = makeV2Context(identity: identity)
        let profileID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
            ?? UUID()
        let observation = SmartConnectionSafeEnvironmentObservation(
            coarseContext: testWiFiContext,
            environmentIdentity: identity,
            observedAt: testNow
        )
        let snapshot = SmartConnectionLearningSnapshot(
            contextProfileRecords: [
                SmartConnectionContextProfileRecord(
                    context: exactContext,
                    profileID: profileID,
                    protocolType: .vless,
                    statistics: SmartConnectionStatistics()
                )
            ],
            lastSafelyKnownEnvironmentObservation: observation
        )

        let data = try JSONEncoder().encode(snapshot)
        let json = String(decoding: data, as: UTF8.self)
        let lowercaseJSON = json.lowercased()

        #expect(json.contains(tag.rawValue))
        #expect(json.contains("\"underlyingASN\""))
        #expect(json.contains(rawNetworkName) == false)
        #expect(json.contains(hmacSecret) == false)
        for forbiddenField in SmartConnectionLearningPrivacyContract
            .forbiddenPersistedFieldNames {
            #expect(
                lowercaseJSON.contains(
                    "\"\(forbiddenField.lowercased())\""
                ) == false
            )
        }
    }

    @Test
    func privacySourceContractEnumeratesEveryForbiddenIdentityClass() {
        let forbidden = SmartConnectionLearningPrivacyContract
            .forbiddenPersistedFieldNames
        let requiredForbidden: Set<String> = [
            "ssid",
            "bssid",
            "rawPublicIP",
            "publicIP",
            "privateIP",
            "localIP",
            "gatewayIP",
            "mac",
            "location",
            "deviceIdentifier",
            "credentials",
            "subscriptionURI",
            "providerConfiguration",
            "hmacSecret",
            "hmacKey"
        ]

        #expect(requiredForbidden.isSubset(of: forbidden))
        #expect(
            SmartConnectionLearningPrivacyContract
                .allowedPersistedIdentityFieldNames
                == ["localNetworkTag", "underlyingASN"]
        )
    }

    @Test
    func V2ContextStorageRemainsBoundedAndRetainsMatchingV1Prior() {
        let profileID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")
            ?? UUID()
        var snapshot = SmartConnectionLearningSnapshot.empty

        for offset in 0..<16 {
            let context = makeV2Context(
                underlyingASN: UInt32(64_512 + offset)
            )
            snapshot = SmartConnectionLearningTransform.mutateStatistics(
                snapshot,
                profileID: profileID,
                protocolType: .vless,
                context: context
            ) {
                $0.recordConnectionSuccess(
                    connectDuration: 1,
                    at: testNow.addingTimeInterval(TimeInterval(offset))
                )
            }
            #expect(
                snapshot.contextProfileRecords
                    .filter { $0.profileID == profileID }
                    .count
                    <= SmartConnectionLearningTransform.maximumContextsPerProfile
            )
        }

        let retained = snapshot.contextProfileRecords.filter {
            $0.profileID == profileID
        }
        #expect(
            retained.count
                == SmartConnectionLearningTransform.maximumContextsPerProfile
        )
        #expect(retained.contains { $0.context == testWiFiContext })
        #expect(
            snapshot.contextStatistics(
                profileID: profileID,
                protocolType: .vless,
                context: testWiFiContext
            ).attemptCount == 16
        )
        #expect(
            snapshot.profileStatistics(
                profileID: profileID,
                protocolType: .vless
            ).attemptCount == 16
        )
        #expect(snapshot.protocolStatistics(.vless).attemptCount == 16)
    }
}

@Suite(.serialized)
struct NetworkContextV2HierarchyTests {
    @Test
    func lowSampleV2ShrinksStronglyTowardMatchingV1() {
        let profile = makeV2TestProfile()
        let exactContext = makeV2Context(underlyingASN: 64_512)
        let coarseStatistics = makeReliabilityStatistics(
            successes: 40,
            failures: 0
        )
        let exactStatistics = makeReliabilityStatistics(
            successes: 0,
            failures: 1
        )
        let learning = SmartConnectionLearningSnapshot(
            contextProfileRecords: [
                SmartConnectionContextProfileRecord(
                    context: testWiFiContext,
                    profileID: profile.id,
                    protocolType: profile.protocolType,
                    statistics: coarseStatistics
                ),
                SmartConnectionContextProfileRecord(
                    context: exactContext,
                    profileID: profile.id,
                    protocolType: profile.protocolType,
                    statistics: exactStatistics
                )
            ]
        )

        let reliability = SmartConnectionScoreCalculator().score(
            profile: profile,
            context: exactContext,
            learning: learning,
            now: testNow
        ).breakdown.reliability

        #expect(reliability > 80)
        #expect(reliability < 95)
    }

    @Test
    func sufficientV2EvidenceDominatesMatchingV1() {
        let profile = makeV2TestProfile()
        let exactContext = makeV2Context(underlyingASN: 64_512)
        let coarseStatistics = makeReliabilityStatistics(
            successes: 40,
            failures: 0
        )
        let exactStatistics = makeReliabilityStatistics(
            successes: 0,
            failures: 200
        )
        let learning = SmartConnectionLearningSnapshot(
            contextProfileRecords: [
                SmartConnectionContextProfileRecord(
                    context: testWiFiContext,
                    profileID: profile.id,
                    protocolType: profile.protocolType,
                    statistics: coarseStatistics
                ),
                SmartConnectionContextProfileRecord(
                    context: exactContext,
                    profileID: profile.id,
                    protocolType: profile.protocolType,
                    statistics: exactStatistics
                )
            ]
        )

        let reliability = SmartConnectionScoreCalculator().score(
            profile: profile,
            context: exactContext,
            learning: learning,
            now: testNow
        ).breakdown.reliability

        #expect(reliability < 10)
    }
}

@Suite(.serialized)
struct NetworkContextV2AsyncSafetyTests {
    @Test
    func staleAsyncIdentityResolutionIsRejectedDeterministically() async {
        let resolver = ControlledNetworkEnvironmentResolver()
        let enricher = SmartConnectionNetworkContextEnricher(resolver: resolver)
        let firstCoarse = testWiFiContext
        let secondCoarse = NetworkContext(
            interfaceClass: .cellular,
            isExpensive: true,
            supportsIPv4: true,
            supportsIPv6: true
        )
        let disconnected = testAuthority(status: .disconnected)

        let firstTask = Task {
            await enricher.resolve(
                coarseContext: firstCoarse,
                authoritativeConnection: disconnected,
                observedAt: testNow
            )
        }
        let firstPending = await waitForPendingCount(1, resolver: resolver)
        #expect(firstPending)

        let secondTask = Task {
            await enricher.resolve(
                coarseContext: secondCoarse,
                authoritativeConnection: disconnected,
                observedAt: testNow.addingTimeInterval(1)
            )
        }
        let secondPending = await waitForPendingCount(2, resolver: resolver)
        #expect(secondPending)

        await resolver.resumeNext(
            with: SmartConnectionEnvironmentIdentity(underlyingASN: 64_512)
        )
        let firstResult = await firstTask.value

        await resolver.resumeNext(
            with: SmartConnectionEnvironmentIdentity(underlyingASN: 64_513)
        )
        let secondResult = await secondTask.value

        #expect(firstResult.disposition == .stale)
        #expect(firstResult.context == firstCoarse)
        #expect(firstResult.context.hasExactEnvironmentIdentity == false)
        #expect(secondResult.disposition == .accepted)
        #expect(secondResult.context.matchingCoarseContext == secondCoarse)
        #expect(secondResult.context.environmentIdentity.underlyingASN == 64_513)
    }

    @Test
    func connectedVPNBlocksOrdinaryASNRefresh() async {
        let client = CountingOwnedMetadataClient(underlyingASN: 64_512)
        let enricher = SmartConnectionNetworkContextEnricher(
            resolver: OwnedASNNetworkEnvironmentResolver(client: client)
        )

        let result = await enricher.resolve(
            coarseContext: testWiFiContext,
            authoritativeConnection: testAuthority(status: .connected),
            observedAt: testNow
        )

        #expect(result.disposition == .blockedByActiveVPN)
        #expect(result.context == testWiFiContext)
        #expect(await client.callCount() == 0)
    }

    @Test
    func restoredConnectedVPNBlocksRefreshAndKeepsLastSafeIdentity() async {
        let oldIdentity = SmartConnectionEnvironmentIdentity(
            underlyingASN: 64_500
        )
        let oldObservation = SmartConnectionSafeEnvironmentObservation(
            coarseContext: testWiFiContext,
            environmentIdentity: oldIdentity,
            observedAt: testNow.addingTimeInterval(-3_600)
        )
        let client = CountingOwnedMetadataClient(underlyingASN: 64_512)
        let enricher = SmartConnectionNetworkContextEnricher(
            resolver: OwnedASNNetworkEnvironmentResolver(client: client),
            lastSafelyKnownObservation: oldObservation
        )

        let result = await enricher.resolve(
            coarseContext: testWiFiContext,
            authoritativeConnection: testAuthority(status: .connected),
            observedAt: testNow
        )
        let retained = await enricher.lastSafelyKnownObservation()

        #expect(result.disposition == .blockedByActiveVPN)
        #expect(await client.callCount() == 0)
        #expect(retained == oldObservation)
    }

    @Test
    func disconnectedVPNPermitsSafeOwnedEnvironmentResolution() async {
        let client = CountingOwnedMetadataClient(underlyingASN: 64_512)
        let enricher = SmartConnectionNetworkContextEnricher(
            resolver: OwnedASNNetworkEnvironmentResolver(client: client)
        )

        let result = await enricher.resolve(
            coarseContext: testWiFiContext,
            authoritativeConnection: testAuthority(status: .disconnected),
            observedAt: testNow
        )

        #expect(result.disposition == .accepted)
        #expect(result.context.hasExactEnvironmentIdentity)
        #expect(result.context.environmentIdentity.underlyingASN == 64_512)
        #expect(result.safeObservation?.isValid == true)
        #expect(await client.callCount() == 1)
    }

    @Test
    func everyActiveOrTransitionalSystemStatusBlocksOrdinaryResolution() {
        for status in [
            VPNSystemConnectionStatus.connected,
            .connecting,
            .reasserting,
            .disconnecting
        ] {
            #expect(
                SmartConnectionNetworkContextEnricher.isResolutionAllowed(
                    access: .ordinaryNetworkRequest,
                    authoritativeConnection: testAuthority(status: status)
                ) == false
            )
        }
        #expect(
            SmartConnectionNetworkContextEnricher.isResolutionAllowed(
                access: .ordinaryNetworkRequest,
                authoritativeConnection: testAuthority(status: .disconnected)
            )
        )
        #expect(
            SmartConnectionNetworkContextEnricher.isResolutionAllowed(
                access: .ordinaryNetworkRequest,
                authoritativeConnection: testAuthority(status: .invalid)
            )
        )
    }
}

@Suite(.serialized)
struct NetworkContextV2ScopeContractTests {
    @Test
    func SwiftRemainsSoleProductionSelector() {
        #expect(
            SmartConnectionSelectionAuthorityContract.production
                == "swift-smart-connection-planner"
        )
    }

    @Test
    func environmentChangesCannotAuthorizeMidSessionSwitching() {
        #expect(SmartConnectionLiveSwitchingContract.isEnabled == false)
        #expect(
            SmartConnectionLiveSwitchingContract
                .automaticRecommendationsApplyOnlyWhileDisconnected
        )
    }
}

private let testNow = Date(timeIntervalSince1970: 2_100_000_000)

private let testWiFiContext = NetworkContext(
    interfaceClass: .wifi,
    isExpensive: false,
    isConstrained: false,
    supportsIPv4: true,
    supportsIPv6: true
)

private func makeV2Context(underlyingASN: UInt32) -> NetworkContext {
    makeV2Context(
        identity: SmartConnectionEnvironmentIdentity(
            underlyingASN: underlyingASN
        )
    )
}

private func makeV2Context(
    identity: SmartConnectionEnvironmentIdentity
) -> NetworkContext {
    guard let context = NetworkContext.observedV2(
        coarseContext: testWiFiContext,
        environmentIdentity: identity
    ) else {
        preconditionFailure("Test identity must produce an exact V2 context.")
    }
    return context
}

private func makeLocalNetworkTag(
    _ rawValue: String
) -> SmartConnectionLocalNetworkTag {
    guard let tag = SmartConnectionLocalNetworkTag(rawValue: rawValue) else {
        preconditionFailure("Test tag must use the production opaque format.")
    }
    return tag
}

private func makeReliabilityStatistics(
    successes: Int,
    failures: Int
) -> SmartConnectionStatistics {
    var statistics = SmartConnectionStatistics()
    statistics.attemptCount = successes + failures
    statistics.successfulConnectionCount = successes
    statistics.failedConnectionCount = failures
    statistics.lastUpdatedAt = testNow
    return statistics
}

private func makeV2TestProfile() -> VPNProfile {
    VPNProfile.draft(
        name: "NetworkContext V2 Test",
        protocolType: .vless,
        serverAddress: "example.invalid",
        port: 443,
        credentialReference: "network-context-v2-test-credential",
        protocolConfiguration: .vless(
            VLESSProfileConfiguration(flow: nil, encryption: "none")
        ),
        source: .manual,
        now: testNow
    )
}

private func testAuthority(
    status: VPNSystemConnectionStatus
) -> VPNAuthoritativeConnection {
    VPNAuthoritativeConnection(
        state: status.dashboardState,
        systemStatus: status,
        profileID: status.isActive
            ? UUID(uuidString: "99999999-8888-7777-6666-555555555555")
            : nil,
        provider: status.isActive ? .wireGuard : nil,
        hasMultipleActiveManagers: false
    )
}

private actor CountingOwnedMetadataClient:
    SmartConnectionOwnedNetworkMetadataFetching {
    private let underlyingASN: UInt32?
    private var calls = 0

    init(underlyingASN: UInt32?) {
        self.underlyingASN = underlyingASN
    }

    func fetchUnderlyingNetworkMetadata() async throws
        -> SmartConnectionOwnedNetworkMetadata {
        calls += 1
        return SmartConnectionOwnedNetworkMetadata(
            underlyingASN: underlyingASN
        )
    }

    func callCount() -> Int {
        calls
    }
}

private final class ControlledNetworkEnvironmentResolver:
    SmartConnectionNetworkEnvironmentResolving,
    @unchecked Sendable {
    let resolutionAccess: SmartConnectionEnvironmentResolutionAccess =
        .ordinaryNetworkRequest

    private let storage = ControlledNetworkEnvironmentStorage()

    func resolveEnvironment(
        for coarseContext: NetworkContext
    ) async throws -> SmartConnectionEnvironmentIdentity? {
        await storage.resolve(coarseContext: coarseContext)
    }

    func pendingCount() async -> Int {
        await storage.pendingCount()
    }

    func resumeNext(
        with identity: SmartConnectionEnvironmentIdentity?
    ) async {
        await storage.resumeNext(with: identity)
    }
}

private actor ControlledNetworkEnvironmentStorage {
    private struct Pending {
        var coarseContext: NetworkContext
        var continuation:
            CheckedContinuation<SmartConnectionEnvironmentIdentity?, Never>
    }

    private var pending: [Pending] = []

    func resolve(
        coarseContext: NetworkContext
    ) async -> SmartConnectionEnvironmentIdentity? {
        await withCheckedContinuation { continuation in
            pending.append(
                Pending(
                    coarseContext: coarseContext,
                    continuation: continuation
                )
            )
        }
    }

    func pendingCount() -> Int {
        pending.count
    }

    func resumeNext(
        with identity: SmartConnectionEnvironmentIdentity?
    ) {
        guard pending.isEmpty == false else {
            return
        }
        pending.removeFirst().continuation.resume(returning: identity)
    }
}

private func waitForPendingCount(
    _ expected: Int,
    resolver: ControlledNetworkEnvironmentResolver
) async -> Bool {
    for _ in 0..<1_000 {
        if await resolver.pendingCount() == expected {
            return true
        }
        await Task.yield()
    }
    return false
}
