//
//  SmartConnectionTests.swift
//  VPNTests
//
//  Deterministic regressions for profile-atomic Smart Connection behavior.
//

import Foundation
import Testing
@testable import VPN

@Suite(.serialized)
struct SmartConnectionPresentationTests {
    @Test
    @MainActor
    func automaticModeDoesNotExposeSelectableProfiles() async throws {
        let profiles = [makeSmartProfile(index: 1), makeSmartProfile(index: 2)]
        let harness = try await makeSmartHarness(profiles: profiles)

        let presentation = harness.viewModel.connectionSelectionPresentation

        #expect(presentation.mode == .automatic)
        #expect(presentation.showsSelectableProfileList == false)
        #expect(presentation.selectableProfileIDs.isEmpty)
    }

    @Test
    @MainActor
    func manualModeExposesCompleteProfileList() async throws {
        let profiles = [makeSmartProfile(index: 1), makeSmartProfile(index: 2)]
        let harness = try await makeSmartHarness(profiles: profiles)

        harness.viewModel.selectConnectionMode(.manual)
        let presentation = harness.viewModel.connectionSelectionPresentation

        #expect(presentation.showsSelectableProfileList)
        #expect(presentation.selectableProfileIDs == profiles.map(\.id))
    }

    @Test
    @MainActor
    func independentServerSelectorIsAbsentFromPresentationContract() async throws {
        let harness = try await makeSmartHarness(
            profiles: [makeSmartProfile(index: 1)]
        )

        #expect(
            harness.viewModel.connectionSelectionPresentation
                .showsIndependentServerSelector == false
        )
    }

    @Test
    @MainActor
    func independentProtocolSelectorIsAbsentFromPresentationContract() async throws {
        let harness = try await makeSmartHarness(
            profiles: [makeSmartProfile(index: 1)]
        )

        #expect(
            harness.viewModel.connectionSelectionPresentation
                .showsIndependentProtocolSelector == false
        )
    }

    @Test
    @MainActor
    func manualSelectionSurvivesAutomaticManualRoundTrip() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let harness = try await makeSmartHarness(profiles: [first, second])
        harness.viewModel.selectConnectionMode(.manual)
        harness.viewModel.selectProfile(second)

        harness.viewModel.selectConnectionMode(.automatic)
        harness.viewModel.selectConnectionMode(.manual)

        #expect(harness.viewModel.manualSelectedProfileID == second.id)
        #expect(harness.viewModel.selectedProfile?.id == second.id)
    }

    @Test
    @MainActor
    func automaticRecommendationDoesNotOverwriteManualSelection() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let harness = try await makeSmartHarness(profiles: [first, second])
        harness.viewModel.selectConnectionMode(.manual)
        harness.viewModel.selectProfile(second)

        harness.viewModel.selectConnectionMode(.automatic)
        let refreshed = await eventually {
            harness.viewModel.automaticRecommendedProfileID != nil
        }

        #expect(refreshed)
        #expect(harness.viewModel.manualSelectedProfileID == second.id)
        #expect(
            harness.viewModel.connectionSelectionPresentation
                .recommendedProfileID == first.id
        )
    }
}

@Suite(.serialized)
struct SmartConnectionNetworkContextTests {
    @Test
    func wifiAndCellularHaveDistinctStableKeys() {
        let wifi = NetworkPathTypeMapper.smartConnectionContext(
            usesWiFi: true,
            usesCellular: false,
            usesEthernet: false,
            isExpensive: false,
            isConstrained: false,
            supportsIPv4: true,
            supportsIPv6: true
        )
        let cellular = NetworkPathTypeMapper.smartConnectionContext(
            usesWiFi: false,
            usesCellular: true,
            usesEthernet: false,
            isExpensive: true,
            isConstrained: false,
            supportsIPv4: true,
            supportsIPv6: true
        )

        #expect(wifi.interfaceClass == .wifi)
        #expect(cellular.interfaceClass == .cellular)
        #expect(wifi.stableKey != cellular.stableKey)
    }

    @Test
    func expensiveAndConstrainedFlagsArePartOfContextIdentity() {
        let baseline = NetworkContext(
            interfaceClass: .wifi,
            supportsIPv4: true,
            supportsIPv6: true
        )
        let expensive = NetworkContext(
            interfaceClass: .wifi,
            isExpensive: true,
            supportsIPv4: true,
            supportsIPv6: true
        )
        let constrained = NetworkContext(
            interfaceClass: .wifi,
            isConstrained: true,
            supportsIPv4: true,
            supportsIPv6: true
        )

        #expect(baseline.stableKey != expensive.stableKey)
        #expect(baseline.stableKey != constrained.stableKey)
        #expect(expensive.stableKey != constrained.stableKey)
    }

    @Test
    @MainActor
    func contextChangeRecomputesNextAutomaticRecommendation() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let wifi = smartWiFiContext
        let cellular = smartCellularContext
        let snapshot = contextPreferenceSnapshot(
            first: first,
            second: second,
            firstPreferredContext: wifi,
            secondPreferredContext: cellular
        )
        let source = MutableSmartNetworkContextSource(context: wifi)
        let harness = try await makeSmartHarness(
            profiles: [first, second],
            learningSnapshot: snapshot,
            networkSource: source
        )
        #expect(harness.viewModel.automaticRecommendedProfileID == first.id)

        await source.set(cellular)
        let changed = await eventually {
            harness.viewModel.automaticRecommendedProfileID == second.id
        }

        #expect(changed)
        #expect(harness.viewModel.currentNetworkContext == cellular)
    }

    @Test
    @MainActor
    func contextChangeDoesNotStopHealthyTunnel() async throws {
        let profile = makeSmartProfile(index: 1)
        let source = MutableSmartNetworkContextSource(context: smartWiFiContext)
        let manager = ScriptedSmartConnectionManager()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            manager: manager,
            networkSource: source
        )
        await harness.viewModel.connect()
        #expect(harness.viewModel.connectionState == .connected)

        await source.set(smartCellularContext)
        _ = await eventually {
            harness.viewModel.currentNetworkContext == smartCellularContext
        }

        #expect(harness.viewModel.connectionState == .connected)
        #expect(await manager.disconnectCallCount() == 0)
        #expect(await manager.attemptedProfileIDs() == [profile.id])
    }

    @Test
    @MainActor
    func initialContextIsAvailableWithoutDebounceDelay() async throws {
        let sleeper = ControlledSmartConnectionDebounceSleeper()
        let harness = try await makeSmartHarness(
            profiles: [makeSmartProfile(index: 1)],
            debounceSleeper: sleeper,
            debounceDuration: .seconds(3)
        )

        #expect(harness.viewModel.currentNetworkContext == smartWiFiContext)
        #expect(await sleeper.pendingCount() == 0)
    }

    @Test
    @MainActor
    func changedContextPromotesOnlyAfterDebounce() async throws {
        let sleeper = ControlledSmartConnectionDebounceSleeper()
        let source = MutableSmartNetworkContextSource(context: smartWiFiContext)
        let haptic = RecordingSmartConnectionHaptic()
        let harness = try await makeSmartHarness(
            profiles: [makeSmartProfile(index: 1)],
            networkSource: source,
            haptic: haptic,
            debounceSleeper: sleeper,
            debounceDuration: .seconds(3)
        )

        await source.set(smartCellularContext)
        let waiting = await eventually { await sleeper.pendingCount() == 1 }
        #expect(waiting)
        #expect(harness.viewModel.currentNetworkContext == smartWiFiContext)

        await sleeper.releaseAll()
        let promoted = await eventually {
            harness.viewModel.currentNetworkContext == smartCellularContext
        }
        #expect(promoted)
        #expect(haptic.callCount == 0)
    }

    @Test
    @MainActor
    func newerContextCancelsPendingPromotion() async throws {
        let sleeper = ControlledSmartConnectionDebounceSleeper()
        let source = MutableSmartNetworkContextSource(context: smartWiFiContext)
        let harness = try await makeSmartHarness(
            profiles: [makeSmartProfile(index: 1)],
            networkSource: source,
            debounceSleeper: sleeper,
            debounceDuration: .seconds(3)
        )

        await source.set(smartCellularContext)
        #expect(await eventually { await sleeper.pendingCount() == 1 })
        await source.set(smartWiredContext)
        #expect(await eventually {
            let calls = await sleeper.sleepCallCount()
            let pending = await sleeper.pendingCount()
            return calls == 2 && pending == 1
        })
        #expect(harness.viewModel.currentNetworkContext == smartWiFiContext)

        await sleeper.releaseAll()
        let promoted = await eventually {
            harness.viewModel.currentNetworkContext == smartWiredContext
        }
        #expect(promoted)
        #expect(harness.viewModel.currentNetworkContext != smartCellularContext)
    }

    @Test
    @MainActor
    func returnToAuthoritativeContextCancelsPendingPromotion() async throws {
        let sleeper = ControlledSmartConnectionDebounceSleeper()
        let source = MutableSmartNetworkContextSource(context: smartWiFiContext)
        let harness = try await makeSmartHarness(
            profiles: [makeSmartProfile(index: 1)],
            networkSource: source,
            debounceSleeper: sleeper,
            debounceDuration: .seconds(3)
        )

        await source.set(smartCellularContext)
        #expect(await eventually { await sleeper.pendingCount() == 1 })

        await source.set(smartWiFiContext)
        #expect(await eventually {
            let calls = await sleeper.sleepCallCount()
            let pending = await sleeper.pendingCount()
            return calls == 1 && pending == 0
        })

        await sleeper.releaseAll()
        await Task.yield()
        #expect(harness.viewModel.currentNetworkContext == smartWiFiContext)
    }
}

@Suite(.serialized)
struct SmartConnectionLearningStoreTests {
    @Test
    func successfulConnectionUpdatesProfileAndContextStatistics() async {
        let profile = makeSmartProfile(index: 1)
        let store = InMemorySmartConnectionLearningStore()
        let now = smartTestNow

        await store.recordConnectionSuccess(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            connectDuration: 3,
            at: now
        )
        let snapshot = await store.snapshot(for: [profile])
        let context = snapshot.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext
        )
        let profileWide = snapshot.profileStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType
        )

        #expect(context.attemptCount == 1)
        #expect(context.successfulConnectionCount == 1)
        #expect(context.failedConnectionCount == 0)
        #expect(profileWide.successfulConnectionCount == 1)
    }

    @Test
    func genuineFailureLowersEffectiveRanking() async {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let store = InMemorySmartConnectionLearningStore()
        let planner = SmartConnectionCandidatePlanner()
        let before = planner.plan(
            profiles: [first, second],
            context: smartWiFiContext,
            learning: .empty,
            now: smartTestNow
        )
        #expect(before.candidateIDs.first == first.id)

        await store.recordConnectionFailure(
            profileID: first.id,
            protocolType: first.protocolType,
            context: smartWiFiContext,
            at: smartTestNow
        )
        let afterLearning = await store.snapshot(for: [first, second])
        let after = planner.plan(
            profiles: [first, second],
            context: smartWiFiContext,
            learning: afterLearning,
            now: smartTestNow
        )

        #expect(after.candidateIDs.first == second.id)
    }

    @Test
    @MainActor
    func userStopDoesNotCountAsFailure() async throws {
        let profile = makeSmartProfile(index: 1)
        let harness = try await makeSmartHarness(profiles: [profile])
        await harness.viewModel.connect()

        await harness.viewModel.disconnect()
        let snapshot = await harness.learningStore.snapshot(for: [profile])
        let statistics = snapshot.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext
        )

        #expect(statistics.failedConnectionCount == 0)
        #expect(statistics.unexpectedDisconnectCount == 0)
        #expect(statistics.consecutiveFailures == 0)
        #expect(statistics.completedSessionCount == 1)
    }

    @Test
    @MainActor
    func unexpectedDisconnectCountsAgainstStability() async throws {
        let profile = makeSmartProfile(index: 1)
        let manager = ScriptedSmartConnectionManager()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            manager: manager
        )
        await harness.viewModel.connect()

        await manager.emitUnexpectedDisconnect()
        let observed = await eventually {
            let snapshot = await harness.learningStore.snapshot(for: [profile])
            return snapshot.contextStatistics(
                profileID: profile.id,
                protocolType: profile.protocolType,
                context: smartWiFiContext
            ).unexpectedDisconnectCount == 1
        }

        #expect(observed)
    }

    @Test
    func latencyEWMAUpdatesWithBoundedAggregate() async {
        let profile = makeSmartProfile(index: 1)
        let store = InMemorySmartConnectionLearningStore()
        await recordSessionMetric(
            store: store,
            profile: profile,
            latency: 100,
            loss: nil
        )
        await recordSessionMetric(
            store: store,
            profile: profile,
            latency: 200,
            loss: nil
        )
        let statistics = await contextStatistics(store: store, profile: profile)

        #expect(statistics.ewmaLatencyMilliseconds == 125)
        #expect(statistics.latencySampleCount == 2)
    }

    @Test
    func lossEWMAUpdatesWithBoundedAggregate() async {
        let profile = makeSmartProfile(index: 1)
        let store = InMemorySmartConnectionLearningStore()
        await recordSessionMetric(
            store: store,
            profile: profile,
            latency: nil,
            loss: 20
        )
        await recordSessionMetric(
            store: store,
            profile: profile,
            latency: nil,
            loss: 0
        )
        let statistics = await contextStatistics(store: store, profile: profile)

        #expect(statistics.ewmaPacketLossPercent == 15)
        #expect(statistics.packetLossSampleCount == 2)
    }

    @Test
    func connectDurationEWMAUpdatesWithNormalizedSeconds() async {
        let profile = makeSmartProfile(index: 1)
        let store = InMemorySmartConnectionLearningStore()
        await store.recordConnectionSuccess(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            connectDuration: 10,
            at: smartTestNow
        )
        await store.recordConnectionSuccess(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            connectDuration: 2,
            at: smartTestNow
        )
        let statistics = await contextStatistics(store: store, profile: profile)

        #expect(statistics.ewmaConnectDurationSeconds == 8)
        #expect(statistics.connectDurationSampleCount == 2)
    }

    @Test
    func renameWithSameUUIDRetainsHistory() async {
        let profile = makeSmartProfile(index: 1)
        let store = InMemorySmartConnectionLearningStore()
        await store.recordConnectionSuccess(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            connectDuration: 2,
            at: smartTestNow
        )
        var renamed = profile
        renamed.name = "Renamed profile"

        let snapshot = await store.snapshot(for: [renamed])

        #expect(snapshot.profileStatistics(
            profileID: renamed.id,
            protocolType: renamed.protocolType
        ).successfulConnectionCount == 1)
    }

    @Test
    func deletedProfileIsPrunedSafely() async {
        let profile = makeSmartProfile(index: 1)
        let store = InMemorySmartConnectionLearningStore()
        await store.recordConnectionSuccess(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            connectDuration: 2,
            at: smartTestNow
        )

        await store.prune(profiles: [])
        let snapshot = await store.snapshot(for: [])

        #expect(snapshot.profileRecords.isEmpty)
        #expect(snapshot.contextProfileRecords.isEmpty)
    }

    @Test
    func protocolMutationWithSameUUIDInvalidatesIncompatibleHistory() async {
        let profile = makeSmartProfile(index: 1)
        let store = InMemorySmartConnectionLearningStore()
        await store.recordConnectionSuccess(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            connectDuration: 2,
            at: smartTestNow
        )
        var changed = makeSmartProfile(index: 1, protocolType: .hysteria2)
        changed.id = profile.id

        await store.prune(profiles: [changed])
        let snapshot = await store.snapshot(for: [changed])

        #expect(snapshot.profileRecords.isEmpty)
        #expect(snapshot.contextProfileRecords.isEmpty)
    }

    @Test
    func corruptLearningFileFailsToEmptyDefaults() async throws {
        let fileURL = temporaryLearningFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL) }
        try Data("not-json".utf8).write(to: fileURL)
        let store = FileSmartConnectionLearningStore(fileURL: fileURL)

        let snapshot = await store.snapshot(for: [makeSmartProfile(index: 1)])

        #expect(snapshot == .empty)
    }

    @Test
    func persistedLearningContainsNoProfileCredentialsOrSecrets() async throws {
        let fileURL = temporaryLearningFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL) }
        var profile = makeSmartProfile(index: 1)
        let secret = "PRIVATE-KEY-PASSWORD-TOKEN-SENTINEL"
        profile.credentialReference = secret
        let store = FileSmartConnectionLearningStore(fileURL: fileURL)

        await store.recordConnectionSuccess(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            connectDuration: 1,
            at: smartTestNow
        )
        _ = await store.snapshot(for: [profile])
        let persisted = try String(contentsOf: fileURL, encoding: .utf8)

        #expect(persisted.contains(secret) == false)
        #expect(persisted.contains("credentialReference") == false)
        #expect(persisted.contains("providerConfiguration") == false)
        #expect(persisted.contains("subscriptionURI") == false)
    }

    @Test
    func notLoadedInventoryRetainsLearningButLoadedEmptyPrunesIt() async throws {
        let profile = makeSmartProfile(index: 1)
        let seed = snapshot(entries: [
            (profile, smartStatistics(attempts: 4, successes: 4))
        ])
        let fileURL = temporaryLearningFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL) }
        try writeLearningSnapshot(seed, to: fileURL)
        let store = FileSmartConnectionLearningStore(fileURL: fileURL)

        let notLoaded = await store.snapshot(for: nil)
        #expect(notLoaded.contextProfileRecords.count == 1)

        let loadedEmpty = await store.snapshot(for: [])
        #expect(loadedEmpty.contextProfileRecords.isEmpty)
        #expect(loadedEmpty.profileRecords.isEmpty)
    }

    @Test
    @MainActor
    func realFileColdStartImmediateContextCannotPruneBeforeProfileLoad() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let fileURL = temporaryLearningFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let seedingStore = FileSmartConnectionLearningStore(fileURL: fileURL)
        for profile in [first, second] {
            await seedingStore.recordConnectionSuccess(
                profileID: profile.id,
                protocolType: profile.protocolType,
                context: smartWiFiContext,
                connectDuration: 1,
                at: smartTestNow
            )
        }
        let bytesBeforeColdStart = try Data(contentsOf: fileURL)
        #expect(bytesBeforeColdStart.isEmpty == false)

        let repository = InMemoryVPNProfileRepository()
        try await repository.save(first)
        try await repository.save(second)
        let source = MutableSmartNetworkContextSource(context: smartWiFiContext)
        let coldStartStore = FileSmartConnectionLearningStore(fileURL: fileURL)
        let viewModel = VPNDashboardViewModel(
            serverProvider: EmptySmartServerProvider(),
            connectionManager: ScriptedSmartConnectionManager(),
            profileRepository: repository,
            subscriptionRepository: InMemorySubscriptionRepository(),
            activeProfileStore: TestSmartActiveProfileStore(profileID: nil),
            manualProfileSelectionStore: TestSmartManualProfileSelectionStore(profileID: nil),
            connectionTelemetryManager: TestSmartConnectionTelemetryManager(),
            learningStore: coldStartStore,
            networkContextSource: source,
            smartConnectionClock: FixedSmartConnectionClock(now: smartTestNow),
            networkContextDebounceSleeper: ImmediateSmartConnectionDebounceSleeper(),
            networkContextDebounceDuration: .zero,
            connectionActionHapticFeedback: RecordingSmartConnectionHaptic()
        )

        for _ in 0..<20 { await Task.yield() }
        #expect(await source.observerCount() == 0)
        #expect(try Data(contentsOf: fileURL) == bytesBeforeColdStart)
        let beforeLoad = try decodeLearningSnapshot(at: fileURL)
        #expect(beforeLoad.profileRecords.count == 2)

        await viewModel.loadInitialData()
        let observed = await eventually { await source.observerCount() == 1 }
        #expect(observed)
        let afterLoad = await coldStartStore.snapshot(for: [first, second])
        #expect(afterLoad.profileRecords.count == 2)
        #expect(afterLoad.contextProfileRecords.count == 2)
    }

    @Test
    func fileAndMemoryParityForNormalInventory() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        try await expectStoreParity(
            seed: paritySeedSnapshot(first: first, second: second),
            profiles: [first, second]
        )
    }

    @Test
    func fileAndMemoryParityForDeletedProfile() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        try await expectStoreParity(
            seed: paritySeedSnapshot(first: first, second: second),
            profiles: [first]
        )
    }

    @Test
    func fileAndMemoryParityForLoadedEmptyInventory() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        try await expectStoreParity(
            seed: paritySeedSnapshot(first: first, second: second),
            profiles: []
        )
    }

    @Test
    func fileAndMemoryParityForNotLoadedInventory() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        try await expectStoreParity(
            seed: paritySeedSnapshot(first: first, second: second),
            profiles: nil
        )
    }

    @Test
    func fileAndMemoryProtocolMutationParity() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let seed = paritySeedSnapshot(first: first, second: second)
        var changed = makeSmartProfile(index: 1, protocolType: .hysteria2)
        changed.id = first.id
        let fileURL = temporaryLearningFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL) }
        try writeLearningSnapshot(seed, to: fileURL)
        let fileStore = FileSmartConnectionLearningStore(fileURL: fileURL)
        let memoryStore = InMemorySmartConnectionLearningStore(snapshot: seed)

        await fileStore.recordConnectionSuccess(
            profileID: changed.id,
            protocolType: changed.protocolType,
            context: smartWiFiContext,
            connectDuration: 2,
            at: smartTestNow
        )
        await memoryStore.recordConnectionSuccess(
            profileID: changed.id,
            protocolType: changed.protocolType,
            context: smartWiFiContext,
            connectDuration: 2,
            at: smartTestNow
        )

        let fileValue = await fileStore.snapshot(for: [changed, second])
        let memoryValue = await memoryStore.snapshot(for: [changed, second])
        #expect(fileValue == memoryValue)
        #expect(fileValue.profileStatistics(
            profileID: changed.id,
            protocolType: first.protocolType
        ).attemptCount == 0)
        #expect(fileValue.profileStatistics(
            profileID: changed.id,
            protocolType: changed.protocolType
        ).attemptCount == 1)
    }

    @Test
    func fileAndMemorySchemaMismatchBothFailToEmpty() async throws {
        let invalid = SmartConnectionLearningSnapshot(
            schemaVersion: SmartConnectionLearningSnapshot.currentSchemaVersion + 1,
            contextProfileRecords: paritySeedSnapshot(
                first: makeSmartProfile(index: 1),
                second: makeSmartProfile(index: 2)
            ).contextProfileRecords
        )
        let fileURL = temporaryLearningFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL) }
        try writeLearningSnapshot(invalid, to: fileURL)
        let fileStore = FileSmartConnectionLearningStore(fileURL: fileURL)
        let memoryStore = InMemorySmartConnectionLearningStore(snapshot: invalid)

        #expect(await fileStore.snapshot(for: nil) == .empty)
        #expect(await memoryStore.snapshot(for: nil) == .empty)
    }

    @Test
    func completedSessionQualityIsIdempotentAcrossStoreRestoration() async throws {
        let profile = makeSmartProfile(index: 1)
        let fileURL = temporaryLearningFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL) }
        let summary = SmartConnectionSessionSummary(
            additionalSuccessfulSessionSeconds: 10,
            latencyMilliseconds: 90,
            packetLossPercent: 1,
            sessionEnded: true,
            unexpectedDisconnect: false,
            sessionID: "stable-provider-session"
        )
        let firstStore = FileSmartConnectionLearningStore(fileURL: fileURL)
        await firstStore.recordSessionSummary(
            summary,
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            at: smartTestNow
        )

        let restoredStore = FileSmartConnectionLearningStore(fileURL: fileURL)
        await restoredStore.recordSessionSummary(
            summary,
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            at: smartTestNow
        )
        let statistics = (await restoredStore.snapshot(for: [profile])).contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext
        )
        #expect(statistics.latencySampleCount == 1)
        #expect(statistics.packetLossSampleCount == 1)
        #expect(statistics.completedSessionCount == 1)
        #expect(statistics.successfulSessionSeconds == 10)
    }

    @Test
    func legacyLearningMigratesOnlyAfterVerifiedAppGroupWrite() async throws {
        let profile = makeSmartProfile(index: 1)
        let seed = snapshot(entries: [
            (profile, smartStatistics(attempts: 4, successes: 4))
        ])
        let directory = temporaryLearningDirectoryURL()
        defer { try? FileManager.default.removeItem(at: directory) }
        let legacyURL = directory.appendingPathComponent("Legacy/learning.json")
        let groupContainer = directory.appendingPathComponent("AppGroup", isDirectory: true)
        let primaryURL = SmartConnectionLearningLocation.appGroupFileURL(
            containerURL: groupContainer
        )
        try writeLearningSnapshot(seed, to: legacyURL)
        let store = FileSmartConnectionLearningStore(
            fileURL: primaryURL,
            legacyFileURL: legacyURL
        )

        let migrated = await store.snapshot(for: [profile])

        #expect(migrated == seed)
        #expect(FileManager.default.fileExists(atPath: primaryURL.path))
        #expect(try decodeLearningSnapshot(at: primaryURL) == seed)
        #expect(FileManager.default.fileExists(atPath: legacyURL.path) == false)
    }

    @Test
    func existingAppGroupLearningWinsOverLegacyLearning() async throws {
        let primaryProfile = makeSmartProfile(index: 1)
        let legacyProfile = makeSmartProfile(index: 2)
        let primarySeed = snapshot(entries: [
            (primaryProfile, smartStatistics(attempts: 5, successes: 5))
        ])
        let legacySeed = snapshot(entries: [
            (legacyProfile, smartStatistics(attempts: 9, successes: 0))
        ])
        let directory = temporaryLearningDirectoryURL()
        defer { try? FileManager.default.removeItem(at: directory) }
        let primaryURL = directory.appendingPathComponent("AppGroup/learning.json")
        let legacyURL = directory.appendingPathComponent("Legacy/learning.json")
        try writeLearningSnapshot(primarySeed, to: primaryURL)
        try writeLearningSnapshot(legacySeed, to: legacyURL)
        let store = FileSmartConnectionLearningStore(
            fileURL: primaryURL,
            legacyFileURL: legacyURL
        )

        let value = await store.snapshot(for: nil)

        #expect(value == primarySeed)
        #expect(FileManager.default.fileExists(atPath: legacyURL.path))
    }

    @Test
    func failedMigrationPreservesLegacyAndLearningRemainsUsable() async throws {
        let profile = makeSmartProfile(index: 1)
        let seed = snapshot(entries: [
            (profile, smartStatistics(attempts: 4, successes: 4))
        ])
        let directory = temporaryLearningDirectoryURL()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let blocker = directory.appendingPathComponent("not-a-directory")
        try Data("blocker".utf8).write(to: blocker)
        let primaryURL = blocker.appendingPathComponent("learning.json")
        let legacyURL = directory.appendingPathComponent("Legacy/learning.json")
        try writeLearningSnapshot(seed, to: legacyURL)
        let store = FileSmartConnectionLearningStore(
            fileURL: primaryURL,
            legacyFileURL: legacyURL
        )

        #expect(await store.snapshot(for: [profile]) == seed)
        #expect(FileManager.default.fileExists(atPath: legacyURL.path))
        #expect(FileManager.default.fileExists(atPath: primaryURL.path) == false)

        await store.recordConnectionFailure(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            at: smartTestNow
        )
        let persistedFallback = try decodeLearningSnapshot(at: legacyURL)
        #expect(persistedFallback.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext
        ).failedConnectionCount == 1)
    }

    @Test
    func appGroupPathAndAtomicPersistenceRemainValidAfterEveryWrite() async throws {
        let profile = makeSmartProfile(index: 1)
        let container = temporaryLearningDirectoryURL()
        defer { try? FileManager.default.removeItem(at: container) }
        let fileURL = SmartConnectionLearningLocation.appGroupFileURL(
            containerURL: container
        )
        #expect(SmartConnectionLearningLocation.appGroupIdentifier == "group.su.24kvn.kvn-app")
        #expect(fileURL.path.contains("Library/Application Support/VPN/SmartConnection"))
        let store = FileSmartConnectionLearningStore(fileURL: fileURL)

        for attempt in 1...8 {
            await store.recordConnectionSuccess(
                profileID: profile.id,
                protocolType: profile.protocolType,
                context: smartWiFiContext,
                connectDuration: Double(attempt),
                at: smartTestNow.addingTimeInterval(Double(attempt))
            )
            let decoded = try decodeLearningSnapshot(at: fileURL)
            #expect(decoded.contextStatistics(
                profileID: profile.id,
                protocolType: profile.protocolType,
                context: smartWiFiContext
            ).attemptCount == attempt)
        }
    }

    @Test(arguments: SmartLearningStoreKind.allCases)
    func qualityCheckpointPersistsPendingAggregateWithoutCommittingSamples(
        kind: SmartLearningStoreKind
    ) async throws {
        let profile = makeSmartProfile(index: 1)
        let harness = try makeLearningStoreHarness(
            kind: kind,
            clock: FixedSmartConnectionClock(now: smartTestNow)
        )
        defer { harness.cleanup() }

        await harness.store.recordSessionSummary(
            qualitySummary(
                sessionID: "checkpoint-session",
                latencyValues: [80, 100],
                lossValues: [1, 3],
                additionalSeconds: 60,
                sessionEnded: false
            ),
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            at: smartTestNow
        )
        let snapshot = await harness.store.snapshot(for: [profile])
        let statistics = snapshot.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext
        )
        let pendingRecords = try #require(snapshot.pendingQualityRecords)
        #expect(pendingRecords.count == 1)
        let pending = try #require(pendingRecords.first)

        #expect(pending.latencySum == 180)
        #expect(pending.latencyCount == 2)
        #expect(pending.packetLossSum == 4)
        #expect(pending.packetLossCount == 2)
        #expect(pending.accumulatedSessionSeconds == 60)
        #expect(statistics.latencySampleCount == 0)
        #expect(statistics.packetLossSampleCount == 0)
        #expect(statistics.completedSessionCount == 0)

        if let fileURL = harness.fileURL {
            let persistedBytes = try String(
                decoding: Data(contentsOf: fileURL),
                as: UTF8.self
            )
            #expect(persistedBytes.contains("\"latencySum\" : 180"))
            #expect(persistedBytes.contains("\"latencyCount\" : 2"))
        }
    }

    @Test
    func jetsamRestorationCommitsPendingQualityExactlyOnceWithoutPenalty() async throws {
        let profile = makeSmartProfile(index: 1)
        let fileURL = temporaryLearningFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL) }

        do {
            let firstStore = FileSmartConnectionLearningStore(
                fileURL: fileURL,
                clock: FixedSmartConnectionClock(now: smartTestNow)
            )
            await firstStore.recordSessionSummary(
                qualitySummary(
                    sessionID: "jetsam-session",
                    latencyValues: [50, 70],
                    lossValues: [1, 2],
                    additionalSeconds: 60,
                    sessionEnded: false
                ),
                profileID: profile.id,
                protocolType: profile.protocolType,
                context: smartWiFiContext,
                at: smartTestNow
            )
            await firstStore.recordSessionSummary(
                qualitySummary(
                    sessionID: "jetsam-session",
                    latencyValues: [50, 70, 90],
                    lossValues: [1, 2, 3],
                    additionalSeconds: 60,
                    sessionEnded: false
                ),
                profileID: profile.id,
                protocolType: profile.protocolType,
                context: smartWiFiContext,
                at: smartTestNow
            )
        }

        let restoredStore = FileSmartConnectionLearningStore(
            fileURL: fileURL,
            clock: FixedSmartConnectionClock(
                now: smartTestNow.addingTimeInterval(11 * 60)
            )
        )
        let restored = await restoredStore.snapshot(for: [profile])
        let statistics = restored.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext
        )

        #expect(restored.pendingQualityRecords == nil)
        #expect(statistics.ewmaLatencyMilliseconds == 70)
        #expect(statistics.ewmaTailLatencyMilliseconds == 70)
        #expect(statistics.latencySampleCount == 1)
        #expect(statistics.packetLossSampleCount == 1)
        #expect(statistics.completedSessionCount == 1)
        #expect(statistics.successfulSessionSeconds == 120)
        #expect(statistics.unexpectedDisconnectCount == 0)
        #expect(statistics.failedConnectionCount == 0)
        #expect(statistics.consecutiveFailures == 0)
        #expect(statistics.lastFailureAt == nil)

        let loadedAgain = await restoredStore.snapshot(for: [profile])
        #expect(loadedAgain == restored)
    }

    @Test(arguments: SmartLearningStoreKind.allCases)
    func recoveredPendingThenRealFinishWithSameSessionRemainsIdempotent(
        kind: SmartLearningStoreKind
    ) async throws {
        let profile = makeSmartProfile(index: 1)
        let sessionID = "restored-then-finished"
        let pending = pendingQualityRecord(
            profile: profile,
            sessionID: sessionID,
            updatedAt: smartTestNow,
            latencyValues: [80, 100],
            lossValues: [1, 3],
            accumulatedSeconds: 120
        )
        let harness = try makeLearningStoreHarness(
            kind: kind,
            snapshot: SmartConnectionLearningSnapshot(
                pendingQualityRecords: [pending]
            ),
            clock: FixedSmartConnectionClock(
                now: smartTestNow.addingTimeInterval(11 * 60)
            )
        )
        defer { harness.cleanup() }

        _ = await harness.store.snapshot(for: [profile])
        await harness.store.recordSessionSummary(
            qualitySummary(
                sessionID: sessionID,
                latencyValues: [80, 100, 120],
                lossValues: [1, 3, 5],
                additionalSeconds: 30,
                sessionEnded: true
            ),
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            at: smartTestNow.addingTimeInterval(11 * 60)
        )
        let value = await harness.store.snapshot(for: [profile])
        let statistics = value.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext
        )

        #expect(statistics.latencySampleCount == 1)
        #expect(statistics.packetLossSampleCount == 1)
        #expect(statistics.completedSessionCount == 1)
        #expect(statistics.successfulSessionSeconds == 120)
    }

    @Test(arguments: SmartLearningStoreKind.allCases)
    func recentPendingQualityRecordRemainsLive(
        kind: SmartLearningStoreKind
    ) async throws {
        let profile = makeSmartProfile(index: 1)
        let pending = pendingQualityRecord(
            profile: profile,
            sessionID: "live-session",
            updatedAt: smartTestNow,
            latencyValues: [75],
            lossValues: [1],
            accumulatedSeconds: 60
        )
        let harness = try makeLearningStoreHarness(
            kind: kind,
            snapshot: SmartConnectionLearningSnapshot(
                pendingQualityRecords: [pending]
            ),
            clock: FixedSmartConnectionClock(
                now: smartTestNow.addingTimeInterval(5 * 60)
            )
        )
        defer { harness.cleanup() }

        let value = await harness.store.snapshot(for: [profile])
        let statistics = value.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext
        )

        #expect(value.pendingQualityRecords == [pending])
        #expect(statistics.latencySampleCount == 0)
        #expect(statistics.completedSessionCount == 0)
    }

    @Test(arguments: SmartLearningStoreKind.allCases)
    func completedQualityStoresSeparateTailEWMAAndLowersLatencyScore(
        kind: SmartLearningStoreKind
    ) async throws {
        let profile = makeSmartProfile(index: 1)
        let latencyValues = Array(repeating: 50.0, count: 55)
            + Array(repeating: 900.0, count: 5)
        let harness = try makeLearningStoreHarness(
            kind: kind,
            clock: FixedSmartConnectionClock(now: smartTestNow)
        )
        defer { harness.cleanup() }

        await harness.store.recordSessionSummary(
            qualitySummary(
                sessionID: "tail-session",
                latencyValues: latencyValues,
                lossValues: [],
                additionalSeconds: 3_600,
                sessionEnded: true
            ),
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext,
            at: smartTestNow
        )
        let value = await harness.store.snapshot(for: [profile])
        let statistics = value.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext
        )
        let mean = try #require(statistics.ewmaLatencyMilliseconds)
        let tail = try #require(statistics.ewmaTailLatencyMilliseconds)

        #expect(abs(mean - 120.833_333_333_333_33) < 0.000_001)
        #expect(abs(tail - 262.5) < 0.000_001)
        #expect(statistics.latencySampleCount == 1)

        let withTail = SmartConnectionScoreCalculator().score(
            profile: profile,
            context: smartWiFiContext,
            learning: value,
            now: smartTestNow
        )
        var withoutTailLearning = value
        for index in withoutTailLearning.contextProfileRecords.indices {
            withoutTailLearning.contextProfileRecords[index].statistics
                .ewmaTailLatencyMilliseconds = nil
        }
        for index in withoutTailLearning.profileRecords.indices {
            withoutTailLearning.profileRecords[index].statistics
                .ewmaTailLatencyMilliseconds = nil
        }
        for index in withoutTailLearning.protocolRecords.indices {
            withoutTailLearning.protocolRecords[index].statistics
                .ewmaTailLatencyMilliseconds = nil
        }
        let withoutTail = SmartConnectionScoreCalculator().score(
            profile: profile,
            context: smartWiFiContext,
            learning: withoutTailLearning,
            now: smartTestNow
        )
        #expect(withTail.breakdown.latency < withoutTail.breakdown.latency)

        var detector = SmartConnectionAnomalyDetector()
        _ = detector.observe(
            latencyMilliseconds: 250,
            packetLossPercent: nil,
            baselineLatencyMilliseconds: statistics.ewmaLatencyMilliseconds,
            baselinePacketLossPercent: nil
        )
        #expect(detector.observe(
            latencyMilliseconds: 250,
            packetLossPercent: nil,
            baselineLatencyMilliseconds: statistics.ewmaLatencyMilliseconds,
            baselinePacketLossPercent: nil
        ) == .degraded)
    }

    @Test(arguments: SmartLearningStoreKind.allCases)
    func ninthPendingQualityRecordEvictsOldestByUpdatedAt(
        kind: SmartLearningStoreKind
    ) async throws {
        let profiles = (1...9).map { makeSmartProfile(index: $0) }
        let harness = try makeLearningStoreHarness(
            kind: kind,
            clock: FixedSmartConnectionClock(now: smartTestNow)
        )
        defer { harness.cleanup() }

        for (index, profile) in profiles.enumerated() {
            await harness.store.recordSessionSummary(
                qualitySummary(
                    sessionID: "bounded-\(index)",
                    latencyValues: [Double(50 + index)],
                    lossValues: [],
                    additionalSeconds: 60,
                    sessionEnded: false
                ),
                profileID: profile.id,
                protocolType: profile.protocolType,
                context: smartWiFiContext,
                at: smartTestNow.addingTimeInterval(Double(index))
            )
        }
        let value = await harness.store.snapshot(for: profiles)
        let pending = try #require(value.pendingQualityRecords)

        #expect(pending.count == SmartConnectionLearningTransform.maximumPendingQualityRecords)
        #expect(pending.contains { $0.profileID == profiles[0].id } == false)
        #expect(pending.contains { $0.profileID == profiles[8].id })
    }
}

@Suite(.serialized)
struct SmartConnectionScoringTests {
    private let calculator = SmartConnectionScoreCalculator()
    private let now = smartTestNow

    @Test
    func higherReliabilityOutranksOtherwiseSimilarProfile() {
        let reliable = makeSmartProfile(index: 1)
        let unreliable = makeSmartProfile(index: 2)
        let learning = snapshot(
            entries: [
                (reliable, smartStatistics(attempts: 80, successes: 76)),
                (unreliable, smartStatistics(attempts: 80, successes: 20))
            ]
        )

        let reliableScore = calculator.score(
            profile: reliable,
            context: smartWiFiContext,
            learning: learning,
            now: now
        )
        let unreliableScore = calculator.score(
            profile: unreliable,
            context: smartWiFiContext,
            learning: learning,
            now: now
        )

        #expect(reliableScore.breakdown.reliability > unreliableScore.breakdown.reliability)
        #expect(reliableScore.breakdown.effectiveScore > unreliableScore.breakdown.effectiveScore)
    }

    @Test
    func lowerLatencyImprovesScore() {
        let fast = makeSmartProfile(index: 1)
        let slow = makeSmartProfile(index: 2)
        let learning = snapshot(entries: [
            (fast, smartStatistics(attempts: 40, successes: 40, latency: 50)),
            (slow, smartStatistics(attempts: 40, successes: 40, latency: 900))
        ])

        let fastScore = score(fast, learning: learning)
        let slowScore = score(slow, learning: learning)

        #expect(fastScore.breakdown.latency > slowScore.breakdown.latency)
        #expect(fastScore.breakdown.effectiveScore > slowScore.breakdown.effectiveScore)
    }

    @Test
    func build8JSONWithoutPendingOrTailFieldsPreservesScoreBitPatterns() throws {
        let profile = makeSmartProfile(index: 1)
        var statistics = SmartConnectionStatistics()
        statistics.attemptCount = 7
        statistics.successfulConnectionCount = 5
        statistics.failedConnectionCount = 2
        statistics.ewmaConnectDurationSeconds = 4.25
        statistics.connectDurationSampleCount = 5
        statistics.ewmaLatencyMilliseconds = 137.5
        statistics.latencySampleCount = 4
        statistics.ewmaPacketLossPercent = 2.75
        statistics.packetLossSampleCount = 4
        statistics.successfulSessionSeconds = 2_345
        statistics.completedSessionCount = 4
        statistics.unexpectedDisconnectCount = 1
        statistics.lastAttemptAt = now
        statistics.lastSuccessAt = now
        statistics.lastUpdatedAt = now
        let build8Snapshot = SmartConnectionLearningSnapshot(
            contextProfileRecords: [SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: profile.id,
                protocolType: profile.protocolType,
                statistics: statistics
            )]
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let build8JSON = try encoder.encode(build8Snapshot)
        let bytes = String(decoding: build8JSON, as: UTF8.self)
        #expect(bytes.contains("pendingQualityRecords") == false)
        #expect(bytes.contains("ewmaTailLatencyMilliseconds") == false)
        #expect(bytes.contains("ewmaTailPacketLossPercent") == false)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(
            SmartConnectionLearningSnapshot.self,
            from: build8JSON
        )
        #expect(decoded.schemaVersion == 1)
        #expect(decoded.pendingQualityRecords == nil)
        let result = calculator.score(
            profile: profile,
            context: smartWiFiContext,
            learning: decoded,
            now: now
        )
        let bitPatterns = [
            result.breakdown.reliability,
            result.breakdown.latency,
            result.breakdown.packetLoss,
            result.breakdown.connectSpeed,
            result.breakdown.stability,
            result.breakdown.baseScore,
            result.breakdown.recentFailurePenalty,
            result.breakdown.recentSuccessBonus,
            result.breakdown.explorationBonus,
            result.breakdown.effectiveScore
        ].map(\.bitPattern)

        #expect(bitPatterns == [
            4_634_673_141_525_424_811,
            4_635_113_872_081_063_864,
            4_635_007_393_060_268_715,
            4_635_134_862_525_020_252,
            4_634_859_447_662_353_521,
            4_634_899_314_130_411_394,
            0,
            4_616_189_618_054_758_400,
            0,
            4_635_180_789_107_122_050
        ])
    }

    @Test
    func lowerLossImprovesScore() {
        let lowLoss = makeSmartProfile(index: 1)
        let highLoss = makeSmartProfile(index: 2)
        let learning = snapshot(entries: [
            (lowLoss, smartStatistics(attempts: 40, successes: 40, loss: 0)),
            (highLoss, smartStatistics(attempts: 40, successes: 40, loss: 20))
        ])

        let lowScore = score(lowLoss, learning: learning)
        let highScore = score(highLoss, learning: learning)

        #expect(lowScore.breakdown.packetLoss > highScore.breakdown.packetLoss)
        #expect(lowScore.breakdown.effectiveScore > highScore.breakdown.effectiveScore)
    }

    @Test
    func fasterEstablishmentImprovesScore() {
        let fast = makeSmartProfile(index: 1)
        let slow = makeSmartProfile(index: 2)
        let learning = snapshot(entries: [
            (fast, smartStatistics(attempts: 40, successes: 40, connectDuration: 1)),
            (slow, smartStatistics(attempts: 40, successes: 40, connectDuration: 30))
        ])

        #expect(
            score(fast, learning: learning).breakdown.effectiveScore
                > score(slow, learning: learning).breakdown.effectiveScore
        )
    }

    @Test
    func sessionStabilityInfluencesScore() {
        let stable = makeSmartProfile(index: 1)
        let unstable = makeSmartProfile(index: 2)
        let learning = snapshot(entries: [
            (stable, smartStatistics(
                attempts: 40,
                successes: 40,
                completedSessions: 20,
                unexpectedDisconnects: 0,
                successfulSessionSeconds: 36_000
            )),
            (unstable, smartStatistics(
                attempts: 40,
                successes: 40,
                completedSessions: 20,
                unexpectedDisconnects: 15,
                successfulSessionSeconds: 3_600
            ))
        ])

        #expect(
            score(stable, learning: learning).breakdown.stability
                > score(unstable, learning: learning).breakdown.stability
        )
    }

    @Test
    func consecutiveRecentFailuresApplyStrongPenalty() {
        var statistics = smartStatistics(attempts: 20, successes: 18)
        statistics.consecutiveFailures = 2
        statistics.lastFailureAt = now

        #expect(calculator.failurePenalty(statistics: statistics, now: now) == 28)
    }

    @Test
    func failurePenaltyDecaysWithTwentyFourHourHalfLife() {
        var statistics = smartStatistics(attempts: 20, successes: 18)
        statistics.consecutiveFailures = 2
        statistics.lastFailureAt = now
        let after48Hours = now.addingTimeInterval(48 * 3_600)

        #expect(calculator.failurePenalty(statistics: statistics, now: after48Hours) == 7)
    }

    @Test
    func lowSampleContextHistoryShrinksTowardBroaderPrior() {
        let profile = makeSmartProfile(index: 1)
        let context = smartStatistics(attempts: 1, successes: 1)
        let profileWide = smartStatistics(attempts: 100, successes: 20)
        let learning = SmartConnectionLearningSnapshot(
            contextProfileRecords: [SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: profile.id,
                protocolType: profile.protocolType,
                statistics: context
            )],
            profileRecords: [SmartConnectionProfileRecord(
                profileID: profile.id,
                protocolType: profile.protocolType,
                statistics: profileWide
            )]
        )

        let result = score(profile, learning: learning)

        #expect(result.breakdown.reliability < 60)
        #expect(result.breakdown.reliability > 20)
    }

    @Test
    func sufficientContextHistoryDominatesBroaderPrior() {
        let profile = makeSmartProfile(index: 1)
        let context = smartStatistics(attempts: 100, successes: 100)
        let profileWide = smartStatistics(attempts: 100, successes: 20)
        let learning = SmartConnectionLearningSnapshot(
            contextProfileRecords: [SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: profile.id,
                protocolType: profile.protocolType,
                statistics: context
            )],
            profileRecords: [SmartConnectionProfileRecord(
                profileID: profile.id,
                protocolType: profile.protocolType,
                statistics: profileWide
            )]
        )

        #expect(score(profile, learning: learning).breakdown.reliability > 85)
    }

    @Test
    func unexploredCandidateReceivesOnlyBoundedBonus() {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [first, second],
            context: smartWiFiContext,
            learning: .empty,
            now: now
        )

        #expect(plan.rankedCandidates.allSatisfy {
            $0.breakdown.explorationBonus >= 0
                && $0.breakdown.explorationBonus <= 5
        })
    }

    @Test
    func establishedWinnerAllowsDeterministicFirstExploration() {
        let excellent = makeSmartProfile(index: 1)
        let newCandidate = makeSmartProfile(index: 2, protocolType: .hysteria2)
        let learning = SmartConnectionLearningSnapshot(
            contextProfileRecords: [SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: excellent.id,
                protocolType: excellent.protocolType,
                statistics: smartStatistics(
                    attempts: 100,
                    successes: 100,
                    latency: 40,
                    loss: 0,
                    connectDuration: 1,
                    completedSessions: 50,
                    successfulSessionSeconds: 90_000
                )
            )]
        )

        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [excellent, newCandidate],
            context: smartWiFiContext,
            learning: learning,
            now: now
        )

        #expect(score(excellent, learning: learning).breakdown.effectiveScore > 80)
        #expect(plan.explorationCandidateID == newCandidate.id)
        #expect(plan.rankedCandidates.first?.profileID == newCandidate.id)
        #expect(plan.candidateIDs.first == newCandidate.id)
        #expect(plan.maximumAttempts <= 3)
        #expect(plan.candidateIDs.count <= plan.maximumAttempts)
    }

    @Test
    func globallySampledProfileRemainsExplorableInFreshContext() {
        let excellent = makeSmartProfile(index: 1)
        let freshContextCandidate = makeSmartProfile(
            index: 2,
            protocolType: .hysteria2
        )
        let winnerStatistics = smartStatistics(
            attempts: 6,
            successes: 6,
            latency: 40,
            loss: 0,
            connectDuration: 1
        )
        let candidateProfileStatistics = smartStatistics(
            attempts: 3,
            successes: 0
        )
        let learning = SmartConnectionLearningSnapshot(
            contextProfileRecords: [SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: excellent.id,
                protocolType: excellent.protocolType,
                statistics: winnerStatistics
            )],
            profileRecords: [
                SmartConnectionProfileRecord(
                    profileID: excellent.id,
                    protocolType: excellent.protocolType,
                    statistics: winnerStatistics
                ),
                SmartConnectionProfileRecord(
                    profileID: freshContextCandidate.id,
                    protocolType: freshContextCandidate.protocolType,
                    statistics: candidateProfileStatistics
                )
            ]
        )

        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [excellent, freshContextCandidate],
            context: smartWiFiContext,
            learning: learning,
            now: now
        )

        #expect(candidateProfileStatistics.attemptCount == 3)
        #expect(learning.contextStatistics(
            profileID: freshContextCandidate.id,
            protocolType: freshContextCandidate.protocolType,
            context: smartWiFiContext
        ).attemptCount == 0)
        #expect(plan.explorationCandidateID == freshContextCandidate.id)
        #expect(plan.candidateIDs.first == freshContextCandidate.id)
    }

    @Test
    func recentFailureCooldownBlocksExploration() {
        let excellent = makeSmartProfile(index: 1)
        let newCandidate = makeSmartProfile(index: 2, protocolType: .hysteria2)
        var recentFailure = smartStatistics(attempts: 1, successes: 0)
        recentFailure.consecutiveFailures = 1
        recentFailure.lastFailureAt = now
        let learning = SmartConnectionLearningSnapshot(contextProfileRecords: [
            SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: excellent.id,
                protocolType: excellent.protocolType,
                statistics: smartStatistics(attempts: 20, successes: 20)
            ),
            SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: newCandidate.id,
                protocolType: newCandidate.protocolType,
                statistics: recentFailure
            )
        ])

        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [excellent, newCandidate],
            context: smartWiFiContext,
            learning: learning,
            now: now
        )

        #expect(plan.explorationCandidateID == nil)
        #expect(plan.candidateIDs.first == excellent.id)

        let afterCooldown = SmartConnectionCandidatePlanner().plan(
            profiles: [excellent, newCandidate],
            context: smartWiFiContext,
            learning: learning,
            now: now.addingTimeInterval(6 * 60 * 60)
        )
        #expect(afterCooldown.explorationCandidateID == newCandidate.id)
    }

    @Test
    func twoContextAttemptsExcludeKnownBadCandidateFromExploration() {
        let excellent = makeSmartProfile(index: 1)
        let sampled = makeSmartProfile(index: 2, protocolType: .hysteria2)
        let learning = SmartConnectionLearningSnapshot(contextProfileRecords: [
            SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: excellent.id,
                protocolType: excellent.protocolType,
                statistics: smartStatistics(attempts: 20, successes: 20)
            ),
            SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: sampled.id,
                protocolType: sampled.protocolType,
                statistics: smartStatistics(attempts: 2, successes: 1)
            )
        ])

        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [excellent, sampled],
            context: smartWiFiContext,
            learning: learning,
            now: now
        )

        #expect(plan.explorationCandidateID == nil)
        #expect(plan.candidateIDs.first == excellent.id)
    }

    @Test(arguments: ExplorationCooldownCase.cases)
    func adaptiveExplorationCooldownUsesUnexploredCandidateTable(
        testCase: ExplorationCooldownCase
    ) {
        let excellent = makeSmartProfile(index: 1)
        let candidates = (0..<testCase.unexploredCount).map {
            makeSmartProfile(index: $0 + 2, protocolType: .hysteria2)
        }
        let learning = explorationCooldownSnapshot(
            winner: excellent,
            explorationProfile: candidates[0],
            attemptedAt: now
        )
        let planner = SmartConnectionCandidatePlanner()
        let profiles = [excellent] + candidates

        let blocked = planner.plan(
            profiles: profiles,
            context: smartWiFiContext,
            learning: learning,
            now: now.addingTimeInterval(testCase.cooldown - 1)
        )
        let available = planner.plan(
            profiles: profiles,
            context: smartWiFiContext,
            learning: learning,
            now: now.addingTimeInterval(testCase.cooldown)
        )

        #expect(
            SmartConnectionCandidatePlanner.explorationCooldown(
                unexploredCount: testCase.unexploredCount
            ) == testCase.cooldown
        )
        #expect(blocked.explorationCandidateID == nil)
        #expect(available.explorationCandidateID != nil)
    }

    @Test
    func unexploredCountExcludesIneligibleAndFailureCooldownProfiles() {
        let excellent = makeSmartProfile(index: 1)
        let firstCandidate = makeSmartProfile(index: 2, protocolType: .hysteria2)
        let secondCandidate = makeSmartProfile(index: 3, protocolType: .hysteria2)
        let coolingCandidate = makeSmartProfile(index: 4, protocolType: .hysteria2)
        var disabledCandidate = makeSmartProfile(index: 5, protocolType: .hysteria2)
        disabledCandidate.isEnabled = false
        var recentFailure = smartStatistics(attempts: 1, successes: 0)
        recentFailure.consecutiveFailures = 1
        recentFailure.lastFailureAt = now.addingTimeInterval(4 * 60 * 60)
        let base = explorationCooldownSnapshot(
            winner: excellent,
            explorationProfile: firstCandidate,
            attemptedAt: now
        )
        let learning = SmartConnectionLearningSnapshot(
            contextProfileRecords: base.contextProfileRecords + [
                SmartConnectionContextProfileRecord(
                    context: smartWiFiContext,
                    profileID: coolingCandidate.id,
                    protocolType: coolingCandidate.protocolType,
                    statistics: recentFailure
                )
            ],
            explorationRecords: base.explorationRecords ?? []
        )
        let profiles = [
            excellent,
            firstCandidate,
            secondCandidate,
            coolingCandidate,
            disabledCandidate
        ]
        let planner = SmartConnectionCandidatePlanner()

        let nineHoursLater = planner.plan(
            profiles: profiles,
            context: smartWiFiContext,
            learning: learning,
            now: now.addingTimeInterval(9 * 60 * 60)
        )
        let thirteenHoursLater = planner.plan(
            profiles: profiles,
            context: smartWiFiContext,
            learning: learning,
            now: now.addingTimeInterval(13 * 60 * 60)
        )

        // Two candidates count at nine hours, so the 12-hour bucket applies.
        #expect(nineHoursLater.explorationCandidateID == nil)
        #expect(thirteenHoursLater.explorationCandidateID != nil)
    }

    @Test
    func explorationRequiresEstablishedWinnerWithFourAttempts() {
        let winner = makeSmartProfile(index: 1)
        let candidate = makeSmartProfile(index: 2, protocolType: .hysteria2)
        let learning = SmartConnectionLearningSnapshot(
            contextProfileRecords: [SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: winner.id,
                protocolType: winner.protocolType,
                statistics: smartStatistics(attempts: 3, successes: 3)
            )]
        )

        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [winner, candidate],
            context: smartWiFiContext,
            learning: learning,
            now: now
        )

        #expect(plan.explorationCandidateID == nil)
        #expect(plan.candidateIDs.first == winner.id)
    }

    @Test
    func explorationPriorityKeepsSixtyThirtyTenWeightsAndUUIDTieBreak() {
        let winner = makeSmartProfile(index: 1)
        let first = makeSmartProfile(index: 2, protocolType: .hysteria2)
        let second = makeSmartProfile(index: 3, protocolType: .hysteria2)
        let learning = SmartConnectionLearningSnapshot(
            contextProfileRecords: [
                SmartConnectionContextProfileRecord(
                    context: smartWiFiContext,
                    profileID: winner.id,
                    protocolType: winner.protocolType,
                    statistics: smartStatistics(attempts: 20, successes: 20)
                ),
                SmartConnectionContextProfileRecord(
                    context: smartWiFiContext,
                    profileID: first.id,
                    protocolType: first.protocolType,
                    statistics: smartStatistics(attempts: 1, successes: 1)
                )
            ],
            profileRecords: [SmartConnectionProfileRecord(
                profileID: second.id,
                protocolType: second.protocolType,
                statistics: smartStatistics(attempts: 2, successes: 2)
            )]
        )

        // first: 0.5*60% + 1*30% + 1*10% = 0.7
        // second: 1*60% + 0*30% + 1*10% = 0.7
        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [winner, second, first],
            context: smartWiFiContext,
            learning: learning,
            now: now
        )

        #expect(first.id.uuidString < second.id.uuidString)
        #expect(plan.explorationCandidateID == first.id)
        #expect(plan.candidateIDs.first == first.id)
    }

    @Test
    func poorKnownCandidateCannotDisplaceProvenExcellentCandidate() {
        let excellent = makeSmartProfile(index: 1, protocolType: .vless)
        let poor = makeSmartProfile(index: 2, protocolType: .hysteria2)
        let learning = SmartConnectionLearningSnapshot(
            contextProfileRecords: [
                SmartConnectionContextProfileRecord(
                    context: smartWiFiContext,
                    profileID: excellent.id,
                    protocolType: excellent.protocolType,
                    statistics: smartStatistics(
                        attempts: 100,
                        successes: 100,
                        latency: 40,
                        loss: 0,
                        connectDuration: 1,
                        completedSessions: 50,
                        unexpectedDisconnects: 0,
                        successfulSessionSeconds: 90_000
                    )
                ),
                SmartConnectionContextProfileRecord(
                    context: smartWiFiContext,
                    profileID: poor.id,
                    protocolType: poor.protocolType,
                    statistics: smartStatistics(attempts: 50, successes: 0)
                )
            ],
            profileRecords: [SmartConnectionProfileRecord(
                profileID: poor.id,
                protocolType: poor.protocolType,
                statistics: smartStatistics(attempts: 50, successes: 0)
            )]
        )

        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [poor, excellent],
            context: smartWiFiContext,
            learning: learning,
            now: now
        )

        #expect(plan.candidateIDs.first == excellent.id)
        #expect(plan.rankedCandidates.first { $0.profileID == poor.id }?
            .breakdown.explorationBonus == 0)
    }

    private func score(
        _ profile: VPNProfile,
        learning: SmartConnectionLearningSnapshot
    ) -> SmartConnectionRankedCandidate {
        calculator.score(
            profile: profile,
            context: smartWiFiContext,
            learning: learning,
            now: now
        )
    }
}

@Suite(.serialized)
struct SmartConnectionSelectionTests {
    @Test
    func productionSelectionAuthorityIsSwiftPlannerOnly() {
        #expect(
            SmartConnectionSelectionAuthorityContract.production
                == "swift-smart-connection-planner"
        )
    }

    @Test
    func automaticPlannerRanksAllEligibleProfiles() {
        let profiles = [
            makeSmartProfile(index: 3),
            makeSmartProfile(index: 1),
            makeSmartProfile(index: 2)
        ]

        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: profiles,
            context: smartWiFiContext,
            learning: .empty,
            now: smartTestNow
        )

        #expect(plan.rankedCandidates.count == 3)
        #expect(Set(plan.rankedCandidates.map(\.profileID)) == Set(profiles.map(\.id)))
    }

    @Test
    func highestEffectiveScoreBecomesRecommendation() {
        let preferred = makeSmartProfile(index: 2)
        let other = makeSmartProfile(index: 1)
        let learning = snapshot(entries: [
            (preferred, smartStatistics(
                attempts: 80,
                successes: 80,
                latency: 40,
                loss: 0,
                connectDuration: 1
            )),
            (other, smartStatistics(
                attempts: 80,
                successes: 30,
                latency: 800,
                loss: 15,
                connectDuration: 25
            ))
        ])

        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [other, preferred],
            context: smartWiFiContext,
            learning: learning,
            now: smartTestNow
        )

        #expect(plan.candidateIDs.first == preferred.id)
    }

    @Test
    func invalidAndUnavailableProfilesAreExcluded() {
        let valid = makeSmartProfile(index: 1)
        var disabled = makeSmartProfile(index: 2)
        disabled.isEnabled = false
        var incomplete = makeSmartProfile(index: 3)
        incomplete.credentialReference = nil

        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [incomplete, disabled, valid],
            context: smartWiFiContext,
            learning: .empty,
            now: smartTestNow
        )

        #expect(plan.rankedCandidates.map(\.profileID) == [valid.id])
    }

    @Test
    func equalScoresUseStableUUIDOrder() {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)

        let plan = SmartConnectionCandidatePlanner().plan(
            profiles: [second, first],
            context: smartWiFiContext,
            learning: .empty,
            now: smartTestNow
        )

        #expect(plan.rankedCandidates.map(\.profileID) == [first.id, second.id])
    }

    @Test
    @MainActor
    func automaticStartConnectsRecommendationNumberOne() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let manager = ScriptedSmartConnectionManager()
        let harness = try await makeSmartHarness(
            profiles: [second, first],
            manager: manager
        )
        #expect(harness.viewModel.automaticRecommendedProfileID == first.id)

        await harness.viewModel.connect()

        #expect(await manager.attemptedProfileIDs() == [first.id])
        #expect(harness.viewModel.connectionState == .connected)
    }

    @Test
    @MainActor
    func manualHysteria2SelectionRemainsAttemptable() async throws {
        let profile = makeSmartProfile(index: 1, protocolType: .hysteria2)
        let manager = ScriptedSmartConnectionManager()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            manager: manager
        )
        #expect(profile.runtimeCapability.isReady)
        harness.viewModel.selectConnectionMode(.manual)
        harness.viewModel.selectProfile(profile)

        await harness.viewModel.connect()

        #expect(await manager.attemptedProfileIDs() == [profile.id])
        #expect(harness.viewModel.connectionState == .connected)
    }
}

@Suite(.serialized)
struct SmartConnectionFallbackTests {
    @Test
    @MainActor
    func firstFailureTriggersSecondCandidate() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let manager = ScriptedSmartConnectionManager(scripts: [
            first.id: [.failure],
            second.id: [.success]
        ])
        let harness = try await makeSmartHarness(
            profiles: [first, second],
            manager: manager
        )

        await harness.viewModel.connect()

        #expect(await manager.attemptedProfileIDs() == [first.id, second.id])
        #expect(harness.viewModel.connectionState == .connected)
    }

    @Test
    @MainActor
    func failedFirstCandidateIsNotRetriedInSamePlan() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let manager = ScriptedSmartConnectionManager(scripts: [
            first.id: [.failure, .success],
            second.id: [.success]
        ])
        let harness = try await makeSmartHarness(
            profiles: [first, second],
            manager: manager
        )

        await harness.viewModel.connect()
        let attempts = await manager.attemptedProfileIDs()

        #expect(attempts.filter { $0 == first.id }.count == 1)
        #expect(attempts == [first.id, second.id])
    }

    @Test
    @MainActor
    func successfulFallbackStopsFurtherAttempts() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let third = makeSmartProfile(index: 3)
        let manager = ScriptedSmartConnectionManager(scripts: [
            first.id: [.failure],
            second.id: [.success],
            third.id: [.success]
        ])
        let harness = try await makeSmartHarness(
            profiles: [first, second, third],
            manager: manager
        )

        await harness.viewModel.connect()

        #expect(await manager.attemptedProfileIDs() == [first.id, second.id])
    }

    @Test
    @MainActor
    func allFailedCandidatesProduceOneFinalFailure() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let manager = ScriptedSmartConnectionManager(scripts: [
            first.id: [.failure],
            second.id: [.failure]
        ])
        let harness = try await makeSmartHarness(
            profiles: [first, second],
            manager: manager
        )

        await harness.viewModel.connect()

        #expect(await manager.attemptedProfileIDs() == [first.id, second.id])
        #expect(harness.viewModel.connectionState == .failed)
        #expect(harness.viewModel.errorMessage != nil)
    }

    @Test
    @MainActor
    func fallbackAttemptsAreBoundedToPlanMaximum() async throws {
        let profiles = (1...5).map { makeSmartProfile(index: $0) }
        let scripts = Dictionary(uniqueKeysWithValues: profiles.map {
            ($0.id, [ScriptedSmartOutcome.failure])
        })
        let manager = ScriptedSmartConnectionManager(scripts: scripts)
        let harness = try await makeSmartHarness(
            profiles: profiles,
            manager: manager
        )

        await harness.viewModel.connect()

        #expect(await manager.attemptedProfileIDs().count == 3)
        #expect(harness.viewModel.automaticCandidatePlan.maximumAttempts == 3)
    }

    @Test
    @MainActor
    func taskCancellationStopsFallbackAndDoesNotPenalizeProfile() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let manager = ScriptedSmartConnectionManager(scripts: [
            first.id: [.waitForCancellation],
            second.id: [.success]
        ])
        let harness = try await makeSmartHarness(
            profiles: [first, second],
            manager: manager
        )
        let task = Task { @MainActor in
            await harness.viewModel.connect()
        }
        let started = await eventually {
            await manager.attemptedProfileIDs().count == 1
        }
        #expect(started)

        task.cancel()
        await task.value
        let snapshot = await harness.learningStore.snapshot(for: [first, second])

        #expect(await manager.attemptedProfileIDs() == [first.id])
        #expect(snapshot.contextStatistics(
            profileID: first.id,
            protocolType: first.protocolType,
            context: smartWiFiContext
        ).failedConnectionCount == 0)
    }

    @Test
    @MainActor
    func manualModeNeverFallsBackToAnotherProfile() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let manager = ScriptedSmartConnectionManager(scripts: [
            first.id: [.failure],
            second.id: [.success]
        ])
        let harness = try await makeSmartHarness(
            profiles: [first, second],
            manager: manager
        )
        harness.viewModel.selectConnectionMode(.manual)
        harness.viewModel.selectProfile(first)

        await harness.viewModel.connect()

        #expect(await manager.attemptedProfileIDs() == [first.id])
        #expect(harness.viewModel.connectionState == .failed)
    }

    @Test
    @MainActor
    func automaticFallbackProducesNoAdditionalHaptics() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let manager = ScriptedSmartConnectionManager(scripts: [
            first.id: [.failure],
            second.id: [.success]
        ])
        let haptic = RecordingSmartConnectionHaptic()
        let harness = try await makeSmartHarness(
            profiles: [first, second],
            manager: manager,
            haptic: haptic
        )

        await harness.viewModel.userDidTapMainConnectionButton()

        #expect(haptic.callCount == 1)
        #expect(await manager.attemptedProfileIDs() == [first.id, second.id])
    }
}

@Suite(.serialized)
struct SmartConnectionSessionIntegrationTests {
    @Test
    @MainActor
    func attemptAndSessionKeepPlanContextDuringPathChanges() async throws {
        let profile = makeSmartProfile(index: 1)
        let manager = ScriptedSmartConnectionManager(scripts: [
            profile.id: [.waitForReleaseThenSuccess]
        ])
        let source = MutableSmartNetworkContextSource(context: smartWiFiContext)
        let telemetry = TestSmartConnectionTelemetryManager()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            manager: manager,
            networkSource: source,
            telemetry: telemetry
        )
        let connectTask = Task { @MainActor in
            await harness.viewModel.connect()
        }
        #expect(await eventually { await manager.pendingAttemptCount() == 1 })

        await source.set(smartCellularContext)
        #expect(await eventually {
            harness.viewModel.currentNetworkContext == smartCellularContext
        })
        await manager.releasePendingAttempts()
        await connectTask.value
        #expect(harness.viewModel.connectionState == .connected)

        await telemetry.emit(DashboardConnectionTelemetrySnapshot(
            sessionID: "immutable-context-session",
            connectedStartedAt: smartTestNow,
            runtimeSeconds: 10,
            latencyMilliseconds: 80,
            packetLossPercent: 2
        ))
        #expect(await eventually {
            harness.viewModel.connectionTelemetry.sessionID
                == "immutable-context-session"
        })
        await harness.viewModel.disconnect()

        let learning = await harness.learningStore.snapshot(for: [profile])
        let plannedContext = learning.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartWiFiContext
        )
        let transientContext = learning.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: smartCellularContext
        )
        #expect(plannedContext.attemptCount == 1)
        #expect(plannedContext.latencySampleCount == 1)
        #expect(plannedContext.packetLossSampleCount == 1)
        #expect(plannedContext.completedSessionCount == 1)
        #expect(transientContext == SmartConnectionStatistics())
    }

    @Test
    @MainActor
    func twoAnomaliesShowPassiveIndicatorWithoutConnectionControlOrHaptic() async throws {
        let profile = makeSmartProfile(index: 1)
        let manager = ScriptedSmartConnectionManager()
        let telemetry = TestSmartConnectionTelemetryManager()
        let haptic = RecordingSmartConnectionHaptic()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            manager: manager,
            learningSnapshot: smartAnomalyBaseline(for: profile),
            telemetry: telemetry,
            haptic: haptic
        )
        await harness.viewModel.connect()

        for runtime in [1.0, 2.0] {
            await telemetry.emit(DashboardConnectionTelemetrySnapshot(
                sessionID: "anomaly-session",
                connectedStartedAt: smartTestNow,
                runtimeSeconds: runtime,
                latencyMilliseconds: 200,
                packetLossPercent: 6
            ))
            _ = await eventually {
                harness.viewModel.connectionTelemetry.runtimeSeconds == runtime
            }
        }

        #expect(harness.viewModel.smartConnectionQualityState == .degraded)
        #expect(harness.viewModel.showsConnectionQualityDegradedIndicator)
        #expect(harness.viewModel.connectionState == .connected)
        #expect(await manager.attemptedProfileIDs() == [profile.id])
        #expect(await manager.disconnectCallCount() == 0)
        #expect(haptic.callCount == 0)
    }

    @Test
    @MainActor
    func oneAnomalyKeepsPassiveIndicatorHidden() async throws {
        let profile = makeSmartProfile(index: 1)
        let telemetry = TestSmartConnectionTelemetryManager()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            learningSnapshot: smartAnomalyBaseline(for: profile),
            telemetry: telemetry
        )
        await harness.viewModel.connect()

        await telemetry.emit(DashboardConnectionTelemetrySnapshot(
            sessionID: "single-anomaly-session",
            connectedStartedAt: smartTestNow,
            runtimeSeconds: 1,
            latencyMilliseconds: 200,
            packetLossPercent: 6
        ))
        #expect(await eventually {
            harness.viewModel.connectionTelemetry.runtimeSeconds == 1
        })

        #expect(harness.viewModel.smartConnectionQualityState == .normal)
        #expect(harness.viewModel.showsConnectionQualityDegradedIndicator == false)
    }

    @Test
    @MainActor
    func healthyMeasurementHidesPassiveIndicator() async throws {
        let profile = makeSmartProfile(index: 1)
        let telemetry = TestSmartConnectionTelemetryManager()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            learningSnapshot: smartAnomalyBaseline(for: profile),
            telemetry: telemetry
        )
        await harness.viewModel.connect()

        for runtime in [1.0, 2.0] {
            await telemetry.emit(DashboardConnectionTelemetrySnapshot(
                sessionID: "recovering-anomaly-session",
                connectedStartedAt: smartTestNow,
                runtimeSeconds: runtime,
                latencyMilliseconds: 200,
                packetLossPercent: 6
            ))
            #expect(await eventually {
                harness.viewModel.connectionTelemetry.runtimeSeconds == runtime
            })
        }
        #expect(harness.viewModel.showsConnectionQualityDegradedIndicator)

        await telemetry.emit(DashboardConnectionTelemetrySnapshot(
            sessionID: "recovering-anomaly-session",
            connectedStartedAt: smartTestNow,
            runtimeSeconds: 3,
            latencyMilliseconds: 50,
            packetLossPercent: 1
        ))
        #expect(await eventually {
            harness.viewModel.connectionTelemetry.runtimeSeconds == 3
        })

        #expect(harness.viewModel.smartConnectionQualityState == .normal)
        #expect(harness.viewModel.showsConnectionQualityDegradedIndicator == false)
    }

    @Test
    @MainActor
    func finishingSessionResetsQualityAndHidesPassiveIndicator() async throws {
        let profile = makeSmartProfile(index: 1)
        let telemetry = TestSmartConnectionTelemetryManager()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            learningSnapshot: smartAnomalyBaseline(for: profile),
            telemetry: telemetry
        )
        await harness.viewModel.connect()

        for runtime in [1.0, 2.0] {
            await telemetry.emit(DashboardConnectionTelemetrySnapshot(
                sessionID: "finished-anomaly-session",
                connectedStartedAt: smartTestNow,
                runtimeSeconds: runtime,
                latencyMilliseconds: 200,
                packetLossPercent: 6
            ))
            #expect(await eventually {
                harness.viewModel.connectionTelemetry.runtimeSeconds == runtime
            })
        }
        #expect(harness.viewModel.showsConnectionQualityDegradedIndicator)

        await harness.viewModel.disconnect()

        #expect(harness.viewModel.smartConnectionQualityState == .normal)
        #expect(harness.viewModel.showsConnectionQualityDegradedIndicator == false)
        #expect(harness.viewModel.connectionState == .disconnected)
    }

    @Test
    @MainActor
    func healthyConnectedTunnelIsNotSwitchedForHigherAlternativeScore() async throws {
        let first = makeSmartProfile(index: 1)
        let second = makeSmartProfile(index: 2)
        let manager = ScriptedSmartConnectionManager()
        let source = MutableSmartNetworkContextSource(context: smartWiFiContext)
        let harness = try await makeSmartHarness(
            profiles: [first, second],
            manager: manager,
            networkSource: source
        )
        await harness.viewModel.connect()
        #expect(await manager.attemptedProfileIDs() == [first.id])

        for _ in 0..<20 {
            await harness.learningStore.recordConnectionSuccess(
                profileID: second.id,
                protocolType: second.protocolType,
                context: smartCellularContext,
                connectDuration: 1,
                at: smartTestNow
            )
        }
        await source.set(smartCellularContext)
        _ = await eventually {
            harness.viewModel.currentNetworkContext == smartCellularContext
        }

        #expect(harness.viewModel.connectionState == .connected)
        #expect(await manager.attemptedProfileIDs() == [first.id])
        #expect(await manager.disconnectCallCount() == 0)
    }

    @Test
    @MainActor
    func sessionAccumulatorKeepsLastTwentyLatencyObservationsAsTail() async throws {
        let profile = makeSmartProfile(index: 1)
        let telemetry = TestSmartConnectionTelemetryManager()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            telemetry: telemetry
        )
        await harness.viewModel.connect()

        let observations = Array(repeating: 50, count: 55)
            + Array(repeating: 900, count: 5)
        for (index, latency) in observations.enumerated() {
            let runtime = Double(index + 1)
            await telemetry.emit(DashboardConnectionTelemetrySnapshot(
                sessionID: "ring-tail-session",
                connectedStartedAt: smartTestNow,
                runtimeSeconds: runtime,
                latencyMilliseconds: latency,
                packetLossPercent: nil
            ))
            #expect(await eventually {
                harness.viewModel.connectionTelemetry.runtimeSeconds == runtime
            })
        }
        #expect(await eventually {
            let snapshot = await harness.learningStore.snapshot(for: [profile])
            return snapshot.pendingQualityRecords?.first?.latencyCount == 60
        })
        await harness.viewModel.disconnect()

        let statistics = await contextStatistics(
            store: harness.learningStore,
            profile: profile
        )
        let mean = try #require(statistics.ewmaLatencyMilliseconds)
        let tail = try #require(statistics.ewmaTailLatencyMilliseconds)
        #expect(abs(mean - 120.833_333_333_333_33) < 0.000_001)
        #expect(abs(tail - 262.5) < 0.000_001)
    }

    @Test
    @MainActor
    func checkpointDoesNotInflateIndependentQualitySamples() async throws {
        let profile = makeSmartProfile(index: 1)
        let telemetry = TestSmartConnectionTelemetryManager()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            telemetry: telemetry
        )
        await harness.viewModel.connect()

        await telemetry.emit(DashboardConnectionTelemetrySnapshot(
            sessionID: "session-one",
            connectedStartedAt: smartTestNow,
            runtimeSeconds: 61,
            latencyMilliseconds: 80,
            packetLossPercent: 2
        ))
        let checkpointed = await eventually {
            let value = await harness.learningStore.snapshot(for: [profile])
            return value.pendingQualityRecords?.first?
                .accumulatedSessionSeconds == 61
        }

        #expect(checkpointed)
        var statistics = await contextStatistics(
            store: harness.learningStore,
            profile: profile
        )
        #expect(statistics.latencySampleCount == 0)
        #expect(statistics.packetLossSampleCount == 0)
        #expect(statistics.successfulSessionSeconds == 0)

        await telemetry.emit(DashboardConnectionTelemetrySnapshot(
            sessionID: "session-one",
            connectedStartedAt: smartTestNow,
            runtimeSeconds: 122,
            latencyMilliseconds: 120,
            packetLossPercent: 4
        ))
        let secondCheckpoint = await eventually {
            let value = await harness.learningStore.snapshot(for: [profile])
            return value.pendingQualityRecords?.first?
                .accumulatedSessionSeconds == 122
        }
        #expect(secondCheckpoint)
        statistics = await contextStatistics(store: harness.learningStore, profile: profile)
        #expect(statistics.latencySampleCount == 0)
        #expect(statistics.packetLossSampleCount == 0)

        await harness.viewModel.disconnect()
        statistics = await contextStatistics(store: harness.learningStore, profile: profile)
        #expect(statistics.latencySampleCount == 1)
        #expect(statistics.packetLossSampleCount == 1)
        #expect(statistics.ewmaLatencyMilliseconds == 100)
        #expect(statistics.ewmaPacketLossPercent == 3)
        #expect(statistics.successfulSessionSeconds == 122)
        #expect(await telemetry.reconcileCallCount() >= 2)
    }

    @Test
    @MainActor
    func newSessionDoesNotInheritTransientTelemetrySnapshot() async throws {
        let profile = makeSmartProfile(index: 1)
        let telemetry = TestSmartConnectionTelemetryManager()
        let harness = try await makeSmartHarness(
            profiles: [profile],
            telemetry: telemetry
        )
        await harness.viewModel.connect()
        await telemetry.emit(DashboardConnectionTelemetrySnapshot(
            sessionID: "first-session",
            connectedStartedAt: smartTestNow,
            runtimeSeconds: 10,
            latencyMilliseconds: 50,
            packetLossPercent: 0
        ))
        _ = await eventually {
            harness.viewModel.connectionTelemetry.sessionID == "first-session"
        }
        await harness.viewModel.disconnect()

        await harness.viewModel.connect()
        let reset = await eventually {
            harness.viewModel.connectionTelemetry == .unavailable
        }

        #expect(reset)
        await telemetry.emit(DashboardConnectionTelemetrySnapshot(
            sessionID: "second-session",
            connectedStartedAt: smartTestNow,
            runtimeSeconds: 1,
            latencyMilliseconds: 200,
            packetLossPercent: nil
        ))
        let secondApplied = await eventually {
            harness.viewModel.connectionTelemetry.sessionID == "second-session"
        }
        #expect(secondApplied)
        #expect(harness.viewModel.connectionTelemetry.latencyMilliseconds == 200)
    }
}

@Suite(.serialized)
struct SmartConnectionAnomalyDetectorTests {
    @Test
    func requiresTwoConsecutiveSourceSupportedAnomalies() {
        var detector = SmartConnectionAnomalyDetector()

        #expect(detector.observe(
            latencyMilliseconds: 199,
            packetLossPercent: nil,
            baselineLatencyMilliseconds: 100,
            baselinePacketLossPercent: nil
        ) == .normal)
        #expect(detector.observe(
            latencyMilliseconds: 200,
            packetLossPercent: nil,
            baselineLatencyMilliseconds: 100,
            baselinePacketLossPercent: nil
        ) == .normal)
        #expect(detector.observe(
            latencyMilliseconds: 200,
            packetLossPercent: nil,
            baselineLatencyMilliseconds: 100,
            baselinePacketLossPercent: nil
        ) == .degraded)
        #expect(detector.observe(
            latencyMilliseconds: 100,
            packetLossPercent: 1,
            baselineLatencyMilliseconds: 100,
            baselinePacketLossPercent: 1
        ) == .normal)
        #expect(detector.observe(
            latencyMilliseconds: nil,
            packetLossPercent: 6,
            baselineLatencyMilliseconds: nil,
            baselinePacketLossPercent: 1
        ) == .normal)
        #expect(detector.observe(
            latencyMilliseconds: nil,
            packetLossPercent: 6,
            baselineLatencyMilliseconds: nil,
            baselinePacketLossPercent: 1
        ) == .degraded)
    }
}

private struct SmartConnectionHarness {
    let viewModel: VPNDashboardViewModel
    let manager: ScriptedSmartConnectionManager
    let learningStore: InMemorySmartConnectionLearningStore
    let networkSource: MutableSmartNetworkContextSource
    let telemetry: TestSmartConnectionTelemetryManager
    let haptic: RecordingSmartConnectionHaptic
}

@MainActor
private func makeSmartHarness(
    profiles: [VPNProfile],
    manager: ScriptedSmartConnectionManager = ScriptedSmartConnectionManager(),
    learningSnapshot: SmartConnectionLearningSnapshot = .empty,
    networkSource: MutableSmartNetworkContextSource =
        MutableSmartNetworkContextSource(context: smartWiFiContext),
    telemetry: TestSmartConnectionTelemetryManager =
        TestSmartConnectionTelemetryManager(),
    haptic: RecordingSmartConnectionHaptic? = nil,
    debounceSleeper: any SmartConnectionDebounceSleeping =
        ImmediateSmartConnectionDebounceSleeper(),
    debounceDuration: Duration = .zero
) async throws -> SmartConnectionHarness {
    let hapticFeedback = haptic ?? RecordingSmartConnectionHaptic()
    let repository = InMemoryVPNProfileRepository()
    for profile in profiles {
        try await repository.save(profile)
    }
    let learningStore = InMemorySmartConnectionLearningStore(
        snapshot: learningSnapshot
    )
    let activeStore = TestSmartActiveProfileStore(profileID: nil)
    let manualStore = TestSmartManualProfileSelectionStore(profileID: nil)
    let viewModel = VPNDashboardViewModel(
        serverProvider: EmptySmartServerProvider(),
        connectionManager: manager,
        profileRepository: repository,
        subscriptionRepository: InMemorySubscriptionRepository(),
        activeProfileStore: activeStore,
        manualProfileSelectionStore: manualStore,
        connectionTelemetryManager: telemetry,
        learningStore: learningStore,
        networkContextSource: networkSource,
        smartConnectionClock: FixedSmartConnectionClock(now: smartTestNow),
        networkContextDebounceSleeper: debounceSleeper,
        networkContextDebounceDuration: debounceDuration,
        connectionActionHapticFeedback: hapticFeedback
    )
    await viewModel.loadInitialData()
    return SmartConnectionHarness(
        viewModel: viewModel,
        manager: manager,
        learningStore: learningStore,
        networkSource: networkSource,
        telemetry: telemetry,
        haptic: hapticFeedback
    )
}

@MainActor
private func eventually(
    _ condition: @escaping @MainActor () async -> Bool
) async -> Bool {
    for _ in 0..<300 {
        if await condition() {
            return true
        }
        await Task.yield()
    }
    return false
}

private let smartTestNow = Date(timeIntervalSince1970: 2_000_000_000)

private let smartWiFiContext = NetworkContext(
    interfaceClass: .wifi,
    isExpensive: false,
    isConstrained: false,
    supportsIPv4: true,
    supportsIPv6: true
)

private let smartCellularContext = NetworkContext(
    interfaceClass: .cellular,
    isExpensive: true,
    isConstrained: false,
    supportsIPv4: true,
    supportsIPv6: true
)

private let smartWiredContext = NetworkContext(
    interfaceClass: .wiredEthernet,
    isExpensive: false,
    isConstrained: false,
    supportsIPv4: true,
    supportsIPv6: true
)

private func makeSmartProfile(
    index: Int,
    protocolType: VPNProtocol = .vless
) -> VPNProfile {
    let configuration: VPNProtocolConfiguration
    switch protocolType {
    case .hysteria2:
        configuration = .hysteria2(
            Hysteria2ProfileConfiguration(obfs: nil, bandwidthHint: nil)
        )
    default:
        configuration = .vless(
            VLESSProfileConfiguration(flow: nil, encryption: "none")
        )
    }
    var profile = VPNProfile.draft(
        name: "Profile \(index)",
        protocolType: protocolType,
        serverAddress: "profile-\(index).example.invalid",
        port: 443,
        credentialReference: "keychain://smart-test/\(index)",
        transportSettings: VPNTransportSettings(
            network: protocolType == .hysteria2 ? "hysteria" : "tcp",
            security: "tls"
        ),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: "profile-\(index).example.invalid"
        ),
        protocolConfiguration: configuration,
        source: .manual,
        now: smartTestNow
    )
    profile.id = UUID(
        uuidString: String(
            format: "00000000-0000-0000-0000-%012d",
            index
        )
    )!
    return profile
}

private func smartStatistics(
    attempts: Int,
    successes: Int,
    latency: Double? = nil,
    loss: Double? = nil,
    connectDuration: Double? = nil,
    completedSessions: Int = 0,
    unexpectedDisconnects: Int = 0,
    successfulSessionSeconds: TimeInterval = 0
) -> SmartConnectionStatistics {
    var statistics = SmartConnectionStatistics()
    statistics.attemptCount = attempts
    statistics.successfulConnectionCount = successes
    statistics.failedConnectionCount = max(0, attempts - successes)
    statistics.ewmaLatencyMilliseconds = latency
    statistics.latencySampleCount = latency == nil ? 0 : max(1, attempts)
    statistics.ewmaPacketLossPercent = loss
    statistics.packetLossSampleCount = loss == nil ? 0 : max(1, attempts)
    statistics.ewmaConnectDurationSeconds = connectDuration
    statistics.connectDurationSampleCount = connectDuration == nil
        ? 0
        : max(1, successes)
    statistics.completedSessionCount = completedSessions
    statistics.unexpectedDisconnectCount = unexpectedDisconnects
    statistics.successfulSessionSeconds = successfulSessionSeconds
    statistics.lastAttemptAt = attempts > 0 ? smartTestNow : nil
    statistics.lastSuccessAt = successes > 0 ? smartTestNow : nil
    statistics.lastUpdatedAt = attempts > 0
        || latency != nil
        || loss != nil
        || completedSessions > 0
        ? smartTestNow
        : nil
    return statistics
}

private func smartAnomalyBaseline(
    for profile: VPNProfile
) -> SmartConnectionLearningSnapshot {
    snapshot(entries: [
        (profile, smartStatistics(
            attempts: 20,
            successes: 20,
            latency: 50,
            loss: 1,
            connectDuration: 1
        ))
    ])
}

private func snapshot(
    entries: [(VPNProfile, SmartConnectionStatistics)]
) -> SmartConnectionLearningSnapshot {
    SmartConnectionLearningSnapshot(
        contextProfileRecords: entries.map { profile, statistics in
            SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: profile.id,
                protocolType: profile.protocolType,
                statistics: statistics
            )
        }
    )
}

private func paritySeedSnapshot(
    first: VPNProfile,
    second: VPNProfile
) -> SmartConnectionLearningSnapshot {
    let firstStatistics = smartStatistics(
        attempts: 6,
        successes: 5,
        latency: 70,
        loss: 1,
        connectDuration: 2,
        completedSessions: 4,
        unexpectedDisconnects: 1,
        successfulSessionSeconds: 1_200
    )
    let secondStatistics = smartStatistics(
        attempts: 3,
        successes: 2,
        latency: 180,
        loss: 3,
        connectDuration: 5,
        completedSessions: 2,
        successfulSessionSeconds: 300
    )
    return SmartConnectionLearningSnapshot(
        contextProfileRecords: [
            SmartConnectionContextProfileRecord(
                context: smartWiFiContext,
                profileID: first.id,
                protocolType: first.protocolType,
                statistics: firstStatistics
            ),
            SmartConnectionContextProfileRecord(
                context: smartCellularContext,
                profileID: second.id,
                protocolType: second.protocolType,
                statistics: secondStatistics
            )
        ],
        profileRecords: [
            SmartConnectionProfileRecord(
                profileID: first.id,
                protocolType: first.protocolType,
                statistics: firstStatistics
            ),
            SmartConnectionProfileRecord(
                profileID: second.id,
                protocolType: second.protocolType,
                statistics: secondStatistics
            )
        ],
        protocolRecords: [SmartConnectionProtocolRecord(
            protocolType: first.protocolType,
            statistics: firstStatistics
        )],
        explorationRecords: [SmartConnectionExplorationRecord(
            profileID: second.id,
            protocolType: second.protocolType,
            context: smartCellularContext,
            attemptedAt: smartTestNow
        )],
        committedSessionIDs: ["already-committed-session"]
    )
}

private func expectStoreParity(
    seed: SmartConnectionLearningSnapshot,
    profiles: [VPNProfile]?
) async throws {
    let fileURL = temporaryLearningFileURL()
    defer { try? FileManager.default.removeItem(at: fileURL) }
    try writeLearningSnapshot(seed, to: fileURL)
    let fileStore = FileSmartConnectionLearningStore(fileURL: fileURL)
    let memoryStore = InMemorySmartConnectionLearningStore(snapshot: seed)

    let fileValue = await fileStore.snapshot(for: profiles)
    let memoryValue = await memoryStore.snapshot(for: profiles)

    #expect(fileValue == memoryValue)
}

private func contextPreferenceSnapshot(
    first: VPNProfile,
    second: VPNProfile,
    firstPreferredContext: NetworkContext,
    secondPreferredContext: NetworkContext
) -> SmartConnectionLearningSnapshot {
    let good = smartStatistics(
        attempts: 40,
        successes: 40,
        latency: 40,
        loss: 0,
        connectDuration: 1
    )
    let poor = smartStatistics(
        attempts: 40,
        successes: 40,
        latency: 950,
        loss: 18,
        connectDuration: 28
    )
    return SmartConnectionLearningSnapshot(contextProfileRecords: [
        SmartConnectionContextProfileRecord(
            context: firstPreferredContext,
            profileID: first.id,
            protocolType: first.protocolType,
            statistics: good
        ),
        SmartConnectionContextProfileRecord(
            context: firstPreferredContext,
            profileID: second.id,
            protocolType: second.protocolType,
            statistics: poor
        ),
        SmartConnectionContextProfileRecord(
            context: secondPreferredContext,
            profileID: first.id,
            protocolType: first.protocolType,
            statistics: poor
        ),
        SmartConnectionContextProfileRecord(
            context: secondPreferredContext,
            profileID: second.id,
            protocolType: second.protocolType,
            statistics: good
        )
    ])
}

private func recordSessionMetric(
    store: InMemorySmartConnectionLearningStore,
    profile: VPNProfile,
    latency: Double?,
    loss: Double?
) async {
    await store.recordSessionSummary(
        SmartConnectionSessionSummary(
            additionalSuccessfulSessionSeconds: 0,
            latencyMilliseconds: latency,
            packetLossPercent: loss,
            sessionEnded: true,
            unexpectedDisconnect: false,
            sessionID: UUID().uuidString
        ),
        profileID: profile.id,
        protocolType: profile.protocolType,
        context: smartWiFiContext,
        at: smartTestNow
    )
}

private func contextStatistics(
    store: InMemorySmartConnectionLearningStore,
    profile: VPNProfile
) async -> SmartConnectionStatistics {
    let snapshot = await store.snapshot(for: [profile])
    return snapshot.contextStatistics(
        profileID: profile.id,
        protocolType: profile.protocolType,
        context: smartWiFiContext
    )
}

private func temporaryLearningFileURL() -> URL {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("smart-learning-\(UUID().uuidString).json")
}

private func temporaryLearningDirectoryURL() -> URL {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("smart-learning-\(UUID().uuidString)", isDirectory: true)
}

private func writeLearningSnapshot(
    _ snapshot: SmartConnectionLearningSnapshot,
    to fileURL: URL
) throws {
    try FileManager.default.createDirectory(
        at: fileURL.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(snapshot).write(to: fileURL, options: [.atomic])
}

private func decodeLearningSnapshot(
    at fileURL: URL
) throws -> SmartConnectionLearningSnapshot {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return try decoder.decode(
        SmartConnectionLearningSnapshot.self,
        from: Data(contentsOf: fileURL)
    )
}

enum SmartLearningStoreKind: CaseIterable, Sendable {
    case file
    case memory
}

nonisolated struct ExplorationCooldownCase: Sendable, CustomTestStringConvertible {
    let unexploredCount: Int
    let cooldown: TimeInterval

    var testDescription: String {
        "\(unexploredCount) unexplored, \(Int(cooldown / 3_600))h"
    }

    static let cases = [
        ExplorationCooldownCase(unexploredCount: 4, cooldown: 4 * 60 * 60),
        ExplorationCooldownCase(unexploredCount: 3, cooldown: 8 * 60 * 60),
        ExplorationCooldownCase(unexploredCount: 2, cooldown: 12 * 60 * 60),
        ExplorationCooldownCase(unexploredCount: 1, cooldown: 24 * 60 * 60)
    ]
}

private func explorationCooldownSnapshot(
    winner: VPNProfile,
    explorationProfile: VPNProfile,
    attemptedAt: Date
) -> SmartConnectionLearningSnapshot {
    SmartConnectionLearningSnapshot(
        contextProfileRecords: [SmartConnectionContextProfileRecord(
            context: smartWiFiContext,
            profileID: winner.id,
            protocolType: winner.protocolType,
            statistics: smartStatistics(
                attempts: 20,
                successes: 20,
                latency: 40,
                loss: 0,
                connectDuration: 1
            )
        )],
        explorationRecords: [SmartConnectionExplorationRecord(
            profileID: explorationProfile.id,
            protocolType: explorationProfile.protocolType,
            context: smartWiFiContext,
            attemptedAt: attemptedAt
        )]
    )
}

private struct SmartLearningStoreHarness {
    let store: any SmartConnectionLearningStoring
    let fileURL: URL?

    func cleanup() {
        guard let fileURL else { return }
        try? FileManager.default.removeItem(at: fileURL)
    }
}

private func makeLearningStoreHarness(
    kind: SmartLearningStoreKind,
    snapshot: SmartConnectionLearningSnapshot = .empty,
    clock: any SmartConnectionClock
) throws -> SmartLearningStoreHarness {
    switch kind {
    case .file:
        let fileURL = temporaryLearningFileURL()
        try writeLearningSnapshot(snapshot, to: fileURL)
        return SmartLearningStoreHarness(
            store: FileSmartConnectionLearningStore(
                fileURL: fileURL,
                clock: clock
            ),
            fileURL: fileURL
        )
    case .memory:
        return SmartLearningStoreHarness(
            store: InMemorySmartConnectionLearningStore(
                snapshot: snapshot,
                clock: clock
            ),
            fileURL: nil
        )
    }
}

private func qualitySummary(
    sessionID: String,
    latencyValues: [Double],
    lossValues: [Double],
    additionalSeconds: TimeInterval,
    sessionEnded: Bool
) -> SmartConnectionSessionSummary {
    let aggregate = SmartConnectionSessionQualityAggregate(
        latencySum: latencyValues.reduce(0, +),
        latencyCount: latencyValues.count,
        tailLatencyMilliseconds: tailMean(latencyValues),
        packetLossSum: lossValues.reduce(0, +),
        packetLossCount: lossValues.count,
        tailPacketLossPercent: tailMean(lossValues)
    )
    return SmartConnectionSessionSummary(
        additionalSuccessfulSessionSeconds: additionalSeconds,
        latencyMilliseconds: aggregate.latencyMeanMilliseconds,
        packetLossPercent: aggregate.packetLossMeanPercent,
        sessionEnded: sessionEnded,
        unexpectedDisconnect: false,
        sessionID: sessionID,
        tailLatencyMilliseconds: aggregate.tailLatencyMilliseconds,
        tailPacketLossPercent: aggregate.tailPacketLossPercent,
        qualityAggregate: aggregate,
        qualityAggregateIsCumulative: true
    )
}

private func pendingQualityRecord(
    profile: VPNProfile,
    sessionID: String,
    updatedAt: Date,
    latencyValues: [Double],
    lossValues: [Double],
    accumulatedSeconds: TimeInterval
) -> SmartConnectionPendingQualityRecord {
    guard let commitKey = SmartConnectionLearningTransform.commitKey(
        profileID: profile.id,
        protocolType: profile.protocolType,
        context: smartWiFiContext,
        sessionID: sessionID
    ) else {
        preconditionFailure("A non-empty test session ID must produce a commit key")
    }
    return SmartConnectionPendingQualityRecord(
        commitKey: commitKey,
        profileID: profile.id,
        protocolType: profile.protocolType,
        context: smartWiFiContext,
        latencySum: latencyValues.reduce(0, +),
        latencyCount: latencyValues.count,
        tailLatencyMilliseconds: tailMean(latencyValues),
        packetLossSum: lossValues.reduce(0, +),
        packetLossCount: lossValues.count,
        tailPacketLossPercent: tailMean(lossValues),
        accumulatedSessionSeconds: accumulatedSeconds,
        updatedAt: updatedAt
    )
}

private func tailMean(_ values: [Double]) -> Double? {
    let tail = values.suffix(20)
    guard tail.isEmpty == false else { return nil }
    return tail.reduce(0, +) / Double(tail.count)
}

private struct FixedSmartConnectionClock: SmartConnectionClock {
    let nowValue: Date

    init(now: Date) {
        nowValue = now
    }

    func now() -> Date {
        nowValue
    }
}

private struct ImmediateSmartConnectionDebounceSleeper:
    SmartConnectionDebounceSleeping {
    func sleep(for duration: Duration) async throws {
        try Task.checkCancellation()
    }
}

private actor ControlledSmartConnectionDebounceSleeper:
    SmartConnectionDebounceSleeping {
    private var waiters: [UUID: CheckedContinuation<Void, Never>] = [:]
    private var calls = 0

    func sleep(for duration: Duration) async throws {
        calls += 1
        let id = UUID()
        try Task.checkCancellation()
        try await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                waiters[id] = continuation
            }
            try Task.checkCancellation()
        } onCancel: {
            Task { await self.release(id: id) }
        }
    }

    func pendingCount() -> Int {
        waiters.count
    }

    func sleepCallCount() -> Int {
        calls
    }

    func releaseAll() {
        let continuations = Array(waiters.values)
        waiters.removeAll()
        continuations.forEach { $0.resume() }
    }

    private func release(id: UUID) {
        waiters.removeValue(forKey: id)?.resume()
    }
}

private struct EmptySmartServerProvider: ServerProviding {
    func fetchServers() async throws -> [VPNServer] {
        []
    }
}

private actor TestSmartActiveProfileStore: ActiveProfileStoring {
    private var profileID: UUID?

    init(profileID: UUID?) {
        self.profileID = profileID
    }

    func activeProfileID() async -> UUID? {
        profileID
    }

    func saveActiveProfileID(_ id: UUID?) async {
        profileID = id
    }
}

private actor TestSmartManualProfileSelectionStore:
    ManualProfileSelectionStoring {
    private var profileID: UUID?

    init(profileID: UUID?) {
        self.profileID = profileID
    }

    func manualSelectedProfileID() async -> UUID? {
        profileID
    }

    func saveManualSelectedProfileID(_ id: UUID?) async {
        profileID = id
    }
}

nonisolated private final class MutableSmartNetworkContextSource:
    SmartConnectionNetworkContextProviding,
    @unchecked Sendable {
    private let storage: MutableSmartNetworkContextStorage

    init(context: NetworkContext) {
        storage = MutableSmartNetworkContextStorage(context: context)
    }

    func currentNetworkContext() async -> NetworkContext {
        await storage.current()
    }

    func networkContextUpdates() -> AsyncStream<NetworkContext> {
        let storage = storage
        return AsyncStream { continuation in
            let id = UUID()
            Task {
                await storage.addContinuation(continuation, id: id)
            }
            continuation.onTermination = { _ in
                Task {
                    await storage.removeContinuation(id: id)
                }
            }
        }
    }

    func set(_ context: NetworkContext) async {
        await storage.set(context)
    }

    func observerCount() async -> Int {
        await storage.observerCount()
    }
}

private actor MutableSmartNetworkContextStorage {
    private var context: NetworkContext
    private var continuations:
        [UUID: AsyncStream<NetworkContext>.Continuation] = [:]

    init(context: NetworkContext) {
        self.context = context
    }

    func current() -> NetworkContext {
        context
    }

    func set(_ newContext: NetworkContext) {
        context = newContext
        continuations.values.forEach { $0.yield(newContext) }
    }

    func addContinuation(
        _ continuation: AsyncStream<NetworkContext>.Continuation,
        id: UUID
    ) {
        continuations[id] = continuation
        continuation.yield(context)
    }

    func removeContinuation(id: UUID) {
        continuations[id] = nil
    }

    func observerCount() -> Int {
        continuations.count
    }
}

private enum ScriptedSmartOutcome: Sendable {
    case success
    case failure
    case waitForCancellation
    case waitForReleaseThenSuccess
}

private enum ScriptedSmartConnectionError: LocalizedError {
    case failed(UUID)

    var errorDescription: String? {
        "Scripted connection failure"
    }
}

nonisolated private final class ScriptedSmartConnectionManager:
    VPNConnectionManaging,
    @unchecked Sendable {
    private let storage: ScriptedSmartConnectionStorage

    init(scripts: [UUID: [ScriptedSmartOutcome]] = [:]) {
        storage = ScriptedSmartConnectionStorage(scripts: scripts)
    }

    func currentState() async -> VPNConnectionState {
        await storage.currentState()
    }

    func stateUpdates() -> AsyncStream<VPNConnectionState> {
        let storage = storage
        return AsyncStream { continuation in
            let id = UUID()
            Task {
                await storage.addContinuation(continuation, id: id)
            }
            continuation.onTermination = { _ in
                Task {
                    await storage.removeContinuation(id: id)
                }
            }
        }
    }

    func authoritativeConnection() async -> VPNAuthoritativeConnection {
        await storage.authoritativeConnection()
    }

    func refreshAuthoritativeConnection() async -> VPNAuthoritativeConnection {
        await storage.authoritativeConnection()
    }

    func connect(using profile: VPNProfile) async throws {
        let outcome = await storage.beginAttempt(profileID: profile.id)
        switch outcome {
        case .success:
            await storage.completeSuccess(profileID: profile.id)
        case .failure:
            await storage.completeFailure()
            throw ScriptedSmartConnectionError.failed(profile.id)
        case .waitForCancellation:
            try await Task.sleep(for: .seconds(60))
            throw ScriptedSmartConnectionError.failed(profile.id)
        case .waitForReleaseThenSuccess:
            await storage.waitForAttemptRelease(profileID: profile.id)
            await storage.completeSuccess(profileID: profile.id)
        }
    }

    func disconnect() async {
        await storage.disconnect()
    }

    func emitUnexpectedDisconnect() async {
        await storage.emitUnexpectedDisconnect()
    }

    func attemptedProfileIDs() async -> [UUID] {
        await storage.attemptedProfileIDs()
    }

    func disconnectCallCount() async -> Int {
        await storage.disconnectCallCount()
    }

    func pendingAttemptCount() async -> Int {
        await storage.pendingAttemptCount()
    }

    func releasePendingAttempts() async {
        await storage.releasePendingAttempts()
    }
}

private actor ScriptedSmartConnectionStorage {
    private var scripts: [UUID: [ScriptedSmartOutcome]]
    private var attempts: [UUID] = []
    private var disconnectCalls = 0
    private var state: VPNConnectionState = .disconnected
    private var connectedProfileID: UUID?
    private var pendingAttemptContinuations:
        [UUID: CheckedContinuation<Void, Never>] = [:]
    private var continuations:
        [UUID: AsyncStream<VPNConnectionState>.Continuation] = [:]

    init(scripts: [UUID: [ScriptedSmartOutcome]] = [:]) {
        self.scripts = scripts
    }

    func currentState() -> VPNConnectionState {
        state
    }

    func authoritativeConnection() -> VPNAuthoritativeConnection {
        guard state == .connected, let connectedProfileID else {
            return VPNAuthoritativeConnection(
                state: state,
                systemStatus: state == .failed ? .invalid : .disconnected,
                profileID: nil,
                provider: nil,
                hasMultipleActiveManagers: false
            )
        }
        return VPNAuthoritativeConnection(
            state: .connected,
            systemStatus: .connected,
            profileID: connectedProfileID,
            provider: .xray,
            hasMultipleActiveManagers: false
        )
    }

    func beginAttempt(profileID: UUID) -> ScriptedSmartOutcome {
        attempts.append(profileID)
        var outcomes = scripts[profileID] ?? [.success]
        let outcome = outcomes.isEmpty ? .success : outcomes.removeFirst()
        scripts[profileID] = outcomes
        return outcome
    }

    func completeSuccess(profileID: UUID) {
        connectedProfileID = profileID
        publish(.connected)
    }

    func completeFailure() {
        connectedProfileID = nil
        publish(.failed)
    }

    func waitForAttemptRelease(profileID: UUID) async {
        await withCheckedContinuation { continuation in
            pendingAttemptContinuations[profileID] = continuation
        }
    }

    func pendingAttemptCount() -> Int {
        pendingAttemptContinuations.count
    }

    func releasePendingAttempts() {
        let continuations = Array(pendingAttemptContinuations.values)
        pendingAttemptContinuations.removeAll()
        continuations.forEach { $0.resume() }
    }

    func disconnect() async {
        disconnectCalls += 1
        connectedProfileID = nil
        publish(.disconnected)
    }

    func emitUnexpectedDisconnect() {
        connectedProfileID = nil
        publish(.disconnected)
    }

    func attemptedProfileIDs() -> [UUID] {
        attempts
    }

    func disconnectCallCount() -> Int {
        disconnectCalls
    }

    private func publish(_ newState: VPNConnectionState) {
        state = newState
        continuations.values.forEach { $0.yield(newState) }
    }

    func addContinuation(
        _ continuation: AsyncStream<VPNConnectionState>.Continuation,
        id: UUID
    ) {
        continuations[id] = continuation
        continuation.yield(state)
    }

    func removeContinuation(id: UUID) {
        continuations[id] = nil
    }
}

nonisolated private final class TestSmartConnectionTelemetryManager:
    DashboardConnectionTelemetryManaging,
    @unchecked Sendable {
    private let storage = TestSmartConnectionTelemetryStorage()

    func updates() -> AsyncStream<DashboardConnectionTelemetrySnapshot> {
        let storage = storage
        return AsyncStream { continuation in
            let id = UUID()
            Task {
                await storage.addContinuation(continuation, id: id)
            }
            continuation.onTermination = { _ in
                Task {
                    await storage.removeContinuation(id: id)
                }
            }
        }
    }

    func reconcile(with connection: VPNAuthoritativeConnection) async {
        await storage.reconcile()
    }

    func stop() async {
        await storage.stop()
    }

    func emit(_ snapshot: DashboardConnectionTelemetrySnapshot) async {
        await storage.emit(snapshot)
    }

    func reconcileCallCount() async -> Int {
        await storage.reconcileCallCount()
    }
}

private actor TestSmartConnectionTelemetryStorage {
    private var reconcileCalls = 0
    private var continuations:
        [UUID: AsyncStream<DashboardConnectionTelemetrySnapshot>.Continuation] = [:]

    func reconcile() {
        reconcileCalls += 1
        continuations.values.forEach { $0.yield(.unavailable) }
    }

    func stop() {
        continuations.values.forEach { $0.yield(.unavailable) }
    }

    func emit(_ snapshot: DashboardConnectionTelemetrySnapshot) {
        continuations.values.forEach { $0.yield(snapshot) }
    }

    func reconcileCallCount() -> Int {
        reconcileCalls
    }

    func addContinuation(
        _ continuation: AsyncStream<DashboardConnectionTelemetrySnapshot>.Continuation,
        id: UUID
    ) {
        continuations[id] = continuation
        continuation.yield(.unavailable)
    }

    func removeContinuation(id: UUID) {
        continuations[id] = nil
    }
}

@MainActor
private final class RecordingSmartConnectionHaptic:
    ConnectionActionHapticFeedbackProviding,
    @unchecked Sendable {
    private(set) var callCount = 0

    func playMediumImpact() {
        callCount += 1
    }
}
