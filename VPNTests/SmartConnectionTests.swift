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
    func poorUnknownCandidateCannotDisplaceProvenExcellentCandidate() {
        let excellent = makeSmartProfile(index: 1, protocolType: .vless)
        let poor = makeSmartProfile(index: 2, protocolType: .hysteria2)
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
                    unexpectedDisconnects: 0,
                    successfulSessionSeconds: 90_000
                )
            )],
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
