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

@Suite(.serialized)
struct SmartConnectionSelectionTests {
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
    func existingTelemetryStreamFeedsLearningAtCheckpoint() async throws {
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
        let learned = await eventually {
            let statistics = await contextStatistics(
                store: harness.learningStore,
                profile: profile
            )
            return statistics.latencySampleCount == 1
                && statistics.packetLossSampleCount == 1
        }

        #expect(learned)
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
    haptic: RecordingSmartConnectionHaptic? = nil
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
        transportSettings: VPNTransportSettings(network: "tcp", security: "tls"),
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
            sessionEnded: false,
            unexpectedDisconnect: false
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

private struct FixedSmartConnectionClock: SmartConnectionClock {
    let nowValue: Date

    init(now: Date) {
        nowValue = now
    }

    func now() -> Date {
        nowValue
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
}

private enum ScriptedSmartOutcome: Sendable {
    case success
    case failure
    case waitForCancellation
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
}

private actor ScriptedSmartConnectionStorage {
    private var scripts: [UUID: [ScriptedSmartOutcome]]
    private var attempts: [UUID] = []
    private var disconnectCalls = 0
    private var state: VPNConnectionState = .disconnected
    private var connectedProfileID: UUID?
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
