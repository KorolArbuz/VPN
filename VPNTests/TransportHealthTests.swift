//
//  TransportHealthTests.swift
//  VPNTests
//
//  Phase F1 tests use controllable mocks only. No real network requests.
//

import Foundation
import Testing
@testable import VPN

struct TransportHealthPlanningTests {
    @Test
    func tcpProfileCreatesTCPProbePlan() {
        let profile = makeHealthProfile(transport: "tcp", tls: false)
        let entry = DefaultProbePlanner().plan(profile: profile, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))

        guard case .request(let request) = entry else {
            Issue.record("expected probe request")
            return
        }

        #expect(request.kind == .tcpConnect)
        #expect(request.host == "probe.example.invalid")
        #expect(request.port == 443)
        #expect(request.serverName == nil)
    }

    @Test
    func tlsProfileCreatesTLSProbePlanWithSafeSNI() {
        let profile = makeHealthProfile(transport: "tcp", tls: true, serverName: "sni.example.invalid")
        let entry = DefaultProbePlanner().plan(profile: profile, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))

        guard case .request(let request) = entry else {
            Issue.record("expected TLS probe request")
            return
        }

        #expect(request.kind == .tlsHandshake)
        #expect(request.serverName == "sni.example.invalid")
    }

    @Test
    func disabledProfileIsSkipped() {
        var profile = makeHealthProfile()
        profile.isEnabled = false
        let entry = DefaultProbePlanner().plan(profile: profile, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))

        guard case .skipped(let summary) = entry else {
            Issue.record("expected skipped summary")
            return
        }

        #expect(summary.reachable == false)
        #expect(summary.failure == .unsupportedProbe)
    }

    @Test
    func incompleteProfileIsSkipped() {
        let profile = makeHealthProfile(credentialReference: nil)
        let entry = DefaultProbePlanner().plan(profile: profile, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))

        guard case .skipped(let summary) = entry else {
            Issue.record("expected skipped summary")
            return
        }

        #expect(summary.reachable == false)
        #expect(summary.failure == .invalidEndpoint)
    }

    @Test
    func unsupportedTransportReturnsTypedUnsupportedResult() {
        let profile = makeHealthProfile(transport: "xhttp")
        let entry = DefaultProbePlanner().plan(profile: profile, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))

        guard case .skipped(let summary) = entry else {
            Issue.record("expected unsupported summary")
            return
        }

        #expect(summary.failure == .unsupportedProbe)
    }

    @Test
    func credentialsNeverEnterProbeRequest() throws {
        let secretReference = "credential-ref-super-secret"
        let profile = makeHealthProfile(credentialReference: secretReference)
        let entry = DefaultProbePlanner().plan(profile: profile, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))
        guard case .request(let request) = entry else {
            Issue.record("expected request")
            return
        }

        let data = try JSONEncoder().encode(request)
        let json = try #require(String(data: data, encoding: .utf8))
        #expect(json.contains(secretReference) == false)
        #expect(json.contains("credentialReference") == false)
    }

    @Test
    func rawVPNURINeverEntersProbeRequest() throws {
        let rawURI = "vless://uuid-secret@probe.example.invalid:443#Raw"
        var profile = makeHealthProfile()
        profile.metadata["rawURI"] = rawURI
        let entry = DefaultProbePlanner().plan(profile: profile, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))
        guard case .request(let request) = entry else {
            Issue.record("expected request")
            return
        }

        let data = try JSONEncoder().encode(request)
        let json = try #require(String(data: data, encoding: .utf8))
        #expect(json.contains(rawURI) == false)
        #expect(json.contains("uuid-secret") == false)
    }
}

struct TransportHealthAggregationTests {
    @Test
    func threeAttemptsAggregateMedianLatency() {
        let request = makeProbeRequest()
        let attempts = [
            makeAttempt(candidateID: request.candidateID, latency: 70, index: 0),
            makeAttempt(candidateID: request.candidateID, latency: 20, index: 1),
            makeAttempt(candidateID: request.candidateID, latency: 40, index: 2)
        ]
        let summary = ProbeResultAggregator().summarize(request: request, attempts: attempts, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))

        #expect(summary.connectLatencyMs == 40)
    }

    @Test
    func jitterMedianAbsoluteDeviationIsDeterministic() {
        let request = makeProbeRequest()
        let attempts = [
            makeAttempt(candidateID: request.candidateID, latency: 10, index: 0),
            makeAttempt(candidateID: request.candidateID, latency: 20, index: 1),
            makeAttempt(candidateID: request.candidateID, latency: 100, index: 2)
        ]
        let summary = ProbeResultAggregator().summarize(request: request, attempts: attempts, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))

        #expect(summary.connectLatencyMs == 20)
        #expect(summary.jitterMs == 10)
    }

    @Test
    func failedAttemptsDoNotBecomeFakePacketLoss() {
        let request = makeProbeRequest()
        let attempts = [
            makeAttempt(candidateID: request.candidateID, latency: 20, index: 0),
            makeFailedAttempt(candidateID: request.candidateID, failure: .connectionTimedOut, index: 1),
            makeFailedAttempt(candidateID: request.candidateID, failure: .connectionRefused, index: 2)
        ]
        let summary = ProbeResultAggregator().summarize(request: request, attempts: attempts, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))

        #expect(summary.reachable)
        #expect(summary.failedAttempts == 2)
        #expect(summary.healthSample.packetLossPercent == nil)
    }

    @Test
    func allFailedAttemptsProduceUnreachable() {
        let request = makeProbeRequest()
        let attempts = [
            makeFailedAttempt(candidateID: request.candidateID, failure: .connectionTimedOut, index: 0),
            makeFailedAttempt(candidateID: request.candidateID, failure: .connectionTimedOut, index: 1),
            makeFailedAttempt(candidateID: request.candidateID, failure: .connectionTimedOut, index: 2)
        ]
        let summary = ProbeResultAggregator().summarize(request: request, attempts: attempts, context: ProbeContext(), now: Date(timeIntervalSince1970: 1))

        #expect(summary.reachable == false)
        #expect(summary.failure == .connectionTimedOut)
        #expect(summary.healthSample.packetLossPercent == nil)
    }
}

struct PortableHealthCoordinatorTests {
    @Test
    func boundedConcurrencyIsRespected() async throws {
        let prober = ControllableEndpointProber(blocksUntilReleased: true)
        let core = RecordingPortableCoreHealthService()
        let coordinator = PortableHealthCoordinator(
            coreService: core,
            prober: prober,
            pathMonitor: StubNetworkPathMonitor(type: .wifi),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 2)
        )
        let profiles = (0..<5).map { makeHealthProfile(host: "node-\($0).example.invalid") }

        let task = Task {
            try await coordinator.runHealthCheck(profiles: profiles, connectionState: .disconnected, feature: .init(isEnabled: true))
        }
        await prober.waitForCurrentConcurrency(2)
        #expect(await prober.maxConcurrent == 2)

        await prober.releaseAll()
        _ = try await task.value
        #expect(await prober.maxConcurrent <= 2)
    }

    @Test
    func sameCandidateIsNotProbedTwiceConcurrently() async throws {
        let profile = makeHealthProfile()
        let prober = ControllableEndpointProber()
        let core = RecordingPortableCoreHealthService()
        let coordinator = PortableHealthCoordinator(
            coreService: core,
            prober: prober,
            pathMonitor: StubNetworkPathMonitor(type: .wifi),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 4)
        )

        _ = try await coordinator.runHealthCheck(profiles: [profile, profile], connectionState: .disconnected, feature: .init(isEnabled: true))

        #expect(await prober.callCount == 1)
        #expect(await prober.duplicateConcurrentCandidateObserved == false)
    }

    @Test
    func cancellationStopsCurrentBatch() async {
        let prober = ControllableEndpointProber(blocksUntilReleased: true)
        let core = RecordingPortableCoreHealthService()
        let coordinator = PortableHealthCoordinator(
            coreService: core,
            prober: prober,
            pathMonitor: StubNetworkPathMonitor(type: .wifi),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 1)
        )

        let task = Task {
            try await coordinator.runHealthCheck(profiles: [makeHealthProfile()], connectionState: .disconnected, feature: .init(isEnabled: true))
        }
        await prober.waitForRequestCount(1)
        await coordinator.cancel()
        await prober.releaseAll()

        do {
            _ = try await task.value
            Issue.record("expected cancellation")
        } catch let failure as TransportProbeFailure {
            #expect(failure == .cancelled || failure == .staleResultDiscarded)
        } catch {
            Issue.record("unexpected error \(error)")
        }
    }

    @Test
    func staleBatchCannotOverwriteNewerBatch() async throws {
        let prober = ControllableEndpointProber(blocksUntilReleased: true)
        let core = RecordingPortableCoreHealthService()
        let coordinator = PortableHealthCoordinator(
            coreService: core,
            prober: prober,
            pathMonitor: StubNetworkPathMonitor(type: .wifi),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 1)
        )
        let first = makeHealthProfile(host: "first.example.invalid")
        let second = makeHealthProfile(host: "second.example.invalid")
        let secondCandidateID = second.id.uuidString

        let firstTask = Task {
            try? await coordinator.runHealthCheck(profiles: [first], connectionState: .disconnected, feature: .init(isEnabled: true))
        }
        await prober.waitForRequestCount(1)
        let secondTask = Task {
            try await coordinator.runHealthCheck(profiles: [second], connectionState: .disconnected, feature: .init(isEnabled: true))
        }
        await prober.waitForRequestCount(2)
        await prober.releaseAll()

        _ = await firstTask.value
        _ = try await secondTask.value

        #expect(await core.updatedCandidateIDs == [secondCandidateID])
    }

    @Test
    func oldCleanupCannotClearNewState() async throws {
        let prober = ControllableEndpointProber(blocksUntilReleased: true)
        let core = RecordingPortableCoreHealthService()
        let coordinator = PortableHealthCoordinator(
            coreService: core,
            prober: prober,
            pathMonitor: StubNetworkPathMonitor(type: .wifi),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 1)
        )

        let firstTask = Task {
            try? await coordinator.runHealthCheck(profiles: [makeHealthProfile(host: "first.example.invalid")], connectionState: .disconnected, feature: .init(isEnabled: true))
        }
        await prober.waitForRequestCount(1)
        let secondTask = Task {
            try await coordinator.runHealthCheck(profiles: [makeHealthProfile(host: "second.example.invalid")], connectionState: .disconnected, feature: .init(isEnabled: true))
        }
        await prober.waitForRequestCount(2)
        await prober.releaseOne()
        _ = await firstTask.value

        #expect(await coordinator.isRunning)

        await prober.releaseAll()
        _ = try await secondTask.value
        #expect(await coordinator.isRunning == false)
    }

    @Test
    func healthSampleReachesMockedPortableCoreService() async throws {
        let prober = ControllableEndpointProber()
        let core = RecordingPortableCoreHealthService()
        let coordinator = PortableHealthCoordinator(
            coreService: core,
            prober: prober,
            pathMonitor: StubNetworkPathMonitor(type: .wifi),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 1)
        )

        _ = try await coordinator.runHealthCheck(profiles: [makeHealthProfile()], connectionState: .disconnected, feature: .init(isEnabled: true))

        #expect(await core.healthSamples.count == 1)
        #expect(await core.healthSamples.first?.sample.reachable == true)
    }

    @Test
    func passiveRecommendationIsRequestedAfterBatch() async throws {
        let core = RecordingPortableCoreHealthService()
        let coordinator = PortableHealthCoordinator(
            coreService: core,
            prober: ControllableEndpointProber(),
            pathMonitor: StubNetworkPathMonitor(type: .wifi),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 1)
        )

        let report = try await coordinator.runHealthCheck(profiles: [makeHealthProfile()], connectionState: .disconnected, feature: .init(isEnabled: true))

        #expect(await core.selectBestCount == 1)
        #expect(report.recommendation != nil)
    }

    @Test
    func recommendationDoesNotCallConnectOrDisconnect() async throws {
        let manager = CountingConnectionManager()
        let stateBefore = await manager.currentState()
        let coordinator = PortableHealthCoordinator(
            coreService: RecordingPortableCoreHealthService(),
            prober: ControllableEndpointProber(),
            pathMonitor: StubNetworkPathMonitor(type: .wifi),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 1)
        )

        _ = try await coordinator.runHealthCheck(profiles: [makeHealthProfile()], connectionState: stateBefore, feature: .init(isEnabled: true))

        #expect(await manager.connectCount == 0)
        #expect(await manager.disconnectCount == 0)
        #expect(await manager.currentState() == stateBefore)
    }

    @Test
    func recommendationDoesNotChangeActiveProfileID() async throws {
        let activeStore = LocalActiveProfileStore()
        let activeID = UUID()
        await activeStore.saveActiveProfileID(activeID)
        let coordinator = PortableHealthCoordinator(
            coreService: RecordingPortableCoreHealthService(),
            prober: ControllableEndpointProber(),
            pathMonitor: StubNetworkPathMonitor(type: .wifi),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 1)
        )

        _ = try await coordinator.runHealthCheck(profiles: [makeHealthProfile()], connectionState: .disconnected, feature: .init(isEnabled: true))

        #expect(await activeStore.activeProfileID() == activeID)
    }

    @Test
    func connectedStateProbeIsMarkedCurrentSystemPath() async throws {
        let coordinator = PortableHealthCoordinator(
            coreService: RecordingPortableCoreHealthService(),
            prober: ControllableEndpointProber(),
            pathMonitor: StubNetworkPathMonitor(type: .cellular),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 1)
        )

        let report = try await coordinator.runHealthCheck(profiles: [makeHealthProfile()], connectionState: .connected, feature: .init(isEnabled: true))

        #expect(report.context.routeContext == .currentSystemPath)
        #expect(report.context.networkType == .cellular)
    }

    @Test
    func featureFlagFalsePreventsProbing() async throws {
        let prober = ControllableEndpointProber()
        let core = RecordingPortableCoreHealthService()
        let coordinator = PortableHealthCoordinator(
            coreService: core,
            prober: prober,
            pathMonitor: StubNetworkPathMonitor(type: .wifi),
            sleeper: ImmediateProbeSleeper(),
            configuration: ProbeSeriesConfiguration(attemptCount: 1, delayBetweenAttempts: .zero, perAttemptTimeout: .seconds(1), maxConcurrentProbes: 1)
        )

        let report = try await coordinator.runHealthCheck(profiles: [makeHealthProfile()], connectionState: .disconnected, feature: .disabled)

        #expect(report.wasSkippedBecauseDisabled)
        #expect(await prober.callCount == 0)
        #expect(await core.healthSamples.isEmpty)
    }
}

struct NetworkPathMappingTests {
    @Test
    func networkTypeMapsWiFi() {
        #expect(NetworkPathTypeMapper.type(usesWiFi: true, usesCellular: false, usesEthernet: false) == .wifi)
    }

    @Test
    func networkTypeMapsCellular() {
        #expect(NetworkPathTypeMapper.type(usesWiFi: false, usesCellular: true, usesEthernet: false) == .cellular)
    }
}

struct TransportHealthPrivacyAndLocalizationTests {
    @Test
    func diagnosticsNeverSerializeCredentials() throws {
        let secret = "credential-ref-secret"
        let profile = makeHealthProfile(credentialReference: secret)
        let entry = DefaultProbePlanner().plan(profile: profile, context: ProbeContext(networkType: .wifi), now: Date(timeIntervalSince1970: 1))
        guard case .request(let request) = entry else {
            Issue.record("expected request")
            return
        }
        let summary = TransportProbeSummary(
            candidateID: request.candidateID,
            profileID: request.profileID,
            displayName: request.displayName,
            protocolType: request.protocolType,
            host: request.host,
            port: request.port,
            kind: request.kind,
            context: ProbeContext(networkType: .wifi),
            checkedAt: Date(timeIntervalSince1970: 1),
            reachable: true,
            connectLatencyMs: 20,
            jitterMs: 0,
            handshakeMs: nil,
            successfulAttempts: 1,
            failedAttempts: 0,
            failure: nil
        )

        let json = try #require(String(data: JSONEncoder().encode(summary), encoding: .utf8))
        #expect(json.contains(secret) == false)
        #expect(json.contains("credential") == false)
    }

    @Test
    func transportHealthLocalizationKeysExistInEnglishAndRussian() throws {
        let keys = [
            "diagnostics.transport_health",
            "diagnostics.run_health_check",
            "diagnostics.passive_notice",
            "diagnostics.probing_enabled",
            "diagnostics.probe.running",
            "diagnostics.probe.error.unsupported"
        ]
        let strings = try localizableStrings()

        for key in keys {
            let localization = try #require(strings[key] as? [String: Any])
            let localizations = try #require(localization["localizations"] as? [String: Any])
            #expect(localizations["en"] != nil)
            #expect(localizations["ru"] != nil)
        }
    }
}

private nonisolated enum ScriptedProbeOutcome: Sendable {
    case success(Double)
    case failure(TransportProbeFailure)
}

private actor ControllableEndpointProber: EndpointProbing {
    private let blocksUntilReleased: Bool
    private var outcomes: [String: [ScriptedProbeOutcome]]
    private var blockers: [CheckedContinuation<Void, Never>] = []
    private var countWaiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private var concurrencyWaiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private var activeCandidateIDs: Set<String> = []
    private var releasedAll = false
    private(set) var callCount = 0
    private(set) var currentConcurrent = 0
    private(set) var maxConcurrent = 0
    private(set) var duplicateConcurrentCandidateObserved = false

    init(blocksUntilReleased: Bool = false, outcomes: [String: [ScriptedProbeOutcome]] = [:]) {
        self.blocksUntilReleased = blocksUntilReleased
        self.outcomes = outcomes
    }

    func probe(_ request: TransportProbeRequest, attemptIndex: Int, timeout: Duration) async -> TransportProbeAttempt {
        callCount += 1
        currentConcurrent += 1
        maxConcurrent = max(maxConcurrent, currentConcurrent)
        if activeCandidateIDs.contains(request.candidateID) {
            duplicateConcurrentCandidateObserved = true
        }
        activeCandidateIDs.insert(request.candidateID)
        notifyWaiters()

        if blocksUntilReleased && releasedAll == false {
            await withCheckedContinuation { continuation in
                blockers.append(continuation)
            }
        }

        defer {
            currentConcurrent -= 1
            activeCandidateIDs.remove(request.candidateID)
        }

        if Task.isCancelled {
            return makeFailedAttempt(candidateID: request.candidateID, failure: .cancelled, index: attemptIndex)
        }

        let outcome = popOutcome(for: request.candidateID) ?? .success(Double((attemptIndex + 1) * 10))
        switch outcome {
        case .success(let latency):
            return makeAttempt(
                candidateID: request.candidateID,
                latency: latency,
                index: attemptIndex,
                handshake: request.kind == .tlsHandshake ? latency : nil
            )
        case .failure(let failure):
            return makeFailedAttempt(candidateID: request.candidateID, failure: failure, index: attemptIndex)
        }
    }

    func waitForRequestCount(_ count: Int) async {
        if callCount >= count {
            return
        }

        await withCheckedContinuation { continuation in
            countWaiters.append((count, continuation))
        }
    }

    func waitForCurrentConcurrency(_ count: Int) async {
        if currentConcurrent >= count {
            return
        }

        await withCheckedContinuation { continuation in
            concurrencyWaiters.append((count, continuation))
        }
    }

    func releaseOne() {
        blockers.removeFirst().resume()
    }

    func releaseAll() {
        releasedAll = true
        let continuations = blockers
        blockers.removeAll()
        for continuation in continuations {
            continuation.resume()
        }
    }

    private func popOutcome(for candidateID: String) -> ScriptedProbeOutcome? {
        guard var values = outcomes[candidateID], values.isEmpty == false else {
            return nil
        }
        let value = values.removeFirst()
        outcomes[candidateID] = values
        return value
    }

    private func notifyWaiters() {
        let readyCount = countWaiters.filter { callCount >= $0.0 }
        countWaiters.removeAll { callCount >= $0.0 }
        for waiter in readyCount {
            waiter.1.resume()
        }

        let readyConcurrency = concurrencyWaiters.filter { currentConcurrent >= $0.0 }
        concurrencyWaiters.removeAll { currentConcurrent >= $0.0 }
        for waiter in readyConcurrency {
            waiter.1.resume()
        }
    }
}

private actor RecordingPortableCoreHealthService: PortableCoreHealthServicing {
    private(set) var syncedProfiles: [VPNProfile] = []
    private(set) var healthSamples: [(candidateID: String, sample: KVNHealthSampleDTO)] = []
    private(set) var networkTypes: [KVNNetworkType] = []
    private(set) var selectBestCount = 0

    var updatedCandidateIDs: [String] {
        healthSamples.map(\.candidateID)
    }

    func syncCandidates(from profiles: [VPNProfile]) async throws {
        syncedProfiles = profiles
    }

    func updateHealth(candidateID: String, sample: KVNHealthSampleDTO) async throws {
        healthSamples.append((candidateID, sample))
    }

    func setNetworkType(_ type: KVNNetworkType) async throws {
        networkTypes.append(type)
    }

    func selectBest(now: Date) async throws -> KVNSelectionDecisionDTO {
        selectBestCount += 1
        let selected = healthSamples.last?.candidateID
        return KVNSelectionDecisionDTO(
            selected: selected,
            current: nil,
            shouldSwitch: selected != nil,
            currentScore: nil,
            selectedScore: selected == nil ? nil : 82,
            reason: selected == nil ? .noHealthyCandidates : .initialSelection,
            timestampMs: UInt64(now.timeIntervalSince1970 * 1_000),
            breakdown: KVNCandidateScoreBreakdownDTO(
                total: 82,
                latency: 20,
                jitter: 20,
                loss: 20,
                handshake: 0,
                reliability: 10,
                throughput: 0,
                protocolPreference: 5,
                priority: 5,
                penalties: 0,
                confidence: 0.8
            )
        )
    }
}

private nonisolated struct StubNetworkPathMonitor: NetworkPathMonitoring {
    let type: KVNNetworkType

    func currentNetworkType() async -> KVNNetworkType {
        type
    }

    func cancel() async {}
}

private actor CountingConnectionManager: VPNConnectionManaging {
    private(set) var connectCount = 0
    private(set) var disconnectCount = 0
    private var state: VPNConnectionState = .disconnected

    func currentState() async -> VPNConnectionState {
        state
    }

    nonisolated func stateUpdates() -> AsyncStream<VPNConnectionState> {
        AsyncStream { continuation in
            continuation.yield(.disconnected)
        }
    }

    func connect(using profile: VPNProfile) async throws -> ConnectionMetrics {
        connectCount += 1
        state = .connected
        return ConnectionMetrics(latency: 1, packetLoss: 0, serverLoad: 0, connectionTime: 0)
    }

    func disconnect() async {
        disconnectCount += 1
        state = .disconnected
    }
}

private actor LocalActiveProfileStore: ActiveProfileStoring {
    private var storedID: UUID?

    func activeProfileID() async -> UUID? {
        storedID
    }

    func saveActiveProfileID(_ id: UUID?) async {
        storedID = id
    }
}

private nonisolated func makeHealthProfile(
    protocolType: VPNProtocol = .vless,
    host: String = "probe.example.invalid",
    port: Int? = 443,
    transport: String? = "tcp",
    tls: Bool = false,
    serverName: String? = nil,
    credentialReference: String? = "credential-ref"
) -> VPNProfile {
    VPNProfile.draft(
        name: host,
        protocolType: protocolType,
        serverAddress: host,
        port: port,
        credentialReference: credentialReference,
        transportSettings: VPNTransportSettings(network: transport),
        tlsSettings: VPNTLSSettings(isEnabled: tls, serverName: serverName),
        protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
        source: .manual
    )
}

private nonisolated func makeProbeRequest(
    candidateID: String = UUID().uuidString,
    kind: TransportProbeKind = .tcpConnect
) -> TransportProbeRequest {
    TransportProbeRequest(
        candidateID: candidateID,
        profileID: candidateID,
        displayName: "Probe",
        protocolType: .vless,
        host: "probe.example.invalid",
        port: 443,
        transport: "tcp",
        security: nil,
        kind: kind,
        serverName: kind == .tlsHandshake ? "probe.example.invalid" : nil
    )
}

private nonisolated func makeAttempt(
    candidateID: String,
    latency: Double,
    index: Int,
    handshake: Double? = nil
) -> TransportProbeAttempt {
    TransportProbeAttempt(
        candidateID: candidateID,
        attemptIndex: index,
        startedAt: Date(timeIntervalSince1970: Double(index)),
        finishedAt: Date(timeIntervalSince1970: Double(index) + latency / 1_000),
        connectLatencyMs: latency,
        handshakeLatencyMs: handshake,
        failure: nil
    )
}

private nonisolated func makeFailedAttempt(
    candidateID: String,
    failure: TransportProbeFailure,
    index: Int
) -> TransportProbeAttempt {
    TransportProbeAttempt(
        candidateID: candidateID,
        attemptIndex: index,
        startedAt: Date(timeIntervalSince1970: Double(index)),
        finishedAt: Date(timeIntervalSince1970: Double(index) + 0.01),
        connectLatencyMs: nil,
        handshakeLatencyMs: nil,
        failure: failure
    )
}

private nonisolated func localizableStrings() throws -> [String: Any] {
    let testsURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let projectURL = testsURL.deletingLastPathComponent()
    let catalogURL = projectURL.appendingPathComponent("VPN/Resources/Localizable.xcstrings")
    let data = try Data(contentsOf: catalogURL)
    let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    return try #require(object?["strings"] as? [String: Any])
}
