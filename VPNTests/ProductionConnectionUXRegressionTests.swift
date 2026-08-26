//
//  ProductionConnectionUXRegressionTests.swift
//  VPNTests
//
//  Focused regressions for authoritative restoration, live telemetry, and Start haptics.
//

import Foundation
import Testing
@testable import VPN

@Suite(.serialized)
struct ProductionConnectionUXRegressionTests {
    @Test
    @MainActor
    func coldLaunchConnectedManagerRestoresConnectedDashboard() async throws {
        let profile = makeTestProfile()
        let harness = try await makeRestorationHarness(
            profile: profile,
            status: .connected,
            provider: .xray
        )

        await harness.viewModel.loadInitialData()

        #expect(harness.viewModel.connectionState == .connected)
    }

    @Test
    @MainActor
    func coldLaunchConnectingManagerRestoresConnectingDashboard() async throws {
        let profile = makeTestProfile()
        let harness = try await makeRestorationHarness(
            profile: profile,
            status: .connecting,
            provider: .xray
        )

        await harness.viewModel.loadInitialData()

        #expect(harness.viewModel.connectionState == .connecting)
    }

    @Test
    @MainActor
    func coldLaunchReassertingManagerDoesNotShowDisconnected() async throws {
        let profile = makeTestProfile()
        let harness = try await makeRestorationHarness(
            profile: profile,
            status: .reasserting,
            provider: .xray
        )

        await harness.viewModel.loadInitialData()

        #expect(harness.viewModel.connectionState == .connecting)
        #expect(harness.viewModel.connectionState != .disconnected)
    }

    @Test
    @MainActor
    func coldLaunchWithNoActiveManagerShowsDisconnected() async throws {
        let profile = makeTestProfile()
        let harness = try await makeRestorationHarness(
            profile: profile,
            status: .disconnected,
            provider: .xray
        )

        await harness.viewModel.loadInitialData()

        #expect(harness.viewModel.connectionState == .disconnected)
    }

    @Test
    @MainActor
    func restorationNeverCallsConnectOrStartsTunnel() async throws {
        let profile = makeTestProfile()
        let routeService = ControllableConnectionManager(profileID: profile.id)
        let harness = try await makeRestorationHarness(
            profile: profile,
            status: .connected,
            provider: .xray,
            xrayService: routeService
        )

        await harness.viewModel.loadInitialData()

        #expect(await routeService.connectCallCount() == 0)
    }

    @Test
    @MainActor
    func restorationSelectsTheActuallyActiveProfile() async throws {
        let restoredProfile = makeTestProfile(name: "Restored")
        let previouslySelectedProfile = makeTestProfile(name: "Previously selected")
        let harness = try await makeRestorationHarness(
            profile: restoredProfile,
            additionalProfiles: [previouslySelectedProfile],
            initiallySelectedProfileID: previouslySelectedProfile.id,
            status: .connected,
            provider: .xray
        )

        await harness.viewModel.loadInitialData()

        #expect(harness.viewModel.activeProfileID == restoredProfile.id)
        #expect(harness.viewModel.selectedProfile?.id == restoredProfile.id)
        #expect(await harness.activeProfileStore.activeProfileID() == restoredProfile.id)
    }

    @Test
    func nativeWireGuardManagerRestorationUsesNativeProviderRoute() async {
        let profileID = UUID()
        let manager = TestAuthoritativeTunnelManager(
            profileID: profileID,
            provider: .wireGuard,
            status: .connected
        )
        let restorer = AuthoritativeVPNConnectionRestorer(
            loader: TestAuthoritativeTunnelManagerLoader(managers: [manager])
        )

        let connection = await restorer.refresh()

        #expect(connection.state == .connected)
        #expect(connection.profileID == profileID)
        #expect(connection.provider == .wireGuard)
    }

    @Test
    func xrayManagerRestorationUsesXrayProviderRoute() async {
        let profileID = UUID()
        let manager = TestAuthoritativeTunnelManager(
            profileID: profileID,
            provider: .xray,
            status: .connected
        )
        let restorer = AuthoritativeVPNConnectionRestorer(
            loader: TestAuthoritativeTunnelManagerLoader(managers: [manager])
        )

        let connection = await restorer.refresh()

        #expect(connection.state == .connected)
        #expect(connection.profileID == profileID)
        #expect(connection.provider == .xray)
    }

    @Test
    @MainActor
    func foregroundTransitionTriggersAuthoritativeRefresh() async throws {
        let profile = makeTestProfile()
        let harness = try await makeRestorationHarness(
            profile: profile,
            status: .connected,
            provider: .xray
        )
        await harness.viewModel.loadInitialData()
        let initialLoads = await harness.loader.loadCount()

        await harness.viewModel.applicationDidBecomeActive()

        #expect(await harness.loader.loadCount() == initialLoads + 1)
    }

    @Test
    func repeatedForegroundRefreshesDoNotDuplicateStatusObservers() async {
        let manager = TestAuthoritativeTunnelManager(
            profileID: UUID(),
            provider: .xray,
            status: .connected
        )
        let restorer = AuthoritativeVPNConnectionRestorer(
            loader: TestAuthoritativeTunnelManagerLoader(managers: [manager])
        )

        await restorer.refresh()
        await restorer.refresh()
        await restorer.refresh()

        #expect(manager.observerInstallCount == 1)
        #expect(manager.observerRemoveCount == 0)
    }

    @Test
    func providerStartedAtSurvivesAppSideStoreRecreation() async throws {
        let profileID = UUID()
        let connectedStartedAt = Date(timeIntervalSince1970: 10_000)
        let fileURL = temporaryTelemetryURL()
        defer {
            try? FileManager.default.removeItem(
                at: fileURL.deletingLastPathComponent()
            )
        }

        let telemetryStore = TunnelTelemetryStore()
        await telemetryStore.markStarting(
            profileID: profileID.uuidString,
            candidateID: nil,
            backendKind: .xray,
            protocolKind: .vless,
            transportKind: "tcp",
            now: connectedStartedAt.addingTimeInterval(-2)
        )
        await telemetryStore.markRunning(now: connectedStartedAt)
        let storedRuntime = await telemetryStore.runtimeSnapshot()

        let firstStore = TunnelTelemetrySnapshotStore(fileURL: fileURL)
        try await firstStore.write(runtime: storedRuntime, events: [])
        let connection = authoritativeConnection(
            profileID: profileID,
            provider: .xray,
            status: .connected
        )
        let firstReader = AppGroupProviderTunnelSessionReader(
            snapshotStore: firstStore
        )
        let firstSession = await firstReader.session(matching: connection)

        let recreatedStore = TunnelTelemetrySnapshotStore(fileURL: fileURL)
        let recreatedReader = AppGroupProviderTunnelSessionReader(
            snapshotStore: recreatedStore
        )
        let recreatedSession = await recreatedReader.session(matching: connection)

        #expect(firstSession?.connectedStartedAt == connectedStartedAt)
        #expect(recreatedSession?.connectedStartedAt == connectedStartedAt)
        #expect(recreatedSession?.sessionID == firstSession?.sessionID)
    }

    @Test
    func runtimeAfterAppRelaunchContinuesFromOriginalProviderStart() async {
        let profileID = UUID()
        let start = Date(timeIntervalSince1970: 20_000)
        let session = ProviderTunnelSession(
            sessionID: UUID().uuidString,
            profileID: profileID,
            provider: .xray,
            protocolKind: .vless,
            connectedStartedAt: start
        )
        let connection = authoritativeConnection(
            profileID: profileID,
            provider: .xray,
            status: .connected
        )

        let firstController = DashboardConnectionTelemetryController(
            sessionReader: FixedProviderSessionReader(session: session),
            probe: FixedLatencyProbe(outcome: .cancelled),
            clock: FixedTelemetryClock(now: start.addingTimeInterval(20))
        )
        await firstController.reconcile(with: connection)
        let firstRuntime = await firstController.snapshot().runtimeSeconds
        await firstController.stop()

        let recreatedController = DashboardConnectionTelemetryController(
            sessionReader: FixedProviderSessionReader(session: session),
            probe: FixedLatencyProbe(outcome: .cancelled),
            clock: FixedTelemetryClock(now: start.addingTimeInterval(55))
        )
        await recreatedController.reconcile(with: connection)
        let recreatedRuntime = await recreatedController.snapshot().runtimeSeconds
        await recreatedController.stop()

        #expect(firstRuntime == 20)
        #expect(recreatedRuntime == 55)
    }

    @Test
    func disconnectedStateStopsRuntimeProgression() async {
        let profileID = UUID()
        let start = Date(timeIntervalSince1970: 30_000)
        let session = ProviderTunnelSession(
            sessionID: UUID().uuidString,
            profileID: profileID,
            provider: .xray,
            protocolKind: .vless,
            connectedStartedAt: start
        )
        let controller = DashboardConnectionTelemetryController(
            sessionReader: FixedProviderSessionReader(session: session),
            probe: FixedLatencyProbe(outcome: .cancelled),
            clock: FixedTelemetryClock(now: start.addingTimeInterval(10))
        )
        await controller.reconcile(
            with: authoritativeConnection(
                profileID: profileID,
                provider: .xray,
                status: .connected
            )
        )

        await controller.reconcile(with: .disconnected)

        #expect(await controller.snapshot().runtimeSeconds == nil)
        #expect(await controller.isSampling() == false)
    }

    @Test
    func reconnectCreatesNewSessionIdentityAndRuntimeOrigin() async {
        let store = TunnelTelemetryStore()
        let profileID = UUID()
        let firstStart = Date(timeIntervalSince1970: 40_000)
        await store.markStarting(
            profileID: profileID.uuidString,
            candidateID: nil,
            backendKind: .xray,
            protocolKind: .vless,
            transportKind: "tcp",
            now: firstStart.addingTimeInterval(-1)
        )
        await store.markRunning(now: firstStart)
        let first = await store.runtimeSnapshot()

        let stoppedAt = firstStart.addingTimeInterval(20)
        await store.markStopped(now: stoppedAt)
        let stopped = await store.runtimeSnapshot()

        let secondStart = firstStart.addingTimeInterval(30)
        await store.markStarting(
            profileID: profileID.uuidString,
            candidateID: nil,
            backendKind: .xray,
            protocolKind: .vless,
            transportKind: "tcp",
            now: secondStart.addingTimeInterval(-1)
        )
        await store.markRunning(now: secondStart)
        let second = await store.runtimeSnapshot()

        #expect(first.sessionID != nil)
        #expect(second.sessionID != nil)
        #expect(first.sessionID != second.sessionID)
        #expect(first.startedAt == firstStart)
        #expect(stopped.stoppedAt == stoppedAt)
        #expect(second.startedAt == secondStart)
        #expect(second.runtimeGeneration == first.runtimeGeneration + 1)
    }

    @Test
    func successfulProbeUpdatesLatency() async {
        let endpointProber = DeterministicEndpointProber(result: .success(42.4))
        let probe = NetworkTunnelLatencyProbe(endpointProber: endpointProber)
        let outcome = await probe.probe()
        var window = RollingTunnelProbeWindow(
            capacity: 10,
            minimumSamplesForLoss: 1
        )

        window.record(outcome)

        #expect(window.latencyMilliseconds == 42)
        #expect(window.packetLossPercent == 0)
    }

    @Test
    func timedOutProbeContributesToRollingPacketLoss() async {
        let endpointProber = DeterministicEndpointProber(result: .timedOut)
        let probe = NetworkTunnelLatencyProbe(endpointProber: endpointProber)
        let outcome = await probe.probe()
        var window = RollingTunnelProbeWindow(
            capacity: 10,
            minimumSamplesForLoss: 1
        )

        window.record(outcome)

        #expect(window.samples.count == 1)
        #expect(window.packetLossPercent == 100)
    }

    @Test
    func cancelledProbeOnDisconnectDoesNotCountAsPacketLoss() async {
        let endpointProber = DeterministicEndpointProber(result: .cancelled)
        let probe = NetworkTunnelLatencyProbe(endpointProber: endpointProber)
        let outcome = await probe.probe()
        var window = RollingTunnelProbeWindow(
            capacity: 10,
            minimumSamplesForLoss: 1
        )

        window.record(outcome)

        #expect(window.samples.isEmpty)
        #expect(window.packetLossPercent == nil)
    }

    @Test
    func rollingPacketLossCalculationUsesActualProbeOutcomes() {
        var window = RollingTunnelProbeWindow(
            capacity: 10,
            minimumSamplesForLoss: 1
        )
        window.record(.success(milliseconds: 20))
        window.record(.success(milliseconds: 30))
        window.record(.failure)
        window.record(.success(milliseconds: 40))

        #expect(window.packetLossPercent == 25)
        #expect(window.latencyMilliseconds == 30)
    }

    @Test
    func noValidProbeSamplesProducesUnavailableMetrics() {
        let window = RollingTunnelProbeWindow(
            capacity: 10,
            minimumSamplesForLoss: 3
        )

        #expect(window.latencyMilliseconds == nil)
        #expect(window.packetLossPercent == nil)
    }

    @Test
    func telemetryStartsExactlyOnceForOneConnectedSession() async {
        let profileID = UUID()
        let start = Date(timeIntervalSince1970: 50_000)
        let session = ProviderTunnelSession(
            sessionID: UUID().uuidString,
            profileID: profileID,
            provider: .xray,
            protocolKind: .vless,
            connectedStartedAt: start
        )
        let probe = CountingLatencyProbe()
        let controller = DashboardConnectionTelemetryController(
            sessionReader: FixedProviderSessionReader(session: session),
            probe: probe,
            clock: FixedTelemetryClock(now: start.addingTimeInterval(5))
        )
        let connection = authoritativeConnection(
            profileID: profileID,
            provider: .xray,
            status: .connected
        )

        await controller.reconcile(with: connection)
        for _ in 0..<20 where await probe.callCount() == 0 {
            await Task.yield()
        }
        await controller.reconcile(with: connection)
        await controller.reconcile(with: connection)
        for _ in 0..<10 {
            await Task.yield()
        }

        #expect(await probe.callCount() == 1)
        #expect(await controller.isSampling())
        await controller.stop()
    }

    @Test
    func telemetryStopsWhenAuthoritativeTunnelDisconnects() async {
        let profileID = UUID()
        let start = Date(timeIntervalSince1970: 60_000)
        let session = ProviderTunnelSession(
            sessionID: UUID().uuidString,
            profileID: profileID,
            provider: .xray,
            protocolKind: .vless,
            connectedStartedAt: start
        )
        let controller = DashboardConnectionTelemetryController(
            sessionReader: FixedProviderSessionReader(session: session),
            probe: FixedLatencyProbe(outcome: .success(milliseconds: 10)),
            clock: FixedTelemetryClock(now: start.addingTimeInterval(5))
        )
        await controller.reconcile(
            with: authoritativeConnection(
                profileID: profileID,
                provider: .xray,
                status: .connected
            )
        )

        await controller.reconcile(with: .disconnected)

        #expect(await controller.isSampling() == false)
        #expect(await controller.snapshot() == .unavailable)
    }

    @Test
    @MainActor
    func restoringConnectedTunnelStartsTelemetryWithoutNewVPNSession() async throws {
        let profile = makeTestProfile()
        let routeService = ControllableConnectionManager(profileID: profile.id)
        let telemetry = RecordingDashboardTelemetryManager()
        let harness = try await makeRestorationHarness(
            profile: profile,
            status: .connected,
            provider: .xray,
            xrayService: routeService,
            telemetry: telemetry
        )

        await harness.viewModel.loadInitialData()

        #expect(await telemetry.startCount() == 1)
        #expect(await routeService.connectCallCount() == 0)
    }

    @Test
    @MainActor
    func userStartActionRequestsOneLightHaptic() async throws {
        let profile = makeTestProfile()
        let connectionManager = ControllableConnectionManager(
            profileID: profile.id
        )
        let haptic = RecordingStartHapticFeedback()
        let viewModel = try await makeViewModel(
            connectionManager: connectionManager,
            profiles: [profile],
            initiallySelectedProfileID: profile.id,
            haptic: haptic
        )
        await viewModel.loadInitialData()

        await viewModel.userDidTapMainConnectionButton()

        #expect(haptic.callCount == 1)
        #expect(await connectionManager.connectCallCount() == 1)
    }

    @Test
    @MainActor
    func stateRestorationRequestsZeroHaptics() async throws {
        let profile = makeTestProfile()
        let haptic = RecordingStartHapticFeedback()
        let harness = try await makeRestorationHarness(
            profile: profile,
            status: .connected,
            provider: .xray,
            haptic: haptic
        )

        await harness.viewModel.loadInitialData()

        #expect(haptic.callCount == 0)
    }

    @Test
    @MainActor
    func statusNotificationsRequestZeroHaptics() async throws {
        let profile = makeTestProfile()
        let connectionManager = ControllableConnectionManager(
            profileID: profile.id
        )
        let haptic = RecordingStartHapticFeedback()
        let viewModel = try await makeViewModel(
            connectionManager: connectionManager,
            profiles: [profile],
            initiallySelectedProfileID: profile.id,
            haptic: haptic
        )
        await viewModel.loadInitialData()

        await connectionManager.emit(.connecting)
        await connectionManager.emit(.connected)
        for _ in 0..<20 where viewModel.connectionState != .connected {
            await Task.yield()
        }

        #expect(viewModel.connectionState == .connected)
        #expect(haptic.callCount == 0)
    }
}

private struct RestorationHarness {
    let viewModel: VPNDashboardViewModel
    let loader: TestAuthoritativeTunnelManagerLoader
    let activeProfileStore: TestActiveProfileStore
}

@MainActor
private func makeRestorationHarness(
    profile: VPNProfile,
    additionalProfiles: [VPNProfile] = [],
    initiallySelectedProfileID: UUID? = nil,
    status: VPNSystemConnectionStatus,
    provider: PacketTunnelProviderKind,
    xrayService: (any VPNConnectionManaging)? = nil,
    telemetry: (any DashboardConnectionTelemetryManaging)? = nil,
    haptic: (any StartHapticFeedbackProviding)? = nil
) async throws -> RestorationHarness {
    let authoritativeManager = TestAuthoritativeTunnelManager(
        profileID: profile.id,
        provider: provider,
        status: status
    )
    let loader = TestAuthoritativeTunnelManagerLoader(
        managers: [authoritativeManager]
    )
    let restorer = AuthoritativeVPNConnectionRestorer(loader: loader)
    let productionManager = ProductionVPNConnectionManager(
        xrayService: xrayService ?? ControllableConnectionManager(
            profileID: profile.id
        ),
        authoritativeRestorer: restorer
    )
    let activeProfileStore = TestActiveProfileStore(
        profileID: initiallySelectedProfileID
    )
    let viewModel = try await makeViewModel(
        connectionManager: productionManager,
        profiles: [profile] + additionalProfiles,
        initiallySelectedProfileID: initiallySelectedProfileID,
        activeProfileStore: activeProfileStore,
        telemetry: telemetry,
        haptic: haptic
    )
    return RestorationHarness(
        viewModel: viewModel,
        loader: loader,
        activeProfileStore: activeProfileStore
    )
}

@MainActor
private func makeViewModel(
    connectionManager: any VPNConnectionManaging,
    profiles: [VPNProfile],
    initiallySelectedProfileID: UUID?,
    activeProfileStore: TestActiveProfileStore? = nil,
    telemetry: (any DashboardConnectionTelemetryManaging)? = nil,
    haptic: (any StartHapticFeedbackProviding)? = nil
) async throws -> VPNDashboardViewModel {
    let profileRepository = InMemoryVPNProfileRepository()
    for profile in profiles {
        try await profileRepository.save(profile)
    }
    let selectedStore = activeProfileStore ?? TestActiveProfileStore(
        profileID: initiallySelectedProfileID
    )
    if activeProfileStore != nil {
        await selectedStore.saveActiveProfileID(initiallySelectedProfileID)
    }

    return VPNDashboardViewModel(
        serverProvider: FastTestServerProvider(),
        connectionManager: connectionManager,
        serverSelector: FastTestServerSelector(),
        profileRepository: profileRepository,
        subscriptionRepository: InMemorySubscriptionRepository(),
        activeProfileStore: selectedStore,
        connectionTelemetryManager: telemetry
            ?? DisabledDashboardConnectionTelemetryManager(),
        startHapticFeedback: haptic ?? DisabledStartHapticFeedback()
    )
}

private func makeTestProfile(
    name: String = "Production profile"
) -> VPNProfile {
    var profile = VPNProfile.draft(
        name: name,
        protocolType: .vless,
        serverAddress: "profile.example.invalid",
        port: 443,
        credentialReference: "keychain://test.credentials/restoration",
        transportSettings: VPNTransportSettings(network: "tcp", security: "tls"),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: "profile.example.invalid"
        ),
        protocolConfiguration: .vless(
            VLESSProfileConfiguration(flow: nil, encryption: "none")
        ),
        source: .manual
    )
    profile.id = UUID()
    return profile
}

private func authoritativeConnection(
    profileID: UUID,
    provider: PacketTunnelProviderKind,
    status: VPNSystemConnectionStatus
) -> VPNAuthoritativeConnection {
    VPNAuthoritativeConnection(
        state: status.dashboardState,
        systemStatus: status,
        profileID: profileID,
        provider: provider,
        hasMultipleActiveManagers: false
    )
}

private func temporaryTelemetryURL() -> URL {
    FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
        .appendingPathComponent("last-runtime-snapshot.json")
}

private final class TestAuthoritativeTunnelManager:
    AuthoritativeTunnelManagerControlling,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var storedSnapshot: AuthoritativeTunnelManagerSnapshot
    private var statusHandler: (@Sendable () -> Void)?
    private(set) var observerInstallCount = 0
    private(set) var observerRemoveCount = 0
    private(set) var stopCount = 0

    init(
        profileID: UUID,
        provider: PacketTunnelProviderKind,
        status: VPNSystemConnectionStatus
    ) {
        storedSnapshot = AuthoritativeTunnelManagerSnapshot(
            managerIdentifier: UUID().uuidString,
            providerBundleIdentifier:
                PacketTunnelProviderRouting.bundleIdentifier(for: provider),
            profileID: profileID,
            status: status
        )
    }

    func snapshot() async -> AuthoritativeTunnelManagerSnapshot {
        lock.withLock { storedSnapshot }
    }

    func observeStatusChanges(_ handler: @escaping @Sendable () -> Void) async {
        lock.withLock {
            observerInstallCount += 1
            statusHandler = handler
        }
    }

    func removeStatusObserver() async {
        lock.withLock {
            observerRemoveCount += 1
            statusHandler = nil
        }
    }

    func stopTunnel() async {
        let handler = lock.withLock { () -> (@Sendable () -> Void)? in
            stopCount += 1
            storedSnapshot.status = .disconnected
            return statusHandler
        }
        handler?()
    }
}

private actor TestAuthoritativeTunnelManagerLoader:
    AuthoritativeTunnelManagerLoading
{
    private let managers: [any AuthoritativeTunnelManagerControlling]
    private var loads = 0

    init(managers: [any AuthoritativeTunnelManagerControlling]) {
        self.managers = managers
    }

    func loadAllManagers() async throws -> [any AuthoritativeTunnelManagerControlling] {
        loads += 1
        return managers
    }

    func loadCount() -> Int {
        loads
    }
}

private actor ControllableConnectionManager: VPNConnectionManaging {
    private let profileID: UUID
    private var status: VPNSystemConnectionStatus = .disconnected
    private var connectCalls = 0
    private var continuations:
        [UUID: AsyncStream<VPNConnectionState>.Continuation] = [:]

    init(profileID: UUID) {
        self.profileID = profileID
    }

    func currentState() async -> VPNConnectionState {
        status.dashboardState
    }

    nonisolated func stateUpdates() -> AsyncStream<VPNConnectionState> {
        AsyncStream { continuation in
            Task {
                let id = UUID()
                await self.addContinuation(continuation, id: id)
                continuation.onTermination = { _ in
                    Task {
                        await self.removeContinuation(id: id)
                    }
                }
            }
        }
    }

    func authoritativeConnection() async -> VPNAuthoritativeConnection {
        if status.isActive {
            return VPNAuthoritativeConnection(
                state: status.dashboardState,
                systemStatus: status,
                profileID: profileID,
                provider: .xray,
                hasMultipleActiveManagers: false
            )
        }
        return .disconnected
    }

    func refreshAuthoritativeConnection() async -> VPNAuthoritativeConnection {
        await authoritativeConnection()
    }

    func connect(using profile: VPNProfile) async throws {
        connectCalls += 1
        await emit(.connected)
    }

    func disconnect() async {
        await emit(.disconnected)
    }

    func emit(_ newStatus: VPNSystemConnectionStatus) async {
        status = newStatus
        continuations.values.forEach { $0.yield(newStatus.dashboardState) }
    }

    func connectCallCount() -> Int {
        connectCalls
    }

    private func addContinuation(
        _ continuation: AsyncStream<VPNConnectionState>.Continuation,
        id: UUID
    ) {
        continuations[id] = continuation
        continuation.yield(status.dashboardState)
    }

    private func removeContinuation(id: UUID) {
        continuations[id] = nil
    }
}

private actor RecordingDashboardTelemetryManager:
    DashboardConnectionTelemetryManaging
{
    private var activeSessionKey: String?
    private var starts = 0
    private var stops = 0

    nonisolated func updates() -> AsyncStream<DashboardConnectionTelemetrySnapshot> {
        AsyncStream { continuation in
            continuation.yield(.unavailable)
            continuation.finish()
        }
    }

    func reconcile(with connection: VPNAuthoritativeConnection) async {
        let shouldRun = connection.systemStatus == .connected
            || connection.systemStatus == .reasserting
        guard shouldRun,
              let profileID = connection.profileID,
              let provider = connection.provider else {
            if activeSessionKey != nil {
                activeSessionKey = nil
                stops += 1
            }
            return
        }

        let key = provider.rawValue + "|" + profileID.uuidString
        guard activeSessionKey != key else {
            return
        }
        activeSessionKey = key
        starts += 1
    }

    func stop() async {
        if activeSessionKey != nil {
            activeSessionKey = nil
            stops += 1
        }
    }

    func startCount() -> Int {
        starts
    }

    func stopCount() -> Int {
        stops
    }
}

private actor TestActiveProfileStore: ActiveProfileStoring {
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

private struct FastTestServerProvider: ServerProviding {
    func fetchServers() async throws -> [VPNServer] {
        MockServerCatalog.servers
    }
}

private struct FastTestServerSelector: ServerSelecting {
    func bestServer(
        from servers: [VPNServer],
        using prober: ServerProbing
    ) async throws -> VPNServer {
        guard let first = servers.first else {
            throw MockVPNError.noAvailableServers
        }
        return first
    }

    func automaticProtocol(for server: VPNServer) -> VPNProtocol? {
        server.supportedProtocols.first
    }
}

private actor FixedProviderSessionReader: ProviderTunnelSessionReading {
    let sessionValue: ProviderTunnelSession

    init(session: ProviderTunnelSession) {
        sessionValue = session
    }

    func session(
        matching connection: VPNAuthoritativeConnection
    ) async -> ProviderTunnelSession? {
        sessionValue
    }
}

private final class FixedTelemetryClock: DashboardTelemetryClock, @unchecked Sendable {
    private let fixedNow: Date

    init(now: Date) {
        fixedNow = now
    }

    func now() -> Date {
        fixedNow
    }

    func sleep(for duration: Duration) async throws {
        try await Task.sleep(for: .seconds(60))
    }
}

private struct FixedLatencyProbe: TunnelLatencyProbing {
    let outcome: TunnelLatencyProbeOutcome

    func probe() async -> TunnelLatencyProbeOutcome {
        outcome
    }
}

private actor CountingLatencyProbe: TunnelLatencyProbing {
    private var calls = 0

    func probe() async -> TunnelLatencyProbeOutcome {
        calls += 1
        return .success(milliseconds: 12)
    }

    func callCount() -> Int {
        calls
    }
}

private enum DeterministicEndpointResult: Sendable {
    case success(Double)
    case timedOut
    case cancelled
}

private actor DeterministicEndpointProber: EndpointProbing {
    let result: DeterministicEndpointResult

    init(result: DeterministicEndpointResult) {
        self.result = result
    }

    func probe(
        _ request: TransportProbeRequest,
        attemptIndex: Int,
        timeout: Duration
    ) async -> TransportProbeAttempt {
        let startedAt = Date(timeIntervalSince1970: 1)
        switch result {
        case .success(let milliseconds):
            return TransportProbeAttempt(
                candidateID: request.candidateID,
                attemptIndex: attemptIndex,
                startedAt: startedAt,
                finishedAt: startedAt.addingTimeInterval(milliseconds / 1_000),
                connectLatencyMs: milliseconds,
                handshakeLatencyMs: milliseconds,
                failure: nil
            )
        case .timedOut:
            return TransportProbeAttempt(
                candidateID: request.candidateID,
                attemptIndex: attemptIndex,
                startedAt: startedAt,
                finishedAt: startedAt.addingTimeInterval(3),
                connectLatencyMs: nil,
                handshakeLatencyMs: nil,
                failure: .connectionTimedOut
            )
        case .cancelled:
            return TransportProbeAttempt(
                candidateID: request.candidateID,
                attemptIndex: attemptIndex,
                startedAt: startedAt,
                finishedAt: startedAt,
                connectLatencyMs: nil,
                handshakeLatencyMs: nil,
                failure: .cancelled
            )
        }
    }
}

@MainActor
private final class RecordingStartHapticFeedback:
    StartHapticFeedbackProviding,
    @unchecked Sendable
{
    private(set) var callCount = 0

    func playLightStartImpact() {
        callCount += 1
    }
}
