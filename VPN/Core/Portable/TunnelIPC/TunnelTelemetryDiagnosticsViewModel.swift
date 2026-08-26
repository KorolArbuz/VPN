//
//  TunnelTelemetryDiagnosticsViewModel.swift
//  VPN
//
//  DEBUG/internal UI adapter for authoritative PacketTunnelExtension telemetry.
//  It is read-only and never calls the production connection manager.
//

import Foundation
import Observation

@MainActor
@Observable
final class TunnelTelemetryDiagnosticsViewModel {
    private let messenger: any TunnelProviderMessaging
    private let snapshotStore: TunnelTelemetrySnapshotStore?
    private let startupDiagnosticsStore: TunnelStartupDiagnosticsStore?
    private let coreUpdater: TunnelTelemetryCoreUpdater?
    private let keychainSmokeTester: TunnelKeychainSentinelSmokeTester?
    private let appGroupSelfTester: TunnelAppGroupSelfTester?
    private let providerPreflightService: TunnelProviderPreflightService?
    private let nativeRuntimeDiagnosticService: NativeTunnelRuntimeDiagnosticService?
    private let runtimeValidationService: RuntimeConfigurationValidationService?
    private let xrayValidationService: XrayConfigurationValidationService?
    private let xrayLifecycleSmokeTestService: XrayLifecycleSmokeTestService?
    private let xrayRemoteEgressProbeService: XrayRemoteEgressProbeService?
    private let udpControlProbeService: UDPControlProbeService?
    private let libXrayPingProbeService: LibXrayPingProbeService?
    #if DEBUG
    private let runtimeOnlyPacketTunnelService: RuntimeOnlyPacketTunnelService?
    private let dataPlanePacketTunnelService: DataPlanePacketTunnelService?
    private let libXrayPingOnlyPacketTunnelService: LibXrayPingOnlyPacketTunnelService?
    private let diagnosticProviderStateService: DiagnosticProviderStateService?
    private let diagnosticProviderRecoveryService: DiagnosticProviderRecoveryService?
    #endif
    private var refreshTask: Task<Void, Never>?
    private var keychainSmokeTask: Task<Void, Never>?
    private var appGroupSelfTestTask: Task<Void, Never>?
    private var providerPreflightTask: Task<Void, Never>?
    private var nativeRuntimeDiagnosticTask: Task<Void, Never>?
    private var runtimeValidationTask: Task<Void, Never>?
    private var xrayValidationTask: Task<Void, Never>?
    private var xrayLifecycleSmokeTestTask: Task<Void, Never>?
    private var xrayRemoteEgressProbeTask: Task<Void, Never>?
    private var activeXrayEgressProbeTask: Task<Void, Never>?
    private var udpControlProbeTask: Task<Void, Never>?
    private var libXrayPingProbeTask: Task<Void, Never>?
    private var runtimeOnlyTunnelTask: Task<Void, Never>?
    private var dataPlaneTunnelTask: Task<Void, Never>?
    private var libXrayPingOnlyTunnelTask: Task<Void, Never>?
    private var diagnosticProviderReconciliationTask: Task<Void, Never>?
    private var diagnosticProviderRecoveryTask: Task<Void, Never>?
    private var generation = 0
    private var runtimeValidationGeneration = 0
    private var xrayValidationGeneration = 0
    private var xrayLifecycleSmokeTestGeneration = 0
    private var xrayRemoteEgressProbeGeneration = 0
    private var activeXrayEgressProbeGeneration = 0
    private var udpControlProbeGeneration = 0
    private var libXrayPingProbeGeneration = 0
    private var runtimeOnlyTunnelGeneration = 0
    private var dataPlaneTunnelGeneration = 0
    private var libXrayPingOnlyTunnelGeneration = 0

    var isRefreshing = false
    var capabilities: TunnelCapabilitySnapshot?
    var runtimeSnapshot: TunnelRuntimeSnapshot?
    var healthSnapshot: TunnelHealthSnapshot?
    var recentEvents: [TunnelEventSnapshot] = []
    var lastKnownSnapshot: TunnelTelemetrySnapshotRead?
    var recommendation: KVNSelectionDecisionDTO?
    var comparability: TunnelTelemetryComparability = .notUpdated
    var errorKey: String?
    var extensionReachable = false
    var lastRefreshedAt: Date?
    var systemConnectionState: VPNConnectionState = .disconnected
    var providerStatus: TunnelProviderSessionStatus = .unknown
    var latestStartupAttempt: TunnelDiagnosticAttemptSnapshot?
    var diagnosticProviderMode: TunnelDiagnosticProviderMode = .idle
    var diagnosticProviderStateIsUnsynchronized = false
    var isReconcilingDiagnosticProviderState = false
    var isRecoveringDiagnosticProvider = false
    var diagnosticProviderRecoveryErrorKey: String?
    var isRunningKeychainSmokeTest = false
    var keychainSmokeResult: [TunnelKeychainSentinelVerification] = []
    var keychainSmokeErrorKey: String?
    var keychainSmokeDiagnostic: TunnelKeychainSentinelDiagnostic?
    var isRunningAppGroupSelfTest = false
    var appGroupSelfTestResult: TunnelAppGroupSelfTestResult?
    var isRunningProviderPreflight = false
    var providerPreflightResult: TunnelProviderPreflightResult?
    var isRunningNativeRuntimeDiagnostic = false
    var nativeRuntimeDiagnosticResult: NativeRuntimeProfileDiagnosticResult?
    var isValidatingRuntimeConfiguration = false
    var runtimeValidationResult: TunnelRuntimeConfigurationValidationResponse?
    var runtimeValidationErrorKey: String?
    var runtimeValidationDiagnostic: TunnelRuntimeConfigurationValidationDiagnostic?
    var isValidatingXrayConfiguration = false
    var xrayValidationResult: TunnelXrayConfigurationValidationResponse?
    var xrayValidationErrorKey: String?
    var xrayValidationDiagnostic: TunnelXrayConfigurationValidationDiagnostic?
    var isRunningXrayLifecycleSmokeTest = false
    var xrayLifecycleSmokeTestResult: TunnelXrayLifecycleSmokeTestResponse?
    var xrayLifecycleSmokeTestErrorKey: String?
    var xrayLifecycleSmokeTestDiagnostic: TunnelXrayLifecycleSmokeTestDiagnostic?
    var isRunningXrayRemoteEgressProbe = false
    var xrayRemoteEgressProbeResult: TunnelXrayRemoteEgressProbeResponse?
    var xrayRemoteEgressProbeErrorKey: String?
    var xrayRemoteEgressProbeDiagnostic: TunnelXrayRemoteEgressProbeDiagnostic?
    var isRunningActiveXrayEgressProbe = false
    var activeXrayEgressProbeResult: TunnelXrayRemoteEgressProbeResponse?
    var activeXrayEgressProbeErrorKey: String?
    var activeXrayEgressProbeDiagnostic: TunnelXrayRemoteEgressProbeDiagnostic?
    var isRunningUDPControlProbe = false
    var udpControlProbeResult: TunnelUDPControlProbeResponse?
    var udpControlProbeErrorKey: String?
    var udpControlProbeDiagnostic: TunnelUDPControlProbeDiagnostic?
    var isRunningLibXrayPingProbe = false
    var libXrayPingProbeResult: TunnelLibXrayPingProbeResponse?
    var libXrayPingProbeErrorKey: String?
    var libXrayPingProbeDiagnostic: TunnelLibXrayPingProbeDiagnostic?
    var isStartingRuntimeOnlyTunnel = false
    var isStoppingRuntimeOnlyTunnel = false
    var runtimeOnlyTunnelResult: TunnelXrayLifecycleSmokeTestResponse?
    var runtimeOnlyTunnelErrorKey: String?
    var runtimeOnlyTunnelDiagnostic: TunnelXrayLifecycleSmokeTestDiagnostic?
    var isStartingDataPlaneTunnel = false
    var isStoppingDataPlaneTunnel = false
    var dataPlaneTunnelResult: TunnelXrayLifecycleSmokeTestResponse?
    var dataPlaneTunnelErrorKey: String?
    var dataPlaneTunnelDiagnostic: TunnelXrayLifecycleSmokeTestDiagnostic?
    var isStartingLibXrayPingOnlyTunnel = false
    var isStoppingLibXrayPingOnlyTunnel = false
    var libXrayPingOnlyTunnelResult: TunnelXrayLifecycleSmokeTestResponse?
    var libXrayPingOnlyTunnelErrorKey: String?
    var libXrayPingOnlyTunnelDiagnostic: TunnelXrayLifecycleSmokeTestDiagnostic?

    #if DEBUG
    init(
        messenger: any TunnelProviderMessaging = NetworkExtensionTunnelMessenger(),
        snapshotStore: TunnelTelemetrySnapshotStore? = TunnelTelemetrySnapshotStore.appGroupStore(),
        startupDiagnosticsStore: TunnelStartupDiagnosticsStore? = TunnelStartupDiagnosticsStore.appGroupStore(),
        coreUpdater: TunnelTelemetryCoreUpdater? = nil,
        keychainSmokeTester: TunnelKeychainSentinelSmokeTester? = TunnelKeychainSentinelSmokeTester(),
        appGroupSelfTester: TunnelAppGroupSelfTester? = TunnelAppGroupSelfTester(),
        providerPreflightService: TunnelProviderPreflightService? = TunnelProviderPreflightService(),
        nativeRuntimeDiagnosticService: NativeTunnelRuntimeDiagnosticService? = NativeTunnelRuntimeDiagnosticService(),
        runtimeValidationService: RuntimeConfigurationValidationService? = RuntimeConfigurationValidationService.appGroupService(),
        xrayValidationService: XrayConfigurationValidationService? = XrayConfigurationValidationService.appGroupService(),
        xrayLifecycleSmokeTestService: XrayLifecycleSmokeTestService? = XrayLifecycleSmokeTestService.appGroupService(),
        xrayRemoteEgressProbeService: XrayRemoteEgressProbeService? = XrayRemoteEgressProbeService.appGroupService(),
        udpControlProbeService: UDPControlProbeService? = UDPControlProbeService.appGroupService(),
        libXrayPingProbeService: LibXrayPingProbeService? = LibXrayPingProbeService.appGroupService(),
        runtimeOnlyPacketTunnelService: RuntimeOnlyPacketTunnelService? = RuntimeOnlyPacketTunnelService.appGroupService(),
        dataPlanePacketTunnelService: DataPlanePacketTunnelService? = DataPlanePacketTunnelService.appGroupService(),
        libXrayPingOnlyPacketTunnelService: LibXrayPingOnlyPacketTunnelService? = LibXrayPingOnlyPacketTunnelService.appGroupService(),
        diagnosticProviderStateService: DiagnosticProviderStateService? = DiagnosticProviderStateService(),
        diagnosticProviderRecoveryService: DiagnosticProviderRecoveryService? = DiagnosticProviderRecoveryService()
    ) {
        self.messenger = messenger
        self.snapshotStore = snapshotStore
        self.startupDiagnosticsStore = startupDiagnosticsStore
        self.coreUpdater = coreUpdater ?? Self.makeDefaultCoreUpdater()
        self.keychainSmokeTester = keychainSmokeTester
        self.appGroupSelfTester = appGroupSelfTester
        self.providerPreflightService = providerPreflightService
        self.nativeRuntimeDiagnosticService = nativeRuntimeDiagnosticService
        self.runtimeValidationService = runtimeValidationService
        self.xrayValidationService = xrayValidationService
        self.xrayLifecycleSmokeTestService = xrayLifecycleSmokeTestService
        self.xrayRemoteEgressProbeService = xrayRemoteEgressProbeService
        self.udpControlProbeService = udpControlProbeService
        self.libXrayPingProbeService = libXrayPingProbeService
        self.runtimeOnlyPacketTunnelService = runtimeOnlyPacketTunnelService
        self.dataPlanePacketTunnelService = dataPlanePacketTunnelService
        self.libXrayPingOnlyPacketTunnelService = libXrayPingOnlyPacketTunnelService
        self.diagnosticProviderStateService = diagnosticProviderStateService
        self.diagnosticProviderRecoveryService = diagnosticProviderRecoveryService
    }
    #else
    init(
        messenger: any TunnelProviderMessaging = NetworkExtensionTunnelMessenger(),
        snapshotStore: TunnelTelemetrySnapshotStore? = TunnelTelemetrySnapshotStore.appGroupStore(),
        startupDiagnosticsStore: TunnelStartupDiagnosticsStore? = TunnelStartupDiagnosticsStore.appGroupStore(),
        coreUpdater: TunnelTelemetryCoreUpdater? = nil,
        keychainSmokeTester: TunnelKeychainSentinelSmokeTester? = TunnelKeychainSentinelSmokeTester(),
        appGroupSelfTester: TunnelAppGroupSelfTester? = TunnelAppGroupSelfTester(),
        providerPreflightService: TunnelProviderPreflightService? = TunnelProviderPreflightService(),
        nativeRuntimeDiagnosticService: NativeTunnelRuntimeDiagnosticService? = NativeTunnelRuntimeDiagnosticService(),
        runtimeValidationService: RuntimeConfigurationValidationService? = RuntimeConfigurationValidationService.appGroupService(),
        xrayValidationService: XrayConfigurationValidationService? = XrayConfigurationValidationService.appGroupService(),
        xrayLifecycleSmokeTestService: XrayLifecycleSmokeTestService? = XrayLifecycleSmokeTestService.appGroupService(),
        xrayRemoteEgressProbeService: XrayRemoteEgressProbeService? = XrayRemoteEgressProbeService.appGroupService(),
        udpControlProbeService: UDPControlProbeService? = UDPControlProbeService.appGroupService(),
        libXrayPingProbeService: LibXrayPingProbeService? = LibXrayPingProbeService.appGroupService()
    ) {
        self.messenger = messenger
        self.snapshotStore = snapshotStore
        self.startupDiagnosticsStore = startupDiagnosticsStore
        self.coreUpdater = coreUpdater ?? Self.makeDefaultCoreUpdater()
        self.keychainSmokeTester = keychainSmokeTester
        self.appGroupSelfTester = appGroupSelfTester
        self.providerPreflightService = providerPreflightService
        self.nativeRuntimeDiagnosticService = nativeRuntimeDiagnosticService
        self.runtimeValidationService = runtimeValidationService
        self.xrayValidationService = xrayValidationService
        self.xrayLifecycleSmokeTestService = xrayLifecycleSmokeTestService
        self.xrayRemoteEgressProbeService = xrayRemoteEgressProbeService
        self.udpControlProbeService = udpControlProbeService
        self.libXrayPingProbeService = libXrayPingProbeService
    }
    #endif

    var runtimeOnlyDiagnosticModeIsRunning: Bool {
        providerIsConnected && diagnosticProviderMode == .runtimeOnly
    }

    var dataPlaneDiagnosticModeIsRunning: Bool {
        providerIsConnected && diagnosticProviderMode == .dataPlane
    }

    var libXrayPingOnlyDiagnosticModeIsRunning: Bool {
        providerIsConnected && diagnosticProviderMode == .libXrayPingOnly
    }

    var persistentDiagnosticStartIsEligible: Bool {
        providerStatus == .disconnected
            && diagnosticProviderMode == .idle
            && diagnosticProviderStateIsUnsynchronized == false
            && isRecoveringDiagnosticProvider == false
            && isReconcilingDiagnosticProviderState == false
    }

    var diagnosticProviderRecoveryIsAvailable: Bool {
        diagnosticProviderStateIsUnsynchronized && isRecoveringDiagnosticProvider == false
    }

    var diagnosticProviderIsOccupied: Bool {
        providerStatus != .disconnected
            && providerStatus != .invalid
            && diagnosticProviderMode != .idle
    }

    private var providerIsConnected: Bool {
        providerStatus == .connected || providerStatus == .reasserting
    }

    func refresh(profiles: [VPNProfile], activeProfileID: UUID?, connectionState: VPNConnectionState) {
        generation += 1
        let currentGeneration = generation
        refreshTask?.cancel()
        systemConnectionState = connectionState
        isRefreshing = true
        errorKey = nil

        refreshTask = Task { [weak self, messenger, snapshotStore, startupDiagnosticsStore, coreUpdater] in
            let startupAttempt = await Self.readLatestStartupAttempt(startupDiagnosticsStore)
            #if DEBUG
            guard let self else { return }
            let diagnosticState = await self.reconcileDiagnosticProviderStateNow()
            let providerStatus = diagnosticState.providerStatus
            #else
            let providerStatus = await messenger.status()
            #endif
            do {
                async let capabilitiesResponse = messenger.send(TunnelMessageRequest(kind: .getCapabilities))
                async let runtimeResponse = messenger.send(TunnelMessageRequest(kind: .getRuntimeSnapshot))
                async let healthResponse = messenger.send(TunnelMessageRequest(kind: .getHealthSnapshot))
                async let eventsResponse = messenger.send(TunnelMessageRequest(kind: .getRecentEvents))

                let capabilities = try await Self.capabilities(from: capabilitiesResponse)
                let runtime = try await Self.runtime(from: runtimeResponse)
                let health = try await Self.health(from: healthResponse)
                let events = try await Self.events(from: eventsResponse)
                let coreResult = try await coreUpdater?.apply(
                    runtime: runtime,
                    profiles: profiles,
                    activeProfileID: activeProfileID
                )

                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    #if DEBUG
                    guard self.generation == currentGeneration else { return }
                    #else
                    guard let self, self.generation == currentGeneration else { return }
                    #endif
                    self.capabilities = capabilities
                    self.runtimeSnapshot = runtime
                    self.healthSnapshot = health
                    self.recentEvents = events
                    self.lastKnownSnapshot = nil
                    self.latestStartupAttempt = startupAttempt
                    self.recommendation = coreResult?.recommendation
                    self.comparability = coreResult?.comparability ?? .notUpdated
                    self.extensionReachable = true
                    #if DEBUG
                    self.applyDiagnosticProviderState(diagnosticState)
                    #else
                    self.providerStatus = providerStatus
                    #endif
                    self.lastRefreshedAt = Date()
                    self.isRefreshing = false
                }
            } catch let failure as TunnelMessageErrorCode {
                let fallback = await Self.readFallback(snapshotStore)
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    #if DEBUG
                    guard self.generation == currentGeneration else { return }
                    #else
                    guard let self, self.generation == currentGeneration else { return }
                    #endif
                    self.errorKey = failure.localizationKey
                    self.extensionReachable = false
                    #if DEBUG
                    self.applyDiagnosticProviderState(diagnosticState)
                    #else
                    self.providerStatus = providerStatus
                    #endif
                    self.lastKnownSnapshot = fallback
                    self.latestStartupAttempt = startupAttempt
                    self.runtimeSnapshot = fallback?.stored.runtime
                    self.healthSnapshot = fallback?.stored.runtime.health
                    self.recentEvents = fallback?.stored.events ?? []
                    self.isRefreshing = false
                }
            } catch {
                let fallback = await Self.readFallback(snapshotStore)
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    #if DEBUG
                    guard self.generation == currentGeneration else { return }
                    #else
                    guard let self, self.generation == currentGeneration else { return }
                    #endif
                    self.errorKey = TunnelMessageErrorCode.unknown.localizationKey
                    self.extensionReachable = false
                    #if DEBUG
                    self.applyDiagnosticProviderState(diagnosticState)
                    #else
                    self.providerStatus = providerStatus
                    #endif
                    self.lastKnownSnapshot = fallback
                    self.latestStartupAttempt = startupAttempt
                    self.runtimeSnapshot = fallback?.stored.runtime
                    self.healthSnapshot = fallback?.stored.runtime.health
                    self.recentEvents = fallback?.stored.events ?? []
                    self.isRefreshing = false
                }
            }
        }
    }

    func loadLatestStartupDiagnostics() {
        let startupDiagnosticsStore = startupDiagnosticsStore
        Task { [weak self] in
            let attempt = await Self.readLatestStartupAttempt(startupDiagnosticsStore)
            guard Task.isCancelled == false else { return }
            await MainActor.run {
                self?.latestStartupAttempt = attempt
            }
        }
    }

    func runAppGroupSelfTest() {
        appGroupSelfTestTask?.cancel()
        appGroupSelfTestResult = nil
        guard let appGroupSelfTester else { return }
        isRunningAppGroupSelfTest = true
        appGroupSelfTestTask = Task { [weak self, appGroupSelfTester] in
            let result = await appGroupSelfTester.run()
            guard Task.isCancelled == false else { return }
            await MainActor.run {
                self?.appGroupSelfTestResult = result
                self?.isRunningAppGroupSelfTest = false
            }
        }
    }

    func runProviderPreflight() {
        providerPreflightTask?.cancel()
        providerPreflightResult = nil
        guard let providerPreflightService else { return }
        isRunningProviderPreflight = true
        providerPreflightTask = Task { [weak self, providerPreflightService] in
            let result = await providerPreflightService.run()
            guard Task.isCancelled == false else { return }
            await MainActor.run {
                self?.providerPreflightResult = result
                self?.isRunningProviderPreflight = false
            }
        }
    }

    func inspectNativeRuntimeProfile(profile: VPNProfile?) {
        nativeRuntimeDiagnosticTask?.cancel()
        nativeRuntimeDiagnosticResult = nil
        guard let profile,
              profile.protocolType == .wireGuard || profile.protocolType == .amneziaWG,
              let nativeRuntimeDiagnosticService else {
            return
        }
        isRunningNativeRuntimeDiagnostic = true
        nativeRuntimeDiagnosticTask = Task { [weak self, nativeRuntimeDiagnosticService] in
            let result = await nativeRuntimeDiagnosticService.inspect(profileID: profile.id)
            guard Task.isCancelled == false else { return }
            await MainActor.run {
                self?.nativeRuntimeDiagnosticResult = result
                self?.isRunningNativeRuntimeDiagnostic = false
            }
        }
    }

    var latestDiagnosticReport: String? {
        latestStartupAttempt.map(TunnelDiagnosticReportExporter.report)
    }

    #if DEBUG
    func reconcileDiagnosticProviderState() {
        diagnosticProviderReconciliationTask?.cancel()
        isReconcilingDiagnosticProviderState = true
        diagnosticProviderRecoveryErrorKey = nil

        diagnosticProviderReconciliationTask = Task { [weak self] in
            guard let self else { return }
            let state = await reconcileDiagnosticProviderStateNow()
            guard Task.isCancelled == false else { return }
            await MainActor.run {
                self.applyDiagnosticProviderState(state)
                self.isReconcilingDiagnosticProviderState = false
            }
        }
    }

    func recoverDiagnosticProvider() {
        diagnosticProviderRecoveryTask?.cancel()
        isRecoveringDiagnosticProvider = true
        diagnosticProviderRecoveryErrorKey = nil

        diagnosticProviderRecoveryTask = Task { [weak self] in
            guard let self else { return }
            do {
                try await diagnosticProviderRecoveryService?.recover()
                let state = await reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    self.applyDiagnosticProviderState(state)
                    self.isRecoveringDiagnosticProvider = false
                }
            } catch {
                let state = await reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    self.applyDiagnosticProviderState(state)
                    self.diagnosticProviderRecoveryErrorKey = "diagnostics.provider_mode.recovery_failed"
                    self.isRecoveringDiagnosticProvider = false
                }
            }
        }
    }

    private func reconcileDiagnosticProviderStateNow() async -> DiagnosticProviderStateSnapshot {
        if let diagnosticProviderStateService {
            return await diagnosticProviderStateService.reconcile()
        }
        return DiagnosticProviderStateSnapshot(
            providerStatus: await messenger.status(),
            mode: .unknown,
            extensionReachable: false,
            recoveryRequired: false
        )
    }

    private func applyDiagnosticProviderState(_ state: DiagnosticProviderStateSnapshot) {
        providerStatus = state.providerStatus
        diagnosticProviderMode = state.mode
        diagnosticProviderStateIsUnsynchronized = state.recoveryRequired
        if state.providerStatus == .disconnected || state.providerStatus == .invalid {
            diagnosticProviderMode = .idle
            diagnosticProviderStateIsUnsynchronized = false
            clearPersistentDiagnosticOwnership()
        }
    }

    private func persistentStartDisposition(after state: DiagnosticProviderStateSnapshot) -> DiagnosticProviderStartDisposition {
        if state.providerStatus == .disconnected && state.mode == .idle && state.recoveryRequired == false {
            return .allowed
        }
        if state.recoveryRequired {
            return .recoveryRequired
        }
        return .busy
    }

    private func clearPersistentDiagnosticOwnership() {
        runtimeOnlyTunnelResult = nil
        runtimeOnlyTunnelErrorKey = nil
        runtimeOnlyTunnelDiagnostic = nil
        dataPlaneTunnelResult = nil
        dataPlaneTunnelErrorKey = nil
        dataPlaneTunnelDiagnostic = nil
        libXrayPingOnlyTunnelResult = nil
        libXrayPingOnlyTunnelErrorKey = nil
        libXrayPingOnlyTunnelDiagnostic = nil
        activeXrayEgressProbeResult = nil
        activeXrayEgressProbeErrorKey = nil
        activeXrayEgressProbeDiagnostic = nil
        udpControlProbeResult = nil
        udpControlProbeErrorKey = nil
        udpControlProbeDiagnostic = nil
        libXrayPingProbeResult = nil
        libXrayPingProbeErrorKey = nil
        libXrayPingProbeDiagnostic = nil
    }

    private enum DiagnosticProviderStartDisposition: Equatable {
        case allowed
        case busy
        case recoveryRequired
    }
    #endif

    func cancel() {
        generation += 1
        refreshTask?.cancel()
        refreshTask = nil
        keychainSmokeTask?.cancel()
        keychainSmokeTask = nil
        runtimeValidationTask?.cancel()
        runtimeValidationTask = nil
        xrayValidationTask?.cancel()
        xrayValidationTask = nil
        xrayLifecycleSmokeTestTask?.cancel()
        xrayLifecycleSmokeTestTask = nil
        xrayRemoteEgressProbeTask?.cancel()
        xrayRemoteEgressProbeTask = nil
        activeXrayEgressProbeTask?.cancel()
        activeXrayEgressProbeTask = nil
        udpControlProbeTask?.cancel()
        udpControlProbeTask = nil
        runtimeOnlyTunnelTask?.cancel()
        runtimeOnlyTunnelTask = nil
        dataPlaneTunnelTask?.cancel()
        dataPlaneTunnelTask = nil
        libXrayPingOnlyTunnelTask?.cancel()
        libXrayPingOnlyTunnelTask = nil
        diagnosticProviderReconciliationTask?.cancel()
        diagnosticProviderReconciliationTask = nil
        diagnosticProviderRecoveryTask?.cancel()
        diagnosticProviderRecoveryTask = nil
        isRunningKeychainSmokeTest = false
        isValidatingRuntimeConfiguration = false
        isValidatingXrayConfiguration = false
        isRunningXrayLifecycleSmokeTest = false
        isRunningXrayRemoteEgressProbe = false
        isRunningActiveXrayEgressProbe = false
        isRunningUDPControlProbe = false
        isStartingRuntimeOnlyTunnel = false
        isStoppingRuntimeOnlyTunnel = false
        isStartingDataPlaneTunnel = false
        isStoppingDataPlaneTunnel = false
        isRunningLibXrayPingProbe = false
        isStartingLibXrayPingOnlyTunnel = false
        isStoppingLibXrayPingOnlyTunnel = false
        isReconcilingDiagnosticProviderState = false
        isRecoveringDiagnosticProvider = false
        isRefreshing = false
    }

    func validateXrayConfiguration(profile: VPNProfile?) {
        let currentGeneration = beginXrayValidationOperation()
        guard isRunningXrayLifecycleSmokeTest == false else {
            xrayValidationErrorKey = "diagnostics.xray_validation.failed"
            xrayValidationDiagnostic = TunnelXrayConfigurationValidationDiagnostic(
                stage: .libXrayInvocation,
                category: .internalLibXrayError,
                extensionRequestReached: false
            )
            return
        }
        guard let profile else {
            xrayValidationErrorKey = "diagnostics.xray_validation.error.no_profile"
            xrayValidationDiagnostic = TunnelXrayConfigurationValidationDiagnostic(
                stage: .runtimeConfiguration,
                category: .runtimeConfigurationInvalid,
                extensionRequestReached: false
            )
            return
        }
        guard Self.isK3B4XrayBackedProtocol(profile.protocolType) else {
            xrayValidationErrorKey = "diagnostics.xray_validation.error.unsupported_protocol"
            xrayValidationDiagnostic = TunnelXrayConfigurationValidationDiagnostic(
                stage: .runtimeConfiguration,
                category: .unsupportedProtocol,
                extensionRequestReached: false
            )
            return
        }
        guard let xrayValidationService else {
            xrayValidationErrorKey = "diagnostics.xray_validation.error.shared_container"
            xrayValidationDiagnostic = TunnelXrayConfigurationValidationDiagnostic(
                stage: .runtimeConfiguration,
                category: .runtimeConfigurationInvalid,
                extensionRequestReached: false
            )
            return
        }

        isValidatingXrayConfiguration = true

        xrayValidationTask = Task { [weak self, xrayValidationService] in
            do {
                let result = try await xrayValidationService.validate(profile: profile)
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayValidationGeneration == currentGeneration else { return }
                    self.xrayValidationResult = result
                    self.xrayValidationDiagnostic = result.diagnostic
                    self.xrayValidationErrorKey = result.success ? nil : "diagnostics.xray_validation.failed"
                    self.isValidatingXrayConfiguration = false
                }
            } catch let failure as TunnelXrayConfigurationValidationFailure {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayValidationGeneration == currentGeneration else { return }
                    self.xrayValidationErrorKey = "diagnostics.xray_validation.failed"
                    self.xrayValidationDiagnostic = failure.diagnostic
                    self.isValidatingXrayConfiguration = false
                }
            } catch let error as RuntimeConfigurationError {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayValidationGeneration == currentGeneration else { return }
                    self.xrayValidationErrorKey = "diagnostics.xray_validation.failed"
                    self.xrayValidationDiagnostic = TunnelXrayConfigurationValidationDiagnostic(
                        stage: .runtimeConfiguration,
                        category: Self.xrayValidationCategory(for: error),
                        extensionRequestReached: false
                    )
                    self.isValidatingXrayConfiguration = false
                }
            } catch {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayValidationGeneration == currentGeneration else { return }
                    self.xrayValidationErrorKey = "diagnostics.xray_validation.failed"
                    self.xrayValidationDiagnostic = TunnelXrayConfigurationValidationDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isValidatingXrayConfiguration = false
                }
            }
        }
    }

    func runKeychainSentinelSmokeTest() {
        guard let keychainSmokeTester else {
            keychainSmokeErrorKey = TunnelMessageErrorCode.keychainUnavailable.localizationKey
            return
        }

        keychainSmokeTask?.cancel()
        keychainSmokeResult = []
        keychainSmokeErrorKey = nil
        keychainSmokeDiagnostic = nil
        isRunningKeychainSmokeTest = true

        keychainSmokeTask = Task { [weak self, keychainSmokeTester] in
            do {
                let result = try await keychainSmokeTester.runTwice()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    self?.keychainSmokeResult = result
                    self?.keychainSmokeErrorKey = nil
                    self?.keychainSmokeDiagnostic = result.last?.diagnostic
                    self?.isRunningKeychainSmokeTest = false
                }
            } catch let failure as TunnelKeychainSentinelDiagnosticFailure {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    self?.keychainSmokeErrorKey = "diagnostics.telemetry.keychain_smoke.failed"
                    self?.keychainSmokeDiagnostic = failure.diagnostic
                    self?.isRunningKeychainSmokeTest = false
                }
            } catch let error as TunnelMessageErrorCode {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    self?.keychainSmokeErrorKey = error.localizationKey
                    self?.keychainSmokeDiagnostic = TunnelKeychainSentinelDiagnostic(
                        stage: .providerMessageSend,
                        status: .failed,
                        category: Self.diagnosticCategory(for: error)
                    )
                    self?.isRunningKeychainSmokeTest = false
                }
            } catch {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    self?.keychainSmokeErrorKey = "diagnostics.telemetry.keychain_smoke.failed"
                    self?.keychainSmokeDiagnostic = TunnelKeychainSentinelDiagnostic(
                        stage: .providerMessageSend,
                        status: .failed,
                        category: .unknown
                    )
                    self?.isRunningKeychainSmokeTest = false
                }
            }
        }
    }

    func runXrayLifecycleSmokeTest(profile: VPNProfile?) {
        let currentGeneration = beginXrayLifecycleSmokeTestOperation()
        guard isValidatingXrayConfiguration == false,
              isStartingLibXrayPingOnlyTunnel == false,
              isStoppingLibXrayPingOnlyTunnel == false,
              isRunningLibXrayPingProbe == false,
              diagnosticProviderIsOccupied == false else {
            xrayLifecycleSmokeTestErrorKey = "diagnostics.xray_lifecycle.failed"
            xrayLifecycleSmokeTestDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .testXray,
                category: .internalRuntimeError,
                extensionRequestReached: false
            )
            return
        }
        guard let profile else {
            xrayLifecycleSmokeTestErrorKey = "diagnostics.xray_lifecycle.error.no_profile"
            xrayLifecycleSmokeTestDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .runtimeConfigurationInvalid,
                extensionRequestReached: false
            )
            return
        }
        guard Self.isK3B4XrayBackedProtocol(profile.protocolType) else {
            xrayLifecycleSmokeTestErrorKey = "diagnostics.xray_lifecycle.error.unsupported_protocol"
            xrayLifecycleSmokeTestDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .unsupportedProfileForRuntimeSmoke,
                extensionRequestReached: false
            )
            return
        }
        guard let xrayLifecycleSmokeTestService else {
            xrayLifecycleSmokeTestErrorKey = "diagnostics.xray_lifecycle.error.shared_container"
            xrayLifecycleSmokeTestDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .runtimeConfigurationInvalid,
                extensionRequestReached: false
            )
            return
        }

        isRunningXrayLifecycleSmokeTest = true

        xrayLifecycleSmokeTestTask = Task { [weak self, xrayLifecycleSmokeTestService] in
            do {
                let result = try await xrayLifecycleSmokeTestService.run(profile: profile)
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayLifecycleSmokeTestGeneration == currentGeneration else { return }
                    self.xrayLifecycleSmokeTestResult = result
                    self.xrayLifecycleSmokeTestDiagnostic = result.diagnostic
                    self.xrayLifecycleSmokeTestErrorKey = result.success ? nil : "diagnostics.xray_lifecycle.failed"
                    self.isRunningXrayLifecycleSmokeTest = false
                }
            } catch let failure as TunnelXrayLifecycleSmokeTestFailure {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayLifecycleSmokeTestGeneration == currentGeneration else { return }
                    self.xrayLifecycleSmokeTestErrorKey = "diagnostics.xray_lifecycle.failed"
                    self.xrayLifecycleSmokeTestDiagnostic = failure.diagnostic
                    self.isRunningXrayLifecycleSmokeTest = false
                }
            } catch let error as RuntimeConfigurationError {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayLifecycleSmokeTestGeneration == currentGeneration else { return }
                    self.xrayLifecycleSmokeTestErrorKey = "diagnostics.xray_lifecycle.failed"
                    self.xrayLifecycleSmokeTestDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                        stage: Self.xrayLifecycleStage(for: error),
                        category: Self.xrayLifecycleCategory(for: error),
                        extensionRequestReached: false
                    )
                    self.isRunningXrayLifecycleSmokeTest = false
                }
            } catch {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayLifecycleSmokeTestGeneration == currentGeneration else { return }
                    self.xrayLifecycleSmokeTestErrorKey = "diagnostics.xray_lifecycle.failed"
                    self.xrayLifecycleSmokeTestDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isRunningXrayLifecycleSmokeTest = false
                }
            }
        }
    }

    func runXrayRemoteEgressProbe(profile: VPNProfile?) {
        let currentGeneration = beginXrayRemoteEgressProbeOperation()
        guard isValidatingXrayConfiguration == false,
              isRunningXrayLifecycleSmokeTest == false,
              isStartingLibXrayPingOnlyTunnel == false,
              isStoppingLibXrayPingOnlyTunnel == false,
              isRunningLibXrayPingProbe == false,
              libXrayPingOnlyDiagnosticModeIsRunning == false else {
            xrayRemoteEgressProbeErrorKey = "diagnostics.xray_remote_egress.failed"
            xrayRemoteEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .preStartState,
                category: .runtimeBusy,
                extensionRequestReached: false
            )
            return
        }
        guard let profile else {
            xrayRemoteEgressProbeErrorKey = "diagnostics.xray_remote_egress.error.no_profile"
            xrayRemoteEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .runtimeConfiguration,
                category: .configurationRejected,
                extensionRequestReached: false
            )
            return
        }
        guard Self.isK3B4XrayBackedProtocol(profile.protocolType) else {
            xrayRemoteEgressProbeErrorKey = "diagnostics.xray_remote_egress.error.unsupported_protocol"
            xrayRemoteEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .runtimeConfiguration,
                category: .configurationRejected,
                extensionRequestReached: false
            )
            return
        }
        guard let xrayRemoteEgressProbeService else {
            xrayRemoteEgressProbeErrorKey = "diagnostics.xray_remote_egress.error.shared_container"
            xrayRemoteEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .runtimeConfiguration,
                category: .providerUnavailable,
                extensionRequestReached: false
            )
            return
        }

        isRunningXrayRemoteEgressProbe = true

        xrayRemoteEgressProbeTask = Task { [weak self, xrayRemoteEgressProbeService] in
            do {
                let result = try await xrayRemoteEgressProbeService.run(profile: profile)
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayRemoteEgressProbeGeneration == currentGeneration else { return }
                    self.xrayRemoteEgressProbeResult = result
                    self.xrayRemoteEgressProbeDiagnostic = result.diagnostic
                    self.xrayRemoteEgressProbeErrorKey = result.success ? nil : "diagnostics.xray_remote_egress.failed"
                    self.isRunningXrayRemoteEgressProbe = false
                }
            } catch let failure as TunnelXrayRemoteEgressProbeFailure {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayRemoteEgressProbeGeneration == currentGeneration else { return }
                    self.xrayRemoteEgressProbeErrorKey = "diagnostics.xray_remote_egress.failed"
                    self.xrayRemoteEgressProbeDiagnostic = failure.diagnostic
                    self.isRunningXrayRemoteEgressProbe = false
                }
            } catch {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.xrayRemoteEgressProbeGeneration == currentGeneration else { return }
                    self.xrayRemoteEgressProbeErrorKey = "diagnostics.xray_remote_egress.failed"
                    self.xrayRemoteEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isRunningXrayRemoteEgressProbe = false
                }
            }
        }
    }

    func probeActiveXrayEgress(profile: VPNProfile?) {
        let currentGeneration = beginActiveXrayEgressProbeOperation()
        guard isRunningXrayRemoteEgressProbe == false,
              isRunningXrayLifecycleSmokeTest == false,
              isValidatingXrayConfiguration == false,
              isStartingRuntimeOnlyTunnel == false,
              isStoppingRuntimeOnlyTunnel == false,
              isStartingDataPlaneTunnel == false,
              isStoppingDataPlaneTunnel == false,
              isStartingLibXrayPingOnlyTunnel == false,
              isStoppingLibXrayPingOnlyTunnel == false,
              isRunningLibXrayPingProbe == false else {
            activeXrayEgressProbeErrorKey = "diagnostics.xray_remote_egress.failed"
            activeXrayEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .preStartState,
                category: .runtimeBusy,
                extensionRequestReached: false
            )
            return
        }
        guard let profile else {
            activeXrayEgressProbeErrorKey = "diagnostics.xray_remote_egress.error.no_profile"
            activeXrayEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .runtimeConfiguration,
                category: .configurationRejected,
                extensionRequestReached: false
            )
            return
        }
        guard Self.isK3B4XrayBackedProtocol(profile.protocolType) else {
            activeXrayEgressProbeErrorKey = "diagnostics.xray_remote_egress.error.unsupported_protocol"
            activeXrayEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .runtimeConfiguration,
                category: .configurationRejected,
                extensionRequestReached: false
            )
            return
        }
        let persistentXrayModeIsRunning = runtimeOnlyDiagnosticModeIsRunning
            || dataPlaneDiagnosticModeIsRunning
        guard persistentXrayModeIsRunning else {
            activeXrayEgressProbeErrorKey = "diagnostics.active_xray_egress.error.not_running"
            activeXrayEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .preStartState,
                category: .runtimeBusy,
                extensionRequestReached: false
            )
            return
        }
        guard let xrayRemoteEgressProbeService else {
            activeXrayEgressProbeErrorKey = "diagnostics.xray_remote_egress.error.shared_container"
            activeXrayEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .runtimeConfiguration,
                category: .providerUnavailable,
                extensionRequestReached: false
            )
            return
        }

        isRunningActiveXrayEgressProbe = true

        activeXrayEgressProbeTask = Task { [weak self, xrayRemoteEgressProbeService] in
            do {
                let result = try await xrayRemoteEgressProbeService.probeActiveXrayEgress(profile: profile)
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.activeXrayEgressProbeGeneration == currentGeneration else { return }
                    self.activeXrayEgressProbeResult = result
                    self.activeXrayEgressProbeDiagnostic = result.diagnostic
                    self.activeXrayEgressProbeErrorKey = result.success ? nil : "diagnostics.xray_remote_egress.failed"
                    self.isRunningActiveXrayEgressProbe = false
                }
            } catch let failure as TunnelXrayRemoteEgressProbeFailure {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.activeXrayEgressProbeGeneration == currentGeneration else { return }
                    self.activeXrayEgressProbeErrorKey = "diagnostics.xray_remote_egress.failed"
                    self.activeXrayEgressProbeDiagnostic = failure.diagnostic
                    self.isRunningActiveXrayEgressProbe = false
                }
            } catch {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.activeXrayEgressProbeGeneration == currentGeneration else { return }
                    self.activeXrayEgressProbeErrorKey = "diagnostics.xray_remote_egress.failed"
                    self.activeXrayEgressProbeDiagnostic = TunnelXrayRemoteEgressProbeDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isRunningActiveXrayEgressProbe = false
                }
            }
        }
    }

    func runUDPControlProbe() {
        let currentGeneration = beginUDPControlProbeOperation()
        guard isRunningXrayRemoteEgressProbe == false,
              isRunningActiveXrayEgressProbe == false,
              isRunningLibXrayPingProbe == false,
              isRunningXrayLifecycleSmokeTest == false,
              isValidatingXrayConfiguration == false,
              isStartingRuntimeOnlyTunnel == false,
              isStoppingRuntimeOnlyTunnel == false,
              isStartingDataPlaneTunnel == false,
              isStoppingDataPlaneTunnel == false,
              isStartingLibXrayPingOnlyTunnel == false,
              isStoppingLibXrayPingOnlyTunnel == false else {
            udpControlProbeErrorKey = "diagnostics.udp_control.failed"
            udpControlProbeDiagnostic = TunnelUDPControlProbeDiagnostic(
                category: .unknown,
                extensionRequestReached: false
            )
            return
        }
        guard runtimeOnlyDiagnosticModeIsRunning else {
            udpControlProbeErrorKey = "diagnostics.udp_control.error.not_runtime_only"
            udpControlProbeDiagnostic = TunnelUDPControlProbeDiagnostic(
                category: .notRuntimeOnly,
                extensionRequestReached: false
            )
            return
        }
        guard let udpControlProbeService else {
            udpControlProbeErrorKey = "diagnostics.udp_control.error.provider_unavailable"
            udpControlProbeDiagnostic = TunnelUDPControlProbeDiagnostic(
                category: .providerUnavailable,
                extensionRequestReached: false
            )
            return
        }

        isRunningUDPControlProbe = true

        udpControlProbeTask = Task { [weak self, udpControlProbeService] in
            do {
                let result = try await udpControlProbeService.run()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.udpControlProbeGeneration == currentGeneration else { return }
                    self.udpControlProbeResult = result
                    self.udpControlProbeDiagnostic = result.diagnostic
                    self.udpControlProbeErrorKey = result.success ? nil : "diagnostics.udp_control.failed"
                    self.isRunningUDPControlProbe = false
                }
            } catch let failure as TunnelUDPControlProbeFailure {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.udpControlProbeGeneration == currentGeneration else { return }
                    self.udpControlProbeErrorKey = "diagnostics.udp_control.failed"
                    self.udpControlProbeDiagnostic = failure.diagnostic
                    self.isRunningUDPControlProbe = false
                }
            } catch {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.udpControlProbeGeneration == currentGeneration else { return }
                    self.udpControlProbeErrorKey = "diagnostics.udp_control.failed"
                    self.udpControlProbeDiagnostic = TunnelUDPControlProbeDiagnostic(
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isRunningUDPControlProbe = false
                }
            }
        }
    }

    func runLibXrayPingProbe(profile: VPNProfile?) {
        let currentGeneration = beginLibXrayPingProbeOperation()
        guard isRunningXrayRemoteEgressProbe == false,
              isRunningActiveXrayEgressProbe == false,
              isRunningUDPControlProbe == false,
              isRunningXrayLifecycleSmokeTest == false,
              isValidatingXrayConfiguration == false,
              isStartingRuntimeOnlyTunnel == false,
              isStoppingRuntimeOnlyTunnel == false,
              isStartingDataPlaneTunnel == false,
              isStoppingDataPlaneTunnel == false,
              isStartingLibXrayPingOnlyTunnel == false,
              isStoppingLibXrayPingOnlyTunnel == false else {
            libXrayPingProbeErrorKey = "diagnostics.libxray_ping.failed"
            libXrayPingProbeDiagnostic = TunnelLibXrayPingProbeDiagnostic(
                stage: .preStartState,
                category: .runtimeBusy,
                extensionRequestReached: false
            )
            return
        }
        guard let profile else {
            libXrayPingProbeErrorKey = "diagnostics.libxray_ping.error.no_profile"
            libXrayPingProbeDiagnostic = TunnelLibXrayPingProbeDiagnostic(
                stage: .runtimeConfiguration,
                category: .configurationRejected,
                extensionRequestReached: false
            )
            return
        }
        guard Self.isK3B4XrayBackedProtocol(profile.protocolType) else {
            libXrayPingProbeErrorKey = "diagnostics.libxray_ping.error.unsupported_protocol"
            libXrayPingProbeDiagnostic = TunnelLibXrayPingProbeDiagnostic(
                stage: .runtimeConfiguration,
                category: .configurationRejected,
                extensionRequestReached: false
            )
            return
        }
        guard libXrayPingOnlyDiagnosticModeIsRunning else {
            libXrayPingProbeErrorKey = "diagnostics.libxray_ping.error.not_ping_only"
            libXrayPingProbeDiagnostic = TunnelLibXrayPingProbeDiagnostic(
                stage: .preStartState,
                category: .runtimeBusy,
                extensionRequestReached: false
            )
            return
        }
        guard let libXrayPingProbeService else {
            libXrayPingProbeErrorKey = "diagnostics.libxray_ping.error.provider_unavailable"
            libXrayPingProbeDiagnostic = TunnelLibXrayPingProbeDiagnostic(
                stage: .runtimeConfiguration,
                category: .providerUnavailable,
                extensionRequestReached: false
            )
            return
        }

        isRunningLibXrayPingProbe = true

        libXrayPingProbeTask = Task { [weak self, libXrayPingProbeService] in
            do {
                let result = try await libXrayPingProbeService.run(profile: profile)
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.libXrayPingProbeGeneration == currentGeneration else { return }
                    self.libXrayPingProbeResult = result
                    self.libXrayPingProbeDiagnostic = result.diagnostic
                    self.libXrayPingProbeErrorKey = result.success ? nil : "diagnostics.libxray_ping.failed"
                    self.isRunningLibXrayPingProbe = false
                }
            } catch let failure as TunnelLibXrayPingProbeFailure {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.libXrayPingProbeGeneration == currentGeneration else { return }
                    self.libXrayPingProbeErrorKey = "diagnostics.libxray_ping.failed"
                    self.libXrayPingProbeDiagnostic = failure.diagnostic
                    self.isRunningLibXrayPingProbe = false
                }
            } catch {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.libXrayPingProbeGeneration == currentGeneration else { return }
                    self.libXrayPingProbeErrorKey = "diagnostics.libxray_ping.failed"
                    self.libXrayPingProbeDiagnostic = TunnelLibXrayPingProbeDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isRunningLibXrayPingProbe = false
                }
            }
        }
    }

    #if DEBUG
    func startRuntimeOnlyTunnel(profile: VPNProfile?) {
        let currentGeneration = beginRuntimeOnlyTunnelOperation()
        guard let profile else {
            runtimeOnlyTunnelErrorKey = "diagnostics.runtime_only.error.no_profile"
            runtimeOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .runtimeConfigurationInvalid,
                extensionRequestReached: false
            )
            return
        }
        guard Self.isK3B4XrayBackedProtocol(profile.protocolType) else {
            runtimeOnlyTunnelErrorKey = "diagnostics.runtime_only.error.unsupported_protocol"
            runtimeOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .unsupportedProfileForRuntimeSmoke,
                extensionRequestReached: false
            )
            return
        }
        guard let runtimeOnlyPacketTunnelService else {
            runtimeOnlyTunnelErrorKey = "diagnostics.runtime_only.error.shared_container"
            runtimeOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .runtimeConfigurationInvalid,
                extensionRequestReached: false
            )
            return
        }

        isStartingRuntimeOnlyTunnel = true

        runtimeOnlyTunnelTask = Task { [weak self, runtimeOnlyPacketTunnelService] in
            do {
                guard let self else { return }
                let reconciliation = await self.reconcileDiagnosticProviderStateNow()
                let disposition = self.persistentStartDisposition(after: reconciliation)
                await MainActor.run {
                    guard self.runtimeOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(reconciliation)
                }
                guard disposition == .allowed else {
                    await MainActor.run {
                        guard self.runtimeOnlyTunnelGeneration == currentGeneration else { return }
                        self.runtimeOnlyTunnelErrorKey = "diagnostics.runtime_only.failed"
                        self.runtimeOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                            stage: .preStartState,
                            category: disposition == .recoveryRequired ? .providerUnavailable : .runtimeAlreadyRunning,
                            extensionRequestReached: false
                        )
                        self.isStartingRuntimeOnlyTunnel = false
                    }
                    return
                }
                let result = try await runtimeOnlyPacketTunnelService.start(profile: profile)
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.runtimeOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.runtimeOnlyTunnelResult = result
                    self.runtimeOnlyTunnelDiagnostic = result.diagnostic
                    self.runtimeOnlyTunnelErrorKey = result.success ? nil : "diagnostics.runtime_only.failed"
                    self.isStartingRuntimeOnlyTunnel = false
                }
            } catch let failure as TunnelXrayLifecycleSmokeTestFailure {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.runtimeOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.runtimeOnlyTunnelErrorKey = "diagnostics.runtime_only.failed"
                    self.runtimeOnlyTunnelDiagnostic = failure.diagnostic
                    self.isStartingRuntimeOnlyTunnel = false
                }
            } catch {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.runtimeOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.runtimeOnlyTunnelErrorKey = "diagnostics.runtime_only.failed"
                    self.runtimeOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isStartingRuntimeOnlyTunnel = false
                }
            }
        }
    }

    func stopRuntimeOnlyTunnel() {
        let currentGeneration = beginRuntimeOnlyTunnelOperation()
        guard let runtimeOnlyPacketTunnelService else {
            runtimeOnlyTunnelErrorKey = "diagnostics.runtime_only.error.shared_container"
            runtimeOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .stopXray,
                category: .providerUnavailable,
                extensionRequestReached: false
            )
            return
        }

        isStoppingRuntimeOnlyTunnel = true

        runtimeOnlyTunnelTask = Task { [weak self, runtimeOnlyPacketTunnelService] in
            do {
                guard let self else { return }
                let result = try await runtimeOnlyPacketTunnelService.stop()
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.runtimeOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.runtimeOnlyTunnelResult = result
                    self.runtimeOnlyTunnelDiagnostic = result.diagnostic
                    self.runtimeOnlyTunnelErrorKey = result.success ? nil : "diagnostics.runtime_only.failed"
                    self.isStoppingRuntimeOnlyTunnel = false
                }
            } catch let failure as TunnelXrayLifecycleSmokeTestFailure {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.runtimeOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.runtimeOnlyTunnelErrorKey = "diagnostics.runtime_only.failed"
                    self.runtimeOnlyTunnelDiagnostic = failure.diagnostic
                    self.isStoppingRuntimeOnlyTunnel = false
                }
            } catch {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.runtimeOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.runtimeOnlyTunnelErrorKey = "diagnostics.runtime_only.failed"
                    self.runtimeOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isStoppingRuntimeOnlyTunnel = false
                }
            }
        }
    }

    func startDataPlaneTunnel(profile: VPNProfile?) {
        let currentGeneration = beginDataPlaneTunnelOperation()
        guard let profile else {
            dataPlaneTunnelErrorKey = "diagnostics.data_plane.error.no_profile"
            dataPlaneTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .runtimeConfigurationInvalid,
                extensionRequestReached: false
            )
            return
        }
        guard Self.isK3B4XrayBackedProtocol(profile.protocolType) else {
            dataPlaneTunnelErrorKey = "diagnostics.data_plane.error.unsupported_protocol"
            dataPlaneTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .unsupportedProfileForRuntimeSmoke,
                extensionRequestReached: false
            )
            return
        }
        guard let dataPlanePacketTunnelService else {
            dataPlaneTunnelErrorKey = "diagnostics.data_plane.error.shared_container"
            dataPlaneTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .dataPlane,
                category: .providerUnavailable,
                extensionRequestReached: false
            )
            return
        }

        isStartingDataPlaneTunnel = true

        dataPlaneTunnelTask = Task { [weak self, dataPlanePacketTunnelService, messenger] in
            do {
                guard let self else { return }
                let reconciliation = await self.reconcileDiagnosticProviderStateNow()
                let disposition = self.persistentStartDisposition(after: reconciliation)
                await MainActor.run {
                    guard self.dataPlaneTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(reconciliation)
                }
                guard disposition == .allowed else {
                    await MainActor.run {
                        guard self.dataPlaneTunnelGeneration == currentGeneration else { return }
                        self.dataPlaneTunnelErrorKey = "diagnostics.data_plane.failed"
                        self.dataPlaneTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                            stage: .preStartState,
                            category: disposition == .recoveryRequired ? .providerUnavailable : .runtimeAlreadyRunning,
                            extensionRequestReached: false
                        )
                        self.isStartingDataPlaneTunnel = false
                    }
                    return
                }
                let result = try await dataPlanePacketTunnelService.start(profile: profile)
                let state = await self.reconcileDiagnosticProviderStateNow()
                let runtime: TunnelRuntimeSnapshot?
                do {
                    runtime = try Self.runtime(from: try await messenger.send(TunnelMessageRequest(kind: .getRuntimeSnapshot)))
                } catch {
                    runtime = nil
                }
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.dataPlaneTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.dataPlaneTunnelResult = result
                    self.dataPlaneTunnelDiagnostic = result.diagnostic
                    self.dataPlaneTunnelErrorKey = result.success ? nil : "diagnostics.data_plane.failed"
                    if let runtime {
                        self.runtimeSnapshot = runtime
                    }
                    self.isStartingDataPlaneTunnel = false
                }
            } catch let failure as TunnelXrayLifecycleSmokeTestFailure {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.dataPlaneTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.dataPlaneTunnelErrorKey = "diagnostics.data_plane.failed"
                    self.dataPlaneTunnelDiagnostic = failure.diagnostic
                    self.isStartingDataPlaneTunnel = false
                }
            } catch {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.dataPlaneTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.dataPlaneTunnelErrorKey = "diagnostics.data_plane.failed"
                    self.dataPlaneTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isStartingDataPlaneTunnel = false
                }
            }
        }
    }

    func stopDataPlaneTunnel() {
        let currentGeneration = beginDataPlaneTunnelOperation()
        guard let dataPlanePacketTunnelService else {
            dataPlaneTunnelErrorKey = "diagnostics.data_plane.error.shared_container"
            dataPlaneTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .tun2SocksStop,
                category: .providerUnavailable,
                extensionRequestReached: false
            )
            return
        }

        isStoppingDataPlaneTunnel = true

        dataPlaneTunnelTask = Task { [weak self, dataPlanePacketTunnelService, messenger] in
            do {
                guard let self else { return }
                let result = try await dataPlanePacketTunnelService.stop()
                let state = await self.reconcileDiagnosticProviderStateNow()
                let runtime: TunnelRuntimeSnapshot?
                do {
                    runtime = try Self.runtime(from: try await messenger.send(TunnelMessageRequest(kind: .getRuntimeSnapshot)))
                } catch {
                    runtime = nil
                }
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.dataPlaneTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.dataPlaneTunnelResult = result
                    self.dataPlaneTunnelDiagnostic = result.diagnostic
                    self.dataPlaneTunnelErrorKey = result.success ? nil : "diagnostics.data_plane.failed"
                    if let runtime {
                        self.runtimeSnapshot = runtime
                    }
                    self.isStoppingDataPlaneTunnel = false
                }
            } catch let failure as TunnelXrayLifecycleSmokeTestFailure {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.dataPlaneTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.dataPlaneTunnelErrorKey = "diagnostics.data_plane.failed"
                    self.dataPlaneTunnelDiagnostic = failure.diagnostic
                    self.isStoppingDataPlaneTunnel = false
                }
            } catch {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.dataPlaneTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.dataPlaneTunnelErrorKey = "diagnostics.data_plane.failed"
                    self.dataPlaneTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isStoppingDataPlaneTunnel = false
                }
            }
        }
    }

    func startLibXrayPingOnlyTunnel(profile: VPNProfile?) {
        let currentGeneration = beginLibXrayPingOnlyTunnelOperation()
        guard let profile else {
            libXrayPingOnlyTunnelErrorKey = "diagnostics.libxray_ping_only.error.no_profile"
            libXrayPingOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .runtimeConfigurationInvalid,
                extensionRequestReached: false
            )
            return
        }
        guard Self.isK3B4XrayBackedProtocol(profile.protocolType) else {
            libXrayPingOnlyTunnelErrorKey = "diagnostics.libxray_ping_only.error.unsupported_protocol"
            libXrayPingOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .unsupportedProfileForRuntimeSmoke,
                extensionRequestReached: false
            )
            return
        }
        guard let libXrayPingOnlyPacketTunnelService else {
            libXrayPingOnlyTunnelErrorKey = "diagnostics.libxray_ping_only.error.shared_container"
            libXrayPingOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .runtimeConfiguration,
                category: .providerUnavailable,
                extensionRequestReached: false
            )
            return
        }

        isStartingLibXrayPingOnlyTunnel = true

        libXrayPingOnlyTunnelTask = Task { [weak self, libXrayPingOnlyPacketTunnelService] in
            do {
                guard let self else { return }
                let reconciliation = await self.reconcileDiagnosticProviderStateNow()
                let disposition = self.persistentStartDisposition(after: reconciliation)
                await MainActor.run {
                    guard self.libXrayPingOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(reconciliation)
                }
                guard disposition == .allowed else {
                    await MainActor.run {
                        guard self.libXrayPingOnlyTunnelGeneration == currentGeneration else { return }
                        self.libXrayPingOnlyTunnelErrorKey = "diagnostics.libxray_ping_only.failed"
                        self.libXrayPingOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                            stage: .preStartState,
                            category: disposition == .recoveryRequired ? .providerUnavailable : .runtimeAlreadyRunning,
                            extensionRequestReached: false
                        )
                        self.isStartingLibXrayPingOnlyTunnel = false
                    }
                    return
                }
                let result = try await libXrayPingOnlyPacketTunnelService.start(profile: profile)
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.libXrayPingOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.libXrayPingOnlyTunnelResult = result
                    self.libXrayPingOnlyTunnelDiagnostic = result.diagnostic
                    self.libXrayPingOnlyTunnelErrorKey = result.success ? nil : "diagnostics.libxray_ping_only.failed"
                    self.isStartingLibXrayPingOnlyTunnel = false
                }
            } catch let failure as TunnelXrayLifecycleSmokeTestFailure {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.libXrayPingOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.libXrayPingOnlyTunnelErrorKey = "diagnostics.libxray_ping_only.failed"
                    self.libXrayPingOnlyTunnelDiagnostic = failure.diagnostic
                    self.isStartingLibXrayPingOnlyTunnel = false
                }
            } catch {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.libXrayPingOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.libXrayPingOnlyTunnelErrorKey = "diagnostics.libxray_ping_only.failed"
                    self.libXrayPingOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isStartingLibXrayPingOnlyTunnel = false
                }
            }
        }
    }

    func stopLibXrayPingOnlyTunnel() {
        let currentGeneration = beginLibXrayPingOnlyTunnelOperation()
        guard let libXrayPingOnlyPacketTunnelService else {
            libXrayPingOnlyTunnelErrorKey = "diagnostics.libxray_ping_only.error.shared_container"
            libXrayPingOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .stoppedState,
                category: .providerUnavailable,
                extensionRequestReached: false
            )
            return
        }

        isStoppingLibXrayPingOnlyTunnel = true

        libXrayPingOnlyTunnelTask = Task { [weak self, libXrayPingOnlyPacketTunnelService] in
            do {
                guard let self else { return }
                let result = try await libXrayPingOnlyPacketTunnelService.stop()
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.libXrayPingOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.libXrayPingOnlyTunnelResult = result
                    self.libXrayPingOnlyTunnelDiagnostic = result.diagnostic
                    self.libXrayPingOnlyTunnelErrorKey = result.success ? nil : "diagnostics.libxray_ping_only.failed"
                    self.isStoppingLibXrayPingOnlyTunnel = false
                }
            } catch let failure as TunnelXrayLifecycleSmokeTestFailure {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.libXrayPingOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.libXrayPingOnlyTunnelErrorKey = "diagnostics.libxray_ping_only.failed"
                    self.libXrayPingOnlyTunnelDiagnostic = failure.diagnostic
                    self.isStoppingLibXrayPingOnlyTunnel = false
                }
            } catch {
                guard let self else { return }
                let state = await self.reconcileDiagnosticProviderStateNow()
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard self.libXrayPingOnlyTunnelGeneration == currentGeneration else { return }
                    self.applyDiagnosticProviderState(state)
                    self.libXrayPingOnlyTunnelErrorKey = "diagnostics.libxray_ping_only.failed"
                    self.libXrayPingOnlyTunnelDiagnostic = TunnelXrayLifecycleSmokeTestDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isStoppingLibXrayPingOnlyTunnel = false
                }
            }
        }
    }
    #endif

    @discardableResult
    private func beginRuntimeValidationOperation() -> Int {
        runtimeValidationGeneration += 1
        runtimeValidationTask?.cancel()
        runtimeValidationResult = nil
        runtimeValidationErrorKey = nil
        runtimeValidationDiagnostic = nil
        isValidatingRuntimeConfiguration = false
        return runtimeValidationGeneration
    }

    @discardableResult
    private func beginXrayValidationOperation() -> Int {
        xrayValidationGeneration += 1
        xrayValidationTask?.cancel()
        xrayValidationResult = nil
        xrayValidationErrorKey = nil
        xrayValidationDiagnostic = nil
        isValidatingXrayConfiguration = false
        return xrayValidationGeneration
    }

    @discardableResult
    private func beginXrayLifecycleSmokeTestOperation() -> Int {
        xrayLifecycleSmokeTestGeneration += 1
        xrayLifecycleSmokeTestTask?.cancel()
        xrayLifecycleSmokeTestResult = nil
        xrayLifecycleSmokeTestErrorKey = nil
        xrayLifecycleSmokeTestDiagnostic = nil
        isRunningXrayLifecycleSmokeTest = false
        return xrayLifecycleSmokeTestGeneration
    }

    @discardableResult
    private func beginXrayRemoteEgressProbeOperation() -> Int {
        xrayRemoteEgressProbeGeneration += 1
        xrayRemoteEgressProbeTask?.cancel()
        xrayRemoteEgressProbeResult = nil
        xrayRemoteEgressProbeErrorKey = nil
        xrayRemoteEgressProbeDiagnostic = nil
        isRunningXrayRemoteEgressProbe = false
        return xrayRemoteEgressProbeGeneration
    }

    @discardableResult
    private func beginActiveXrayEgressProbeOperation() -> Int {
        activeXrayEgressProbeGeneration += 1
        activeXrayEgressProbeTask?.cancel()
        activeXrayEgressProbeResult = nil
        activeXrayEgressProbeErrorKey = nil
        activeXrayEgressProbeDiagnostic = nil
        isRunningActiveXrayEgressProbe = false
        return activeXrayEgressProbeGeneration
    }

    @discardableResult
    private func beginUDPControlProbeOperation() -> Int {
        udpControlProbeGeneration += 1
        udpControlProbeTask?.cancel()
        udpControlProbeResult = nil
        udpControlProbeErrorKey = nil
        udpControlProbeDiagnostic = nil
        isRunningUDPControlProbe = false
        return udpControlProbeGeneration
    }

    @discardableResult
    private func beginLibXrayPingProbeOperation() -> Int {
        libXrayPingProbeGeneration += 1
        libXrayPingProbeTask?.cancel()
        libXrayPingProbeResult = nil
        libXrayPingProbeErrorKey = nil
        libXrayPingProbeDiagnostic = nil
        isRunningLibXrayPingProbe = false
        return libXrayPingProbeGeneration
    }

    #if DEBUG
    @discardableResult
    private func beginRuntimeOnlyTunnelOperation() -> Int {
        runtimeOnlyTunnelGeneration += 1
        runtimeOnlyTunnelTask?.cancel()
        activeXrayEgressProbeTask?.cancel()
        udpControlProbeTask?.cancel()
        libXrayPingProbeTask?.cancel()
        libXrayPingOnlyTunnelTask?.cancel()
        runtimeOnlyTunnelResult = nil
        runtimeOnlyTunnelErrorKey = nil
        runtimeOnlyTunnelDiagnostic = nil
        activeXrayEgressProbeResult = nil
        activeXrayEgressProbeErrorKey = nil
        activeXrayEgressProbeDiagnostic = nil
        udpControlProbeResult = nil
        udpControlProbeErrorKey = nil
        udpControlProbeDiagnostic = nil
        libXrayPingProbeResult = nil
        libXrayPingProbeErrorKey = nil
        libXrayPingProbeDiagnostic = nil
        libXrayPingOnlyTunnelResult = nil
        libXrayPingOnlyTunnelErrorKey = nil
        libXrayPingOnlyTunnelDiagnostic = nil
        isStartingRuntimeOnlyTunnel = false
        isStoppingRuntimeOnlyTunnel = false
        isRunningActiveXrayEgressProbe = false
        isRunningUDPControlProbe = false
        isRunningLibXrayPingProbe = false
        isStartingLibXrayPingOnlyTunnel = false
        isStoppingLibXrayPingOnlyTunnel = false
        return runtimeOnlyTunnelGeneration
    }

    @discardableResult
    private func beginDataPlaneTunnelOperation() -> Int {
        dataPlaneTunnelGeneration += 1
        dataPlaneTunnelTask?.cancel()
        activeXrayEgressProbeTask?.cancel()
        udpControlProbeTask?.cancel()
        libXrayPingProbeTask?.cancel()
        libXrayPingOnlyTunnelTask?.cancel()
        dataPlaneTunnelResult = nil
        dataPlaneTunnelErrorKey = nil
        dataPlaneTunnelDiagnostic = nil
        activeXrayEgressProbeResult = nil
        activeXrayEgressProbeErrorKey = nil
        activeXrayEgressProbeDiagnostic = nil
        udpControlProbeResult = nil
        udpControlProbeErrorKey = nil
        udpControlProbeDiagnostic = nil
        libXrayPingProbeResult = nil
        libXrayPingProbeErrorKey = nil
        libXrayPingProbeDiagnostic = nil
        libXrayPingOnlyTunnelResult = nil
        libXrayPingOnlyTunnelErrorKey = nil
        libXrayPingOnlyTunnelDiagnostic = nil
        isStartingDataPlaneTunnel = false
        isStoppingDataPlaneTunnel = false
        isRunningActiveXrayEgressProbe = false
        isRunningUDPControlProbe = false
        isRunningLibXrayPingProbe = false
        isStartingLibXrayPingOnlyTunnel = false
        isStoppingLibXrayPingOnlyTunnel = false
        return dataPlaneTunnelGeneration
    }

    @discardableResult
    private func beginLibXrayPingOnlyTunnelOperation() -> Int {
        libXrayPingOnlyTunnelGeneration += 1
        libXrayPingOnlyTunnelTask?.cancel()
        libXrayPingProbeTask?.cancel()
        activeXrayEgressProbeTask?.cancel()
        udpControlProbeTask?.cancel()
        runtimeOnlyTunnelTask?.cancel()
        dataPlaneTunnelTask?.cancel()
        libXrayPingOnlyTunnelResult = nil
        libXrayPingOnlyTunnelErrorKey = nil
        libXrayPingOnlyTunnelDiagnostic = nil
        libXrayPingProbeResult = nil
        libXrayPingProbeErrorKey = nil
        libXrayPingProbeDiagnostic = nil
        activeXrayEgressProbeResult = nil
        activeXrayEgressProbeErrorKey = nil
        activeXrayEgressProbeDiagnostic = nil
        udpControlProbeResult = nil
        udpControlProbeErrorKey = nil
        udpControlProbeDiagnostic = nil
        runtimeOnlyTunnelResult = nil
        runtimeOnlyTunnelErrorKey = nil
        runtimeOnlyTunnelDiagnostic = nil
        dataPlaneTunnelResult = nil
        dataPlaneTunnelErrorKey = nil
        dataPlaneTunnelDiagnostic = nil
        isStartingLibXrayPingOnlyTunnel = false
        isStoppingLibXrayPingOnlyTunnel = false
        isRunningLibXrayPingProbe = false
        isRunningActiveXrayEgressProbe = false
        isRunningUDPControlProbe = false
        isStartingRuntimeOnlyTunnel = false
        isStoppingRuntimeOnlyTunnel = false
        isStartingDataPlaneTunnel = false
        isStoppingDataPlaneTunnel = false
        return libXrayPingOnlyTunnelGeneration
    }
    #endif

    private static func isK3B4XrayBackedProtocol(_ protocolType: VPNProtocol) -> Bool {
        switch protocolType {
        case .vless, .vmess, .trojan, .shadowsocks, .hysteria2:
            return true
        case .wireGuard, .amneziaWG, .ikev2, .tuic:
            return false
        }
    }

    func validateRuntimeConfiguration(profile: VPNProfile?) {
        let currentGeneration = beginRuntimeValidationOperation()
        guard let profile else {
            runtimeValidationErrorKey = "diagnostics.runtime_validation.error.no_profile"
            runtimeValidationDiagnostic = TunnelRuntimeConfigurationValidationDiagnostic(
                stage: .sharedRecord,
                category: .profileRecordNotFound,
                extensionRequestReached: false
            )
            return
        }
        guard Self.isK3B4XrayBackedProtocol(profile.protocolType) else {
            runtimeValidationErrorKey = "diagnostics.runtime_validation.error.unsupported_protocol"
            runtimeValidationDiagnostic = TunnelRuntimeConfigurationValidationDiagnostic(
                stage: .sharedRecord,
                category: .unsupportedProtocol,
                extensionRequestReached: false
            )
            return
        }
        guard let runtimeValidationService else {
            runtimeValidationErrorKey = "diagnostics.runtime_validation.error.shared_container"
            runtimeValidationDiagnostic = TunnelRuntimeConfigurationValidationDiagnostic(
                stage: .sharedRecord,
                category: .sharedContainerUnavailable,
                extensionRequestReached: false
            )
            return
        }

        isValidatingRuntimeConfiguration = true

        runtimeValidationTask = Task { [weak self, runtimeValidationService] in
            do {
                let result = try await runtimeValidationService.validate(profile: profile)
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.runtimeValidationGeneration == currentGeneration else { return }
                    self.runtimeValidationResult = result
                    self.runtimeValidationDiagnostic = result.diagnostic
                    self.runtimeValidationErrorKey = result.success ? nil : "diagnostics.runtime_validation.failed"
                    self.isValidatingRuntimeConfiguration = false
                }
            } catch let failure as TunnelRuntimeConfigurationValidationFailure {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.runtimeValidationGeneration == currentGeneration else { return }
                    self.runtimeValidationErrorKey = "diagnostics.runtime_validation.failed"
                    self.runtimeValidationDiagnostic = failure.diagnostic
                    self.isValidatingRuntimeConfiguration = false
                }
            } catch let error as RuntimeConfigurationError {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.runtimeValidationGeneration == currentGeneration else { return }
                    self.runtimeValidationErrorKey = "diagnostics.runtime_validation.failed"
                    self.runtimeValidationDiagnostic = TunnelRuntimeConfigurationValidationDiagnostic(
                        stage: Self.runtimeValidationStage(for: error),
                        category: TunnelRuntimeConfigurationValidationCategory(rawValue: error.rawValue) ?? .unknown,
                        extensionRequestReached: false
                    )
                    self.isValidatingRuntimeConfiguration = false
                }
            } catch {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    guard let self, self.runtimeValidationGeneration == currentGeneration else { return }
                    self.runtimeValidationErrorKey = "diagnostics.runtime_validation.failed"
                    self.runtimeValidationDiagnostic = TunnelRuntimeConfigurationValidationDiagnostic(
                        stage: .unknown,
                        category: .unknown,
                        extensionRequestReached: false
                    )
                    self.isValidatingRuntimeConfiguration = false
                }
            }
        }
    }

    private static func runtimeValidationStage(for error: RuntimeConfigurationError) -> TunnelRuntimeConfigurationValidationStage {
        switch error {
        case .missingProviderConfiguration, .malformedProviderConfiguration,
             .providerConfigurationUnknownKey, .providerConfigurationMissingSchemaVersion,
             .providerConfigurationWrongSchemaVersionType, .providerConfigurationUnsupportedSchemaVersion,
             .providerConfigurationMissingProfileID, .providerConfigurationWrongProfileIDType,
             .providerConfigurationMalformedProfileID, .providerConfigurationMissingRecordRevision,
             .providerConfigurationWrongRecordRevisionType, .providerConfigurationInvalidRecordRevision,
             .providerConfigurationPersistedMismatch, .providerConfigurationContractMismatch,
             .providerConfigurationStaleSession, .unsupportedProviderSchema, .missingProfileID,
             .invalidProfileID, .missingRevision, .invalidRevision:
            .providerConfiguration
        case .profileRecordNotFound, .profileRecordTooLarge, .profileRecordMalformed, .profileRecordCountExceeded,
             .profileSchemaMismatch, .profileIdentityMismatch, .profileRevisionMismatch,
             .profileDisabled, .profileIncomplete, .unsupportedProtocol, .invalidEndpoint,
             .unsupportedTransport, .invalidTransportConfiguration, .invalidXHTTPConfiguration,
             .invalidXHTTPMode, .invalidXHTTPPath, .invalidXHTTPHost, .invalidSecurityConfiguration,
             .sharedContainerUnavailable, .writeFailed, .deleteFailed:
            .sharedRecord
        case .missingCredentialReference, .malformedCredentialReference:
            .credentialReference
        case .credentialUnavailable, .credentialMalformed, .sharedKeychainConfigurationInvalid:
            .credential
        }
    }

    private static func xrayValidationCategory(for error: RuntimeConfigurationError) -> TunnelXrayConfigurationValidationCategory {
        switch error {
        case .profileIdentityMismatch:
            .profileIdentityMismatch
        case .profileRevisionMismatch:
            .profileRevisionMismatch
        case .unsupportedProtocol:
            .unsupportedProtocol
        case .unsupportedTransport:
            .unsupportedTransport
        case .invalidEndpoint:
            .invalidEndpoint
        case .invalidXHTTPConfiguration:
            .invalidXHTTPConfiguration
        case .invalidXHTTPMode:
            .invalidXHTTPMode
        case .invalidXHTTPPath:
            .invalidXHTTPPath
        case .invalidXHTTPHost:
            .invalidXHTTPHost
        case .invalidSecurityConfiguration:
            .invalidRealityConfiguration
        case .credentialMalformed:
            .invalidCredential
        case .providerConfigurationStaleSession:
            .providerConfigurationStaleSession
        default:
            .runtimeConfigurationInvalid
        }
    }

    private static func xrayLifecycleStage(for error: RuntimeConfigurationError) -> TunnelXrayLifecycleSmokeTestStage {
        switch runtimeValidationStage(for: error) {
        case .providerConfiguration:
            .providerConfiguration
        case .sharedRecord, .credentialReference, .credential:
            .runtimeConfiguration
        case .responseValidation:
            .responseValidation
        case .unknown:
            .unknown
        }
    }

    private static func xrayLifecycleCategory(for error: RuntimeConfigurationError) -> TunnelXrayLifecycleSmokeTestCategory {
        switch error {
        case .providerConfigurationStaleSession:
            .providerConfigurationStaleSession
        case .profileIdentityMismatch:
            .profileIdentityMismatch
        case .profileRevisionMismatch:
            .profileRevisionMismatch
        case .unsupportedProtocol, .unsupportedTransport:
            .unsupportedProfileForRuntimeSmoke
        default:
            .runtimeConfigurationInvalid
        }
    }

    private static func diagnosticCategory(for error: TunnelMessageErrorCode) -> TunnelKeychainSentinelDiagnosticCategory {
        switch error {
        case .malformedRequest:
            .malformedRequest
        case .schemaMismatch:
            .schemaMismatch
        case .providerUnavailable:
            .providerUnavailable
        case .providerResponseMissing:
            .providerResponseMissing
        case .timeout:
            .providerTimeout
        case .requestIDMismatch:
            .requestIDMismatch
        case .invalidResponse:
            .invalidResponse
        case .keychainUnavailable:
            .keychainUnavailable
        case .unsupportedRequest,
             .providerStatusNotConnected,
             .payloadTooLarge,
             .unknown:
            .unknown
        }
    }

    private static func makeDefaultCoreUpdater() -> TunnelTelemetryCoreUpdater? {
        do {
            return TunnelTelemetryCoreUpdater(coreService: try PortableCoreService(feature: .disabled))
        } catch {
            return nil
        }
    }

    private static func readFallback(_ store: TunnelTelemetrySnapshotStore?) async -> TunnelTelemetrySnapshotRead? {
        guard let store else {
            return nil
        }

        return try? await store.read()
    }

    private static func readLatestStartupAttempt(
        _ store: TunnelStartupDiagnosticsStore?
    ) async -> TunnelDiagnosticAttemptSnapshot? {
        guard let store else { return nil }
        return try? await store.latestAttempt()
    }

    private static func capabilities(from response: TunnelMessageResponse) throws -> TunnelCapabilitySnapshot {
        guard case .capabilities(let snapshot) = response.payload else {
            throw TunnelMessageErrorCode.invalidResponse
        }
        return snapshot
    }

    private static func runtime(from response: TunnelMessageResponse) throws -> TunnelRuntimeSnapshot {
        guard case .runtime(let snapshot) = response.payload else {
            throw TunnelMessageErrorCode.invalidResponse
        }
        return snapshot
    }

    private static func health(from response: TunnelMessageResponse) throws -> TunnelHealthSnapshot {
        guard case .health(let snapshot) = response.payload else {
            throw TunnelMessageErrorCode.invalidResponse
        }
        return snapshot
    }

    private static func events(from response: TunnelMessageResponse) throws -> [TunnelEventSnapshot] {
        guard case .events(let snapshots) = response.payload else {
            throw TunnelMessageErrorCode.invalidResponse
        }
        return snapshots
    }
}
