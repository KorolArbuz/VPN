//
//  NetworkExtensionNativeVPNConnectionManager.swift
//  VPN
//
//  Production routing for WireGuard/AmneziaWG. The main application publishes
//  a secret-free runtime record and asks Network Extension to launch the
//  PacketTunnelExtension; it never imports or links WireGuardKit.
//

import Foundation
import Dispatch
import NetworkExtension
import OSLog

nonisolated enum NativeTunnelProviderFailure: Int, CaseIterable, Equatable, Sendable {
    case sharedContainerUnavailable = 1
    case providerConfigurationInvalid
    case recordUnavailable
    case recordMalformed
    case schemaMismatch
    case revisionMismatch
    case modeMismatch
    case profileDisabled
    case credentialUnavailable
    case configurationInvalid
    case alreadyRunning
    case adapterStartFailed
    case cancelled
    case cannotLocateTunnelFileDescriptor
    case adapterInvalidState
    case endpointDNSResolutionFailed
    case networkSettingsRejected
    case backendStartFailed
    case startupCompletionTimeout
    case adapterStartTimeout
    case nativeBackendControllerUnavailable
    case runtimeLoaderUnavailable
    case providerStartupStalled
}

nonisolated struct NativeTunnelDisconnectErrorDescriptor: Equatable, Sendable {
    let domain: String
    let code: Int
    let diagnosticError: TunnelDiagnosticError?
    let neConnectionErrorCase: String?

    init(domain: String, code: Int, diagnosticError: TunnelDiagnosticError? = nil) {
        self.domain = domain
        self.code = code
        self.diagnosticError = diagnosticError
        self.neConnectionErrorCase = NativeTunnelNEVPNConnectionErrorDecoder.caseName(
            domain: domain,
            code: code
        )
    }
}

nonisolated enum NativeTunnelNEVPNConnectionErrorDecoder {
    static func caseName(domain: String, code: Int) -> String? {
        guard domain == NEVPNConnectionErrorDomain,
              let error = NEVPNConnectionError(rawValue: code) else {
            return nil
        }
        if error == .pluginFailed {
            return "pluginFailed"
        }
        return "rawValue.\(error.rawValue)"
    }

    static func terminationEvidence(domain: String, code: Int) -> String? {
        guard caseName(domain: domain, code: code) == "pluginFailed" else {
            return nil
        }
        return "NEVPNConnectionError.pluginFailed"
    }
}

nonisolated enum NativeTunnelDisconnectErrorMapper {
    static let providerErrorDomain = "su.24kvn.packet-tunnel.native-wireguard"

    static func connectionError(
        for descriptor: NativeTunnelDisconnectErrorDescriptor?,
        fallback: NativeTunnelConnectionError
    ) -> NativeTunnelConnectionError {
        guard let descriptor,
              descriptor.domain == providerErrorDomain,
              let failure = NativeTunnelProviderFailure(rawValue: descriptor.code) else {
            return fallback
        }
        return .providerFailure(failure)
    }
}

nonisolated enum NativeTunnelPersistedFailureMapper {
    static func connectionError(
        for category: NativeTunnelFailureCategory?
    ) -> NativeTunnelConnectionError? {
        guard let category else { return nil }
        let providerFailure: NativeTunnelProviderFailure
        switch category {
        case .invalidProviderConfiguration:
            providerFailure = .providerConfigurationInvalid
        case .runtimeProfileUnavailable:
            providerFailure = .recordUnavailable
        case .runtimeProfileMalformed:
            providerFailure = .recordMalformed
        case .runtimeSchemaMismatch:
            providerFailure = .schemaMismatch
        case .runtimeRevisionMismatch:
            providerFailure = .revisionMismatch
        case .runtimeModeMismatch:
            providerFailure = .modeMismatch
        case .profileDisabled:
            providerFailure = .profileDisabled
        case .sharedCredentialUnavailable:
            providerFailure = .credentialUnavailable
        case .awgConfigurationInvalid:
            providerFailure = .configurationInvalid
        case .dnsResolutionFailed:
            providerFailure = .endpointDNSResolutionFailed
        case .tunnelFileDescriptorUnavailable:
            providerFailure = .cannotLocateTunnelFileDescriptor
        case .networkSettingsRejected:
            providerFailure = .networkSettingsRejected
        case .nativeBackendStartupFailed:
            providerFailure = .backendStartFailed
        case .adapterInvalidState:
            providerFailure = .adapterInvalidState
        case .providerActivationFailure:
            return .connectionFailed
        case .providerStartTimeout:
            providerFailure = .startupCompletionTimeout
        case .adapterStartTimeout:
            providerFailure = .adapterStartTimeout
        case .cancelled:
            providerFailure = .cancelled
        case .nativeBackendControllerUnavailable:
            providerFailure = .nativeBackendControllerUnavailable
        case .runtimeLoaderUnavailable:
            providerFailure = .runtimeLoaderUnavailable
        case .providerStartupStalled:
            providerFailure = .providerStartupStalled
        case .providerWasNeverLaunched,
             .providerStartTunnelNotEntered,
             .providerExitedDuringStartup,
             .providerStartupAbortedBeforeRuntimeLoad,
             .activationContextInvalid,
             .startupTaskNeverEntered,
             .appConnectionObservationTimeout,
             .unknownProviderStartupFailure,
             .unknown:
            return nil
        }
        return .providerFailure(providerFailure)
    }
}

nonisolated struct NativeTunnelDisconnectFailureResolver: Sendable {
    private let fetchDescriptor: @Sendable () async -> NativeTunnelDisconnectErrorDescriptor?

    init(
        fetchDescriptor: @escaping @Sendable () async -> NativeTunnelDisconnectErrorDescriptor?
    ) {
        self.fetchDescriptor = fetchDescriptor
    }

    func connectionError(
        fallback: NativeTunnelConnectionError
    ) async -> NativeTunnelConnectionError {
        NativeTunnelDisconnectErrorMapper.connectionError(
            for: await fetchDescriptor(),
            fallback: fallback
        )
    }
}

nonisolated enum NativeTunnelConnectionError: LocalizedError, Equatable, Sendable {
    case runtimeStoreUnavailable
    case unsupportedProtocol
    case profileNotReady(String)
    case managerUnavailable
    case multipleManagers
    case providerConfigurationMismatch
    case invalidSession
    case connectionFailed
    case connectionTimedOut
    case providerFailure(NativeTunnelProviderFailure)

    var errorDescription: String? {
        switch self {
        case .runtimeStoreUnavailable:
            "The shared native tunnel runtime store is unavailable."
        case .unsupportedProtocol:
            "Only WireGuard and AmneziaWG use the native tunnel manager."
        case .profileNotReady(let reason):
            reason
        case .managerUnavailable:
            "The packet tunnel manager is unavailable."
        case .multipleManagers:
            "More than one packet tunnel manager matches this application."
        case .providerConfigurationMismatch:
            "The persisted packet tunnel configuration does not match the selected profile."
        case .invalidSession:
            "The packet tunnel session is unavailable."
        case .connectionFailed:
            "The native packet tunnel failed to connect."
        case .connectionTimedOut:
            "The native packet tunnel did not reach the requested state in time."
        case .providerFailure(let failure):
            switch failure {
            case .sharedContainerUnavailable, .recordUnavailable:
                "Native runtime record could not be loaded."
            case .providerConfigurationInvalid:
                "The native tunnel provider configuration is invalid."
            case .recordMalformed:
                "The native runtime record is malformed."
            case .schemaMismatch:
                "The native runtime record uses an unsupported schema."
            case .revisionMismatch:
                "The native runtime record revision does not match the selected profile."
            case .modeMismatch:
                "The native tunnel protocol does not match the selected profile."
            case .profileDisabled:
                "The selected native tunnel profile is disabled."
            case .credentialUnavailable:
                "Secure WireGuard credential is unavailable."
            case .configurationInvalid:
                "The native WireGuard configuration is invalid."
            case .alreadyRunning, .adapterInvalidState:
                "The native WireGuard adapter is in an invalid state."
            case .adapterStartFailed:
                "The native WireGuard adapter could not start."
            case .cancelled:
                "Native tunnel startup was cancelled."
            case .cannotLocateTunnelFileDescriptor:
                "The native WireGuard tunnel interface is unavailable."
            case .endpointDNSResolutionFailed:
                "WireGuard endpoint DNS resolution failed."
            case .networkSettingsRejected:
                "iOS rejected tunnel network settings."
            case .backendStartFailed:
                "WireGuard native backend failed to start."
            case .startupCompletionTimeout:
                "The packet tunnel provider did not complete native startup in time."
            case .adapterStartTimeout:
                "The native WireGuard adapter did not complete startup in time."
            case .nativeBackendControllerUnavailable:
                "The native WireGuard controller could not be constructed."
            case .runtimeLoaderUnavailable:
                "The native runtime configuration loader is unavailable."
            case .providerStartupStalled:
                "The packet tunnel provider stalled during native startup."
            }
        }
    }

    var diagnosticCaseName: String {
        switch self {
        case .runtimeStoreUnavailable:
            "runtimeStoreUnavailable"
        case .unsupportedProtocol:
            "unsupportedProtocol"
        case .profileNotReady:
            "profileNotReady"
        case .managerUnavailable:
            "managerUnavailable"
        case .multipleManagers:
            "multipleManagers"
        case .providerConfigurationMismatch:
            "providerConfigurationMismatch"
        case .invalidSession:
            "invalidSession"
        case .connectionFailed:
            "connectionFailed"
        case .connectionTimedOut:
            "connectionTimedOut"
        case .providerFailure(let failure):
            "providerFailure.\(String(describing: failure))"
        }
    }
}

nonisolated enum NativeTunnelStartupFailureClassifier {
    static func category(
        for error: any Error,
        events: [TunnelDiagnosticEvent]
    ) -> NativeTunnelFailureCategory {
        if let explicit = events.reversed().compactMap(\.failureCategory).first,
           explicit != .providerActivationFailure,
           explicit != .unknown {
            return explicit
        }
        if (error as? NativeTunnelConnectionError) == .connectionTimedOut {
            return .appConnectionObservationTimeout
        }

        let providerStages = events.filter { $0.source == .provider }.map(\.stage)
        let providerStageSet = Set(providerStages)
        guard providerStageSet.contains(.providerProcessEntered) else {
            return .providerWasNeverLaunched
        }
        guard providerStageSet.contains(.providerStartTunnelEntered) else {
            return .providerStartTunnelNotEntered
        }
        if providerStageSet.contains(.providerStartupWatchdogFired) {
            return .providerStartupStalled
        }
        if providerStageSet.contains(.startupTaskCreated),
           providerStageSet.contains(.startupTaskEntered) == false {
            return .startupTaskNeverEntered
        }
        if providerStageSet.contains(.runtimeLoaderResolutionStarted),
           providerStageSet.contains(.runtimeLoaderResolved) == false {
            return .runtimeLoaderUnavailable
        }
        if providerStageSet.contains(.nativeBackendControllerResolutionStarted),
           providerStageSet.contains(.nativeBackendControllerResolved) == false {
            // A missing return from the nonthrowing controller factory does not
            // prove that the dependency was unavailable. It may also indicate
            // a synchronous stall or process-level termination at that boundary.
            return .providerStartupAbortedBeforeRuntimeLoad
        }
        if providerStageSet.contains(.runtimeProfileLoadStarted) == false {
            return .providerStartupAbortedBeforeRuntimeLoad
        }
        return .providerExitedDuringStartup
    }
}

nonisolated struct NativeTunnelLaunchContract: Equatable, Sendable {
    let providerConfiguration: RuntimeProviderConfiguration
    let mode: NativeWireGuardMode

    init(record: NativeWireGuardProfileRecord) throws {
        providerConfiguration = try RuntimeProviderConfiguration(
            profileID: record.profileID,
            sharedRecordRevision: record.recordRevision
        )
        mode = record.mode
    }
}

nonisolated protocol NativeTunnelSystemManaging: Sendable {
    func currentState() async -> VPNConnectionState
    func stateUpdates() async -> AsyncStream<VPNConnectionState>
    func configureAndStart(
        record: NativeWireGuardProfileRecord,
        displayName: String,
        attemptID: UUID
    ) async throws
    func stop() async
}

private actor NativeTunnelConnectionStateRelay {
    private var state: VPNConnectionState = .disconnected
    private var latestSequence: UInt64 = 0
    private var continuations: [UUID: AsyncStream<VPNConnectionState>.Continuation] = [:]

    func currentState() -> VPNConnectionState {
        state
    }

    func updates() -> AsyncStream<VPNConnectionState> {
        let id = UUID()
        return AsyncStream { continuation in
            continuations[id] = continuation
            continuation.onTermination = { _ in
                Task { await self.removeContinuation(id: id) }
            }
        }
    }

    func publish(_ newState: VPNConnectionState, sequence: UInt64) {
        guard sequence >= latestSequence else { return }
        latestSequence = sequence
        guard state != newState else { return }
        state = newState
        continuations.values.forEach { $0.yield(newState) }
    }

    private func removeContinuation(id: UUID) {
        continuations[id] = nil
    }
}

nonisolated final class NetworkExtensionNativeTunnelSystemManager: NativeTunnelSystemManaging, @unchecked Sendable {
    private static let modeOptionKey = "kvn.native.mode"
    private static let attemptIDOptionKey = "kvn.native.attemptID"

    private let providerBundleIdentifier: String
    private let connectionTimeout: Duration
    private let stateRelay = NativeTunnelConnectionStateRelay()
    private let lock = NSLock()
    private var activeManager: NetworkExtensionNativeTunnelManager?
    private var stateSequence: UInt64 = 0

    init(
        providerBundleIdentifier: String = PacketTunnelProviderRouting.wireGuardBundleIdentifier,
        connectionTimeout: Duration = .seconds(30)
    ) {
        self.providerBundleIdentifier = providerBundleIdentifier
        self.connectionTimeout = connectionTimeout
    }

    func currentState() async -> VPNConnectionState {
        await stateRelay.currentState()
    }

    func stateUpdates() async -> AsyncStream<VPNConnectionState> {
        await stateRelay.updates()
    }

    func configureAndStart(
        record: NativeWireGuardProfileRecord,
        displayName: String,
        attemptID: UUID
    ) async throws {
        await NativeTunnelTrace.event(
            .managerLoadStarted,
            outcome: .started,
            attemptID: attemptID,
            profileID: record.profileID,
            mode: record.mode,
            revision: record.recordRevision
        ).value
        let launchContract = try NativeTunnelLaunchContract(record: record)
        let managers = try await Self.loadAllManagers()
        await NativeTunnelTrace.event(
            .managerLoaded,
            attemptID: attemptID,
            profileID: record.profileID,
            mode: record.mode,
            revision: record.recordRevision,
            details: ["managerCount": String(managers.count)]
        ).value
        var matchingManagers: [NetworkExtensionNativeTunnelManager] = []
        for manager in managers {
            if await manager.providerBundleIdentifier() == providerBundleIdentifier {
                matchingManagers.append(manager)
            }
        }
        guard matchingManagers.count <= 1 else {
            throw NativeTunnelConnectionError.multipleManagers
        }

        let manager: NetworkExtensionNativeTunnelManager
        if let existingManager = matchingManagers.first {
            manager = existingManager
        } else {
            var eligibleStaleManagers: [NetworkExtensionNativeTunnelManager] = []
            for candidate in managers {
                let status = await candidate.status()
                guard status == .disconnected || status == .invalid else {
                    continue
                }
                let reconcilerStatus: TunnelProviderSessionStatus = status == .invalid ? .invalid : .disconnected
                if TunnelProviderManagerReconciler.canRetarget(
                    savedBundleIdentifier: await candidate.providerBundleIdentifier(),
                    savedConfiguration: await candidate.providerConfiguration(),
                    desiredBundleIdentifier: providerBundleIdentifier,
                    desiredConfiguration: launchContract.providerConfiguration,
                    status: reconcilerStatus
                ) {
                    eligibleStaleManagers.append(candidate)
                }
            }
            guard eligibleStaleManagers.count <= 1 else {
                throw NativeTunnelConnectionError.multipleManagers
            }
            if let staleManager = eligibleStaleManagers.first {
                manager = staleManager
            } else {
                let newManager = await MainActor.run { NETunnelProviderManager() }
                manager = NetworkExtensionNativeTunnelManager(manager: newManager, isNew: true)
            }
        }
        let snapshot = await manager.snapshot()

        do {
            await manager.stopIfNecessary(timeout: connectionTimeout)
            await manager.configure(
                providerBundleIdentifier: providerBundleIdentifier,
                providerConfiguration: launchContract.providerConfiguration,
                displayName: displayName
            )
            await NativeTunnelTrace.event(
                .managerSaveStarted,
                outcome: .started,
                attemptID: attemptID,
                profileID: record.profileID,
                mode: record.mode,
                revision: record.recordRevision
            ).value
            try await manager.saveToPreferences()
            await NativeTunnelTrace.event(
                .managerSaved,
                attemptID: attemptID,
                profileID: record.profileID,
                mode: record.mode,
                revision: record.recordRevision
            ).value
            await NativeTunnelTrace.event(
                .managerReloadStarted,
                outcome: .started,
                attemptID: attemptID,
                profileID: record.profileID,
                mode: record.mode,
                revision: record.recordRevision
            ).value
            try await manager.loadFromPreferences()
            await NativeTunnelTrace.event(
                .managerReloaded,
                attemptID: attemptID,
                profileID: record.profileID,
                mode: record.mode,
                revision: record.recordRevision
            ).value
            guard await manager.matches(
                providerBundleIdentifier: providerBundleIdentifier,
                providerConfiguration: launchContract.providerConfiguration
            ) else {
                throw NativeTunnelConnectionError.providerConfigurationMismatch
            }
            await NativeTunnelTrace.event(
                .managerConfigurationValidated,
                attemptID: attemptID,
                profileID: record.profileID,
                mode: record.mode,
                revision: record.recordRevision,
                details: ["providerBundleID": providerBundleIdentifier]
            ).value
            setActiveManager(manager)
            await manager.observeStatus { [weak self] status in
                self?.receive(
                    status: status,
                    attemptID: attemptID,
                    profileID: record.profileID,
                    mode: record.mode,
                    revision: record.recordRevision
                )
            }
            await publishState(.connecting)
            let sessionStartRequestedAtNanoseconds = DispatchTime.now().uptimeNanoseconds
            await NativeTunnelTrace.event(
                .sessionStartRequested,
                outcome: .started,
                attemptID: attemptID,
                profileID: record.profileID,
                mode: record.mode,
                revision: record.recordRevision
            ).value
            try await manager.start(
                mode: launchContract.mode,
                modeOptionKey: Self.modeOptionKey,
                attemptID: attemptID,
                attemptIDOptionKey: Self.attemptIDOptionKey
            )
            try await manager.waitUntilConnected(
                timeout: connectionTimeout,
                attemptID: attemptID,
                sessionStartRequestedAtNanoseconds: sessionStartRequestedAtNanoseconds
            )
            guard await manager.status() == .connected else {
                throw await manager.disconnectFailure(fallback: .connectionFailed, attemptID: attemptID)
            }
            await publishState(.connected)
        } catch {
            let observation = manager.lastObservationFailure()
            let lastStatus = await manager.status()
            let disconnectDescriptor = await manager.lastDisconnectErrorDescriptor()
            let category = await NativeTunnelTrace.classifiedFailureCategory(
                attemptID: attemptID,
                error: error
            )
            let lastProviderStage = await NativeTunnelTrace.lastProviderStage(attemptID: attemptID)
            await NativeTunnelTrace.event(
                .connectionObservationFailed,
                outcome: .failed,
                attemptID: attemptID,
                profileID: record.profileID,
                mode: record.mode,
                revision: record.recordRevision,
                state: Self.connectionState(for: lastStatus),
                details: [
                    "lastNEVPNStatus": observation?.lastStatus ?? String(describing: lastStatus),
                    "elapsedMilliseconds": observation.map { String($0.elapsedMilliseconds) } ?? "unknown",
                    "triggeringCondition": observation?.triggeringCondition ?? "configureAndStartCatch",
                    "lastProviderStage": lastProviderStage?.rawValue ?? "unknown",
                    "nativeConnectionErrorCase": (error as? NativeTunnelConnectionError)?.diagnosticCaseName ?? "nonNativeTunnelError",
                    "systemErrorDomain": disconnectDescriptor?.domain ?? "none",
                    "systemErrorCode": disconnectDescriptor.map { String($0.code) } ?? "none",
                    "neConnectionErrorCase": disconnectDescriptor?.neConnectionErrorCase ?? "none",
                    "providerTerminationEvidence": disconnectDescriptor.flatMap {
                        NativeTunnelNEVPNConnectionErrorDecoder.terminationEvidence(
                            domain: $0.domain,
                            code: $0.code
                        )
                    } ?? "none",
                    "providerErrorRecovered": String(
                        disconnectDescriptor?.domain == NativeTunnelDisconnectErrorMapper.providerErrorDomain
                    )
                ],
                error: error,
                failureCategory: category,
                supplementalUnderlying: disconnectDescriptor?.diagnosticError
            ).value

            let shouldRequestStop = lastStatus != .disconnected && lastStatus != .invalid
            if shouldRequestStop {
                await NativeTunnelTrace.event(
                    .appStopRequested,
                    outcome: .started,
                    attemptID: attemptID,
                    profileID: record.profileID,
                    mode: record.mode,
                    revision: record.recordRevision,
                    details: [
                        "lastNEVPNStatus": String(describing: lastStatus),
                        "appStopRequested": "true",
                        "triggeringCondition": "startupFailureCleanup"
                    ]
                ).value
            }
            let stopResult = await manager.stopIfNecessary(timeout: .seconds(5))
            await NativeTunnelTrace.event(
                .appStopCompleted,
                outcome: .informational,
                attemptID: attemptID,
                profileID: record.profileID,
                mode: record.mode,
                revision: record.recordRevision,
                details: [
                    "lastNEVPNStatus": stopResult.finalStatus,
                    "appStopRequested": String(stopResult.stopRequested),
                    "appStopTimedOut": String(stopResult.timedOut),
                    "elapsedMilliseconds": String(stopResult.elapsedMilliseconds),
                    "triggeringCondition": "startupFailureCleanup"
                ]
            ).value
            await manager.removeStatusObserver()
            try? await manager.restore(snapshot)
            clearActiveManager(ifMatching: manager)
            await publishState(error is CancellationError ? .disconnected : .failed)
            throw error
        }
    }

    func stop() async {
        let manager = takeActiveManager()
        if let manager {
            await publishState(.disconnecting)
            await manager.stopIfNecessary(timeout: .seconds(15))
            await manager.removeStatusObserver()
            await publishState(.disconnected)
            return
        }
        guard let managers = try? await Self.loadAllManagers() else { return }
        var stoppedMatchingManager = false
        for candidate in managers {
            if await candidate.providerBundleIdentifier() == providerBundleIdentifier {
                stoppedMatchingManager = true
                await candidate.stopIfNecessary(timeout: .seconds(15))
            }
        }
        if stoppedMatchingManager {
            await publishState(.disconnected)
        }
    }

    static func connectionState(for status: NEVPNStatus) -> VPNConnectionState {
        switch status {
        case .invalid:
            .failed
        case .disconnected:
            .disconnected
        case .connecting, .reasserting:
            .connecting
        case .connected:
            .connected
        case .disconnecting:
            .disconnecting
        @unknown default:
            .failed
        }
    }

    private func receive(
        status: NEVPNStatus,
        attemptID: UUID,
        profileID: UUID,
        mode: NativeWireGuardMode,
        revision: String
    ) {
        let state = Self.connectionState(for: status)
        let sequence = nextStateSequence()
        NativeTunnelTrace.event(
            .networkExtensionStatusChanged,
            outcome: .informational,
            attemptID: attemptID,
            profileID: profileID,
            mode: mode,
            revision: revision,
            state: state,
            details: ["neStatus": String(describing: status)]
        )
        Task { [stateRelay] in
            await stateRelay.publish(state, sequence: sequence)
        }
    }

    private func publishState(_ state: VPNConnectionState) async {
        let sequence = nextStateSequence()
        await stateRelay.publish(state, sequence: sequence)
    }

    private func nextStateSequence() -> UInt64 {
        lock.withLock {
            stateSequence &+= 1
            return stateSequence
        }
    }

    private func setActiveManager(_ manager: NetworkExtensionNativeTunnelManager) {
        lock.withLock {
            activeManager = manager
        }
    }

    private func takeActiveManager() -> NetworkExtensionNativeTunnelManager? {
        lock.withLock {
            defer { activeManager = nil }
            return activeManager
        }
    }

    private func clearActiveManager(ifMatching manager: NetworkExtensionNativeTunnelManager) {
        lock.withLock {
            if activeManager === manager {
                activeManager = nil
            }
        }
    }

    private static func loadAllManagers() async throws -> [NetworkExtensionNativeTunnelManager] {
        let managers: [NETunnelProviderManager] = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
        return managers.map { NetworkExtensionNativeTunnelManager(manager: $0, isNew: false) }
    }
}

nonisolated private struct NetworkExtensionNativeTunnelManagerSnapshot: @unchecked Sendable {
    var protocolConfiguration: NEVPNProtocol?
    var localizedDescription: String?
    var isEnabled: Bool
}

nonisolated struct NativeTunnelConnectionObservationFailure: Equatable, Sendable {
    var lastStatus: String
    var elapsedMilliseconds: UInt64
    var triggeringCondition: String
}

nonisolated struct NativeTunnelStopResult: Equatable, Sendable {
    var initialStatus: String
    var finalStatus: String
    var stopRequested: Bool
    var timedOut: Bool
    var elapsedMilliseconds: UInt64
}

nonisolated private final class NetworkExtensionNativeTunnelManager: @unchecked Sendable {
    let manager: NETunnelProviderManager
    let isNew: Bool
    private var statusObserver: NSObjectProtocol?
    private let observationLock = NSLock()
    private var observationFailure: NativeTunnelConnectionObservationFailure?

    init(manager: NETunnelProviderManager, isNew: Bool) {
        self.manager = manager
        self.isNew = isNew
    }

    func providerBundleIdentifier() async -> String? {
        await MainActor.run {
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
        }
    }

    func providerConfiguration() async -> RuntimeProviderConfiguration? {
        await MainActor.run {
            guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                return nil
            }
            return try? RuntimeProviderConfiguration.parse(tunnelProtocol.providerConfiguration)
        }
    }

    func snapshot() async -> NetworkExtensionNativeTunnelManagerSnapshot {
        await MainActor.run {
            NetworkExtensionNativeTunnelManagerSnapshot(
                protocolConfiguration: manager.protocolConfiguration?.copy() as? NEVPNProtocol,
                localizedDescription: manager.localizedDescription,
                isEnabled: manager.isEnabled
            )
        }
    }

    func configure(
        providerBundleIdentifier: String,
        providerConfiguration: RuntimeProviderConfiguration,
        displayName: String
    ) async {
        await MainActor.run {
            let tunnelProtocol = NETunnelProviderProtocol()
            tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
            tunnelProtocol.providerConfiguration = providerConfiguration.propertyList
            tunnelProtocol.serverAddress = "KVN Native Tunnel"
            manager.protocolConfiguration = tunnelProtocol
            let trimmedName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
            manager.localizedDescription = trimmedName.isEmpty ? "KVN Native Tunnel" : "KVN · \(trimmedName.prefix(80))"
            manager.isEnabled = true
        }
    }

    func matches(
        providerBundleIdentifier: String,
        providerConfiguration: RuntimeProviderConfiguration
    ) async -> Bool {
        await MainActor.run {
            guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  tunnelProtocol.providerBundleIdentifier == providerBundleIdentifier,
                  let parsed = try? RuntimeProviderConfiguration.parse(tunnelProtocol.providerConfiguration) else {
                return false
            }
            return parsed == providerConfiguration && manager.isEnabled
        }
    }

    func saveToPreferences() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            Task { @MainActor in
                manager.saveToPreferences { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(returning: ())
                    }
                }
            }
        }
    }

    func loadFromPreferences() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            Task { @MainActor in
                manager.loadFromPreferences { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(returning: ())
                    }
                }
            }
        }
    }

    func start(
        mode: NativeWireGuardMode,
        modeOptionKey: String,
        attemptID: UUID,
        attemptIDOptionKey: String
    ) async throws {
        try await MainActor.run {
            guard let session = manager.connection as? NETunnelProviderSession else {
                throw NativeTunnelConnectionError.invalidSession
            }
            try session.startTunnel(options: [
                modeOptionKey: mode.rawValue as NSString,
                attemptIDOptionKey: attemptID.uuidString as NSString
            ])
        }
    }

    func status() async -> NEVPNStatus {
        await MainActor.run { manager.connection.status }
    }

    func observeStatus(_ handler: @escaping @Sendable (NEVPNStatus) -> Void) async {
        await MainActor.run {
            if let statusObserver {
                NotificationCenter.default.removeObserver(statusObserver)
            }
            let connection = manager.connection
            statusObserver = NotificationCenter.default.addObserver(
                forName: .NEVPNStatusDidChange,
                object: connection,
                queue: .main
            ) { [weak self] _ in
                guard let self else { return }
                handler(self.manager.connection.status)
            }
        }
    }

    func removeStatusObserver() async {
        await MainActor.run {
            if let statusObserver {
                NotificationCenter.default.removeObserver(statusObserver)
                self.statusObserver = nil
            }
        }
    }

    func waitUntilConnected(
        timeout: Duration,
        attemptID: UUID,
        sessionStartRequestedAtNanoseconds: UInt64
    ) async throws {
        let clock = ContinuousClock()
        let startedAtNanoseconds = sessionStartRequestedAtNanoseconds
        let deadline = clock.now.advanced(by: timeout)
        var observedConnectingState = false
        while clock.now < deadline {
            try Task.checkCancellation()
            let status = await MainActor.run { manager.connection.status }
            switch status {
            case .connected:
                return
            case .connecting, .reasserting:
                observedConnectingState = true
            case .invalid:
                recordObservationFailure(
                    status: status,
                    triggeringCondition: "networkExtensionSessionBecameInvalid",
                    startedAtNanoseconds: startedAtNanoseconds
                )
                throw await disconnectFailure(fallback: .invalidSession, attemptID: attemptID)
            case .disconnected:
                if observedConnectingState {
                    recordObservationFailure(
                        status: status,
                        triggeringCondition: "statusTransitionedFromConnectingToDisconnected",
                        startedAtNanoseconds: startedAtNanoseconds
                    )
                    throw await disconnectFailure(fallback: .connectionFailed, attemptID: attemptID)
                }
            case .disconnecting:
                break
            @unknown default:
                break
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        let finalStatus = await MainActor.run { manager.connection.status }
        recordObservationFailure(
            status: finalStatus,
            triggeringCondition: "connectionObservationDeadlineExceeded",
            startedAtNanoseconds: startedAtNanoseconds
        )
        throw NativeTunnelConnectionError.connectionTimedOut
    }

    func lastObservationFailure() -> NativeTunnelConnectionObservationFailure? {
        observationLock.withLock { observationFailure }
    }

    func disconnectFailure(
        fallback: NativeTunnelConnectionError,
        attemptID: UUID
    ) async -> NativeTunnelConnectionError {
        let systemResult = await NativeTunnelDisconnectFailureResolver { [self] in
            await lastDisconnectErrorDescriptor()
        }.connectionError(fallback: fallback)
        if systemResult != fallback {
            return systemResult
        }
        guard let store = TunnelStartupDiagnosticsStore.appGroupStore(),
              let snapshot = try? await store.attempt(id: attemptID),
              let failure = snapshot.events.last(where: {
                  $0.source == .provider && $0.outcome == .failed
              }),
              let persisted = NativeTunnelPersistedFailureMapper.connectionError(
                  for: failure.failureCategory
              ) else {
            return systemResult
        }
        return persisted
    }

    @discardableResult
    func stopIfNecessary(timeout: Duration) async -> NativeTunnelStopResult {
        let startedAtNanoseconds = DispatchTime.now().uptimeNanoseconds
        let initialStatus = await MainActor.run { manager.connection.status }
        guard initialStatus != .disconnected && initialStatus != .invalid else {
            return NativeTunnelStopResult(
                initialStatus: String(describing: initialStatus),
                finalStatus: String(describing: initialStatus),
                stopRequested: false,
                timedOut: false,
                elapsedMilliseconds: 0
            )
        }
        await MainActor.run {
            manager.connection.stopVPNTunnel()
        }
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while clock.now < deadline {
            let status = await MainActor.run { manager.connection.status }
            if status == .disconnected || status == .invalid {
                return NativeTunnelStopResult(
                    initialStatus: String(describing: initialStatus),
                    finalStatus: String(describing: status),
                    stopRequested: true,
                    timedOut: false,
                    elapsedMilliseconds: elapsedMilliseconds(since: startedAtNanoseconds)
                )
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        let finalStatus = await MainActor.run { manager.connection.status }
        return NativeTunnelStopResult(
            initialStatus: String(describing: initialStatus),
            finalStatus: String(describing: finalStatus),
            stopRequested: true,
            timedOut: true,
            elapsedMilliseconds: elapsedMilliseconds(since: startedAtNanoseconds)
        )
    }

    func restore(_ snapshot: NetworkExtensionNativeTunnelManagerSnapshot) async throws {
        if isNew {
            try await removeFromPreferences()
            return
        }
        await MainActor.run {
            manager.protocolConfiguration = snapshot.protocolConfiguration
            manager.localizedDescription = snapshot.localizedDescription
            manager.isEnabled = snapshot.isEnabled
        }
        try await saveToPreferences()
        try await loadFromPreferences()
    }

    private func removeFromPreferences() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            Task { @MainActor in
                manager.removeFromPreferences { error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(returning: ())
                    }
                }
            }
        }
    }

    func lastDisconnectErrorDescriptor() async -> NativeTunnelDisconnectErrorDescriptor? {
        await withCheckedContinuation { continuation in
            Task { @MainActor in
                manager.connection.fetchLastDisconnectError { error in
                    guard let error else {
                        continuation.resume(returning: nil)
                        return
                    }
                    let nsError = error as NSError
                    continuation.resume(returning: NativeTunnelDisconnectErrorDescriptor(
                        domain: nsError.domain,
                        code: nsError.code,
                        diagnosticError: TunnelDiagnosticError(error: error)
                    ))
                }
            }
        }
    }

    private func recordObservationFailure(
        status: NEVPNStatus,
        triggeringCondition: String,
        startedAtNanoseconds: UInt64
    ) {
        let value = NativeTunnelConnectionObservationFailure(
            lastStatus: String(describing: status),
            elapsedMilliseconds: elapsedMilliseconds(since: startedAtNanoseconds),
            triggeringCondition: triggeringCondition
        )
        observationLock.withLock {
            observationFailure = value
        }
    }

    private func elapsedMilliseconds(since startedAtNanoseconds: UInt64) -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds &- startedAtNanoseconds) / 1_000_000
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }
}

actor NativeWireGuardVPNConnectionService {
    private let publisher: NativeWireGuardProfilePublisher?
    private let systemManager: any NativeTunnelSystemManaging

    init(
        publisher: NativeWireGuardProfilePublisher? = NativeWireGuardProfilePublisher.appGroupPublisher(),
        systemManager: any NativeTunnelSystemManaging = NetworkExtensionNativeTunnelSystemManager()
    ) {
        self.publisher = publisher
        self.systemManager = systemManager
    }

    func currentState() async -> VPNConnectionState {
        await systemManager.currentState()
    }

    func stateUpdates() async -> AsyncStream<VPNConnectionState> {
        await systemManager.stateUpdates()
    }

    func connect(using profile: VPNProfile, attemptID: UUID) async throws {
        guard profile.protocolType == .wireGuard || profile.protocolType == .amneziaWG else {
            throw NativeTunnelConnectionError.unsupportedProtocol
        }
        let capability = NativeWireGuardProfileValidator.capability(for: profile)
        guard capability.isReady else {
            throw NativeTunnelConnectionError.profileNotReady(capability.statusText)
        }
        guard let publisher else {
            throw NativeTunnelConnectionError.runtimeStoreUnavailable
        }

        let previousRecord = try await publisher.snapshot(profileID: profile.id)
        await NativeTunnelTrace.event(
            .runtimePublishStarted,
            outcome: .started,
            attemptID: attemptID,
            profileID: profile.id,
            mode: profile.protocolType == .wireGuard ? .wireGuard : .amneziaWG,
            details: [
                "requestedProfileID": profile.id.uuidString,
                "runtimeSnapshotExists": String(previousRecord != nil)
            ]
        ).value
        let record = try await publisher.publish(profile)
        await NativeTunnelTrace.event(
            .runtimePublished,
            attemptID: attemptID,
            profileID: record.profileID,
            mode: record.mode,
            revision: record.recordRevision,
            details: [
                "requestedProfileID": profile.id.uuidString,
                "runtimeProfileID": record.profileID.uuidString,
                "expectedPublicationRevision": record.recordRevision,
                "runtimeSnapshotExists": "true",
                "runtimeProfileMatchesSelected": String(record.profileID == profile.id)
            ]
        ).value
        do {
            try await systemManager.configureAndStart(
                record: record,
                displayName: profile.name,
                attemptID: attemptID
            )
            try Task.checkCancellation()
        } catch {
            await systemManager.stop()
            try? await publisher.restore(previousRecord, profileID: profile.id)
            throw error
        }
    }

    func disconnect() async {
        await systemManager.stop()
    }
}

actor ProductionVPNConnectionManager: VPNConnectionManaging {
    private enum Route {
        case native
        case xray
        case fallback
    }

    private let nativeService: NativeWireGuardVPNConnectionService
    private let xrayService: any VPNConnectionManaging
    private let fallback: any VPNConnectionManaging
    private let authoritativeRestorer: AuthoritativeVPNConnectionRestorer
    private var state: VPNConnectionState = .disconnected
    private var authoritativeState: VPNAuthoritativeConnection = .disconnected
    private var activeRoute: Route?
    private var operationID: UUID?
    private var nativeStateObservationTask: Task<Void, Never>?
    private var xrayStateObservationTask: Task<Void, Never>?
    private var authoritativeStateObservationTask: Task<Void, Never>?
    private var continuations: [UUID: AsyncStream<VPNConnectionState>.Continuation] = [:]

    init(
        nativeService: NativeWireGuardVPNConnectionService = NativeWireGuardVPNConnectionService(),
        xrayService: any VPNConnectionManaging = XrayVPNConnectionService(),
        fallback: any VPNConnectionManaging = MockVPNConnectionManager(),
        authoritativeRestorer: AuthoritativeVPNConnectionRestorer =
            AuthoritativeVPNConnectionRestorer()
    ) {
        self.nativeService = nativeService
        self.xrayService = xrayService
        self.fallback = fallback
        self.authoritativeRestorer = authoritativeRestorer
    }

    func currentState() async -> VPNConnectionState {
        state
    }

    func authoritativeConnection() async -> VPNAuthoritativeConnection {
        authoritativeState
    }

    func refreshAuthoritativeConnection() async -> VPNAuthoritativeConnection {
        await beginAuthoritativeStateObservationIfNeeded()
        let shouldAttachObserver = activeRoute != .native || operationID == nil
        let connection = await authoritativeRestorer.refresh(
            attachStatusObservers: shouldAttachObserver
        )
        applyAuthoritativeConnection(connection)
        return connection
    }

    nonisolated func stateUpdates() -> AsyncStream<VPNConnectionState> {
        AsyncStream { continuation in
            Task {
                let id = UUID()
                await addContinuation(continuation, id: id)
                continuation.onTermination = { _ in
                    Task { await self.removeContinuation(id: id) }
                }
            }
        }
    }

    nonisolated func routesTrafficThroughProductionCore(using profile: VPNProfile) -> Bool {
        PacketTunnelProviderRouting.provider(for: profile.protocolType) != nil
    }

    func connect(using profile: VPNProfile) async throws {
        if activeRoute != nil {
            await disconnectActiveRoute()
        }
        let route: Route
        switch PacketTunnelProviderRouting.provider(for: profile.protocolType) {
        case .wireGuard:
            route = .native
        case .xray:
            route = .xray
        case nil:
            route = .fallback
        }
        let currentOperation = UUID()
        if route == .native {
            await NativeTunnelTrace.beginAttempt(
                attemptID: currentOperation,
                profileID: profile.id,
                mode: profile.protocolType == .wireGuard ? .wireGuard : .amneziaWG
            )
        }
        operationID = currentOperation
        activeRoute = route
        publish(.connecting)
        if route == .native {
            let mode: NativeWireGuardMode = profile.protocolType == .wireGuard ? .wireGuard : .amneziaWG
            NativeTunnelTrace.event(
                .appConnectRequested,
                outcome: .started,
                attemptID: currentOperation,
                profileID: profile.id,
                mode: mode
            )
            NativeTunnelTrace.event(
                .appProfileSelected,
                attemptID: currentOperation,
                profileID: profile.id,
                mode: mode
            )
        }

        do {
            let routeState: VPNConnectionState
            switch route {
            case .native:
                await beginNativeStateObservation(operationID: currentOperation)
                try await nativeService.connect(using: profile, attemptID: currentOperation)
                routeState = await nativeService.currentState()
            case .xray:
                await beginXrayStateObservation(operationID: currentOperation)
                try await xrayService.connect(using: profile)
                routeState = await xrayService.currentState()
            case .fallback:
                try await fallback.connect(using: profile)
                routeState = await fallback.currentState()
            }
            guard operationID == currentOperation, Task.isCancelled == false else {
                await disconnectRoute(route)
                throw CancellationError()
            }
            guard routeState == .connected else {
                await disconnectRoute(route)
                throw NativeTunnelConnectionError.connectionFailed
            }

            let provider = PacketTunnelProviderRouting.provider(for: profile.protocolType)
            authoritativeState = VPNAuthoritativeConnection(
                state: routeState,
                systemStatus: provider == nil ? nil : .connected,
                profileID: profile.id,
                provider: provider,
                hasMultipleActiveManagers: false
            )
            publish(routeState)

            if let provider {
                await beginAuthoritativeStateObservationIfNeeded()
                if let restored = await authoritativeRestorer.bindAfterUserStart(
                    profileID: profile.id,
                    provider: provider
                ) {
                    applyAuthoritativeConnection(restored)
                }
            }

            if route == .native {
                let mode: NativeWireGuardMode = profile.protocolType == .wireGuard ? .wireGuard : .amneziaWG
                await NativeTunnelTrace.event(
                    .tunnelStartCompleted,
                    attemptID: currentOperation,
                    profileID: profile.id,
                    mode: mode,
                    state: routeState
                ).value
            }
        } catch {
            if route == .native {
                let mode: NativeWireGuardMode = profile.protocolType == .wireGuard ? .wireGuard : .amneziaWG
                let category = await NativeTunnelTrace.classifiedFailureCategory(
                    attemptID: currentOperation,
                    error: error
                )
                await NativeTunnelTrace.event(
                    error is CancellationError ? .tunnelStartCancelled : .tunnelStartFailed,
                    outcome: .failed,
                    attemptID: currentOperation,
                    profileID: profile.id,
                    mode: mode,
                    error: error,
                    failureCategory: error is CancellationError ? .cancelled : category
                ).value
            }
            if operationID == currentOperation {
                nativeStateObservationTask?.cancel()
                nativeStateObservationTask = nil
                xrayStateObservationTask?.cancel()
                xrayStateObservationTask = nil
                activeRoute = nil
                operationID = nil
                let failedState: VPNConnectionState =
                    error is CancellationError ? .disconnected : .failed
                authoritativeState = VPNAuthoritativeConnection(
                    state: failedState,
                    systemStatus: nil,
                    profileID: nil,
                    provider: nil,
                    hasMultipleActiveManagers: false
                )
                publish(failedState)
            }
            throw error
        }
    }

    func disconnect() async {
        let wasRestoredConnection = operationID == nil && authoritativeState.isSystemActive
        operationID = nil

        if wasRestoredConnection {
            publish(.disconnecting)
            if await authoritativeRestorer.stopAuthoritativeConnection() {
                let refreshed = await authoritativeRestorer.refresh()
                applyAuthoritativeConnection(refreshed)
                return
            }
        }

        guard let route = activeRoute else {
            authoritativeState = .disconnected
            publish(.disconnected)
            return
        }
        publish(.disconnecting)
        await disconnectActiveRoute()
        let routeState: VPNConnectionState
        switch route {
        case .native:
            routeState = await nativeService.currentState()
        case .xray:
            routeState = await xrayService.currentState()
        case .fallback:
            routeState = await fallback.currentState()
        }
        authoritativeState = VPNAuthoritativeConnection(
            state: routeState,
            systemStatus: routeState == .connected ? .connected : .disconnected,
            profileID: routeState == .connected ? authoritativeState.profileID : nil,
            provider: routeState == .connected ? authoritativeState.provider : nil,
            hasMultipleActiveManagers: false
        )
        publish(routeState)
    }

    private func disconnectActiveRoute() async {
        guard let route = activeRoute else { return }
        await disconnectRoute(route)
        nativeStateObservationTask?.cancel()
        nativeStateObservationTask = nil
        xrayStateObservationTask?.cancel()
        xrayStateObservationTask = nil
        activeRoute = nil
    }

    private func disconnectRoute(_ route: Route) async {
        switch route {
        case .native:
            await nativeService.disconnect()
        case .xray:
            await xrayService.disconnect()
        case .fallback:
            await fallback.disconnect()
        }
    }

    private func beginNativeStateObservation(operationID observedOperationID: UUID) async {
        nativeStateObservationTask?.cancel()
        let updates = await nativeService.stateUpdates()
        nativeStateObservationTask = Task { [weak self] in
            for await _ in updates {
                guard Task.isCancelled == false else { return }
                await self?.refreshNativeState(operationID: observedOperationID)
            }
        }
    }

    private func refreshNativeState(operationID observedOperationID: UUID) async {
        guard activeRoute == .native, operationID == observedOperationID else { return }
        let routeState = await nativeService.currentState()
        guard activeRoute == .native, operationID == observedOperationID else { return }
        applyRouteState(routeState, provider: .wireGuard)
    }

    private func beginXrayStateObservation(operationID observedOperationID: UUID) async {
        xrayStateObservationTask?.cancel()
        let updates = xrayService.stateUpdates()
        xrayStateObservationTask = Task { [weak self] in
            for await _ in updates {
                guard Task.isCancelled == false else { return }
                await self?.refreshXrayState(operationID: observedOperationID)
            }
        }
    }

    private func refreshXrayState(operationID observedOperationID: UUID) async {
        guard activeRoute == .xray, operationID == observedOperationID else { return }
        let routeState = await xrayService.currentState()
        guard activeRoute == .xray, operationID == observedOperationID else { return }
        applyRouteState(routeState, provider: .xray)
    }

    private func applyRouteState(
        _ routeState: VPNConnectionState,
        provider: PacketTunnelProviderKind
    ) {
        let systemStatus: VPNSystemConnectionStatus?
        switch routeState {
        case .connected:
            systemStatus = .connected
        case .connecting:
            systemStatus = .connecting
        case .disconnecting:
            systemStatus = .disconnecting
        case .disconnected:
            systemStatus = .disconnected
        case .failed:
            systemStatus = .invalid
        case .testing:
            systemStatus = nil
        }

        let profileID = systemStatus?.isActive == true
            ? authoritativeState.profileID
            : nil
        authoritativeState = VPNAuthoritativeConnection(
            state: routeState,
            systemStatus: systemStatus,
            profileID: profileID,
            provider: systemStatus?.isActive == true ? provider : nil,
            hasMultipleActiveManagers: false
        )
        publish(routeState)
    }

    private func beginAuthoritativeStateObservationIfNeeded() async {
        guard authoritativeStateObservationTask == nil else {
            return
        }
        let updates = authoritativeRestorer.updates()
        authoritativeStateObservationTask = Task { [weak self] in
            for await connection in updates {
                guard Task.isCancelled == false else {
                    return
                }
                await self?.receiveAuthoritativeConnection(connection)
            }
        }
    }

    private func receiveAuthoritativeConnection(
        _ connection: VPNAuthoritativeConnection
    ) {
        applyAuthoritativeConnection(connection)
    }

    private func applyAuthoritativeConnection(
        _ connection: VPNAuthoritativeConnection
    ) {
        authoritativeState = connection
        if connection.isSystemActive {
            switch connection.provider {
            case .wireGuard:
                activeRoute = .native
            case .xray:
                activeRoute = .xray
            case nil:
                break
            }
        } else if operationID == nil {
            activeRoute = nil
        }
        publish(connection.state)
    }

    private func addContinuation(_ continuation: AsyncStream<VPNConnectionState>.Continuation, id: UUID) {
        continuations[id] = continuation
        continuation.yield(state)
    }

    private func removeContinuation(id: UUID) {
        continuations[id] = nil
    }

    private func publish(_ newState: VPNConnectionState) {
        guard state != newState else { return }
        state = newState
        continuations.values.forEach { $0.yield(newState) }
    }
}

nonisolated enum ProductionVPNConnectionComposition {
    static func makeConnectionManager(
        nativeService: NativeWireGuardVPNConnectionService = NativeWireGuardVPNConnectionService(),
        xrayService: any VPNConnectionManaging = XrayVPNConnectionService(),
        fallback: any VPNConnectionManaging = MockVPNConnectionManager(),
        authoritativeRestorer: AuthoritativeVPNConnectionRestorer =
            AuthoritativeVPNConnectionRestorer()
    ) -> ProductionVPNConnectionManager {
        ProductionVPNConnectionManager(
            nativeService: nativeService,
            xrayService: xrayService,
            fallback: fallback,
            authoritativeRestorer: authoritativeRestorer
        )
    }
}

nonisolated private enum NativeTunnelTrace {
    private static let diagnosticsStore = TunnelStartupDiagnosticsStore.appGroupStore()
    private static let appBuild = TunnelBuildIdentity.current()
    private static let logger = Logger(subsystem: "su.24kvn.kvn-app", category: "Tunnel.App")

    static func beginAttempt(
        attemptID: UUID,
        profileID: UUID,
        mode: NativeWireGuardMode
    ) async {
        guard let diagnosticsStore else {
            logger.error(
                "startup diagnostics unavailable attempt=\(attemptID.uuidString, privacy: .public)"
            )
            return
        }
        do {
            try await diagnosticsStore.beginAttempt(
                attemptID: attemptID,
                profileID: profileID,
                protocolName: mode.rawValue,
                appBuild: appBuild
            )
        } catch {
            let nsError = error as NSError
            logger.error(
                "startup diagnostics begin failed attempt=\(attemptID.uuidString, privacy: .public) error=\(nsError.domain, privacy: .public)/\(nsError.code, privacy: .public)"
            )
        }
    }

    @discardableResult
    static func event(
        _ stage: TunnelStartupStage,
        outcome: TunnelDiagnosticOutcome = .succeeded,
        attemptID: UUID,
        profileID: UUID? = nil,
        mode: NativeWireGuardMode? = nil,
        revision: String? = nil,
        state: VPNConnectionState? = nil,
        details: [String: String] = [:],
        error: (any Error)? = nil,
        failureCategory: NativeTunnelFailureCategory? = nil,
        supplementalUnderlying: TunnelDiagnosticError? = nil
    ) -> Task<Void, Never> {
        let category = failureCategory ?? error.map(sanitizedFailureCategory)
        var safeDetails = details
        if let profileID {
            safeDetails["profileID"] = profileID.uuidString
        }
        if let mode {
            safeDetails["protocol"] = mode.rawValue
            safeDetails["backend"] = "nativeWireGuardAdapter"
        }
        if let revision {
            safeDetails["runtimeRevision"] = revision
        }
        if let state {
            safeDetails["neStatus"] = state.rawValue
        }
        if let category {
            safeDetails["failureCategory"] = category.rawValue
        }
        if let connectionError = error as? NativeTunnelConnectionError {
            safeDetails["nativeConnectionErrorCase"] = connectionError.diagnosticCaseName
        }

        let diagnosticEvent = TunnelDiagnosticEvent(
            attemptID: attemptID,
            source: .app,
            stage: stage,
            outcome: outcome,
            details: safeDetails,
            failureCategory: category,
            error: error.map {
                TunnelDiagnosticError(error: $0, supplementalUnderlying: supplementalUnderlying)
            }
        )
        logger.notice(
            "\(stage.rawValue, privacy: .public) attempt=\(attemptID.uuidString, privacy: .public) profile=\(profileID?.uuidString ?? "-", privacy: .public) protocol=\(mode?.rawValue ?? "-", privacy: .public) revision=\(revision ?? "-", privacy: .public) state=\(state?.rawValue ?? "-", privacy: .public) error=\(category?.rawValue ?? "-", privacy: .public)"
        )
        return Task {
            guard let diagnosticsStore else { return }
            do {
                try await diagnosticsStore.record(diagnosticEvent, build: appBuild)
            } catch {
                let nsError = error as NSError
                logger.error(
                    "startup diagnostics write failed attempt=\(attemptID.uuidString, privacy: .public) error=\(nsError.domain, privacy: .public)/\(nsError.code, privacy: .public)"
                )
            }
        }
    }

    static func classifiedFailureCategory(
        attemptID: UUID,
        error: any Error
    ) async -> NativeTunnelFailureCategory {
        guard let diagnosticsStore,
              let snapshot = try? await diagnosticsStore.attempt(id: attemptID) else {
            return sanitizedFailureCategory(for: error)
        }
        return NativeTunnelStartupFailureClassifier.category(for: error, events: snapshot.events)
    }

    static func lastProviderStage(attemptID: UUID) async -> TunnelStartupStage? {
        guard let diagnosticsStore,
              let snapshot = try? await diagnosticsStore.attempt(id: attemptID) else {
            return nil
        }
        return snapshot.events.last(where: { $0.source == .provider })?.stage
    }

    static func sanitizedFailureCategory(for error: any Error) -> NativeTunnelFailureCategory {
        guard let error = error as? NativeTunnelConnectionError else {
            return .unknown
        }
        switch error {
        case .runtimeStoreUnavailable:
            return .runtimeProfileUnavailable
        case .unsupportedProtocol:
            return .invalidProviderConfiguration
        case .profileNotReady:
            return .awgConfigurationInvalid
        case .managerUnavailable:
            return .providerWasNeverLaunched
        case .multipleManagers:
            return .providerWasNeverLaunched
        case .providerConfigurationMismatch:
            return .invalidProviderConfiguration
        case .invalidSession:
            return .unknownProviderStartupFailure
        case .connectionFailed:
            return .unknownProviderStartupFailure
        case .connectionTimedOut:
            return .appConnectionObservationTimeout
        case .providerFailure(let failure):
            switch failure {
            case .sharedContainerUnavailable, .recordUnavailable:
                return .runtimeProfileUnavailable
            case .providerConfigurationInvalid:
                return .invalidProviderConfiguration
            case .recordMalformed:
                return .runtimeProfileMalformed
            case .schemaMismatch:
                return .runtimeSchemaMismatch
            case .revisionMismatch:
                return .runtimeRevisionMismatch
            case .modeMismatch:
                return .runtimeModeMismatch
            case .profileDisabled:
                return .profileDisabled
            case .credentialUnavailable:
                return .sharedCredentialUnavailable
            case .configurationInvalid:
                return .awgConfigurationInvalid
            case .alreadyRunning, .adapterInvalidState:
                return .adapterInvalidState
            case .adapterStartFailed, .backendStartFailed:
                return .nativeBackendStartupFailed
            case .cancelled:
                return .cancelled
            case .cannotLocateTunnelFileDescriptor:
                return .tunnelFileDescriptorUnavailable
            case .endpointDNSResolutionFailed:
                return .dnsResolutionFailed
            case .networkSettingsRejected:
                return .networkSettingsRejected
            case .startupCompletionTimeout:
                return .providerStartupStalled
            case .adapterStartTimeout:
                return .adapterStartTimeout
            case .nativeBackendControllerUnavailable:
                return .nativeBackendControllerUnavailable
            case .runtimeLoaderUnavailable:
                return .runtimeLoaderUnavailable
            case .providerStartupStalled:
                return .providerStartupStalled
            }
        }
    }
}
