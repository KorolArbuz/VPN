//
//  TunnelProviderMessaging.swift
//  VPN
//
//  App-side read-only IPC client for PacketTunnelExtension telemetry. This
//  layer never starts, stops, creates, or mutates VPN configurations.
//

import Foundation
import NetworkExtension

nonisolated enum TunnelProviderSessionStatus: Equatable, Sendable {
    case invalid
    case disconnected
    case connecting
    case connected
    case reasserting
    case disconnecting
    case unknown

    var allowsProviderMessage: Bool {
        switch self {
        case .connected, .reasserting:
            true
        case .invalid, .disconnected, .connecting, .disconnecting, .unknown:
            false
        }
    }

    var diagnosticValue: String {
        switch self {
        case .invalid:
            "invalid"
        case .disconnected:
            "disconnected"
        case .connecting:
            "connecting"
        case .connected:
            "connected"
        case .reasserting:
            "reasserting"
        case .disconnecting:
            "disconnecting"
        case .unknown:
            "unknown"
        }
    }
}

nonisolated protocol TunnelProviderSessionConnection: Sendable {
    func status() async -> TunnelProviderSessionStatus
    func sendProviderMessage(
        _ data: Data,
        responseHandler: @escaping @Sendable (Result<Data?, any Error>) -> Void
    )
}

nonisolated protocol TunnelProviderSessionProviding: Sendable {
    func currentSession() async throws -> any TunnelProviderSessionConnection
}

nonisolated protocol TunnelProviderMessaging: Sendable {
    func status() async -> TunnelProviderSessionStatus
    func send(_ request: TunnelMessageRequest) async throws -> TunnelMessageResponse
}

nonisolated protocol TunnelKeychainSentinelMessaging: Sendable {
    func sendKeychainSentinel(_ request: TunnelMessageRequest) async throws -> TunnelKeychainSentinelMessageResult
}

nonisolated protocol TunnelRuntimeConfigurationValidationMessaging: Sendable {
    func sendRuntimeConfigurationValidation(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelRuntimeConfigurationValidationMessageResult
}

nonisolated protocol TunnelXrayConfigurationValidationMessaging: Sendable {
    func sendXrayConfigurationValidation(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelXrayConfigurationValidationMessageResult
}

nonisolated protocol TunnelXrayLifecycleSmokeTestMessaging: Sendable {
    func sendXrayLifecycleSmokeTest(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelXrayLifecycleSmokeTestMessageResult
}

nonisolated protocol TunnelXrayRemoteEgressProbeMessaging: Sendable {
    func sendXrayRemoteEgressProbe(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelXrayRemoteEgressProbeMessageResult
}

nonisolated protocol TunnelUDPControlProbeMessaging: Sendable {
    func sendUDPControlProbe(_ request: TunnelMessageRequest) async throws -> TunnelUDPControlProbeMessageResult
}

nonisolated protocol TunnelLibXrayPingProbeMessaging: Sendable {
    func sendLibXrayPingProbe(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelLibXrayPingProbeMessageResult
}

#if DEBUG
nonisolated enum RuntimeOnlyPacketTunnelStartOptions {
    static let runtimeOnlyKey = "kvn.debug.runtimeOnly"
    static let allowedKeys: Set<String> = [runtimeOnlyKey]

    static var propertyList: [String: NSObject] {
        [runtimeOnlyKey: NSNumber(value: true)]
    }
}

nonisolated protocol RuntimeOnlyPacketTunnelSessionConnection: TunnelProviderSessionConnection {
    func startRuntimeOnlyTunnel(options: [String: NSObject]) async throws
    func stopRuntimeOnlyTunnel() async
}
#endif

nonisolated enum DataPlanePacketTunnelStartOptions {
    static let dataPlaneKey = "kvn.xray.dataPlane"
    static let allowedKeys: Set<String> = [dataPlaneKey]

    static var propertyList: [String: NSObject] {
        [dataPlaneKey: NSNumber(value: true)]
    }
}

nonisolated protocol DataPlanePacketTunnelSessionConnection: TunnelProviderSessionConnection {
    func startDataPlaneTunnel(options: [String: NSObject]) async throws
    func stopDataPlaneTunnel() async
}

#if DEBUG
nonisolated enum LibXrayPingOnlyPacketTunnelStartOptions {
    static let libXrayPingOnlyKey = "kvn.debug.libXrayPingOnly"
    static let allowedKeys: Set<String> = [libXrayPingOnlyKey]

    static var propertyList: [String: NSObject] {
        [libXrayPingOnlyKey: NSNumber(value: true)]
    }
}

nonisolated protocol LibXrayPingOnlyPacketTunnelSessionConnection: TunnelProviderSessionConnection {
    func startLibXrayPingOnlyTunnel(options: [String: NSObject]) async throws
    func stopLibXrayPingOnlyTunnel() async
}

nonisolated protocol DiagnosticProviderRecoverySessionConnection: TunnelProviderSessionConnection {
    func stopDiagnosticProviderTunnel() async
}
#endif

nonisolated final class NetworkExtensionTunnelMessenger: TunnelProviderMessaging, @unchecked Sendable {
    private let sessionProvider: any TunnelProviderSessionProviding
    private let timeout: Duration
    private let maximumResponseBytes: Int
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(
        sessionProvider: any TunnelProviderSessionProviding = NetworkExtensionTunnelSessionProvider(),
        timeout: Duration = .seconds(3),
        maximumResponseBytes: Int = TunnelMessageProtocol.maximumResponseBytes
    ) {
        self.sessionProvider = sessionProvider
        self.timeout = timeout
        self.maximumResponseBytes = maximumResponseBytes
        decoder.dateDecodingStrategy = .iso8601
    }

    func status() async -> TunnelProviderSessionStatus {
        do {
            return await (try await sessionProvider.currentSession()).status()
        } catch {
            return .unknown
        }
    }

    func send(_ request: TunnelMessageRequest) async throws -> TunnelMessageResponse {
        try await send(request, requiresConnectedStatus: true)
    }

    func sendDiagnostic(_ request: TunnelMessageRequest) async throws -> TunnelMessageResponse {
        try await send(request, requiresConnectedStatus: false)
    }

    private func send(_ request: TunnelMessageRequest, requiresConnectedStatus: Bool) async throws -> TunnelMessageResponse {
        guard request.schemaVersion == TunnelMessageProtocol.schemaVersion else {
            throw TunnelMessageErrorCode.schemaMismatch
        }

        let session = try await sessionProvider.currentSession()
        let status = await session.status()
        guard requiresConnectedStatus == false || status.allowsProviderMessage else {
            throw TunnelMessageErrorCode.providerStatusNotConnected
        }

        let requestData = try encoder.encode(request)
        let responseData = try await sendProviderMessage(requestData, through: session, timeout: timeout)

        guard let responseData else {
            throw TunnelMessageErrorCode.providerResponseMissing
        }

        guard responseData.count <= maximumResponseBytes else {
            throw TunnelMessageErrorCode.payloadTooLarge
        }

        let response: TunnelMessageResponse
        do {
            response = try decoder.decode(TunnelMessageResponse.self, from: responseData)
        } catch {
            throw TunnelMessageErrorCode.invalidResponse
        }

        guard response.schemaVersion == TunnelMessageProtocol.schemaVersion else {
            throw TunnelMessageErrorCode.schemaMismatch
        }
        guard response.requestID == request.requestID else {
            throw TunnelMessageErrorCode.requestIDMismatch
        }
        guard response.success else {
            throw response.error?.code ?? TunnelMessageErrorCode.unknown
        }
        return response
    }

    private func sendProviderMessage(
        _ requestData: Data,
        through session: any TunnelProviderSessionConnection,
        timeout: Duration
    ) async throws -> Data? {
        let gate = TunnelProviderMessageCompletionGate<Data?>()

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                gate.install(continuation)

                let timeoutTask = Task { [gate] in
                    do {
                        try await Task.sleep(for: timeout)
                        gate.complete(.failure(TunnelMessageErrorCode.timeout))
                    } catch {
                        // Cancellation means another result already won the one-shot gate.
                    }
                }
                gate.setTimeoutTask(timeoutTask)

                session.sendProviderMessage(requestData) { result in
                    gate.complete(result)
                }
            }
        } onCancel: {
            gate.complete(.failure(CancellationError()))
        }
    }
}

private nonisolated final class TunnelProviderMessageCompletionGate<Value: Sendable>: @unchecked Sendable {
    private enum State {
        case waiting(CheckedContinuation<Value, any Error>?)
        case completed(pendingResult: Result<Value, any Error>?)
    }

    private let lock = NSLock()
    private var state: State = .waiting(nil)
    private var timeoutTask: Task<Void, Never>?

    func install(_ continuation: CheckedContinuation<Value, any Error>) {
        let completedResult: Result<Value, any Error>? = lock.withLock {
            switch state {
            case .waiting(nil):
                state = .waiting(continuation)
                return nil
            case .waiting(.some):
                state = .completed(pendingResult: .failure(TunnelMessageErrorCode.unknown))
                return .failure(TunnelMessageErrorCode.unknown)
            case .completed(let pendingResult):
                return pendingResult
            }
        }

        if let completedResult {
            continuation.resume(with: completedResult)
        }
    }

    func setTimeoutTask(_ task: Task<Void, Never>) {
        let shouldCancel = lock.withLock {
            switch state {
            case .waiting:
                timeoutTask = task
                return false
            case .completed:
                return true
            }
        }

        if shouldCancel {
            task.cancel()
        }
    }

    func complete(_ result: Result<Value, any Error>) {
        let completion = lock.withLock {
            switch state {
            case .waiting(let continuation):
                state = .completed(pendingResult: continuation == nil ? result : nil)
                let task = timeoutTask
                timeoutTask = nil
                return (continuation, task)
            case .completed:
                return (nil, nil)
            }
        }

        completion.1?.cancel()
        completion.0?.resume(with: result)
    }
}

nonisolated final class NetworkExtensionTunnelSessionProvider: TunnelProviderSessionProviding, @unchecked Sendable {
    private let providerBundleIdentifier: String

    init(providerBundleIdentifier: String = NetworkExtensionTunnelSessionProvider.defaultProviderBundleIdentifier()) {
        self.providerBundleIdentifier = providerBundleIdentifier
    }

    func currentSession() async throws -> any TunnelProviderSessionConnection {
        let managers = try await Self.loadAllManagers()
        guard let manager = managers.first(where: { candidate in
            guard let proto = candidate.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return proto.providerBundleIdentifier == providerBundleIdentifier
        }) else {
            throw TunnelMessageErrorCode.providerUnavailable
        }

        guard let session = manager.connection as? NETunnelProviderSession else {
            throw TunnelMessageErrorCode.providerUnavailable
        }

        return NetworkExtensionTunnelProviderSession(session: session)
    }

    private static func defaultProviderBundleIdentifier() -> String {
        if let bundleID = Bundle.main.bundleIdentifier, bundleID.isEmpty == false {
            return "\(bundleID).PacketTunnelExtension"
        }

        return "su.24kvn.kvn-app.PacketTunnelExtension"
    }

    private static func loadAllManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: managers ?? [])
            }
        }
    }
}

nonisolated struct TunnelSentinelProviderConfiguration: Equatable, Sendable {
    static let diagnosticPurpose = "sharedKeychainSentinel"

    var schemaVersion: UInt32 = TunnelMessageProtocol.schemaVersion
    var diagnosticPurpose: String = Self.diagnosticPurpose

    var propertyList: [String: NSObject] {
        [
            "schemaVersion": NSNumber(value: schemaVersion),
            "diagnosticPurpose": diagnosticPurpose as NSString
        ]
    }
}

nonisolated protocol DiagnosticTunnelProviderManagerStore: Sendable {
    func loadAllManagers() async throws -> [any DiagnosticTunnelProviderManager]
    func makeManager() async throws -> any DiagnosticTunnelProviderManager
}

nonisolated protocol DiagnosticTunnelProviderManager: Sendable {
    func providerBundleIdentifier() async -> String?
    func providerConfigurationPropertyList() async -> [String: Any]?
    func prepareExistingForSentinel(providerBundleIdentifier: String) async
    func configureForSentinel(
        providerBundleIdentifier: String,
        configuration: TunnelSentinelProviderConfiguration
    ) async
    func configureForRuntimeValidation(
        providerBundleIdentifier: String,
        configuration: RuntimeProviderConfiguration
    ) async
    func saveToPreferences() async throws
    func loadFromPreferences() async throws
    func tunnelProviderSession() async throws -> any TunnelProviderSessionConnection
}

extension DiagnosticTunnelProviderManager {
    func configureForRuntimeValidation(
        providerBundleIdentifier: String,
        configuration: RuntimeProviderConfiguration
    ) async {
        await configureForSentinel(
            providerBundleIdentifier: providerBundleIdentifier,
            configuration: TunnelSentinelProviderConfiguration()
        )
    }
}

nonisolated final class NetworkExtensionDiagnosticTunnelProviderManagerStore: DiagnosticTunnelProviderManagerStore, @unchecked Sendable {
    func loadAllManagers() async throws -> [any DiagnosticTunnelProviderManager] {
        let managers: [NETunnelProviderManager] = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: managers ?? [])
            }
        }
        return managers.map { NetworkExtensionDiagnosticTunnelProviderManager(manager: $0) }
    }

    func makeManager() async throws -> any DiagnosticTunnelProviderManager {
        await MainActor.run {
            NetworkExtensionDiagnosticTunnelProviderManager(manager: NETunnelProviderManager())
        }
    }
}

nonisolated final class NetworkExtensionDiagnosticTunnelProviderManager: DiagnosticTunnelProviderManager, @unchecked Sendable {
    private let manager: NETunnelProviderManager

    init(manager: NETunnelProviderManager) {
        self.manager = manager
    }

    func providerBundleIdentifier() async -> String? {
        await MainActor.run {
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
        }
    }

    func providerConfigurationPropertyList() async -> [String: Any]? {
        await MainActor.run {
            (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        }
    }

    func prepareExistingForSentinel(providerBundleIdentifier: String) async {
        await MainActor.run {
            guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                return
            }
            tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
            manager.protocolConfiguration = tunnelProtocol
            manager.localizedDescription = "KVN Diagnostics"
            manager.isEnabled = true
        }
    }

    func configureForSentinel(
        providerBundleIdentifier: String,
        configuration: TunnelSentinelProviderConfiguration
    ) async {
        await MainActor.run {
            let tunnelProtocol: NETunnelProviderProtocol
            if let existing = manager.protocolConfiguration as? NETunnelProviderProtocol {
                tunnelProtocol = existing
            } else {
                tunnelProtocol = NETunnelProviderProtocol()
            }
            tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
            tunnelProtocol.providerConfiguration = configuration.propertyList
            tunnelProtocol.serverAddress = "KVN Shared Keychain Diagnostic"

            manager.protocolConfiguration = tunnelProtocol
            manager.localizedDescription = "KVN Diagnostics"
            manager.isEnabled = true
        }
    }

    func configureForRuntimeValidation(
        providerBundleIdentifier: String,
        configuration: RuntimeProviderConfiguration
    ) async {
        await MainActor.run {
            let tunnelProtocol: NETunnelProviderProtocol
            if let existing = manager.protocolConfiguration as? NETunnelProviderProtocol {
                tunnelProtocol = existing
            } else {
                tunnelProtocol = NETunnelProviderProtocol()
            }
            tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
            tunnelProtocol.providerConfiguration = configuration.propertyList
            tunnelProtocol.serverAddress = "KVN Runtime Configuration Validation"

            manager.protocolConfiguration = tunnelProtocol
            manager.localizedDescription = "KVN Diagnostics"
            manager.isEnabled = true
        }
    }

    func saveToPreferences() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            Task { @MainActor in
                manager.saveToPreferences { error in
                    if let error {
                        continuation.resume(throwing: error)
                        return
                    }
                    continuation.resume()
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
                        return
                    }
                    continuation.resume()
                }
            }
        }
    }

    func tunnelProviderSession() async throws -> any TunnelProviderSessionConnection {
        try await MainActor.run {
            guard let session = manager.connection as? NETunnelProviderSession else {
                throw TunnelMessageErrorCode.providerUnavailable
            }
            return NetworkExtensionTunnelProviderSession(session: session)
        }
    }
}

nonisolated private enum DiagnosticTunnelProviderManagerSelectionError: Error {
    case ambiguousStaleManagers
}

actor DiagnosticTunnelProviderSessionBootstrapper {
    private let managerStore: any DiagnosticTunnelProviderManagerStore
    private let providerBundleIdentifier: String

    init(
        managerStore: any DiagnosticTunnelProviderManagerStore = NetworkExtensionDiagnosticTunnelProviderManagerStore(),
        providerBundleIdentifier: String = PacketTunnelProviderRouting.wireGuardBundleIdentifier
    ) {
        self.managerStore = managerStore
        self.providerBundleIdentifier = providerBundleIdentifier
    }

    func sessionForSentinel() async throws -> DiagnosticTunnelProviderSessionBootstrapResult {
        try await configuredSession { manager, managerAction in
            switch managerAction {
            case .created:
                await manager.configureForSentinel(
                    providerBundleIdentifier: providerBundleIdentifier,
                    configuration: TunnelSentinelProviderConfiguration()
                )
            case .reused:
                await manager.prepareExistingForSentinel(providerBundleIdentifier: providerBundleIdentifier)
            case .none:
                break
            }
        }
    }

    func sessionForRuntimeValidation(providerConfiguration: RuntimeProviderConfiguration) async throws -> DiagnosticTunnelProviderSessionBootstrapResult {
        try await configuredSession(
            reconciling: providerConfiguration,
            configure: { manager, _ in
                await manager.configureForRuntimeValidation(
                    providerBundleIdentifier: providerBundleIdentifier,
                    configuration: providerConfiguration
                )
            },
            verifyAfterReload: { manager, managerAction in
                let persisted = await manager.providerConfigurationPropertyList()
                let parsed: RuntimeProviderConfiguration
                do {
                    parsed = try RuntimeProviderConfiguration.parse(persisted)
                } catch {
                    let category = Self.runtimeConfigurationCategory(for: error)
                    var providerDiagnostic = RuntimeProviderConfiguration.diagnostic(
                        for: persisted,
                        category: category
                    )
                    providerDiagnostic.appPersistedMatchesIntent = false
                    throw TunnelRuntimeConfigurationValidationFailure(
                        diagnostic: TunnelRuntimeConfigurationValidationDiagnostic(
                            stage: .providerConfiguration,
                            category: category,
                            extensionRequestReached: false,
                            providerConfiguration: providerDiagnostic
                        )
                    )
                }

                guard parsed == providerConfiguration else {
                    var providerDiagnostic = RuntimeProviderConfiguration.diagnostic(
                        for: persisted,
                        category: .providerConfigurationPersistedMismatch
                    )
                    providerDiagnostic.appPersistedMatchesIntent = false
                    throw TunnelRuntimeConfigurationValidationFailure(
                        diagnostic: TunnelRuntimeConfigurationValidationDiagnostic(
                            stage: .providerConfiguration,
                            category: .providerConfigurationPersistedMismatch,
                            extensionRequestReached: false,
                            providerConfiguration: providerDiagnostic
                        )
                    )
                }
            }
        )
    }

    private func configuredSession(
        reconciling desiredConfiguration: RuntimeProviderConfiguration? = nil,
        configure: @Sendable (any DiagnosticTunnelProviderManager, TunnelKeychainSentinelManagerAction) async -> Void,
        verifyAfterReload: (@Sendable (any DiagnosticTunnelProviderManager, TunnelKeychainSentinelManagerAction) async throws -> Void)? = nil
    ) async throws -> DiagnosticTunnelProviderSessionBootstrapResult {
        let managers: [any DiagnosticTunnelProviderManager]
        do {
            managers = try await managerStore.loadAllManagers()
        } catch {
            throw Self.failure(stage: .managerLoad, category: .managerLoadFailed, error: error)
        }

        let selected: any DiagnosticTunnelProviderManager
        let managerAction: TunnelKeychainSentinelManagerAction
        let existing: (any DiagnosticTunnelProviderManager)?
        do {
            existing = try await existingManager(
                in: managers,
                reconciling: desiredConfiguration
            )
        } catch {
            throw Self.failure(stage: .managerLoad, category: .managerLoadFailed, error: error)
        }
        if let existing {
            selected = existing
            managerAction = .reused
        } else {
            do {
                selected = try await managerStore.makeManager()
                managerAction = .created
            } catch {
                throw Self.failure(stage: .managerCreate, category: .managerCreateFailed, error: error)
            }
        }
        await configure(selected, managerAction)
        do {
            try await selected.saveToPreferences()
        } catch {
            throw Self.failure(
                stage: .managerSave,
                category: .managerSaveFailed,
                error: error,
                managerAction: managerAction
            )
        }
        do {
            try await selected.loadFromPreferences()
        } catch {
            throw Self.failure(
                stage: .managerReload,
                category: .managerReloadFailed,
                error: error,
                managerAction: managerAction
            )
        }

        let matchesProviderID = await selected.providerBundleIdentifier() == providerBundleIdentifier
        guard matchesProviderID else {
            throw Self.failure(
                stage: .providerSession,
                category: .providerBundleMismatch,
                managerAction: managerAction,
                providerBundleIDMatches: false
            )
        }

        if let verifyAfterReload {
            try await verifyAfterReload(selected, managerAction)
        }

        do {
            let session = try await selected.tunnelProviderSession()
            return DiagnosticTunnelProviderSessionBootstrapResult(
                session: session,
                managerAction: managerAction,
                providerBundleIDMatches: true
            )
        } catch {
            throw Self.failure(
                stage: .providerSession,
                category: .providerSessionUnavailable,
                error: error,
                managerAction: managerAction,
                providerBundleIDMatches: true
            )
        }
    }

    private func existingManager(
        in managers: [any DiagnosticTunnelProviderManager],
        reconciling desiredConfiguration: RuntimeProviderConfiguration?
    ) async throws -> (any DiagnosticTunnelProviderManager)? {
        for manager in managers {
            if await manager.providerBundleIdentifier() == providerBundleIdentifier {
                return manager
            }
        }

        guard let desiredConfiguration else {
            return nil
        }

        var eligibleStaleManagers: [any DiagnosticTunnelProviderManager] = []
        for manager in managers {
            let savedBundleIdentifier = await manager.providerBundleIdentifier()
            let propertyList = await manager.providerConfigurationPropertyList()
            let savedConfiguration = try? RuntimeProviderConfiguration.parse(propertyList)
            guard let session = try? await manager.tunnelProviderSession() else {
                continue
            }
            let status = await session.status()
            if TunnelProviderManagerReconciler.canRetarget(
                savedBundleIdentifier: savedBundleIdentifier,
                savedConfiguration: savedConfiguration,
                desiredBundleIdentifier: providerBundleIdentifier,
                desiredConfiguration: desiredConfiguration,
                status: status
            ) {
                eligibleStaleManagers.append(manager)
            }
        }

        guard eligibleStaleManagers.count <= 1 else {
            throw DiagnosticTunnelProviderManagerSelectionError.ambiguousStaleManagers
        }
        return eligibleStaleManagers.first
    }

    private static func runtimeConfigurationCategory(for error: any Error) -> TunnelRuntimeConfigurationValidationCategory {
        guard let error = error as? RuntimeConfigurationError else {
            return .unknown
        }
        return TunnelRuntimeConfigurationValidationCategory(rawValue: error.rawValue) ?? .unknown
    }

    private static func failure(
        stage: TunnelKeychainSentinelDiagnosticStage,
        category: TunnelKeychainSentinelDiagnosticCategory,
        error: (any Error)? = nil,
        managerAction: TunnelKeychainSentinelManagerAction = .none,
        providerBundleIDMatches: Bool? = nil
    ) -> TunnelKeychainSentinelDiagnosticFailure {
        var diagnostic = TunnelKeychainSentinelDiagnostic(
            stage: stage,
            status: .failed,
            category: category,
            managerAction: managerAction,
            providerBundleIDMatches: providerBundleIDMatches
        )
        if let error {
            let nsError = error as NSError
            diagnostic.errorDomain = nsError.domain
            diagnostic.errorCode = nsError.code
            diagnostic.errorSymbol = NetworkExtensionErrorSymbol.symbol(domain: nsError.domain, code: nsError.code)
        }
        return TunnelKeychainSentinelDiagnosticFailure(diagnostic: diagnostic)
    }
}

nonisolated struct DiagnosticTunnelProviderSessionBootstrapResult: Sendable {
    var session: any TunnelProviderSessionConnection
    var managerAction: TunnelKeychainSentinelManagerAction
    var providerBundleIDMatches: Bool
}

nonisolated struct TunnelRuntimeConfigurationValidationMessageResult: Sendable {
    var response: TunnelMessageResponse
    var diagnostic: TunnelRuntimeConfigurationValidationDiagnostic
}

nonisolated struct TunnelXrayConfigurationValidationMessageResult: Sendable {
    var response: TunnelMessageResponse
    var diagnostic: TunnelXrayConfigurationValidationDiagnostic
}

nonisolated struct TunnelXrayLifecycleSmokeTestMessageResult: Sendable {
    var response: TunnelMessageResponse
    var diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic
}

nonisolated struct TunnelXrayRemoteEgressProbeMessageResult: Sendable {
    var response: TunnelMessageResponse
    var diagnostic: TunnelXrayRemoteEgressProbeDiagnostic
}

nonisolated struct TunnelUDPControlProbeMessageResult: Sendable {
    var response: TunnelMessageResponse
    var diagnostic: TunnelUDPControlProbeDiagnostic
}

nonisolated struct TunnelLibXrayPingProbeMessageResult: Sendable {
    var response: TunnelMessageResponse
    var diagnostic: TunnelLibXrayPingProbeDiagnostic
}

nonisolated final class NetworkExtensionKeychainSentinelMessenger: TunnelKeychainSentinelMessaging, @unchecked Sendable {
    private let bootstrapper: DiagnosticTunnelProviderSessionBootstrapper
    private let timeout: Duration
    private let maximumResponseBytes: Int

    init(
        bootstrapper: DiagnosticTunnelProviderSessionBootstrapper = DiagnosticTunnelProviderSessionBootstrapper(),
        timeout: Duration = .seconds(3),
        maximumResponseBytes: Int = TunnelMessageProtocol.maximumResponseBytes
    ) {
        self.bootstrapper = bootstrapper
        self.timeout = timeout
        self.maximumResponseBytes = maximumResponseBytes
    }

    func sendKeychainSentinel(_ request: TunnelMessageRequest) async throws -> TunnelKeychainSentinelMessageResult {
        guard request.kind == .verifyKeychainSentinel else {
            throw TunnelMessageErrorCode.unsupportedRequest
        }
        guard case .keychainSentinel? = request.payload else {
            throw TunnelMessageErrorCode.malformedRequest
        }

        let bootstrap: DiagnosticTunnelProviderSessionBootstrapResult
        do {
            bootstrap = try await bootstrapper.sessionForSentinel()
        } catch let failure as TunnelKeychainSentinelDiagnosticFailure {
            throw failure
        } catch {
            throw Self.failure(stage: .managerLoad, category: .managerLoadFailed, error: error)
        }

        let status = await bootstrap.session.status()
        let messenger = NetworkExtensionTunnelMessenger(
            sessionProvider: SingleTunnelProviderSessionProvider(session: bootstrap.session),
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes
        )
        do {
            let response = try await messenger.sendDiagnostic(request)
            return TunnelKeychainSentinelMessageResult(
                response: response,
                diagnostic: TunnelKeychainSentinelDiagnostic(
                    stage: .providerMessageSend,
                    status: .succeeded,
                    vpnStatus: status.diagnosticValue,
                    managerAction: bootstrap.managerAction,
                    providerBundleIDMatches: bootstrap.providerBundleIDMatches,
                    extensionRequestReached: true
                )
            )
        } catch let code as TunnelMessageErrorCode {
            throw Self.failure(
                stage: code == .timeout ? .providerTimeout : .providerMessageSend,
                category: Self.category(for: code, status: status),
                vpnStatus: status,
                managerAction: bootstrap.managerAction,
                providerBundleIDMatches: bootstrap.providerBundleIDMatches
            )
        } catch {
            throw Self.failure(
                stage: .providerMessageSend,
                category: .providerMessageSendFailed,
                error: error,
                vpnStatus: status,
                managerAction: bootstrap.managerAction,
                providerBundleIDMatches: bootstrap.providerBundleIDMatches
            )
        }
    }

    private static func failure(
        stage: TunnelKeychainSentinelDiagnosticStage,
        category: TunnelKeychainSentinelDiagnosticCategory,
        error: (any Error)? = nil,
        vpnStatus: TunnelProviderSessionStatus? = nil,
        managerAction: TunnelKeychainSentinelManagerAction = .none,
        providerBundleIDMatches: Bool? = nil
    ) -> TunnelKeychainSentinelDiagnosticFailure {
        var diagnostic = TunnelKeychainSentinelDiagnostic(
            stage: stage,
            status: .failed,
            category: category,
            vpnStatus: vpnStatus?.diagnosticValue,
            managerAction: managerAction,
            providerBundleIDMatches: providerBundleIDMatches,
            extensionRequestReached: false
        )
        if let error {
            let nsError = error as NSError
            diagnostic.errorDomain = nsError.domain
            diagnostic.errorCode = nsError.code
            diagnostic.errorSymbol = NetworkExtensionErrorSymbol.symbol(domain: nsError.domain, code: nsError.code)
        }
        return TunnelKeychainSentinelDiagnosticFailure(diagnostic: diagnostic)
    }

    private static func category(
        for code: TunnelMessageErrorCode,
        status: TunnelProviderSessionStatus
    ) -> TunnelKeychainSentinelDiagnosticCategory {
        switch code {
        case .providerUnavailable where status == .disconnected:
            .providerNotRunningWhileDisconnected
        case .providerUnavailable:
            .providerUnavailable
        case .providerResponseMissing:
            .providerResponseMissing
        case .timeout:
            .providerTimeout
        case .schemaMismatch:
            .schemaMismatch
        case .requestIDMismatch:
            .requestIDMismatch
        case .invalidResponse:
            .invalidResponse
        case .malformedRequest:
            .malformedRequest
        case .keychainUnavailable:
            .keychainUnavailable
        default:
            .unknown
        }
    }
}

nonisolated final class NetworkExtensionRuntimeConfigurationValidationMessenger: TunnelRuntimeConfigurationValidationMessaging, TunnelXrayConfigurationValidationMessaging, TunnelXrayLifecycleSmokeTestMessaging, TunnelXrayRemoteEgressProbeMessaging, TunnelUDPControlProbeMessaging, TunnelLibXrayPingProbeMessaging, @unchecked Sendable {
    private let bootstrapper: DiagnosticTunnelProviderSessionBootstrapper
    private let activeSessionProvider: any TunnelProviderSessionProviding
    private let timeout: Duration
    private let maximumResponseBytes: Int

    init(
        bootstrapper: DiagnosticTunnelProviderSessionBootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        ),
        activeSessionProvider: any TunnelProviderSessionProviding = NetworkExtensionTunnelSessionProvider(
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        ),
        timeout: Duration = .seconds(3),
        maximumResponseBytes: Int = TunnelMessageProtocol.maximumResponseBytes
    ) {
        self.bootstrapper = bootstrapper
        self.activeSessionProvider = activeSessionProvider
        self.timeout = timeout
        self.maximumResponseBytes = maximumResponseBytes
    }

    func sendRuntimeConfigurationValidation(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelRuntimeConfigurationValidationMessageResult {
        guard request.kind == .validateRuntimeConfiguration else {
            throw TunnelMessageErrorCode.unsupportedRequest
        }
        guard case .runtimeConfigurationValidation? = request.payload else {
            throw TunnelMessageErrorCode.malformedRequest
        }

        let session: any TunnelProviderSessionConnection
        if request.kind == .probeActiveXrayEgress {
            session = try await activeSessionProvider.currentSession()
            let status = await session.status()
            guard status == .connected || status == .reasserting else {
                throw TunnelMessageErrorCode.providerUnavailable
            }
        } else {
            let bootstrap = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: providerConfiguration)
            session = bootstrap.session
        }
        let messenger = NetworkExtensionTunnelMessenger(
            sessionProvider: SingleTunnelProviderSessionProvider(session: session),
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes
        )
        do {
            let response = try await messenger.sendDiagnostic(request)
            return TunnelRuntimeConfigurationValidationMessageResult(
                response: response,
                diagnostic: TunnelRuntimeConfigurationValidationDiagnostic(
                    stage: .responseValidation,
                    category: .none,
                    extensionRequestReached: true
                )
            )
        } catch let code as TunnelMessageErrorCode {
            throw Self.failure(code: code, extensionReached: false)
        } catch {
            throw Self.failure(code: .unknown, extensionReached: false)
        }
    }

    func sendXrayConfigurationValidation(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelXrayConfigurationValidationMessageResult {
        guard request.kind == .validateXrayConfiguration else {
            throw TunnelMessageErrorCode.unsupportedRequest
        }
        guard case .xrayConfigurationValidation? = request.payload else {
            throw TunnelMessageErrorCode.malformedRequest
        }

        let bootstrap = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: providerConfiguration)
        let messenger = NetworkExtensionTunnelMessenger(
            sessionProvider: SingleTunnelProviderSessionProvider(session: bootstrap.session),
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes
        )
        do {
            let response = try await messenger.sendDiagnostic(request)
            return TunnelXrayConfigurationValidationMessageResult(
                response: response,
                diagnostic: TunnelXrayConfigurationValidationDiagnostic(
                    stage: .responseValidation,
                    category: .none,
                    extensionRequestReached: true
                )
            )
        } catch let code as TunnelMessageErrorCode {
            throw Self.xrayFailure(code: code, extensionReached: false)
        } catch {
            throw Self.xrayFailure(code: .unknown, extensionReached: false)
        }
    }

    func sendXrayLifecycleSmokeTest(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelXrayLifecycleSmokeTestMessageResult {
        guard request.kind == .runXrayLifecycleSmokeTest else {
            throw TunnelMessageErrorCode.unsupportedRequest
        }
        guard case .xrayLifecycleSmokeTest? = request.payload else {
            throw TunnelMessageErrorCode.malformedRequest
        }

        let bootstrap = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: providerConfiguration)
        let messenger = NetworkExtensionTunnelMessenger(
            sessionProvider: SingleTunnelProviderSessionProvider(session: bootstrap.session),
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes
        )
        do {
            let response = try await messenger.sendDiagnostic(request)
            return TunnelXrayLifecycleSmokeTestMessageResult(
                response: response,
                diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                    stage: .responseValidation,
                    category: .none,
                    extensionRequestReached: true
                )
            )
        } catch let code as TunnelMessageErrorCode {
            throw Self.lifecycleFailure(code: code, extensionReached: false)
        } catch {
            throw Self.lifecycleFailure(code: .unknown, extensionReached: false)
        }
    }

    func sendXrayRemoteEgressProbe(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelXrayRemoteEgressProbeMessageResult {
        guard request.kind == .runXrayRemoteEgressProbe || request.kind == .probeActiveXrayEgress else {
            throw TunnelMessageErrorCode.unsupportedRequest
        }
        guard case .xrayRemoteEgressProbe? = request.payload else {
            throw TunnelMessageErrorCode.malformedRequest
        }

        let bootstrap = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: providerConfiguration)
        let messenger = NetworkExtensionTunnelMessenger(
            sessionProvider: SingleTunnelProviderSessionProvider(session: bootstrap.session),
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes
        )
        do {
            let response = try await messenger.sendDiagnostic(request)
            return TunnelXrayRemoteEgressProbeMessageResult(
                response: response,
                diagnostic: TunnelXrayRemoteEgressProbeDiagnostic(
                    stage: .responseValidation,
                    category: .none,
                    extensionRequestReached: true
                )
            )
        } catch let code as TunnelMessageErrorCode {
            throw Self.remoteEgressFailure(code: code, extensionReached: false)
        } catch {
            throw Self.remoteEgressFailure(code: .unknown, extensionReached: false)
        }
    }

    func sendUDPControlProbe(_ request: TunnelMessageRequest) async throws -> TunnelUDPControlProbeMessageResult {
        guard request.kind == .runUDPControlProbe else {
            throw TunnelMessageErrorCode.unsupportedRequest
        }
        guard case .udpControlProbe? = request.payload else {
            throw TunnelMessageErrorCode.malformedRequest
        }

        let session = try await activeSessionProvider.currentSession()
        let status = await session.status()
        guard status == .connected || status == .reasserting else {
            throw TunnelMessageErrorCode.providerUnavailable
        }

        let messenger = NetworkExtensionTunnelMessenger(
            sessionProvider: SingleTunnelProviderSessionProvider(session: session),
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes
        )
        do {
            let response = try await messenger.sendDiagnostic(request)
            return TunnelUDPControlProbeMessageResult(
                response: response,
                diagnostic: TunnelUDPControlProbeDiagnostic(
                    category: .none,
                    extensionRequestReached: true
                )
            )
        } catch let code as TunnelMessageErrorCode {
            throw Self.udpControlFailure(code: code, extensionReached: false)
        } catch {
            throw Self.udpControlFailure(code: .unknown, extensionReached: false)
        }
    }

    func sendLibXrayPingProbe(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelLibXrayPingProbeMessageResult {
        guard request.kind == .runLibXrayPingProbe else {
            throw TunnelMessageErrorCode.unsupportedRequest
        }
        guard case .libXrayPingProbe? = request.payload else {
            throw TunnelMessageErrorCode.malformedRequest
        }

        let session = try await activeSessionProvider.currentSession()
        let status = await session.status()
        guard status == .connected || status == .reasserting else {
            throw TunnelMessageErrorCode.providerUnavailable
        }

        let messenger = NetworkExtensionTunnelMessenger(
            sessionProvider: SingleTunnelProviderSessionProvider(session: session),
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes
        )
        do {
            let response = try await messenger.sendDiagnostic(request)
            return TunnelLibXrayPingProbeMessageResult(
                response: response,
                diagnostic: TunnelLibXrayPingProbeDiagnostic(
                    stage: .responseValidation,
                    category: .none,
                    extensionRequestReached: true
                )
            )
        } catch let code as TunnelMessageErrorCode {
            throw Self.libXrayPingFailure(code: code, extensionReached: false)
        } catch {
            throw Self.libXrayPingFailure(code: .unknown, extensionReached: false)
        }
    }

    private static func failure(
        code: TunnelMessageErrorCode,
        extensionReached: Bool
    ) -> TunnelRuntimeConfigurationValidationFailure {
        let category: TunnelRuntimeConfigurationValidationCategory
        switch code {
        case .providerUnavailable:
            category = .providerUnavailable
        case .timeout:
            category = .providerTimeout
        case .invalidResponse:
            category = .invalidResponse
        case .requestIDMismatch:
            category = .requestIDMismatch
        default:
            category = .unknown
        }
        return TunnelRuntimeConfigurationValidationFailure(
            diagnostic: TunnelRuntimeConfigurationValidationDiagnostic(
                stage: .responseValidation,
                category: category,
                extensionRequestReached: extensionReached
            )
        )
    }

    private static func xrayFailure(
        code: TunnelMessageErrorCode,
        extensionReached: Bool
    ) -> TunnelXrayConfigurationValidationFailure {
        let category: TunnelXrayConfigurationValidationCategory
        switch code {
        case .providerUnavailable:
            category = .providerUnavailable
        case .timeout:
            category = .providerTimeout
        case .invalidResponse:
            category = .invalidResponse
        case .requestIDMismatch:
            category = .requestIDMismatch
        default:
            category = .unknown
        }
        return TunnelXrayConfigurationValidationFailure(
            diagnostic: TunnelXrayConfigurationValidationDiagnostic(
                stage: .responseValidation,
                category: category,
                extensionRequestReached: extensionReached
            )
        )
    }

    private static func lifecycleFailure(
        code: TunnelMessageErrorCode,
        extensionReached: Bool
    ) -> TunnelXrayLifecycleSmokeTestFailure {
        let category: TunnelXrayLifecycleSmokeTestCategory
        switch code {
        case .providerUnavailable:
            category = .providerUnavailable
        case .timeout:
            category = .providerTimeout
        case .invalidResponse:
            category = .invalidResponse
        case .requestIDMismatch:
            category = .requestIDMismatch
        default:
            category = .unknown
        }
        return TunnelXrayLifecycleSmokeTestFailure(
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .responseValidation,
                category: category,
                extensionRequestReached: extensionReached
            )
        )
    }

    private static func remoteEgressFailure(
        code: TunnelMessageErrorCode,
        extensionReached: Bool
    ) -> TunnelXrayRemoteEgressProbeFailure {
        let category: TunnelXrayRemoteEgressProbeCategory
        switch code {
        case .providerUnavailable:
            category = .providerUnavailable
        case .timeout:
            category = .providerTimeout
        case .invalidResponse:
            category = .invalidResponse
        case .requestIDMismatch:
            category = .requestIDMismatch
        default:
            category = .unknown
        }
        return TunnelXrayRemoteEgressProbeFailure(
            diagnostic: TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .responseValidation,
                category: category,
                extensionRequestReached: extensionReached
            )
        )
    }

    private static func udpControlFailure(
        code: TunnelMessageErrorCode,
        extensionReached: Bool
    ) -> TunnelUDPControlProbeFailure {
        let category: TunnelUDPControlProbeCategory
        switch code {
        case .providerUnavailable:
            category = .providerUnavailable
        case .timeout:
            category = .providerTimeout
        case .requestIDMismatch:
            category = .requestIDMismatch
        case .invalidResponse:
            category = .invalidResponse
        default:
            category = .unknown
        }
        return TunnelUDPControlProbeFailure(
            diagnostic: TunnelUDPControlProbeDiagnostic(
                category: category,
                extensionRequestReached: extensionReached
            )
        )
    }

    private static func libXrayPingFailure(
        code: TunnelMessageErrorCode,
        extensionReached: Bool
    ) -> TunnelLibXrayPingProbeFailure {
        let category: TunnelLibXrayPingProbeCategory
        switch code {
        case .providerUnavailable:
            category = .providerUnavailable
        case .timeout:
            category = .providerTimeout
        case .requestIDMismatch:
            category = .requestIDMismatch
        case .invalidResponse:
            category = .invalidResponse
        default:
            category = .unknown
        }
        return TunnelLibXrayPingProbeFailure(
            diagnostic: TunnelLibXrayPingProbeDiagnostic(
                stage: .responseValidation,
                category: category,
                extensionRequestReached: extensionReached
            )
        )
    }
}

private nonisolated struct SingleTunnelProviderSessionProvider: TunnelProviderSessionProviding {
    let session: any TunnelProviderSessionConnection

    func currentSession() async throws -> any TunnelProviderSessionConnection {
        session
    }
}

private nonisolated enum NetworkExtensionErrorSymbol {
    static func symbol(domain: String, code: Int) -> String? {
        guard domain == NEVPNErrorDomain else {
            return nil
        }

        guard let vpnCode = NEVPNError.Code(rawValue: code) else {
            return nil
        }

        switch vpnCode {
        case .configurationInvalid:
            return "configurationInvalid"
        case .configurationDisabled:
            return "configurationDisabled"
        case .connectionFailed:
            return "connectionFailed"
        case .configurationStale:
            return "configurationStale"
        case .configurationReadWriteFailed:
            return "configurationReadWriteFailed"
        case .configurationUnknown:
            return "configurationUnknown"
        @unknown default:
            return nil
        }
    }
}

nonisolated final class NetworkExtensionTunnelProviderSession: TunnelProviderSessionConnection, @unchecked Sendable {
    private let session: NETunnelProviderSession

    init(session: NETunnelProviderSession) {
        self.session = session
    }

    func status() async -> TunnelProviderSessionStatus {
        await MainActor.run {
            TunnelProviderSessionStatus(session.status)
        }
    }

    func sendProviderMessage(
        _ data: Data,
        responseHandler: @escaping @Sendable (Result<Data?, any Error>) -> Void
    ) {
        Task { @MainActor in
            do {
                try session.sendProviderMessage(data) { responseData in
                    responseHandler(.success(responseData))
                }
            } catch {
                responseHandler(.failure(error))
            }
        }
    }
}

#if DEBUG
extension NetworkExtensionTunnelProviderSession: RuntimeOnlyPacketTunnelSessionConnection {
    func startRuntimeOnlyTunnel(options: [String: NSObject]) async throws {
        try await MainActor.run {
            try session.startTunnel(options: options)
        }
    }

    func stopRuntimeOnlyTunnel() async {
        await MainActor.run {
            session.stopTunnel()
        }
    }
}
#endif

extension NetworkExtensionTunnelProviderSession: DataPlanePacketTunnelSessionConnection {
    func startDataPlaneTunnel(options: [String: NSObject]) async throws {
        try await MainActor.run {
            try session.startTunnel(options: options)
        }
    }

    func stopDataPlaneTunnel() async {
        await MainActor.run {
            session.stopTunnel()
        }
    }
}

#if DEBUG
extension NetworkExtensionTunnelProviderSession: LibXrayPingOnlyPacketTunnelSessionConnection {
    func startLibXrayPingOnlyTunnel(options: [String: NSObject]) async throws {
        try await MainActor.run {
            try session.startTunnel(options: options)
        }
    }

    func stopLibXrayPingOnlyTunnel() async {
        await MainActor.run {
            session.stopTunnel()
        }
    }
}

extension NetworkExtensionTunnelProviderSession: DiagnosticProviderRecoverySessionConnection {
    func stopDiagnosticProviderTunnel() async {
        await MainActor.run {
            session.stopTunnel()
        }
    }
}
#endif

private extension TunnelProviderSessionStatus {
    init(_ status: NEVPNStatus) {
        switch status {
        case .invalid:
            self = .invalid
        case .disconnected:
            self = .disconnected
        case .connecting:
            self = .connecting
        case .connected:
            self = .connected
        case .reasserting:
            self = .reasserting
        case .disconnecting:
            self = .disconnecting
        @unknown default:
            self = .unknown
        }
    }
}

extension TunnelMessageErrorCode {
    var localizationKey: String {
        switch self {
        case .malformedRequest:
            "diagnostics.telemetry.error.malformed_request"
        case .unsupportedRequest:
            "diagnostics.telemetry.error.unsupported_request"
        case .schemaMismatch:
            "diagnostics.telemetry.error.schema_mismatch"
        case .providerUnavailable:
            "diagnostics.telemetry.error.provider_unavailable"
        case .providerResponseMissing:
            "diagnostics.telemetry.error.response_missing"
        case .providerStatusNotConnected:
            "diagnostics.telemetry.error.not_connected"
        case .timeout:
            "diagnostics.telemetry.error.timeout"
        case .payloadTooLarge:
            "diagnostics.telemetry.error.payload_too_large"
        case .requestIDMismatch:
            "diagnostics.telemetry.error.request_id_mismatch"
        case .invalidResponse:
            "diagnostics.telemetry.error.invalid_response"
        case .keychainUnavailable:
            "diagnostics.telemetry.error.keychain_unavailable"
        case .unknown:
            "diagnostics.telemetry.error.unknown"
        }
    }
}
