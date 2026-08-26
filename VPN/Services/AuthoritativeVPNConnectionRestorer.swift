//
//  AuthoritativeVPNConnectionRestorer.swift
//  VPN
//
//  Reconciles dashboard state with the saved Network Extension managers.
//

import Foundation
import NetworkExtension
import OSLog

nonisolated enum VPNSystemConnectionStatus: String, Codable, Equatable, Sendable {
    case connected
    case connecting
    case reasserting
    case disconnecting
    case disconnected
    case invalid

    var isActive: Bool {
        switch self {
        case .connected, .connecting, .reasserting, .disconnecting:
            true
        case .disconnected, .invalid:
            false
        }
    }

    var dashboardState: VPNConnectionState {
        switch self {
        case .connected:
            .connected
        case .connecting, .reasserting:
            .connecting
        case .disconnecting:
            .disconnecting
        case .disconnected:
            .disconnected
        case .invalid:
            .failed
        }
    }

    init(_ status: NEVPNStatus) {
        switch status {
        case .connected:
            self = .connected
        case .connecting:
            self = .connecting
        case .reasserting:
            self = .reasserting
        case .disconnecting:
            self = .disconnecting
        case .disconnected:
            self = .disconnected
        case .invalid:
            self = .invalid
        @unknown default:
            self = .invalid
        }
    }
}

nonisolated struct VPNAuthoritativeConnection: Equatable, Sendable {
    var state: VPNConnectionState
    var systemStatus: VPNSystemConnectionStatus?
    var profileID: UUID?
    var provider: PacketTunnelProviderKind?
    var hasMultipleActiveManagers: Bool

    static let disconnected = VPNAuthoritativeConnection(
        state: .disconnected,
        systemStatus: .disconnected,
        profileID: nil,
        provider: nil,
        hasMultipleActiveManagers: false
    )

    var isSystemActive: Bool {
        systemStatus?.isActive == true
    }
}

nonisolated struct AuthoritativeTunnelManagerSnapshot: Equatable, Sendable {
    var managerIdentifier: String
    var providerBundleIdentifier: String?
    var profileID: UUID?
    var status: VPNSystemConnectionStatus

    var provider: PacketTunnelProviderKind? {
        guard let providerBundleIdentifier else {
            return nil
        }
        return PacketTunnelProviderRouting.provider(forBundleIdentifier: providerBundleIdentifier)
    }

    var observerKey: String {
        if let providerBundleIdentifier, let profileID {
            return providerBundleIdentifier + "|" + profileID.uuidString
        }
        return managerIdentifier
    }
}

nonisolated protocol AuthoritativeTunnelManagerControlling: AnyObject, Sendable {
    func snapshot() async -> AuthoritativeTunnelManagerSnapshot
    func observeStatusChanges(_ handler: @escaping @Sendable () -> Void) async
    func removeStatusObserver() async
    func stopTunnel() async
}

nonisolated protocol AuthoritativeTunnelManagerLoading: Sendable {
    func loadAllManagers() async throws -> [any AuthoritativeTunnelManagerControlling]
}

nonisolated final class NetworkExtensionAuthoritativeTunnelManagerLoader:
    AuthoritativeTunnelManagerLoading,
    @unchecked Sendable
{
    func loadAllManagers() async throws -> [any AuthoritativeTunnelManagerControlling] {
        let managers: [NETunnelProviderManager] = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            Task { @MainActor in
                NETunnelProviderManager.loadAllFromPreferences { managers, error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(returning: managers ?? [])
                    }
                }
            }
        }

        return managers.map(NetworkExtensionAuthoritativeTunnelManager.init)
    }
}

nonisolated private final class NetworkExtensionAuthoritativeTunnelManager:
    AuthoritativeTunnelManagerControlling,
    @unchecked Sendable
{
    private let manager: NETunnelProviderManager
    private let managerIdentifier: String
    private var statusObserver: NSObjectProtocol?

    init(manager: NETunnelProviderManager) {
        self.manager = manager
        managerIdentifier = String(ObjectIdentifier(manager).hashValue)
    }

    func snapshot() async -> AuthoritativeTunnelManagerSnapshot {
        await MainActor.run {
            let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol
            let providerConfiguration = try? RuntimeProviderConfiguration.parse(
                tunnelProtocol?.providerConfiguration
            )
            return AuthoritativeTunnelManagerSnapshot(
                managerIdentifier: managerIdentifier,
                providerBundleIdentifier: tunnelProtocol?.providerBundleIdentifier,
                profileID: providerConfiguration?.profileID,
                status: VPNSystemConnectionStatus(manager.connection.status)
            )
        }
    }

    func observeStatusChanges(_ handler: @escaping @Sendable () -> Void) async {
        await MainActor.run {
            if let statusObserver {
                NotificationCenter.default.removeObserver(statusObserver)
            }
            statusObserver = NotificationCenter.default.addObserver(
                forName: .NEVPNStatusDidChange,
                object: manager.connection,
                queue: .main
            ) { _ in
                handler()
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

    func stopTunnel() async {
        await MainActor.run {
            manager.connection.stopVPNTunnel()
        }
    }

    deinit {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }
}

actor AuthoritativeVPNConnectionRestorer {
    private struct ActiveManager {
        var controller: any AuthoritativeTunnelManagerControlling
        var snapshot: AuthoritativeTunnelManagerSnapshot
    }

    private static let logger = Logger(
        subsystem: "su.24kvn.kvn-app",
        category: "AuthoritativeConnection"
    )

    private let loader: any AuthoritativeTunnelManagerLoading
    private var currentConnection: VPNAuthoritativeConnection = .disconnected
    private var observedManagers: [String: any AuthoritativeTunnelManagerControlling] = [:]
    private var continuations: [UUID: AsyncStream<VPNAuthoritativeConnection>.Continuation] = [:]

    init(
        loader: any AuthoritativeTunnelManagerLoading =
            NetworkExtensionAuthoritativeTunnelManagerLoader()
    ) {
        self.loader = loader
    }

    nonisolated func updates() -> AsyncStream<VPNAuthoritativeConnection> {
        AsyncStream { continuation in
            Task {
                let id = UUID()
                await addContinuation(continuation, id: id)
                continuation.onTermination = { _ in
                    Task {
                        await self.removeContinuation(id: id)
                    }
                }
            }
        }
    }

    func current() -> VPNAuthoritativeConnection {
        currentConnection
    }

    @discardableResult
    func refresh(attachStatusObservers: Bool = true) async -> VPNAuthoritativeConnection {
        Self.logger.notice("authoritativeStatusRefreshStarted")
        do {
            let managers = try await loader.loadAllManagers()
            let result = await reconcile(
                managers: managers,
                attachStatusObservers: attachStatusObservers,
                publishWhenNoActiveManager: true
            )
            Self.logger.notice(
                "authoritativeStatusRefreshCompleted status=\(result.systemStatus?.rawValue ?? "none", privacy: .public) profile=\(result.profileID?.uuidString ?? "-", privacy: .public) provider=\(result.provider?.rawValue ?? "-", privacy: .public)"
            )
            return result
        } catch {
            let nsError = error as NSError
            Self.logger.error(
                "authoritativeStatusRefreshCompleted status=loadFailed error=\(nsError.domain, privacy: .public)/\(nsError.code, privacy: .public)"
            )
            return currentConnection
        }
    }

    @discardableResult
    func bindAfterUserStart(
        profileID: UUID,
        provider: PacketTunnelProviderKind
    ) async -> VPNAuthoritativeConnection? {
        do {
            let managers = try await loader.loadAllManagers()
            let result = await reconcile(
                managers: managers,
                attachStatusObservers: true,
                publishWhenNoActiveManager: false
            )
            guard result.profileID == profileID,
                  result.provider == provider,
                  result.isSystemActive else {
                return nil
            }
            return result
        } catch {
            return nil
        }
    }

    func stopAuthoritativeConnection() async -> Bool {
        guard currentConnection.hasMultipleActiveManagers == false,
              let provider = currentConnection.provider,
              let profileID = currentConnection.profileID else {
            return false
        }

        let key = PacketTunnelProviderRouting.bundleIdentifier(for: provider)
            + "|"
            + profileID.uuidString
        guard let manager = observedManagers[key] else {
            _ = await refresh()
            guard let refreshedManager = observedManagers[key] else {
                return false
            }
            await refreshedManager.stopTunnel()
            return true
        }

        await manager.stopTunnel()
        return true
    }

    private func reconcile(
        managers: [any AuthoritativeTunnelManagerControlling],
        attachStatusObservers: Bool,
        publishWhenNoActiveManager: Bool
    ) async -> VPNAuthoritativeConnection {
        var activeManagers: [ActiveManager] = []
        for manager in managers {
            let snapshot = await manager.snapshot()
            guard snapshot.status.isActive,
                  snapshot.provider != nil,
                  snapshot.profileID != nil else {
                continue
            }
            activeManagers.append(ActiveManager(controller: manager, snapshot: snapshot))
        }
        activeManagers.sort {
            if $0.snapshot.observerKey == $1.snapshot.observerKey {
                return $0.snapshot.managerIdentifier < $1.snapshot.managerIdentifier
            }
            return $0.snapshot.observerKey < $1.snapshot.observerKey
        }

        if attachStatusObservers {
            await reconcileObservers(with: activeManagers)
        }

        let connection: VPNAuthoritativeConnection
        switch activeManagers.count {
        case 0:
            if attachStatusObservers {
                await removeAllObservers()
            }
            guard publishWhenNoActiveManager else {
                return currentConnection
            }
            connection = .disconnected
        case 1:
            let active = activeManagers[0].snapshot
            connection = VPNAuthoritativeConnection(
                state: active.status.dashboardState,
                systemStatus: active.status,
                profileID: active.profileID,
                provider: active.provider,
                hasMultipleActiveManagers: false
            )
            Self.logger.notice(
                "activeManagerRestored profile=\(active.profileID?.uuidString ?? "-", privacy: .public) provider=\(active.provider?.rawValue ?? "-", privacy: .public) status=\(active.status.rawValue, privacy: .public)"
            )
            Self.logger.notice(
                "activeProfileRestored profile=\(active.profileID?.uuidString ?? "-", privacy: .public)"
            )
        default:
            connection = VPNAuthoritativeConnection(
                state: .failed,
                systemStatus: nil,
                profileID: nil,
                provider: nil,
                hasMultipleActiveManagers: true
            )
            let managerKeys = activeManagers.map(\.snapshot.observerKey).joined(separator: ",")
            Self.logger.error(
                "authoritativeStatusRefreshCompleted status=multipleActiveManagers managers=\(managerKeys, privacy: .public)"
            )
        }

        publish(connection)
        return connection
    }

    private func reconcileObservers(with activeManagers: [ActiveManager]) async {
        var desired: [String: ActiveManager] = [:]
        for active in activeManagers where desired[active.snapshot.observerKey] == nil {
            desired[active.snapshot.observerKey] = active
        }

        for (key, manager) in observedManagers where desired[key] == nil {
            await manager.removeStatusObserver()
            observedManagers[key] = nil
        }

        for (key, active) in desired where observedManagers[key] == nil {
            observedManagers[key] = active.controller
            await active.controller.observeStatusChanges { [weak self] in
                Task {
                    await self?.refresh()
                }
            }
        }
    }

    private func removeAllObservers() async {
        let managers = Array(observedManagers.values)
        observedManagers.removeAll()
        for manager in managers {
            await manager.removeStatusObserver()
        }
    }

    private func publish(_ connection: VPNAuthoritativeConnection) {
        guard currentConnection != connection else {
            return
        }
        currentConnection = connection
        continuations.values.forEach { $0.yield(connection) }
    }

    private func addContinuation(
        _ continuation: AsyncStream<VPNAuthoritativeConnection>.Continuation,
        id: UUID
    ) {
        continuations[id] = continuation
    }

    private func removeContinuation(id: UUID) {
        continuations[id] = nil
    }
}
