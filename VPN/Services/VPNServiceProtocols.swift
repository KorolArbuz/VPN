//
//  VPNServiceProtocols.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated protocol ServerProviding: Sendable {
    func fetchServers() async throws -> [VPNServer]
}

nonisolated protocol ServerProbing: Sendable {
    func metrics(for server: VPNServer) async throws -> ConnectionMetrics
}

nonisolated protocol VPNConnectionManaging: Sendable {
    func currentState() async -> VPNConnectionState
    func stateUpdates() -> AsyncStream<VPNConnectionState>
    func authoritativeConnection() async -> VPNAuthoritativeConnection
    func refreshAuthoritativeConnection() async -> VPNAuthoritativeConnection
    func connect(using profile: VPNProfile) async throws
    func disconnect() async
    func routesTrafficThroughProductionCore(using profile: VPNProfile) -> Bool
}

extension VPNConnectionManaging {
    func authoritativeConnection() async -> VPNAuthoritativeConnection {
        VPNAuthoritativeConnection(
            state: await currentState(),
            systemStatus: nil,
            profileID: nil,
            provider: nil,
            hasMultipleActiveManagers: false
        )
    }

    func refreshAuthoritativeConnection() async -> VPNAuthoritativeConnection {
        await authoritativeConnection()
    }

    nonisolated func routesTrafficThroughProductionCore(using profile: VPNProfile) -> Bool {
        false
    }
}

nonisolated protocol ServerSelecting: Sendable {
    func bestServer(from servers: [VPNServer], using prober: ServerProbing) async throws -> VPNServer
    func automaticProtocol(for server: VPNServer) -> VPNProtocol?
}
