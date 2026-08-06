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
    func connect(using profile: VPNProfile) async throws -> ConnectionMetrics
    func disconnect() async
}

nonisolated protocol ServerSelecting: Sendable {
    func bestServer(from servers: [VPNServer], using prober: ServerProbing) async throws -> VPNServer
    func automaticProtocol(for server: VPNServer) -> VPNProtocol?
}
