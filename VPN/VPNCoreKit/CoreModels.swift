//
//  CoreModels.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated enum CoreProtocol: String, CaseIterable, Codable, Hashable, Sendable {
    case vless
    case trojan
    case hysteria2
    case wireGuard
    case shadowsocks
    case vmess
    case tuic
    case ikev2
}

nonisolated enum CoreState: String, Codable, Hashable, Sendable {
    case idle
    case preparing
    case ready
    case starting
    case running
    case stopping
    case stopped
    case failed
}

nonisolated struct CoreEndpoint: Codable, Hashable, Sendable {
    var host: String
    var port: Int
}

nonisolated enum CoreTransportConfiguration: Codable, Hashable, Sendable {
    case tcp(options: [String: String])
    case udp(options: [String: String])
    case websocket(path: String?, host: String?, options: [String: String])
    case grpc(serviceName: String?, options: [String: String])
    case httpUpgrade(path: String?, host: String?, options: [String: String])
    case xhttp(path: String?, host: String?, mode: String?, options: [String: String])
    case quic(options: [String: String])
}

nonisolated enum CoreSecurityConfiguration: Codable, Hashable, Sendable {
    case none
    case tls(CoreTLSConfiguration)
    case reality(CoreRealityConfiguration)
}

nonisolated struct CoreTLSConfiguration: Codable, Hashable, Sendable {
    var serverName: String?
    var allowInsecure: Bool
    var fingerprint: String?
}

nonisolated struct CoreRealityConfiguration: Codable, Hashable, Sendable {
    var serverName: String
    var fingerprint: String?
    var publicKeyReference: String
    var shortID: String
}

nonisolated struct CoreDNSConfiguration: Codable, Hashable, Sendable {
    var servers: [String]
}

nonisolated struct CoreRoutingConfiguration: Codable, Hashable, Sendable {
    var routeAllTraffic: Bool
    var excludedRoutes: [String]
}

nonisolated struct CoreConfiguration: Codable, Hashable, Sendable {
    var profileID: UUID
    var protocolType: CoreProtocol
    var endpoint: CoreEndpoint
    var transport: CoreTransportConfiguration
    var security: CoreSecurityConfiguration
    var dns: CoreDNSConfiguration
    var routing: CoreRoutingConfiguration
    var credentialReference: String
    var metadata: [String: String]
}

nonisolated struct CoreStatistics: Codable, Hashable, Sendable {
    var startedAt: Date?
    var bytesSent: Int64
    var bytesReceived: Int64
    var currentLatency: TimeInterval?
    var packetLoss: Double
    var reconnectCount: Int

    static let empty = CoreStatistics(
        startedAt: nil,
        bytesSent: 0,
        bytesReceived: 0,
        currentLatency: nil,
        packetLoss: 0,
        reconnectCount: 0
    )
}

nonisolated enum CoreEvent: Hashable, Sendable {
    case stateChanged(CoreState)
    case statisticsUpdated(CoreStatistics)
    case warning(String)
    case recoverableError(CoreError)
    case fatalError(CoreError)
}

nonisolated enum CoreError: LocalizedError, Hashable, Sendable {
    case invalidConfiguration(String)
    case unsupportedProtocol(CoreProtocol)
    case missingCredential
    case backendUnavailable(String)
    case alreadyRunning
    case notRunning
    case preparationFailed(String)
    case startupFailed(String)
    case cancelled

    var errorDescription: String? {
        switch self {
        case .invalidConfiguration(let message):
            "Invalid core configuration: \(message)"
        case .unsupportedProtocol(let coreProtocol):
            "Unsupported protocol: \(coreProtocol.rawValue)"
        case .missingCredential:
            "The profile credential is unavailable."
        case .backendUnavailable(let identifier):
            "Backend unavailable: \(identifier)"
        case .alreadyRunning:
            "The VPN core is already running."
        case .notRunning:
            "The VPN core is not running."
        case .preparationFailed(let message):
            "Core preparation failed: \(message)"
        case .startupFailed(let message):
            "Core startup failed: \(message)"
        case .cancelled:
            "The operation was cancelled."
        }
    }
}

extension CoreProtocol {
    init(vpnProtocol: VPNProtocol) {
        switch vpnProtocol {
        case .vless: self = .vless
        case .trojan: self = .trojan
        case .hysteria2: self = .hysteria2
        case .wireGuard: self = .wireGuard
        case .shadowsocks: self = .shadowsocks
        case .vmess: self = .vmess
        case .tuic: self = .tuic
        case .ikev2: self = .ikev2
        }
    }
}
