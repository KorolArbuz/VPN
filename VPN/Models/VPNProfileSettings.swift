//
//  VPNProfileSettings.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct VPNTransportSettings: Codable, Hashable, Sendable {
    var network: String?
    var security: String?
    var path: String?
    var host: String?
    var serviceName: String?
    var metadata: [String: String]

    init(
        network: String? = nil,
        security: String? = nil,
        path: String? = nil,
        host: String? = nil,
        serviceName: String? = nil,
        metadata: [String: String] = [:]
    ) {
        self.network = network
        self.security = security
        self.path = path
        self.host = host
        self.serviceName = serviceName
        self.metadata = metadata
    }
}

nonisolated struct VPNTLSSettings: Codable, Hashable, Sendable {
    var isEnabled: Bool
    var serverName: String?
    var allowInsecure: Bool
    var fingerprint: String?
    var publicKeyReference: String?
    var shortID: String?

    init(
        isEnabled: Bool = false,
        serverName: String? = nil,
        allowInsecure: Bool = false,
        fingerprint: String? = nil,
        publicKeyReference: String? = nil,
        shortID: String? = nil
    ) {
        self.isEnabled = isEnabled
        self.serverName = serverName
        self.allowInsecure = allowInsecure
        self.fingerprint = fingerprint
        self.publicKeyReference = publicKeyReference
        self.shortID = shortID
    }
}

nonisolated struct VPNRoutingSettings: Codable, Hashable, Sendable {
    var routeAllTraffic: Bool
    var dnsServers: [String]
    var excludedRoutes: [String]

    init(routeAllTraffic: Bool = true, dnsServers: [String] = [], excludedRoutes: [String] = []) {
        self.routeAllTraffic = routeAllTraffic
        self.dnsServers = dnsServers
        self.excludedRoutes = excludedRoutes
    }
}

nonisolated enum VPNProtocolConfiguration: Codable, Hashable, Sendable {
    case wireGuard(WireGuardProfileConfiguration)
    case ikev2(IKEv2ProfileConfiguration)
    case vless(VLESSProfileConfiguration)
    case hysteria2(Hysteria2ProfileConfiguration)
    case trojan(TrojanProfileConfiguration)
    case shadowsocks(ShadowsocksProfileConfiguration)
    case tuic(TUICProfileConfiguration)
    case vmess(VMessProfileConfiguration)
}

nonisolated struct WireGuardProfileConfiguration: Codable, Hashable, Sendable {
    var peerPublicKeyReference: String?
    var presharedKeyReference: String?
    var allowedIPs: [String]
}

nonisolated struct IKEv2ProfileConfiguration: Codable, Hashable, Sendable {
    var remoteIdentifier: String?
    var localIdentifier: String?
    var authenticationMethod: String?
}

nonisolated struct VLESSProfileConfiguration: Codable, Hashable, Sendable {
    var flow: String?
    var encryption: String?
}

nonisolated struct Hysteria2ProfileConfiguration: Codable, Hashable, Sendable {
    var obfs: String?
    var bandwidthHint: String?
}

nonisolated struct TrojanProfileConfiguration: Codable, Hashable, Sendable {
    var alpn: [String]
}

nonisolated struct ShadowsocksProfileConfiguration: Codable, Hashable, Sendable {
    var method: String?
    var plugin: String?
}

nonisolated struct TUICProfileConfiguration: Codable, Hashable, Sendable {
    var congestionControl: String?
    var udpRelayMode: String?
}

nonisolated struct VMessProfileConfiguration: Codable, Hashable, Sendable {
    var alterID: Int?
    var security: String?
}
