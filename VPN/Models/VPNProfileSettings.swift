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
    var alpn: [String]?
    var realityPublicKey: String?
    var publicKeyReference: String?
    var shortID: String?
    var spiderX: String?

    init(
        isEnabled: Bool = false,
        serverName: String? = nil,
        allowInsecure: Bool = false,
        fingerprint: String? = nil,
        alpn: [String]? = nil,
        realityPublicKey: String? = nil,
        publicKeyReference: String? = nil,
        shortID: String? = nil,
        spiderX: String? = nil
    ) {
        self.isEnabled = isEnabled
        self.serverName = serverName
        self.allowInsecure = allowInsecure
        self.fingerprint = fingerprint
        self.alpn = alpn
        self.realityPublicKey = realityPublicKey
        self.publicKeyReference = publicKeyReference
        self.shortID = shortID
        self.spiderX = spiderX
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
    case amneziaWG(WireGuardProfileConfiguration)
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
    var interfaceAddresses: [String]
    var dnsServers: [String]
    var dnsSearchDomains: [String]
    var listenPort: UInt16?
    var mtu: UInt16?
    var peers: [WireGuardPeerProfileConfiguration]
    var headerProtectionKeyReference: String?
    var amnezia: AmneziaWGProfileParameters?

    init(
        peerPublicKeyReference: String? = nil,
        presharedKeyReference: String? = nil,
        allowedIPs: [String] = [],
        interfaceAddresses: [String] = [],
        dnsServers: [String] = [],
        dnsSearchDomains: [String] = [],
        listenPort: UInt16? = nil,
        mtu: UInt16? = nil,
        peers: [WireGuardPeerProfileConfiguration] = [],
        headerProtectionKeyReference: String? = nil,
        amnezia: AmneziaWGProfileParameters? = nil
    ) {
        self.peerPublicKeyReference = peerPublicKeyReference
        self.presharedKeyReference = presharedKeyReference
        self.allowedIPs = allowedIPs
        self.interfaceAddresses = interfaceAddresses
        self.dnsServers = dnsServers
        self.dnsSearchDomains = dnsSearchDomains
        self.listenPort = listenPort
        self.mtu = mtu
        self.peers = peers
        self.headerProtectionKeyReference = headerProtectionKeyReference
        self.amnezia = amnezia
    }

    private enum CodingKeys: String, CodingKey {
        case peerPublicKeyReference
        case presharedKeyReference
        case allowedIPs
        case interfaceAddresses
        case dnsServers
        case dnsSearchDomains
        case listenPort
        case mtu
        case peers
        case headerProtectionKeyReference
        case amnezia
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        peerPublicKeyReference = try container.decodeIfPresent(String.self, forKey: .peerPublicKeyReference)
        presharedKeyReference = try container.decodeIfPresent(String.self, forKey: .presharedKeyReference)
        allowedIPs = try container.decodeIfPresent([String].self, forKey: .allowedIPs) ?? []
        interfaceAddresses = try container.decodeIfPresent([String].self, forKey: .interfaceAddresses) ?? []
        dnsServers = try container.decodeIfPresent([String].self, forKey: .dnsServers) ?? []
        dnsSearchDomains = try container.decodeIfPresent([String].self, forKey: .dnsSearchDomains) ?? []
        listenPort = try container.decodeIfPresent(UInt16.self, forKey: .listenPort)
        mtu = try container.decodeIfPresent(UInt16.self, forKey: .mtu)
        peers = try container.decodeIfPresent([WireGuardPeerProfileConfiguration].self, forKey: .peers) ?? []
        headerProtectionKeyReference = try container.decodeIfPresent(String.self, forKey: .headerProtectionKeyReference)
        amnezia = try container.decodeIfPresent(AmneziaWGProfileParameters.self, forKey: .amnezia)
    }
}

nonisolated struct WireGuardEndpointProfileConfiguration: Codable, Hashable, Sendable {
    var host: String
    var port: UInt16
}

nonisolated struct WireGuardPeerProfileConfiguration: Codable, Hashable, Sendable {
    var publicKey: String
    var presharedKeyReference: String?
    var allowedIPs: [String]
    var excludedIPs: [String]
    var endpoint: WireGuardEndpointProfileConfiguration?
    var persistentKeepAlive: String?

    init(
        publicKey: String,
        presharedKeyReference: String? = nil,
        allowedIPs: [String],
        excludedIPs: [String] = [],
        endpoint: WireGuardEndpointProfileConfiguration? = nil,
        persistentKeepAlive: String? = nil
    ) {
        self.publicKey = publicKey
        self.presharedKeyReference = presharedKeyReference
        self.allowedIPs = allowedIPs
        self.excludedIPs = excludedIPs
        self.endpoint = endpoint
        self.persistentKeepAlive = persistentKeepAlive
    }
}

nonisolated struct AmneziaWGProfileParameters: Codable, Hashable, Sendable {
    var junkPacketCount: UInt16? = nil
    var junkPacketMinSize: UInt16? = nil
    var junkPacketMaxSize: UInt16? = nil
    var initPacketJunkSize: UInt16? = nil
    var responsePacketJunkSize: UInt16? = nil
    var cookieReplyPacketJunkSize: UInt16? = nil
    var transportPacketJunkSize: UInt16? = nil
    var initPacketMagicHeader: String? = nil
    var responsePacketMagicHeader: String? = nil
    var underloadPacketMagicHeader: String? = nil
    var transportPacketMagicHeader: String? = nil
    var specialJunk1: String? = nil
    var specialJunk2: String? = nil
    var specialJunk3: String? = nil
    var specialJunk4: String? = nil
    var specialJunk5: String? = nil
    var contentPaddingAddition: String? = nil
    var rekeyAfterTime: String? = nil
    var rekeyTimeout: String? = nil
    var rejectAfterTime: String? = nil
    var keepaliveTimeout: String? = nil
    var maxHandshakeAttempts: String? = nil
    var randomTrailers: String? = nil
    var disableCookies: String? = nil

    var hasAnyValue: Bool {
        junkPacketCount != nil
            || junkPacketMinSize != nil
            || junkPacketMaxSize != nil
            || initPacketJunkSize != nil
            || responsePacketJunkSize != nil
            || cookieReplyPacketJunkSize != nil
            || transportPacketJunkSize != nil
            || initPacketMagicHeader != nil
            || responsePacketMagicHeader != nil
            || underloadPacketMagicHeader != nil
            || transportPacketMagicHeader != nil
            || specialJunk1 != nil
            || specialJunk2 != nil
            || specialJunk3 != nil
            || specialJunk4 != nil
            || specialJunk5 != nil
            || contentPaddingAddition != nil
            || rekeyAfterTime != nil
            || rekeyTimeout != nil
            || rejectAfterTime != nil
            || keepaliveTimeout != nil
            || maxHandshakeAttempts != nil
            || randomTrailers != nil
            || disableCookies != nil
    }
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
    var obfsPasswordReference: String?

    init(
        obfs: String? = nil,
        bandwidthHint: String? = nil,
        obfsPasswordReference: String? = nil
    ) {
        self.obfs = obfs
        self.bandwidthHint = bandwidthHint
        self.obfsPasswordReference = obfsPasswordReference
    }
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
