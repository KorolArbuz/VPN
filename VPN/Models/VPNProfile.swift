//
//  VPNProfile.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct VPNProfile: Identifiable, Codable, Hashable, Sendable {
    var id: UUID
    var name: String
    var protocolType: VPNProtocol
    var serverAddress: String
    var port: Int?
    var username: String?
    var credentialReference: String?
    var transportSettings: VPNTransportSettings
    var tlsSettings: VPNTLSSettings
    var routingSettings: VPNRoutingSettings
    var protocolConfiguration: VPNProtocolConfiguration
    var source: VPNProfileSource
    var createdAt: Date
    var updatedAt: Date
    var isEnabled: Bool
    var metadata: [String: String]
    var sourceSubscriptionID: UUID?
    var externalIdentity: String?
    var importedAt: Date?
    var lastSeenAt: Date?
    var customDisplayName: String?
    var isFavorite: Bool?
    var localNotes: String?

    var isComplete: Bool {
        missingRequiredFields.isEmpty
    }

    var missingRequiredFields: [String] {
        var missing: [String] = []

        if serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            missing.append("server address")
        }

        if port == nil {
            missing.append("port")
        }

        switch protocolType {
        case .wireGuard:
            if credentialReference == nil {
                missing.append("private key reference")
            }
        case .ikev2:
            if username == nil {
                missing.append("username")
            }
            if credentialReference == nil {
                missing.append("credential reference")
            }
        case .vless, .hysteria2, .trojan, .shadowsocks, .tuic, .vmess:
            if credentialReference == nil {
                missing.append("credential reference")
            }
        }

        return missing
    }

    static func draft(
        name: String,
        protocolType: VPNProtocol,
        serverAddress: String,
        port: Int?,
        username: String? = nil,
        credentialReference: String? = nil,
        transportSettings: VPNTransportSettings = VPNTransportSettings(),
        tlsSettings: VPNTLSSettings = VPNTLSSettings(),
        routingSettings: VPNRoutingSettings = VPNRoutingSettings(),
        protocolConfiguration: VPNProtocolConfiguration,
        source: VPNProfileSource,
        metadata: [String: String] = [:],
        now: Date = Date()
    ) -> VPNProfile {
        VPNProfile(
            id: UUID(),
            name: name,
            protocolType: protocolType,
            serverAddress: serverAddress,
            port: port,
            username: username,
            credentialReference: credentialReference,
            transportSettings: transportSettings,
            tlsSettings: tlsSettings,
            routingSettings: routingSettings,
            protocolConfiguration: protocolConfiguration,
            source: source,
            createdAt: now,
            updatedAt: now,
            isEnabled: true,
            metadata: metadata,
            sourceSubscriptionID: nil,
            externalIdentity: nil,
            importedAt: nil,
            lastSeenAt: nil,
            customDisplayName: nil,
            isFavorite: nil,
            localNotes: nil
        )
    }

    static func bundledMock(server: VPNServer, protocolType: VPNProtocol) -> VPNProfile {
        VPNProfile.draft(
            name: server.name,
            protocolType: protocolType,
            serverAddress: server.hostname,
            port: 443,
            credentialReference: "mock-bundled-profile",
            transportSettings: VPNTransportSettings(network: "mock"),
            tlsSettings: VPNTLSSettings(isEnabled: true, serverName: server.hostname),
            protocolConfiguration: mockConfiguration(for: protocolType),
            source: .bundledMock
        )
    }

    private static func mockConfiguration(for protocolType: VPNProtocol) -> VPNProtocolConfiguration {
        switch protocolType {
        case .wireGuard:
            .wireGuard(WireGuardProfileConfiguration(peerPublicKeyReference: nil, presharedKeyReference: nil, allowedIPs: ["0.0.0.0/0"]))
        case .ikev2:
            .ikev2(IKEv2ProfileConfiguration(remoteIdentifier: nil, localIdentifier: nil, authenticationMethod: "mock"))
        case .vless:
            .vless(VLESSProfileConfiguration(flow: nil, encryption: "none"))
        case .hysteria2:
            .hysteria2(Hysteria2ProfileConfiguration(obfs: nil, bandwidthHint: nil))
        case .trojan:
            .trojan(TrojanProfileConfiguration(alpn: []))
        case .shadowsocks:
            .shadowsocks(ShadowsocksProfileConfiguration(method: "mock", plugin: nil))
        case .tuic:
            .tuic(TUICProfileConfiguration(congestionControl: nil, udpRelayMode: nil))
        case .vmess:
            .vmess(VMessProfileConfiguration(alterID: nil, security: nil))
        }
    }
}
