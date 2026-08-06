//
//  SimpleVPNLinkParser.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct SimpleVPNLinkParser {
    let credentialStore: CredentialStoring

    func parse(_ text: String, scheme: String) async throws -> VPNImportResult {
        let components = try ParserSupport.components(from: text)
        let host = try ParserSupport.requiredHost(from: components)
        let port = try ParserSupport.requiredPort(from: components, defaultPort: 443)
        let query = ParserSupport.queryDictionary(from: components)
        let name = ParserSupport.displayName(from: components, fallback: host)
        let credential = components.user ?? query["password"] ?? query["token"] ?? query["privateKey"]
        let credentialReference: String?
        if let credential {
            credentialReference = try await credentialStore.store(credential, label: "\(scheme) credential")
        } else {
            credentialReference = nil
        }
        let protocolType = protocolType(for: scheme)

        let profile = VPNProfile.draft(
            name: name,
            protocolType: protocolType,
            serverAddress: host,
            port: port,
            username: query["username"],
            credentialReference: credentialReference,
            transportSettings: VPNTransportSettings(network: query["type"], security: query["security"], metadata: query),
            tlsSettings: VPNTLSSettings(isEnabled: query["tls"] == "1" || query["security"] == "tls", serverName: query["sni"], allowInsecure: query["allowInsecure"] == "1"),
            protocolConfiguration: configuration(for: protocolType, query: query),
            source: .importedURL,
            metadata: query
        )

        return VPNImportResult(
            kind: .profile(profile),
            detectedScheme: scheme,
            displayName: name,
            sanitizedSummary: SecretMasker.sanitizedQuerySummary(from: components.queryItems ?? [])
                .merging(["credential": SecretMasker.masked(credential), "host": host, "port": "\(port)"]) { current, _ in current }
        )
    }

    private func protocolType(for scheme: String) -> VPNProtocol {
        switch scheme {
        case "wireguard":
            .wireGuard
        case "ikev2":
            .ikev2
        case "tuic":
            .tuic
        default:
            .vless
        }
    }

    private func configuration(for protocolType: VPNProtocol, query: [String: String]) -> VPNProtocolConfiguration {
        switch protocolType {
        case .wireGuard:
            .wireGuard(WireGuardProfileConfiguration(peerPublicKeyReference: nil, presharedKeyReference: nil, allowedIPs: query["allowedIPs"]?.components(separatedBy: ",") ?? []))
        case .ikev2:
            .ikev2(IKEv2ProfileConfiguration(remoteIdentifier: query["remoteID"], localIdentifier: query["localID"], authenticationMethod: query["auth"]))
        case .tuic:
            .tuic(TUICProfileConfiguration(congestionControl: query["congestion"], udpRelayMode: query["udpRelayMode"]))
        case .vless:
            .vless(VLESSProfileConfiguration(flow: query["flow"], encryption: query["encryption"]))
        case .hysteria2:
            .hysteria2(Hysteria2ProfileConfiguration(obfs: query["obfs"], bandwidthHint: query["bandwidth"]))
        case .trojan:
            .trojan(TrojanProfileConfiguration(alpn: []))
        case .shadowsocks:
            .shadowsocks(ShadowsocksProfileConfiguration(method: query["method"], plugin: query["plugin"]))
        case .vmess:
            .vmess(VMessProfileConfiguration(alterID: nil, security: query["security"]))
        }
    }
}
