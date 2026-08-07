//
//  ProfileConfigurationCompiler.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated protocol ProfileConfigurationCompiling: Sendable {
    func compile(profile: VPNProfile) throws -> CoreConfiguration
}

nonisolated struct VLESSProfileConfigurationCompiler: ProfileConfigurationCompiling {
    func compile(profile: VPNProfile) throws -> CoreConfiguration {
        guard profile.protocolType == .vless else {
            throw CoreError.unsupportedProtocol(CoreProtocol(vpnProtocol: profile.protocolType))
        }

        let host = profile.serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard host.isEmpty == false, host.contains(" ") == false else {
            throw CoreError.invalidConfiguration("Host is missing or malformed.")
        }
        guard let port = profile.port, (1...65_535).contains(port) else {
            throw CoreError.invalidConfiguration("Port must be in range 1...65535.")
        }
        guard let credentialReference = profile.credentialReference, credentialReference.isEmpty == false else {
            throw CoreError.missingCredential
        }

        return CoreConfiguration(
            profileID: profile.id,
            protocolType: .vless,
            endpoint: CoreEndpoint(host: host, port: port),
            transport: try compileTransport(profile: profile),
            security: try compileSecurity(profile: profile),
            dns: CoreDNSConfiguration(servers: profile.routingSettings.dnsServers),
            routing: CoreRoutingConfiguration(
                routeAllTraffic: profile.routingSettings.routeAllTraffic,
                excludedRoutes: profile.routingSettings.excludedRoutes
            ),
            credentialReference: credentialReference,
            metadata: profile.metadata
        )
    }

    private func compileTransport(profile: VPNProfile) throws -> CoreTransportConfiguration {
        let network = profile.transportSettings.network?.lowercased() ?? "tcp"
        let metadata = profile.transportSettings.metadata

        switch network {
        case "tcp":
            return .tcp(options: metadata)
        case "udp":
            return .udp(options: metadata)
        case "ws", "websocket":
            return .websocket(path: profile.transportSettings.path, host: profile.transportSettings.host, options: metadata)
        case "grpc":
            return .grpc(serviceName: profile.transportSettings.serviceName, options: metadata)
        case "httpupgrade":
            return .httpUpgrade(path: profile.transportSettings.path, host: profile.transportSettings.host, options: metadata)
        case "xhttp":
            let mode = profile.metadata["mode"] ?? profile.transportSettings.metadata["mode"]
            if let mode, ["auto", "packet-up", "stream-up"].contains(mode) == false {
                throw CoreError.invalidConfiguration("Unsupported xhttp mode.")
            }
            return .xhttp(path: profile.transportSettings.path, host: profile.transportSettings.host, mode: mode, options: metadata)
        case "quic":
            return .quic(options: metadata)
        default:
            throw CoreError.invalidConfiguration("Unsupported VLESS transport: \(network).")
        }
    }

    private func compileSecurity(profile: VPNProfile) throws -> CoreSecurityConfiguration {
        let security = profile.transportSettings.security?.lowercased() ?? profile.metadata["security"]?.lowercased()

        if security == "reality" || profile.tlsSettings.publicKeyReference != nil {
            guard let serverName = profile.tlsSettings.serverName, serverName.isEmpty == false else {
                throw CoreError.invalidConfiguration("Reality requires SNI/server name.")
            }
            guard let publicKeyReference = profile.tlsSettings.publicKeyReference, publicKeyReference.isEmpty == false else {
                throw CoreError.invalidConfiguration("Reality requires public key reference.")
            }
            guard let shortID = profile.tlsSettings.shortID, shortID.isEmpty == false else {
                throw CoreError.invalidConfiguration("Reality requires short ID.")
            }

            return .reality(CoreRealityConfiguration(
                serverName: serverName,
                fingerprint: profile.tlsSettings.fingerprint,
                publicKeyReference: publicKeyReference,
                shortID: shortID
            ))
        }

        if profile.tlsSettings.isEnabled || security == "tls" {
            return .tls(CoreTLSConfiguration(
                serverName: profile.tlsSettings.serverName,
                allowInsecure: profile.tlsSettings.allowInsecure,
                fingerprint: profile.tlsSettings.fingerprint
            ))
        }

        return .none
    }
}

nonisolated struct CompositeProfileConfigurationCompiler: ProfileConfigurationCompiling {
    private let vlessCompiler: VLESSProfileConfigurationCompiler

    init(vlessCompiler: VLESSProfileConfigurationCompiler = VLESSProfileConfigurationCompiler()) {
        self.vlessCompiler = vlessCompiler
    }

    func compile(profile: VPNProfile) throws -> CoreConfiguration {
        switch profile.protocolType {
        case .vless:
            return try vlessCompiler.compile(profile: profile)
        case .trojan, .hysteria2, .wireGuard, .shadowsocks, .vmess, .tuic, .ikev2:
            return try compileGeneric(profile: profile)
        }
    }

    private func compileGeneric(profile: VPNProfile) throws -> CoreConfiguration {
        let host = profile.serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard host.isEmpty == false, host.contains(" ") == false else {
            throw CoreError.invalidConfiguration("Host is missing or malformed.")
        }
        guard let port = profile.port, (1...65_535).contains(port) else {
            throw CoreError.invalidConfiguration("Port must be in range 1...65535.")
        }
        guard let credentialReference = profile.credentialReference, credentialReference.isEmpty == false else {
            throw CoreError.missingCredential
        }

        return CoreConfiguration(
            profileID: profile.id,
            protocolType: CoreProtocol(vpnProtocol: profile.protocolType),
            endpoint: CoreEndpoint(host: host, port: port),
            transport: .tcp(options: profile.transportSettings.metadata),
            security: profile.tlsSettings.isEnabled ? .tls(CoreTLSConfiguration(
                serverName: profile.tlsSettings.serverName,
                allowInsecure: profile.tlsSettings.allowInsecure,
                fingerprint: profile.tlsSettings.fingerprint
            )) : .none,
            dns: CoreDNSConfiguration(servers: profile.routingSettings.dnsServers),
            routing: CoreRoutingConfiguration(
                routeAllTraffic: profile.routingSettings.routeAllTraffic,
                excludedRoutes: profile.routingSettings.excludedRoutes
            ),
            credentialReference: credentialReference,
            metadata: profile.metadata
        )
    }
}
