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
        try validateRepresentedRuntimeOptions(profile: profile)

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

    func compileTransport(profile: VPNProfile) throws -> CoreTransportConfiguration {
        let network = profile.transportSettings.network?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? "tcp"
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
        case "xhttp", "splithttp":
            let mode = normalizedOptional(profile.metadata["mode"] ?? profile.transportSettings.metadata["mode"])
            if let mode, ["auto", "packet-up", "stream-up", "stream-one"].contains(mode) == false {
                throw CoreError.invalidConfiguration("Unsupported xhttp mode.")
            }
            return .xhttp(
                path: normalizedOptional(profile.transportSettings.path),
                host: normalizedOptional(profile.transportSettings.host),
                mode: mode,
                options: metadata
            )
        case "quic":
            return .quic(options: metadata)
        default:
            throw CoreError.invalidConfiguration("Unsupported transport: \(network).")
        }
    }

    private func normalizedOptional(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }

    func validateRepresentedRuntimeOptions(profile: VPNProfile) throws {
        if hasUnsupportedMetadataValue(
            in: profile,
            keys: ["headertype", "header-type"],
            allowedValues: ["none"]
        ) {
            throw CoreError.invalidConfiguration("TCP header modes are not supported by the current Xray data plane.")
        }
        if hasUnsupportedMetadataValue(
            in: profile,
            keys: ["packetencoding", "packet-encoding"],
            allowedValues: ["none"]
        ) {
            throw CoreError.invalidConfiguration("Packet encoding is not supported by the current Xray data plane.")
        }
        if hasUnsupportedMetadataValue(
            in: profile,
            keys: ["mux"],
            allowedValues: ["0", "false", "none", "off"]
        ) {
            throw CoreError.invalidConfiguration("Mux is not supported by the current Xray data plane.")
        }
    }

    private func hasUnsupportedMetadataValue(
        in profile: VPNProfile,
        keys: Set<String>,
        allowedValues: Set<String>
    ) -> Bool {
        [profile.transportSettings.metadata, profile.metadata].contains { metadata in
            metadata.contains { key, value in
                guard keys.contains(key.lowercased()), let value = normalizedOptional(value)?.lowercased() else {
                    return false
                }
                return allowedValues.contains(value) == false
            }
        }
    }

    func compileSecurity(profile: VPNProfile) throws -> CoreSecurityConfiguration {
        let security = normalizedOptional(profile.transportSettings.security ?? profile.metadata["security"])?.lowercased()
        let supportedRequestedSecurities: Set<String>
        switch profile.protocolType {
        case .vless, .vmess:
            supportedRequestedSecurities = ["none", "tls", "reality"]
        case .trojan:
            supportedRequestedSecurities = ["tls", "reality"]
        case .wireGuard, .amneziaWG, .ikev2, .shadowsocks, .hysteria2, .tuic:
            supportedRequestedSecurities = []
        }
        if let security, supportedRequestedSecurities.contains(security) == false {
            throw CoreError.invalidConfiguration("Unsupported security mode for \(profile.protocolType.displayName).")
        }

        if security == "reality" || profile.tlsSettings.realityPublicKey != nil || profile.tlsSettings.publicKeyReference != nil {
            guard hasCustomRealityALPN(in: profile) == false else {
                throw CoreError.invalidConfiguration("Custom ALPN values with REALITY are not supported by the current Xray data plane.")
            }
            guard let serverName = profile.tlsSettings.serverName, serverName.isEmpty == false else {
                throw CoreError.invalidConfiguration("Reality requires SNI/server name.")
            }
            guard let publicKey = profile.tlsSettings.realityPublicKey, publicKey.isEmpty == false else {
                throw CoreError.invalidConfiguration("Reality requires public key.")
            }
            guard let shortID = profile.tlsSettings.shortID, shortID.isEmpty == false else {
                throw CoreError.invalidConfiguration("Reality requires short ID.")
            }

            return .reality(CoreRealityConfiguration(
                serverName: serverName,
                fingerprint: profile.tlsSettings.fingerprint,
                publicKey: publicKey,
                shortID: shortID,
                spiderX: profile.tlsSettings.spiderX
            ))
        }

        if profile.tlsSettings.isEnabled || security == "tls" {
            return .tls(CoreTLSConfiguration(
                serverName: profile.tlsSettings.serverName,
                allowInsecure: profile.tlsSettings.allowInsecure,
                fingerprint: profile.tlsSettings.fingerprint,
                alpn: profile.tlsSettings.alpn
            ))
        }

        return .none
    }

    private func hasCustomRealityALPN(in profile: VPNProfile) -> Bool {
        let tlsALPN = profile.tlsSettings.alpn ?? []
        let protocolALPN: [String]
        if case .trojan(let configuration) = profile.protocolConfiguration {
            protocolALPN = configuration.alpn
        } else {
            protocolALPN = []
        }
        return (tlsALPN + protocolALPN).contains { value in
            value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
        }
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
        case .trojan, .hysteria2, .wireGuard, .amneziaWG, .shadowsocks, .vmess, .tuic, .ikev2:
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
        try vlessCompiler.validateRepresentedRuntimeOptions(profile: profile)

        let transport: CoreTransportConfiguration
        let security: CoreSecurityConfiguration
        switch profile.protocolType {
        case .vmess:
            transport = try vlessCompiler.compileTransport(profile: profile)
            security = try vlessCompiler.compileSecurity(profile: profile)
        case .trojan:
            transport = try vlessCompiler.compileTransport(profile: profile)
            security = try vlessCompiler.compileSecurity(profile: profile)
            if case .none = security {
                throw CoreError.invalidConfiguration("Trojan runtime requires TLS or REALITY.")
            }
        case .shadowsocks:
            if let plugin = profile.transportSettings.metadata["plugin"] ?? profile.metadata["plugin"],
               plugin.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false {
                throw CoreError.invalidConfiguration("Shadowsocks plugins are not supported by the Xray data plane yet.")
            }
            transport = .tcp(options: profile.transportSettings.metadata)
            security = .none
        case .hysteria2:
            let requestedSecurity = profile.transportSettings.security?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                ?? profile.metadata["security"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if requestedSecurity == "reality" {
                throw CoreError.invalidConfiguration("Hysteria2 runtime does not support REALITY.")
            }
            if let pin = profile.metadata["pinSHA256"] ?? profile.transportSettings.metadata["pinSHA256"],
               pin.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false {
                throw CoreError.invalidConfiguration("Hysteria2 pinSHA256 is not supported by the current Xray data plane.")
            }
            if containsUnsupportedHysteria2ECH(in: profile.metadata)
                || containsUnsupportedHysteria2ECH(in: profile.transportSettings.metadata) {
                throw CoreError.invalidConfiguration("Hysteria2 ECH is not supported by the current Xray data plane.")
            }
            if let port = profile.metadata["mport"] ?? profile.transportSettings.metadata["mport"],
               port.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false {
                throw CoreError.invalidConfiguration("Hysteria2 port hopping is not supported by the current Xray data plane.")
            }
            if let alpn = profile.metadata["alpn"] ?? profile.transportSettings.metadata["alpn"] {
                let values = alpn
                    .split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                    .filter { $0.isEmpty == false }
                if values.isEmpty == false, values != ["h3"] {
                    throw CoreError.invalidConfiguration("Hysteria2 custom ALPN is not supported by the current Xray data plane.")
                }
            }
            transport = .udp(options: profile.transportSettings.metadata)
            security = .tls(CoreTLSConfiguration(
                serverName: profile.tlsSettings.serverName,
                allowInsecure: profile.tlsSettings.allowInsecure,
                fingerprint: profile.tlsSettings.fingerprint,
                alpn: profile.tlsSettings.alpn
            ))
        case .wireGuard, .amneziaWG, .tuic, .ikev2, .vless:
            throw CoreError.unsupportedProtocol(CoreProtocol(vpnProtocol: profile.protocolType))
        }

        return CoreConfiguration(
            profileID: profile.id,
            protocolType: CoreProtocol(vpnProtocol: profile.protocolType),
            endpoint: CoreEndpoint(host: host, port: port),
            transport: transport,
            security: security,
            dns: CoreDNSConfiguration(servers: profile.routingSettings.dnsServers),
            routing: CoreRoutingConfiguration(
                routeAllTraffic: profile.routingSettings.routeAllTraffic,
                excludedRoutes: profile.routingSettings.excludedRoutes
            ),
            credentialReference: credentialReference,
            metadata: profile.metadata
        )
    }

    private func containsUnsupportedHysteria2ECH(in metadata: [String: String]) -> Bool {
        metadata.contains { key, value in
            guard value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false else {
                return false
            }
            let normalized = key
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .replacingOccurrences(of: "-", with: "")
                .replacingOccurrences(of: "_", with: "")
                .lowercased()
            return normalized == "ech" || normalized == "echconfig" || normalized == "echconfiglist"
        }
    }
}
