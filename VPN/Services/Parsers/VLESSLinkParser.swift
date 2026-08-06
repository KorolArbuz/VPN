//
//  VLESSLinkParser.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct VLESSLinkParser {
    let credentialStore: CredentialStoring

    func parse(_ text: String) async throws -> VPNImportResult {
        let components = try ParserSupport.components(from: text)
        let host = try ParserSupport.requiredHost(from: components)
        let port = try ParserSupport.requiredPort(from: components, defaultPort: 443)
        let query = ParserSupport.queryDictionary(from: components)

        guard let user = components.user, user.isEmpty == false else {
            throw VPNImportError.missingRequiredComponent("user id")
        }

        let credentialReference = try await credentialStore.store(user, label: "VLESS user id")
        let name = ParserSupport.displayName(from: components, fallback: host)
        let transport = VPNTransportSettings(
            network: query["type"],
            security: query["security"],
            path: query["path"],
            host: query["host"],
            serviceName: query["serviceName"],
            metadata: query
        )
        let tls = VPNTLSSettings(
            isEnabled: ["tls", "reality"].contains(query["security"]?.lowercased()),
            serverName: query["sni"] ?? query["host"],
            allowInsecure: query["allowInsecure"] == "1",
            fingerprint: query["fp"],
            publicKeyReference: query["pbk"] == nil ? nil : try await credentialStore.store(query["pbk"] ?? "", label: "Reality public key"),
            shortID: query["sid"]
        )
        let profile = VPNProfile.draft(
            name: name,
            protocolType: .vless,
            serverAddress: host,
            port: port,
            credentialReference: credentialReference,
            transportSettings: transport,
            tlsSettings: tls,
            protocolConfiguration: .vless(VLESSProfileConfiguration(flow: query["flow"], encryption: query["encryption"])),
            source: .importedURL,
            metadata: query
        )

        return VPNImportResult(
            kind: .profile(profile),
            detectedScheme: "vless",
            displayName: name,
            sanitizedSummary: SecretMasker.sanitizedQuerySummary(from: components.queryItems ?? [])
                .merging(["credential": SecretMasker.masked(user), "host": host, "port": "\(port)"]) { current, _ in current }
        )
    }
}
