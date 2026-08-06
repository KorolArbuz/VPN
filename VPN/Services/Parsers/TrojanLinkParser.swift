//
//  TrojanLinkParser.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct TrojanLinkParser {
    let credentialStore: CredentialStoring

    func parse(_ text: String) async throws -> VPNImportResult {
        let components = try ParserSupport.components(from: text)
        let host = try ParserSupport.requiredHost(from: components)
        let port = try ParserSupport.requiredPort(from: components, defaultPort: 443)
        let query = ParserSupport.queryDictionary(from: components)

        guard let password = components.user, password.isEmpty == false else {
            throw VPNImportError.missingRequiredComponent("password")
        }

        let credentialReference = try await credentialStore.store(password, label: "Trojan password")
        let name = ParserSupport.displayName(from: components, fallback: host)
        let profile = VPNProfile.draft(
            name: name,
            protocolType: .trojan,
            serverAddress: host,
            port: port,
            credentialReference: credentialReference,
            transportSettings: VPNTransportSettings(network: query["type"], security: query["security"], path: query["path"], host: query["host"], metadata: query),
            tlsSettings: VPNTLSSettings(isEnabled: true, serverName: query["sni"] ?? query["host"], allowInsecure: query["allowInsecure"] == "1"),
            protocolConfiguration: .trojan(TrojanProfileConfiguration(alpn: query["alpn"]?.components(separatedBy: ",") ?? [])),
            source: .importedURL,
            metadata: query
        )

        return VPNImportResult(
            kind: .profile(profile),
            detectedScheme: "trojan",
            displayName: name,
            sanitizedSummary: ["credential": SecretMasker.masked(password), "host": host, "port": "\(port)"]
        )
    }
}
