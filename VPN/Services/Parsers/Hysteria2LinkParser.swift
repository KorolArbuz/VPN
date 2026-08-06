//
//  Hysteria2LinkParser.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct Hysteria2LinkParser {
    let credentialStore: CredentialStoring

    func parse(_ text: String) async throws -> VPNImportResult {
        let components = try ParserSupport.components(from: text)
        let host = try ParserSupport.requiredHost(from: components)
        let port = try ParserSupport.requiredPort(from: components, defaultPort: 443)
        let query = ParserSupport.queryDictionary(from: components)

        guard let password = ParserSupport.decodedUser(from: components), password.isEmpty == false else {
            throw VPNImportError.missingRequiredComponent("password")
        }

        let credentialReference = try await credentialStore.store(password, label: "Hysteria 2 password")
        let name = ParserSupport.displayName(from: components, fallback: host)
        let profile = VPNProfile.draft(
            name: name,
            protocolType: .hysteria2,
            serverAddress: host,
            port: port,
            credentialReference: credentialReference,
            transportSettings: VPNTransportSettings(network: "udp", security: "tls", metadata: query),
            tlsSettings: VPNTLSSettings(isEnabled: true, serverName: query["sni"], allowInsecure: query["insecure"] == "1"),
            protocolConfiguration: .hysteria2(Hysteria2ProfileConfiguration(obfs: query["obfs"], bandwidthHint: query["bandwidth"])),
            source: .importedURL,
            metadata: query
        )

        return VPNImportResult(
            kind: .profile(profile),
            detectedScheme: components.scheme?.lowercased() ?? "hysteria2",
            displayName: name,
            sanitizedSummary: SecretMasker.sanitizedQuerySummary(from: components.queryItems ?? [])
                .merging(["credential": SecretMasker.masked(password), "host": host, "port": "\(port)"]) { current, _ in current }
        )
    }
}
