//
//  ShadowsocksLinkParser.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct ShadowsocksLinkParser {
    let credentialStore: CredentialStoring

    func parse(_ text: String) async throws -> VPNImportResult {
        if let sip002 = try await parseSIP002(text) {
            return sip002
        }

        let payload = String(text.dropFirst("ss://".count))
        let withoutFragment = payload.split(separator: "#", maxSplits: 1).first.map(String.init) ?? payload
        guard let data = ParserSupport.decodedBase64(withoutFragment), let decoded = String(data: data, encoding: .utf8) else {
            throw VPNImportError.invalidBase64Payload
        }

        return try await parseDecoded(decoded, originalText: text)
    }

    private func parseSIP002(_ text: String) async throws -> VPNImportResult? {
        guard let components = URLComponents(string: text), components.host != nil, components.user != nil else {
            return nil
        }

        let user = components.user ?? ""
        let decodedUser: String
        if let data = ParserSupport.decodedBase64(user), let decoded = String(data: data, encoding: .utf8), decoded.contains(":") {
            decodedUser = decoded
        } else {
            decodedUser = user
        }

        let methodAndPassword = decodedUser.split(separator: ":", maxSplits: 1).map(String.init)
        guard methodAndPassword.count == 2 else {
            throw VPNImportError.missingRequiredComponent("method or password")
        }

        let host = try ParserSupport.requiredHost(from: components)
        let port = try ParserSupport.requiredPort(from: components)
        let password = methodAndPassword[1]
        let credentialReference = try await credentialStore.store(password, label: "Shadowsocks password")
        let name = ParserSupport.displayName(from: components, fallback: host)
        let query = ParserSupport.queryDictionary(from: components)
        let profile = VPNProfile.draft(
            name: name,
            protocolType: .shadowsocks,
            serverAddress: host,
            port: port,
            credentialReference: credentialReference,
            transportSettings: VPNTransportSettings(metadata: query),
            protocolConfiguration: .shadowsocks(ShadowsocksProfileConfiguration(method: methodAndPassword[0], plugin: query["plugin"])),
            source: .importedURL,
            metadata: query
        )

        return VPNImportResult(
            kind: .profile(profile),
            detectedScheme: "ss",
            displayName: name,
            sanitizedSummary: ["method": methodAndPassword[0], "credential": SecretMasker.masked(password), "host": host, "port": "\(port)"]
        )
    }

    private func parseDecoded(_ decoded: String, originalText: String) async throws -> VPNImportResult {
        let userAndHost = decoded.split(separator: "@", maxSplits: 1).map(String.init)
        guard userAndHost.count == 2 else {
            throw VPNImportError.invalidPayload("Unsupported Shadowsocks URI structure.")
        }

        let methodAndPassword = userAndHost[0].split(separator: ":", maxSplits: 1).map(String.init)
        let hostAndPort = userAndHost[1].split(separator: ":", maxSplits: 1).map(String.init)

        guard methodAndPassword.count == 2 else {
            throw VPNImportError.missingRequiredComponent("method or password")
        }
        guard hostAndPort.count == 2, let port = Int(hostAndPort[1]) else {
            throw VPNImportError.invalidPort
        }

        let password = methodAndPassword[1]
        let credentialReference = try await credentialStore.store(password, label: "Shadowsocks password")
        let host = hostAndPort[0]
        let name = URLComponents(string: originalText)?.percentEncodedFragment?.removingPercentEncoding ?? host
        let profile = VPNProfile.draft(
            name: name,
            protocolType: .shadowsocks,
            serverAddress: host,
            port: port,
            credentialReference: credentialReference,
            protocolConfiguration: .shadowsocks(ShadowsocksProfileConfiguration(method: methodAndPassword[0], plugin: nil)),
            source: .importedURL
        )

        return VPNImportResult(
            kind: .profile(profile),
            detectedScheme: "ss",
            displayName: name,
            sanitizedSummary: ["method": methodAndPassword[0], "credential": SecretMasker.masked(password), "host": host, "port": "\(port)"]
        )
    }
}
