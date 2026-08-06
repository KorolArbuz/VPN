//
//  VPNProfileImporting.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated protocol VPNProfileImporting: Sendable {
    func parse(_ text: String) async throws -> VPNImportResult
}

nonisolated struct VPNLinkParser: VPNProfileImporting {
    private let credentialStore: CredentialStoring

    init(credentialStore: CredentialStoring = InMemoryCredentialStore()) {
        self.credentialStore = credentialStore
    }

    func parse(_ text: String) async throws -> VPNImportResult {
        let trimmedText = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmedText.isEmpty == false else {
            throw VPNImportError.emptyInput
        }

        guard let scheme = trimmedText.split(separator: ":", maxSplits: 1).first?.lowercased() else {
            throw VPNImportError.malformedURL
        }

        switch scheme {
        case "http", "https":
            return try SubscriptionURLParser().parse(trimmedText)
        case "vless":
            return try await VLESSLinkParser(credentialStore: credentialStore).parse(trimmedText)
        case "trojan":
            return try await TrojanLinkParser(credentialStore: credentialStore).parse(trimmedText)
        case "ss":
            return try await ShadowsocksLinkParser(credentialStore: credentialStore).parse(trimmedText)
        case "hysteria2", "hy2":
            return try await Hysteria2LinkParser(credentialStore: credentialStore).parse(trimmedText)
        case "vmess":
            return try await VMessLinkParser(credentialStore: credentialStore).parse(trimmedText)
        case "tuic", "wireguard", "ikev2":
            return try await SimpleVPNLinkParser(credentialStore: credentialStore).parse(trimmedText, scheme: scheme)
        default:
            throw VPNImportError.unsupportedScheme(scheme)
        }
    }
}
