//
//  StructuredConfigParsers.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated protocol StructuredProfileParsing: Sendable {
    func parseProfiles(from content: String) async throws -> [VPNProfile]
}

nonisolated struct SingBoxJSONProfileParser: StructuredProfileParsing {
    func parseProfiles(from content: String) async throws -> [VPNProfile] {
        guard let data = content.data(using: .utf8),
              (try? JSONSerialization.jsonObject(with: data)) != nil else {
            throw VPNImportError.invalidPayload("The sing-box JSON is invalid.")
        }

        // TODO: Map sing-box outbounds into VPNProfile drafts once adapter schemas are finalized.
        return []
    }
}

nonisolated struct ClashYAMLProfileParser: StructuredProfileParsing {
    func parseProfiles(from content: String) async throws -> [VPNProfile] {
        guard content.contains("proxies:") || content.contains("Proxy:") else {
            throw VPNImportError.invalidPayload("The Clash YAML does not contain a proxies section.")
        }

        // TODO: Add a minimal YAML scanner without third-party dependencies.
        return []
    }
}
