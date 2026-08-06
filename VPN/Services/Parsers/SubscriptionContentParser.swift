//
//  SubscriptionContentParser.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated struct SubscriptionContentParser: Sendable {
    private let linkParser: VPNProfileImporting

    init(linkParser: VPNProfileImporting) {
        self.linkParser = linkParser
    }

    func parse(_ content: String) async throws -> [VPNProfile] {
        let normalizedContent = decodedSubscriptionContent(content) ?? content
        let lines = normalizedContent
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { $0.isEmpty == false && $0.hasPrefix("#") == false }

        var profiles: [VPNProfile] = []

        for line in lines {
            let result = try await linkParser.parse(line)
            if case .profile(let profile) = result.kind {
                profiles.append(profile)
            }
        }

        return profiles
    }

    private func decodedSubscriptionContent(_ content: String) -> String? {
        let compact = content.trimmingCharacters(in: .whitespacesAndNewlines)
        guard compact.contains("://") == false,
              let data = ParserSupport.decodedBase64(compact),
              let decoded = String(data: data, encoding: .utf8),
              decoded.contains("://") else {
            return nil
        }

        return decoded
    }
}
