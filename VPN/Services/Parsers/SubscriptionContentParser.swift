//
//  SubscriptionContentParser.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated struct SubscriptionContentParser: Sendable {
    private let linkParser: VPNProfileImporting
    private let detector: SubscriptionContentDetecting
    private let decoder: SubscriptionDecoding
    private let singBoxParser: StructuredProfileParsing
    private let clashParser: StructuredProfileParsing

    init(
        linkParser: VPNProfileImporting,
        detector: SubscriptionContentDetecting = DefaultSubscriptionContentDetector(),
        decoder: SubscriptionDecoding = DefaultSubscriptionDecoder(),
        singBoxParser: StructuredProfileParsing = SingBoxJSONProfileParser(),
        clashParser: StructuredProfileParsing = ClashYAMLProfileParser()
    ) {
        self.linkParser = linkParser
        self.detector = detector
        self.decoder = decoder
        self.singBoxParser = singBoxParser
        self.clashParser = clashParser
    }

    func parse(_ content: String) async throws -> [VPNProfile] {
        let result = try await parseResult(from: Data(content.utf8))
        return result.profiles
    }

    func parseResult(from data: Data) async throws -> SubscriptionContentParseResult {
        let decoded = try decoder.decode(data)
        let format = decoded.formatHint ?? detector.detect(decoded.content)

        switch format {
        case .singleURI, .plainURIList, .base64URIList:
            return await parseURIList(decoded.content, format: format)
        case .singBoxJSON:
            let profiles = try await singBoxParser.parseProfiles(from: decoded.content)
            return SubscriptionContentParseResult(format: .singBoxJSON, profiles: profiles, invalidEntries: profiles.isEmpty ? ["No supported sing-box outbounds were found."] : [])
        case .clashYAML:
            return SubscriptionContentParseResult(
                format: .clashYAML,
                profiles: [],
                invalidEntries: ["Clash subscriptions are recognized but are not fully supported in this build."]
            )
        case .unsupported:
            throw SubscriptionError.unsupportedFormat("The subscription returned an unsupported format.")
        }
    }

    private func parseURIList(_ content: String, format: SubscriptionContentFormat) async -> SubscriptionContentParseResult {
        let lines = content
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { line in
                line.isEmpty == false && line.hasPrefix("#") == false && line.hasPrefix("//") == false
            }

        var profiles: [VPNProfile] = []
        var invalidEntries: [String] = []

        for line in lines {
            do {
                let result = try await linkParser.parse(line)
                if case .profile(let profile) = result.kind {
                    profiles.append(profile)
                }
            } catch {
                invalidEntries.append(error.localizedDescription)
            }
        }

        return SubscriptionContentParseResult(format: format, profiles: profiles, invalidEntries: invalidEntries)
    }
}

nonisolated struct SubscriptionContentParseResult: Codable, Hashable, Sendable {
    var format: SubscriptionContentFormat
    var profiles: [VPNProfile]
    var invalidEntries: [String]
}
