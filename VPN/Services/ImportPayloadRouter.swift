//
//  ImportPayloadRouter.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated struct ImportPayloadRouter: Sendable {
    private let importer: VPNProfileImporting
    private let subscriptionParser: SubscriptionContentParser
    private let maxPayloadSize: Int

    init(
        importer: VPNProfileImporting,
        subscriptionParser: SubscriptionContentParser,
        maxPayloadSize: Int = 2 * 1024 * 1024
    ) {
        self.importer = importer
        self.subscriptionParser = subscriptionParser
        self.maxPayloadSize = maxPayloadSize
    }

    func route(data: Data, title: String) async throws -> ImportPayloadRoute {
        guard data.count <= maxPayloadSize else {
            throw VPNImportError.invalidPayload("The file is too large.")
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw VPNImportError.invalidPayload("The file could not be read.")
        }
        return try await route(text: text, title: title)
    }

    func route(text: String, title: String) async throws -> ImportPayloadRoute {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false else {
            throw VPNImportError.emptyInput
        }

        if isSingleVPNLink(trimmed) {
            let result = try await importer.parse(trimmed)
            return .single(result)
        }

        let result = try await subscriptionParser.parseResult(from: Data(trimmed.utf8))
        guard result.profiles.isEmpty == false else {
            if result.format == .clashYAML {
                throw VPNImportError.invalidPayload("Clash subscriptions are recognized but are not fully supported in this build.")
            }
            throw VPNImportError.invalidPayload("No supported VPN profiles were found.")
        }

        if result.profiles.count == 1, let profile = result.profiles.first {
            return .single(VPNImportResult(
                kind: .profile(profile),
                detectedScheme: profile.protocolType.rawValue,
                displayName: profile.name,
                warnings: result.invalidEntries,
                sanitizedSummary: [
                    "format": result.format.displayName,
                    "host": profile.serverAddress,
                    "port": profile.port.map(String.init) ?? ""
                ]
            ))
        }

        return .batch(BatchImportDraft(
            title: title,
            detectedFormat: result.format,
            profiles: result.profiles.map { BatchImportProfileDraft(profile: $0, isSelected: $0.isComplete) },
            warnings: result.invalidEntries
        ))
    }

    private func isSingleVPNLink(_ text: String) -> Bool {
        let lowercased = text.lowercased()
        return VPNLinkParser.supportedProfileSchemes.contains { lowercased.hasPrefix("\($0)://") }
    }
}
