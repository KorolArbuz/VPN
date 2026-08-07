//
//  SubscriptionPipeline.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated protocol SubscriptionClient: Sendable {
    func fetch(url: URL) async throws -> Data
}

nonisolated protocol SubscriptionContentDetecting: Sendable {
    func detect(_ content: String) -> SubscriptionContentFormat
}

nonisolated protocol SubscriptionDecoding: Sendable {
    func decode(_ data: Data) throws -> (content: String, formatHint: SubscriptionContentFormat?)
}

nonisolated protocol SubscriptionMerging: Sendable {
    func stableIdentity(for profile: VPNProfile) -> String
    func makeSubscriptionProfile(_ profile: VPNProfile, subscriptionID: UUID, now: Date) -> VPNProfile
}

nonisolated protocol SubscriptionUpdatePlanning: Sendable {
    func planUpdate(subscription: VPNSubscription, incoming: [VPNProfile], existing: [VPNProfile]) -> SubscriptionUpdatePlan
}

nonisolated enum SubscriptionError: LocalizedError, Equatable, Sendable {
    case invalidURL
    case insecureRedirect
    case responseTooLarge
    case invalidUTF8
    case noProfilesFound
    case credentialsUnavailable
    case unsupportedFormat(String)
    case httpStatus(Int)

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            "The subscription URL is invalid."
        case .insecureRedirect:
            "The provider redirected to an insecure URL."
        case .responseTooLarge:
            "The subscription response was too large."
        case .invalidUTF8:
            "The subscription response is not valid UTF-8."
        case .noProfilesFound:
            "No profiles were found."
        case .credentialsUnavailable:
            "The subscription credentials are unavailable."
        case .unsupportedFormat(let message):
            message
        case .httpStatus(let status):
            switch status {
            case 401: "Could not authenticate with the provider."
            case 404: "The subscription was not found."
            case 500...599: "The provider is temporarily unavailable."
            default: "The provider returned HTTP \(status)."
            }
        }
    }
}

nonisolated struct URLSessionSubscriptionClient: SubscriptionClient {
    private let maxResponseSize: Int
    private let timeout: TimeInterval

    init(maxResponseSize: Int = 3 * 1024 * 1024, timeout: TimeInterval = 20) {
        self.maxResponseSize = maxResponseSize
        self.timeout = timeout
    }

    func fetch(url: URL) async throws -> Data {
        guard ["https", "http"].contains(url.scheme?.lowercased() ?? "") else {
            throw SubscriptionError.invalidURL
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }

        let (data, response) = try await session.data(for: request)
        guard data.count <= maxResponseSize else {
            throw SubscriptionError.responseTooLarge
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            return data
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw SubscriptionError.httpStatus(httpResponse.statusCode)
        }

        return data
    }
}

nonisolated struct DefaultSubscriptionContentDetector: SubscriptionContentDetecting {
    func detect(_ content: String) -> SubscriptionContentFormat {
        let trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)
        if VPNLinkParser.supportedProfileSchemes.contains(where: { trimmed.lowercased().hasPrefix("\($0)://") }) {
            return .singleURI
        }
        if trimmed.hasPrefix("{") {
            return .singBoxJSON
        }
        if trimmed.contains("proxies:") || trimmed.contains("Proxy:") {
            return .clashYAML
        }
        if trimmed.contains("://") {
            return .plainURIList
        }
        return .unsupported
    }
}

nonisolated struct DefaultSubscriptionDecoder: SubscriptionDecoding {
    private let maxDecodedSize: Int

    init(maxDecodedSize: Int = 3 * 1024 * 1024) {
        self.maxDecodedSize = maxDecodedSize
    }

    func decode(_ data: Data) throws -> (content: String, formatHint: SubscriptionContentFormat?) {
        guard data.count <= maxDecodedSize else {
            throw SubscriptionError.responseTooLarge
        }
        guard let raw = String(data: data, encoding: .utf8) else {
            throw SubscriptionError.invalidUTF8
        }

        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.contains("://") == false else {
            return (raw, nil)
        }
        guard let decodedData = ParserSupport.decodedBase64(trimmed) else {
            if trimmed.range(of: #"^[A-Za-z0-9_\-+/=]+$"#, options: .regularExpression) != nil {
                throw VPNImportError.invalidBase64Payload
            }
            return (raw, nil)
        }
        guard decodedData.count <= maxDecodedSize else {
            throw SubscriptionError.responseTooLarge
        }
        guard let decoded = String(data: decodedData, encoding: .utf8) else {
            throw VPNImportError.invalidBase64Payload
        }
        return (decoded, .base64URIList)
    }
}

nonisolated struct DefaultSubscriptionMerger: SubscriptionMerging {
    func stableIdentity(for profile: VPNProfile) -> String {
        [
            "v1",
            profile.protocolType.rawValue,
            profile.serverAddress.lowercased(),
            profile.port.map(String.init) ?? "",
            profile.transportSettings.network?.lowercased() ?? "",
            profile.transportSettings.path ?? "",
            profile.transportSettings.host?.lowercased() ?? "",
            profile.tlsSettings.serverName?.lowercased() ?? "",
            profile.tlsSettings.shortID ?? "",
            providerStableValue(for: profile)
        ].joined(separator: "|")
    }

    func makeSubscriptionProfile(_ profile: VPNProfile, subscriptionID: UUID, now: Date) -> VPNProfile {
        var updated = profile
        updated.source = .subscription
        updated.sourceSubscriptionID = subscriptionID
        updated.externalIdentity = stableIdentity(for: profile)
        updated.importedAt = profile.importedAt ?? now
        updated.lastSeenAt = now
        return updated
    }

    private func providerStableValue(for profile: VPNProfile) -> String {
        switch profile.protocolConfiguration {
        case .vless(let configuration):
            configuration.flow ?? ""
        case .trojan(let configuration):
            configuration.alpn.joined(separator: ",")
        case .hysteria2(let configuration):
            [configuration.obfs, configuration.bandwidthHint].compactMap { $0 }.joined(separator: "|")
        case .shadowsocks(let configuration):
            configuration.method ?? ""
        case .tuic(let configuration):
            [configuration.congestionControl, configuration.udpRelayMode].compactMap { $0 }.joined(separator: "|")
        case .vmess(let configuration):
            [configuration.alterID.map(String.init), configuration.security].compactMap { $0 }.joined(separator: "|")
        case .wireGuard, .ikev2:
            ""
        }
    }
}

nonisolated struct DefaultSubscriptionUpdatePlanner: SubscriptionUpdatePlanning {
    private let merger: SubscriptionMerging

    init(merger: SubscriptionMerging = DefaultSubscriptionMerger()) {
        self.merger = merger
    }

    func planUpdate(subscription: VPNSubscription, incoming: [VPNProfile], existing: [VPNProfile]) -> SubscriptionUpdatePlan {
        let existingForSubscription = existing.filter { $0.sourceSubscriptionID == subscription.id }
        var existingByIdentity: [String: VPNProfile] = [:]
        for profile in existingForSubscription {
            let identity = profile.externalIdentity ?? merger.stableIdentity(for: profile)
            existingByIdentity[identity] = profile
        }
        let duplicateIdentities = Set(Dictionary(grouping: incoming, by: merger.stableIdentity(for:)).filter { $0.value.count > 1 }.keys)
        var seenIdentities: Set<String> = []
        var changes: [SubscriptionProfileChange] = []

        for profile in incoming {
            let identity = merger.stableIdentity(for: profile)
            if duplicateIdentities.contains(identity), seenIdentities.contains(identity) {
                changes.append(SubscriptionProfileChange(kind: .duplicate, incomingProfile: profile, message: "Duplicate provider entry", isSelected: false))
                continue
            }
            seenIdentities.insert(identity)

            guard profile.isComplete else {
                changes.append(SubscriptionProfileChange(kind: .invalid, incomingProfile: profile, message: profile.missingRequiredFields.joined(separator: ", "), isSelected: false))
                continue
            }

            if let existingProfile = existingByIdentity[identity] {
                changes.append(SubscriptionProfileChange(
                    kind: hasProviderManagedChanges(existing: existingProfile, incoming: profile) ? .updated : .unchanged,
                    incomingProfile: profile,
                    existingProfile: existingProfile
                ))
            } else {
                changes.append(SubscriptionProfileChange(kind: .added, incomingProfile: profile))
            }
        }

        let incomingIdentities = Set(incoming.map { merger.stableIdentity(for: $0) })
        for profile in existingForSubscription where incomingIdentities.contains(profile.externalIdentity ?? merger.stableIdentity(for: profile)) == false {
            changes.append(SubscriptionProfileChange(kind: .missing, existingProfile: profile, message: "No longer returned by provider", isSelected: false))
        }

        return SubscriptionUpdatePlan(
            id: UUID(),
            subscription: subscription,
            providerURLReference: subscription.credentialReference ?? "",
            detectedFormat: .plainURIList,
            changes: changes
        )
    }

    private func hasProviderManagedChanges(existing: VPNProfile, incoming: VPNProfile) -> Bool {
        existing.protocolType != incoming.protocolType ||
            existing.serverAddress != incoming.serverAddress ||
            existing.port != incoming.port ||
            existing.transportSettings != incoming.transportSettings ||
            existing.tlsSettings != incoming.tlsSettings ||
            existing.protocolConfiguration != incoming.protocolConfiguration
    }
}
