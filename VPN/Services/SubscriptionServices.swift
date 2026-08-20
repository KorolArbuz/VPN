//
//  SubscriptionServices.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated protocol SubscriptionRepository: Sendable {
    func subscriptions() async throws -> [VPNSubscription]
    func save(_ subscription: VPNSubscription) async throws
    func delete(id: VPNSubscription.ID) async throws
    func setEnabled(_ isEnabled: Bool, id: VPNSubscription.ID) async throws
    func rename(id: VPNSubscription.ID, to name: String) async throws
}

nonisolated protocol SubscriptionUpdating: Sendable {
    func preview(_ subscription: VPNSubscription, url: URL) async throws -> SubscriptionPreview
    func planRefresh(_ subscription: VPNSubscription, existingProfiles: [VPNProfile], url: URL) async throws -> SubscriptionUpdatePlan
}

actor InMemorySubscriptionRepository: SubscriptionRepository {
    private var storedSubscriptions: [VPNSubscription] = []

    func subscriptions() async throws -> [VPNSubscription] {
        storedSubscriptions
    }

    func save(_ subscription: VPNSubscription) async throws {
        var updated = subscription
        updated.updatedAt = Date()
        if let index = storedSubscriptions.firstIndex(where: { $0.id == subscription.id }) {
            storedSubscriptions[index] = updated
        } else {
            storedSubscriptions.append(updated)
        }
    }

    func delete(id: VPNSubscription.ID) async throws {
        storedSubscriptions.removeAll { $0.id == id }
    }

    func setEnabled(_ isEnabled: Bool, id: VPNSubscription.ID) async throws {
        guard let index = storedSubscriptions.firstIndex(where: { $0.id == id }) else {
            return
        }
        storedSubscriptions[index].isEnabled = isEnabled
        storedSubscriptions[index].updatedAt = Date()
    }

    func rename(id: VPNSubscription.ID, to name: String) async throws {
        guard let index = storedSubscriptions.firstIndex(where: { $0.id == id }) else {
            return
        }
        storedSubscriptions[index].name = name
        storedSubscriptions[index].updatedAt = Date()
    }
}

actor FileSubscriptionRepository: SubscriptionRepository {
    private let fileURL: URL
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    init(fileURL: URL? = nil) {
        if let fileURL {
            self.fileURL = fileURL
        } else {
            let applicationSupportURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? FileManager.default.temporaryDirectory
            self.fileURL = applicationSupportURL
                .appendingPathComponent("VPN", isDirectory: true)
                .appendingPathComponent("subscriptions.json")
        }
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    func subscriptions() async throws -> [VPNSubscription] {
        try loadSubscriptions()
    }

    func save(_ subscription: VPNSubscription) async throws {
        var subscriptions = try loadSubscriptions()
        var updated = subscription
        updated.updatedAt = Date()
        if let index = subscriptions.firstIndex(where: { $0.id == subscription.id }) {
            subscriptions[index] = updated
        } else {
            subscriptions.append(updated)
        }
        try writeSubscriptions(subscriptions)
    }

    func delete(id: VPNSubscription.ID) async throws {
        var subscriptions = try loadSubscriptions()
        subscriptions.removeAll { $0.id == id }
        try writeSubscriptions(subscriptions)
    }

    func setEnabled(_ isEnabled: Bool, id: VPNSubscription.ID) async throws {
        var subscriptions = try loadSubscriptions()
        guard let index = subscriptions.firstIndex(where: { $0.id == id }) else {
            return
        }
        subscriptions[index].isEnabled = isEnabled
        subscriptions[index].updatedAt = Date()
        try writeSubscriptions(subscriptions)
    }

    func rename(id: VPNSubscription.ID, to name: String) async throws {
        var subscriptions = try loadSubscriptions()
        guard let index = subscriptions.firstIndex(where: { $0.id == id }) else {
            return
        }
        subscriptions[index].name = name
        subscriptions[index].updatedAt = Date()
        try writeSubscriptions(subscriptions)
    }

    private func loadSubscriptions() throws -> [VPNSubscription] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return []
        }
        let data = try Data(contentsOf: fileURL)
        return try decoder.decode([VPNSubscription].self, from: data)
    }

    private func writeSubscriptions(_ subscriptions: [VPNSubscription]) throws {
        let directoryURL = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        let data = try encoder.encode(subscriptions)
        try data.write(to: fileURL, options: [.atomic])
    }
}

nonisolated struct URLSessionSubscriptionUpdater: SubscriptionUpdating {
    private let client: SubscriptionClient
    private let parser: SubscriptionContentParser
    private let credentialStore: any CredentialStoring
    private let merger: SubscriptionMerging
    private let planner: SubscriptionUpdatePlanning

    init(
        client: SubscriptionClient = URLSessionSubscriptionClient(),
        parser: SubscriptionContentParser? = nil,
        credentialStore: any CredentialStoring = KeychainCredentialStore(),
        merger: SubscriptionMerging = DefaultSubscriptionMerger(),
        planner: SubscriptionUpdatePlanning = DefaultSubscriptionUpdatePlanner()
    ) {
        self.client = client
        self.parser = parser ?? SubscriptionContentParser(
            linkParser: VPNLinkParser(credentialStore: credentialStore)
        )
        self.credentialStore = credentialStore
        self.merger = merger
        self.planner = planner
    }

    func preview(_ subscription: VPNSubscription, url: URL) async throws -> SubscriptionPreview {
        let data = try await client.fetch(url: url)
        let result = try await parser.parseResult(from: data)
        guard result.profiles.isEmpty == false else {
            if result.format == .clashYAML {
                throw SubscriptionError.unsupportedFormat("Clash subscriptions are recognized but are not fully supported in this build.")
            }
            throw SubscriptionError.noProfilesFound
        }

        let now = Date()
        let subscriptionProfiles = result.profiles.map { merger.makeSubscriptionProfile($0, subscriptionID: subscription.id, now: now) }
        let duplicateIdentities = Set(Dictionary(grouping: subscriptionProfiles) { profile in
            profile.externalIdentity ?? merger.stableIdentity(for: profile)
        }.filter { $0.value.count > 1 }.keys)
        var seenIdentities: Set<String> = []
        let previews = subscriptionProfiles.map { profile in
            let identity = profile.externalIdentity ?? merger.stableIdentity(for: profile)
            let isDuplicate = duplicateIdentities.contains(identity) && seenIdentities.contains(identity)
            seenIdentities.insert(identity)
            let state: SubscriptionProfileState
            if isDuplicate {
                state = .duplicate
            } else {
                switch profile.runtimeCapability {
                case .ready:
                    state = .valid
                case .incomplete:
                    state = .incomplete
                case .unsupported, .invalid:
                    state = .invalid
                }
            }
            let message = state == .valid || state == .duplicate ? nil : profile.runtimeCapability.statusText
            return SubscriptionProfilePreview(profile: profile, state: state, message: message, isSelected: state == .valid)
        }

        return SubscriptionPreview(
            id: UUID(),
            subscription: subscription,
            providerURLReference: subscription.credentialReference ?? "",
            detectedFormat: result.format,
            profiles: previews,
            warnings: result.invalidEntries
        )
    }

    func planRefresh(_ subscription: VPNSubscription, existingProfiles: [VPNProfile], url: URL) async throws -> SubscriptionUpdatePlan {
        let preview = try await preview(subscription, url: url)
        let incomingProfiles = preview.profiles.map(\.profile)
        let incomingReferences = credentialReferences(in: incomingProfiles)
        let existingReferences = credentialReferences(in: existingProfiles)

        do {
            let reconciledProfiles = try await reconcileCredentialReferences(
                in: incomingProfiles,
                subscription: subscription,
                existingProfiles: existingProfiles
            )
            let reconciledReferences = credentialReferences(in: reconciledProfiles)
            try await deleteCredentialReferences(
                incomingReferences.subtracting(reconciledReferences).subtracting(existingReferences)
            )

            var plan = planner.planUpdate(
                subscription: subscription,
                incoming: reconciledProfiles,
                existing: existingProfiles
            )
            plan.detectedFormat = preview.detectedFormat
            return plan
        } catch let reconciliationError {
            do {
                try await deleteCredentialReferences(incomingReferences.subtracting(existingReferences))
            } catch {
                // Cleanup failure is the actionable error: returning the original
                // error would hide a prepared credential that may now be orphaned.
                throw error
            }
            throw reconciliationError
        }
    }

    private func reconcileCredentialReferences(
        in incomingProfiles: [VPNProfile],
        subscription: VPNSubscription,
        existingProfiles: [VPNProfile]
    ) async throws -> [VPNProfile] {
        let existingForSubscription = existingProfiles.filter {
            $0.sourceSubscriptionID == subscription.id
        }
        var existingByIdentity: [String: VPNProfile] = [:]
        for profile in existingForSubscription {
            let identity = profile.externalIdentity ?? merger.stableIdentity(for: profile)
            existingByIdentity[identity] = profile
        }

        var reconciledProfiles: [VPNProfile] = []
        reconciledProfiles.reserveCapacity(incomingProfiles.count)
        var matchedExistingProfileIDs = Set<UUID>()

        for var incomingProfile in incomingProfiles {
            let identity = incomingProfile.externalIdentity ?? merger.stableIdentity(for: incomingProfile)
            let exactMatch = existingByIdentity[identity]
            let existingProfile: VPNProfile?
            if let exactMatch {
                existingProfile = exactMatch
            } else {
                existingProfile = try await uniqueSemanticCredentialMatch(
                    for: incomingProfile,
                    candidates: existingForSubscription.filter {
                        matchedExistingProfileIDs.contains($0.id) == false
                    }
                )
                if let existingProfile {
                    // Content-derived identities legitimately change when a
                    // provider changes endpoint, transport, or protocol options.
                    // Preserve continuity only after a unique, in-memory
                    // credential comparison; no secret material enters the
                    // persisted identity or diagnostics.
                    incomingProfile.externalIdentity = existingProfile.externalIdentity
                        ?? merger.stableIdentity(for: existingProfile)
                }
            }

            guard let existingProfile else {
                reconciledProfiles.append(incomingProfile)
                continue
            }
            matchedExistingProfileIDs.insert(existingProfile.id)

            for slot in VPNProfileCredentialSlot.allCases {
                guard let incomingReference = incomingProfile.credentialReference(for: slot) else {
                    continue
                }
                guard let incomingSecret = try await credentialStore.secret(for: incomingReference) else {
                    throw SubscriptionError.credentialsUnavailable
                }
                guard let existingReference = existingProfile.credentialReference(for: slot),
                      existingReference != incomingReference,
                      let existingSecret = try await credentialStore.secret(for: existingReference),
                      existingSecret == incomingSecret else {
                    continue
                }

                // Equal secret material is a semantic no-op. Reuse the committed
                // reference so a parser-generated random UUID cannot create a
                // false provider change or an unnecessary profile revision.
                incomingProfile.setCredentialReference(existingReference, for: slot)
            }
            reconciledProfiles.append(incomingProfile)
        }

        return reconciledProfiles
    }

    private func uniqueSemanticCredentialMatch(
        for incomingProfile: VPNProfile,
        candidates: [VPNProfile]
    ) async throws -> VPNProfile? {
        var match: VPNProfile?
        for candidate in candidates where candidate.protocolType == incomingProfile.protocolType {
            guard try await credentialsAreSemanticallyEqual(
                incomingProfile,
                candidate
            ) else {
                continue
            }
            guard match == nil else {
                // Reused credentials do not uniquely identify a provider entry.
                return nil
            }
            match = candidate
        }
        return match
    }

    private func credentialsAreSemanticallyEqual(
        _ lhs: VPNProfile,
        _ rhs: VPNProfile
    ) async throws -> Bool {
        for slot in VPNProfileCredentialSlot.allCases {
            let lhsReference = lhs.credentialReference(for: slot)
            let rhsReference = rhs.credentialReference(for: slot)
            switch (lhsReference, rhsReference) {
            case (nil, nil):
                continue
            case (.some(let lhsReference), .some(let rhsReference)):
                if lhsReference == rhsReference {
                    continue
                }
                guard let lhsSecret = try await credentialStore.secret(for: lhsReference),
                      let rhsSecret = try await credentialStore.secret(for: rhsReference) else {
                    throw SubscriptionError.credentialsUnavailable
                }
                guard lhsSecret == rhsSecret else {
                    return false
                }
            case (.some, nil), (nil, .some):
                return false
            }
        }
        return true
    }

    private func credentialReferences(in profiles: [VPNProfile]) -> Set<String> {
        profiles.reduce(into: Set<String>()) { references, profile in
            references.formUnion(profile.credentialReferences)
        }
    }

    private func deleteCredentialReferences(_ references: Set<String>) async throws {
        var firstError: (any Error)?
        for reference in references.sorted() {
            do {
                try await credentialStore.delete(reference: reference)
            } catch {
                if firstError == nil {
                    firstError = error
                }
            }
        }
        if let firstError {
            throw firstError
        }
    }
}
