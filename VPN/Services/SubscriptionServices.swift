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
        do {
            let data = try Data(contentsOf: fileURL)
            return try decoder.decode([VPNSubscription].self, from: data)
        } catch {
            return []
        }
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
    private let merger: SubscriptionMerging
    private let planner: SubscriptionUpdatePlanning

    init(
        client: SubscriptionClient = URLSessionSubscriptionClient(),
        parser: SubscriptionContentParser = SubscriptionContentParser(linkParser: VPNLinkParser()),
        merger: SubscriptionMerging = DefaultSubscriptionMerger(),
        planner: SubscriptionUpdatePlanning = DefaultSubscriptionUpdatePlanner()
    ) {
        self.client = client
        self.parser = parser
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
                state = profile.isComplete ? .valid : .incomplete
            }
            return SubscriptionProfilePreview(profile: profile, state: state, message: profile.isComplete ? nil : profile.missingRequiredFields.joined(separator: ", "), isSelected: state == .valid)
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
        var plan = planner.planUpdate(subscription: subscription, incoming: preview.profiles.map(\.profile), existing: existingProfiles)
        plan.detectedFormat = preview.detectedFormat
        return plan
    }
}
