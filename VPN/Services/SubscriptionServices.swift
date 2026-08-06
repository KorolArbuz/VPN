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
}

nonisolated protocol SubscriptionUpdating: Sendable {
    func preview(_ subscription: VPNSubscription) async throws -> [VPNProfile]
    func refresh(_ subscription: VPNSubscription) async throws -> [VPNProfile]
}

actor InMemorySubscriptionRepository: SubscriptionRepository {
    private var storedSubscriptions: [VPNSubscription] = []

    func subscriptions() async throws -> [VPNSubscription] {
        storedSubscriptions
    }

    func save(_ subscription: VPNSubscription) async throws {
        if let index = storedSubscriptions.firstIndex(where: { $0.id == subscription.id }) {
            storedSubscriptions[index] = subscription
        } else {
            storedSubscriptions.append(subscription)
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
    }
}

nonisolated struct MockSubscriptionUpdater: SubscriptionUpdating {
    func preview(_ subscription: VPNSubscription) async throws -> [VPNProfile] {
        throw VPNImportError.invalidPayload("Subscription refresh is not available in this build.")
    }

    func refresh(_ subscription: VPNSubscription) async throws -> [VPNProfile] {
        throw VPNImportError.invalidPayload("Subscription refresh is not available in this build.")
    }
}
