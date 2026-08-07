//
//  VPNSubscription.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct VPNSubscription: Identifiable, Codable, Hashable, Sendable {
    var id: UUID
    var name: String
    var sanitizedHost: String
    var sanitizedURLDisplay: String
    var credentialReference: String?
    var createdAt: Date
    var updatedAt: Date
    var lastRefreshAt: Date?
    var lastSuccessfulRefreshAt: Date?
    var updateInterval: TimeInterval
    var isEnabled: Bool
    var profileCount: Int
    var lastError: String?
    var refreshState: VPNSubscriptionRefreshState

    init(
        id: UUID = UUID(),
        name: String,
        sanitizedHost: String,
        sanitizedURLDisplay: String,
        credentialReference: String? = nil,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        lastRefreshAt: Date? = nil,
        lastSuccessfulRefreshAt: Date? = nil,
        updateInterval: TimeInterval = 86_400,
        isEnabled: Bool = true,
        profileCount: Int = 0,
        lastError: String? = nil,
        refreshState: VPNSubscriptionRefreshState = .idle
    ) {
        self.id = id
        self.name = name
        self.sanitizedHost = sanitizedHost
        self.sanitizedURLDisplay = sanitizedURLDisplay
        self.credentialReference = credentialReference
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.lastRefreshAt = lastRefreshAt
        self.lastSuccessfulRefreshAt = lastSuccessfulRefreshAt
        self.updateInterval = updateInterval
        self.isEnabled = isEnabled
        self.profileCount = profileCount
        self.lastError = lastError
        self.refreshState = refreshState
    }
}

nonisolated enum VPNSubscriptionRefreshState: String, Codable, Hashable, Sendable {
    case idle
    case validating
    case downloading
    case decoding
    case parsing
    case reviewing
    case saving
    case completed
    case failed
    case cancelled
}

nonisolated enum VPNSubscriptionRemovalMode: String, Codable, Hashable, Sendable {
    case deleteProfiles
    case keepProfiles
}
