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
    var url: URL
    var lastUpdatedAt: Date?
    var updateInterval: TimeInterval
    var isEnabled: Bool
    var profileCount: Int
    var lastError: String?

    init(
        id: UUID = UUID(),
        name: String,
        url: URL,
        lastUpdatedAt: Date? = nil,
        updateInterval: TimeInterval = 86_400,
        isEnabled: Bool = true,
        profileCount: Int = 0,
        lastError: String? = nil
    ) {
        self.id = id
        self.name = name
        self.url = url
        self.lastUpdatedAt = lastUpdatedAt
        self.updateInterval = updateInterval
        self.isEnabled = isEnabled
        self.profileCount = profileCount
        self.lastError = lastError
    }
}
