//
//  SubscriptionImportModels.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated enum SubscriptionContentFormat: String, Codable, Hashable, Sendable {
    case plainURIList
    case base64URIList
    case singBoxJSON
    case clashYAML
    case singleURI
    case unsupported

    var displayName: String {
        switch self {
        case .plainURIList: "Plain URI list"
        case .base64URIList: "Base64 subscription"
        case .singBoxJSON: "sing-box JSON"
        case .clashYAML: "Clash YAML"
        case .singleURI: "Single profile link"
        case .unsupported: "Unsupported"
        }
    }
}

nonisolated enum SubscriptionProfileState: String, Codable, Hashable, Sendable {
    case valid
    case incomplete
    case invalid
    case duplicate
}

nonisolated struct SubscriptionProfilePreview: Identifiable, Codable, Hashable, Sendable {
    var id: UUID
    var profile: VPNProfile
    var state: SubscriptionProfileState
    var message: String?
    var isSelected: Bool

    init(
        id: UUID = UUID(),
        profile: VPNProfile,
        state: SubscriptionProfileState,
        message: String? = nil,
        isSelected: Bool = true
    ) {
        self.id = id
        self.profile = profile
        self.state = state
        self.message = message
        self.isSelected = isSelected
    }
}

nonisolated struct SubscriptionPreview: Identifiable, Codable, Hashable, Sendable {
    var id: UUID
    var subscription: VPNSubscription
    var providerURLReference: String
    var detectedFormat: SubscriptionContentFormat
    var profiles: [SubscriptionProfilePreview]
    var warnings: [String]

    var selectedProfiles: [VPNProfile] {
        profiles.filter(\.isSelected).map(\.profile)
    }

    var validCount: Int {
        profiles.filter { $0.state == .valid }.count
    }

    var incompleteCount: Int {
        profiles.filter { $0.state == .incomplete }.count
    }

    var invalidCount: Int {
        profiles.filter { $0.state == .invalid }.count
    }

    var duplicateCount: Int {
        profiles.filter { $0.state == .duplicate }.count
    }
}

nonisolated enum SubscriptionProfileChangeKind: String, Codable, Hashable, Sendable {
    case added
    case updated
    case unchanged
    case missing
    case invalid
    case duplicate
}

nonisolated struct SubscriptionProfileChange: Identifiable, Codable, Hashable, Sendable {
    var id: UUID
    var kind: SubscriptionProfileChangeKind
    var incomingProfile: VPNProfile?
    var existingProfile: VPNProfile?
    var message: String?
    var isSelected: Bool

    init(
        id: UUID = UUID(),
        kind: SubscriptionProfileChangeKind,
        incomingProfile: VPNProfile? = nil,
        existingProfile: VPNProfile? = nil,
        message: String? = nil,
        isSelected: Bool = true
    ) {
        self.id = id
        self.kind = kind
        self.incomingProfile = incomingProfile
        self.existingProfile = existingProfile
        self.message = message
        self.isSelected = isSelected
    }
}

nonisolated struct SubscriptionUpdatePlan: Identifiable, Codable, Hashable, Sendable {
    var id: UUID
    var subscription: VPNSubscription
    var providerURLReference: String
    var detectedFormat: SubscriptionContentFormat
    var changes: [SubscriptionProfileChange]

    var addedCount: Int { changes.filter { $0.kind == .added }.count }
    var updatedCount: Int { changes.filter { $0.kind == .updated }.count }
    var unchangedCount: Int { changes.filter { $0.kind == .unchanged }.count }
    var missingCount: Int { changes.filter { $0.kind == .missing }.count }
    var invalidCount: Int { changes.filter { $0.kind == .invalid }.count }
    var duplicateCount: Int { changes.filter { $0.kind == .duplicate }.count }
}

nonisolated enum MissingSubscriptionProfilePolicy: String, Codable, Hashable, Sendable {
    case keep
    case disable
    case remove
}
