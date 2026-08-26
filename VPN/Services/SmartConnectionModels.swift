//
//  SmartConnectionModels.swift
//  VPN
//
//  Privacy-safe, local-only models used to rank complete VPN profiles.
//

import Foundation

nonisolated enum ConnectionSelectionMode: String, CaseIterable, Codable, Identifiable, Sendable {
    case automatic
    case manual

    var id: String { rawValue }

    var title: LocalizedStringResource {
        switch self {
        case .automatic:
            "connection.mode.automatic"
        case .manual:
            "connection.mode.manual"
        }
    }
}

nonisolated enum SmartConnectionInterfaceClass: String, Codable, CaseIterable, Sendable {
    case wifi
    case cellular
    case wiredEthernet
    case other
}

/// A deliberately coarse network key. It contains no SSID, BSSID, carrier,
/// address, account, or other persistent network/device identifier.
nonisolated struct NetworkContext: Codable, Hashable, Sendable {
    static let currentSchemaVersion = 1

    var schemaVersion: Int
    var interfaceClass: SmartConnectionInterfaceClass
    var isExpensive: Bool
    var isConstrained: Bool
    var supportsIPv4: Bool
    var supportsIPv6: Bool

    init(
        schemaVersion: Int = Self.currentSchemaVersion,
        interfaceClass: SmartConnectionInterfaceClass = .other,
        isExpensive: Bool = false,
        isConstrained: Bool = false,
        supportsIPv4: Bool = false,
        supportsIPv6: Bool = false
    ) {
        self.schemaVersion = schemaVersion
        self.interfaceClass = interfaceClass
        self.isExpensive = isExpensive
        self.isConstrained = isConstrained
        self.supportsIPv4 = supportsIPv4
        self.supportsIPv6 = supportsIPv6
    }

    /// Stable, inspectable identity used only inside the local learning file.
    var stableKey: String {
        [
            "v\(schemaVersion)",
            interfaceClass.rawValue,
            isExpensive ? "expensive" : "not-expensive",
            isConstrained ? "constrained" : "not-constrained",
            supportsIPv4 ? "ipv4" : "no-ipv4",
            supportsIPv6 ? "ipv6" : "no-ipv6"
        ].joined(separator: "|")
    }

    static let unknown = NetworkContext()
}

nonisolated protocol SmartConnectionNetworkContextProviding: Sendable {
    func currentNetworkContext() async -> NetworkContext
    func networkContextUpdates() -> AsyncStream<NetworkContext>
}

nonisolated enum SmartConnectionRecommendationReason: String, Codable, Sendable {
    case mostReliable
    case lowestLatency
    case lowestLoss
    case fastestConnection
    case stableSessions
    case learningThisNetwork
    case availableData

    var title: LocalizedStringResource {
        switch self {
        case .mostReliable:
            "connection.smart.reason.reliable"
        case .lowestLatency:
            "connection.smart.reason.latency"
        case .lowestLoss:
            "connection.smart.reason.loss"
        case .fastestConnection:
            "connection.smart.reason.speed"
        case .stableSessions:
            "connection.smart.reason.stability"
        case .learningThisNetwork:
            "connection.smart.reason.learning"
        case .availableData:
            "connection.smart.reason.available_data"
        }
    }
}

nonisolated struct SmartConnectionScoreBreakdown: Equatable, Sendable {
    var reliability: Double
    var latency: Double
    var packetLoss: Double
    var connectSpeed: Double
    var stability: Double
    var baseScore: Double
    var recentFailurePenalty: Double
    var recentSuccessBonus: Double
    var explorationBonus: Double
    var effectiveScore: Double
}

nonisolated struct SmartConnectionRankedCandidate: Identifiable, Equatable, Sendable {
    var id: UUID { profileID }

    var profileID: UUID
    var protocolType: VPNProtocol
    var contextAttemptCount: Int
    var latencyMilliseconds: Double?
    var packetLossPercent: Double?
    var reasons: [SmartConnectionRecommendationReason]
    var breakdown: SmartConnectionScoreBreakdown
}

nonisolated struct SmartConnectionCandidatePlan: Equatable, Sendable {
    var id: UUID
    var createdAt: Date
    var context: NetworkContext
    var rankedCandidates: [SmartConnectionRankedCandidate]

    var candidateIDs: [UUID] {
        rankedCandidates.map(\.profileID)
    }

    static func empty(context: NetworkContext, now: Date) -> SmartConnectionCandidatePlan {
        SmartConnectionCandidatePlan(
            id: UUID(),
            createdAt: now,
            context: context,
            rankedCandidates: []
        )
    }
}

nonisolated struct SmartConnectionSessionSummary: Equatable, Sendable {
    var additionalSuccessfulSessionSeconds: TimeInterval
    var latencyMilliseconds: Double?
    var packetLossPercent: Double?
    var unexpectedDisconnect: Bool

    static let empty = SmartConnectionSessionSummary(
        additionalSuccessfulSessionSeconds: 0,
        latencyMilliseconds: nil,
        packetLossPercent: nil,
        unexpectedDisconnect: false
    )
}

nonisolated protocol SmartConnectionClock: Sendable {
    func now() -> Date
}

nonisolated struct SystemSmartConnectionClock: SmartConnectionClock {
    func now() -> Date {
        Date()
    }
}

nonisolated struct FixedSmartConnectionNetworkContextSource: SmartConnectionNetworkContextProviding {
    var context: NetworkContext

    func currentNetworkContext() async -> NetworkContext {
        context
    }

    func networkContextUpdates() -> AsyncStream<NetworkContext> {
        AsyncStream { continuation in
            continuation.yield(context)
            continuation.finish()
        }
    }
}
