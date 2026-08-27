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
            LocalizedStringResource(
                "connection.mode.automatic",
                defaultValue: "Automatic"
            )
        case .manual:
            LocalizedStringResource(
                "connection.mode.manual",
                defaultValue: "Manual"
            )
        }
    }
}

/// Build 8 has one production Automatic-selection authority. The Rust
/// ConnectionScorer/SelectionPolicy stack remains diagnostic-only.
///
/// TODO: A future authority migration must choose exactly one end state:
/// A. delete the unused Rust selection stack, or
/// B. prove Swift/Rust parity, move production authority to kvn-core, and then
///    remove the Swift scorer. A permanent dual-authority design is forbidden.
nonisolated enum SmartConnectionSelectionAuthorityContract {
    static let production = "swift-smart-connection-planner"
}

nonisolated struct ConnectionSelectionPresentation: Equatable, Sendable {
    var mode: ConnectionSelectionMode
    var selectableProfileIDs: [UUID]
    var recommendedProfileID: UUID?

    // Complete profiles are atomic. These remain explicit product contracts,
    // not derived from legacy server/protocol metadata.
    let showsIndependentServerSelector = false
    let showsIndependentProtocolSelector = false

    var showsSelectableProfileList: Bool {
        mode == .manual
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
            LocalizedStringResource(
                "connection.smart.reason.reliable",
                defaultValue: "Most reliable on this network"
            )
        case .lowestLatency:
            LocalizedStringResource(
                "connection.smart.reason.latency",
                defaultValue: "Lowest recent latency"
            )
        case .lowestLoss:
            LocalizedStringResource(
                "connection.smart.reason.loss",
                defaultValue: "Lowest recent packet loss"
            )
        case .fastestConnection:
            LocalizedStringResource(
                "connection.smart.reason.speed",
                defaultValue: "Fastest connection"
            )
        case .stableSessions:
            LocalizedStringResource(
                "connection.smart.reason.stability",
                defaultValue: "Stable over recent sessions"
            )
        case .learningThisNetwork:
            LocalizedStringResource(
                "connection.smart.reason.learning",
                defaultValue: "Learning this network"
            )
        case .availableData:
            LocalizedStringResource(
                "connection.smart.reason.available_data",
                defaultValue: "Recommended based on available data"
            )
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
    var maximumAttempts: Int
    var rankedCandidates: [SmartConnectionRankedCandidate]
    var explorationCandidateID: UUID? = nil

    var candidateIDs: [UUID] {
        rankedCandidates.prefix(maximumAttempts).map(\.profileID)
    }

    static func empty(context: NetworkContext, now: Date) -> SmartConnectionCandidatePlan {
        SmartConnectionCandidatePlan(
            id: UUID(),
            createdAt: now,
            context: context,
            maximumAttempts: 0,
            rankedCandidates: [],
            explorationCandidateID: nil
        )
    }
}

nonisolated struct SmartConnectionSessionSummary: Equatable, Sendable {
    var additionalSuccessfulSessionSeconds: TimeInterval
    var latencyMilliseconds: Double?
    var packetLossPercent: Double?
    var sessionEnded: Bool
    var unexpectedDisconnect: Bool
    var sessionID: String?

    init(
        additionalSuccessfulSessionSeconds: TimeInterval,
        latencyMilliseconds: Double?,
        packetLossPercent: Double?,
        sessionEnded: Bool,
        unexpectedDisconnect: Bool,
        sessionID: String? = nil
    ) {
        self.additionalSuccessfulSessionSeconds = additionalSuccessfulSessionSeconds
        self.latencyMilliseconds = latencyMilliseconds
        self.packetLossPercent = packetLossPercent
        self.sessionEnded = sessionEnded
        self.unexpectedDisconnect = unexpectedDisconnect
        self.sessionID = sessionID
    }

    static let empty = SmartConnectionSessionSummary(
        additionalSuccessfulSessionSeconds: 0,
        latencyMilliseconds: nil,
        packetLossPercent: nil,
        sessionEnded: false,
        unexpectedDisconnect: false,
        sessionID: nil
    )
}

nonisolated protocol SmartConnectionDebounceSleeping: Sendable {
    func sleep(for duration: Duration) async throws
}

nonisolated struct TaskSmartConnectionDebounceSleeper: SmartConnectionDebounceSleeping {
    func sleep(for duration: Duration) async throws {
        try await Task.sleep(for: duration)
    }
}

nonisolated enum SmartConnectionQualityState: String, Equatable, Sendable {
    case normal
    case degraded
}

/// Passive diagnostics only. A measurement is anomalous when latency is both
/// at least 2x and 100 ms above its learned EWMA, or loss is both at least 2x
/// and 5 percentage points above its learned EWMA. Two consecutive anomalous
/// measurements are required; this type has no connection-control capability.
nonisolated struct SmartConnectionAnomalyDetector: Equatable, Sendable {
    private(set) var consecutiveAnomalies = 0
    private(set) var state: SmartConnectionQualityState = .normal

    mutating func observe(
        latencyMilliseconds: Double?,
        packetLossPercent: Double?,
        baselineLatencyMilliseconds: Double?,
        baselinePacketLossPercent: Double?
    ) -> SmartConnectionQualityState {
        let latencyIsAnomalous = Self.exceedsBaseline(
            observation: latencyMilliseconds,
            baseline: baselineLatencyMilliseconds,
            minimumAbsoluteIncrease: 100
        )
        let lossIsAnomalous = Self.exceedsBaseline(
            observation: packetLossPercent,
            baseline: baselinePacketLossPercent,
            minimumAbsoluteIncrease: 5
        )

        if latencyIsAnomalous || lossIsAnomalous {
            consecutiveAnomalies += 1
        } else {
            consecutiveAnomalies = 0
        }
        state = consecutiveAnomalies >= 2 ? .degraded : .normal
        return state
    }

    private static func exceedsBaseline(
        observation: Double?,
        baseline: Double?,
        minimumAbsoluteIncrease: Double
    ) -> Bool {
        guard let observation, let baseline, baseline >= 0 else {
            return false
        }
        return observation >= baseline * 2
            && observation >= baseline + minimumAbsoluteIncrease
    }
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
