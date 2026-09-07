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

/// Network-environment observations may refine the next recommendation, but
/// they never authorize a live tunnel replacement.
nonisolated enum SmartConnectionLiveSwitchingContract {
    static let isEnabled = false
    static let automaticRecommendationsApplyOnlyWhileDisconnected = true
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

/// The source that made an environment-specific V2 context possible.
///
/// Build-8 coarse contexts decode as ``coarseOnly`` and remain V1 records.
/// A V2 record is created only by ``NetworkContext/observedV2(coarseContext:environmentIdentity:)``
/// after a non-empty environment identity was actually observed.
nonisolated enum SmartConnectionNetworkIdentitySource: String, Codable, Sendable {
    case localNetwork
    case asn
    case coarseOnly
}

/// A future SSID-derived tag is a 128-bit truncation of HMAC-SHA256, represented
/// as 32 lowercase hexadecimal characters. This type stores only the opaque
/// output; this build intentionally has no SSID reader or HMAC-key implementation.
nonisolated struct SmartConnectionLocalNetworkTag:
    RawRepresentable,
    Codable,
    Hashable,
    Sendable {
    static let byteCount = 16

    let rawValue: String

    init?(rawValue: String) {
        let normalized = rawValue.lowercased()
        guard normalized.utf8.count == Self.byteCount * 2,
              normalized.utf8.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
              }) else {
            return nil
        }
        self.rawValue = normalized
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(String.self)
        guard let tag = Self(rawValue: value) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Local network tag must be 128-bit lowercase hex."
            )
        }
        self = tag
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

/// The only network-environment identity fields permitted in Smart Connection
/// persistence. Raw network names, addresses, location, and key material have
/// no representation in this model.
nonisolated struct SmartConnectionEnvironmentIdentity:
    Codable,
    Hashable,
    Sendable {
    var localNetworkTag: SmartConnectionLocalNetworkTag?
    var underlyingASN: UInt32?

    init(
        localNetworkTag: SmartConnectionLocalNetworkTag? = nil,
        underlyingASN: UInt32? = nil
    ) {
        self.localNetworkTag = localNetworkTag
        self.underlyingASN = underlyingASN == 0 ? nil : underlyingASN
    }

    static let empty = SmartConnectionEnvironmentIdentity()

    var isEmpty: Bool {
        localNetworkTag == nil && underlyingASN == nil
    }

    var preferredSource: SmartConnectionNetworkIdentitySource {
        if localNetworkTag != nil {
            return .localNetwork
        }
        if underlyingASN != nil {
            return .asn
        }
        return .coarseOnly
    }

    var stableKey: String {
        [
            "local:\(localNetworkTag?.rawValue ?? "none")",
            "asn:\(underlyingASN.map(String.init) ?? "none")"
        ].joined(separator: "|")
    }
}

/// Versioned network context used by the existing local learning hierarchy.
///
/// V1 is the exact Build-8 coarse shape. V2 adds an observed physical
/// environment identity while retaining interface and route-capability
/// metadata. IPv4/IPv6 support remains useful metadata, never the sole
/// physical-network identity.
nonisolated struct NetworkContext: Codable, Hashable, Sendable {
    static let coarseSchemaVersion = 1
    static let currentSchemaVersion = 2

    private(set) var schemaVersion: Int
    var interfaceClass: SmartConnectionInterfaceClass
    var isExpensive: Bool
    var isConstrained: Bool
    var supportsIPv4: Bool
    var supportsIPv6: Bool
    private(set) var environmentIdentity: SmartConnectionEnvironmentIdentity
    private(set) var identitySource: SmartConnectionNetworkIdentitySource

    /// Creates the Build-8-compatible coarse context produced by NWPath.
    init(
        interfaceClass: SmartConnectionInterfaceClass = .other,
        isExpensive: Bool = false,
        isConstrained: Bool = false,
        supportsIPv4: Bool = false,
        supportsIPv6: Bool = false
    ) {
        schemaVersion = Self.coarseSchemaVersion
        self.interfaceClass = interfaceClass
        self.isExpensive = isExpensive
        self.isConstrained = isConstrained
        self.supportsIPv4 = supportsIPv4
        self.supportsIPv6 = supportsIPv6
        environmentIdentity = .empty
        identitySource = .coarseOnly
    }

    private init(
        schemaVersion: Int,
        interfaceClass: SmartConnectionInterfaceClass,
        isExpensive: Bool,
        isConstrained: Bool,
        supportsIPv4: Bool,
        supportsIPv6: Bool,
        environmentIdentity: SmartConnectionEnvironmentIdentity,
        identitySource: SmartConnectionNetworkIdentitySource
    ) {
        self.schemaVersion = schemaVersion
        self.interfaceClass = interfaceClass
        self.isExpensive = isExpensive
        self.isConstrained = isConstrained
        self.supportsIPv4 = supportsIPv4
        self.supportsIPv6 = supportsIPv6
        self.environmentIdentity = environmentIdentity
        self.identitySource = identitySource
    }

    /// Promotes an actually observed environment to an exact V2 context.
    /// Empty/unavailable enrichment deliberately remains the original V1 prior.
    static func observedV2(
        coarseContext: NetworkContext,
        environmentIdentity: SmartConnectionEnvironmentIdentity
    ) -> NetworkContext? {
        guard environmentIdentity.isEmpty == false else {
            return nil
        }
        return NetworkContext(
            schemaVersion: Self.currentSchemaVersion,
            interfaceClass: coarseContext.interfaceClass,
            isExpensive: coarseContext.isExpensive,
            isConstrained: coarseContext.isConstrained,
            supportsIPv4: coarseContext.supportsIPv4,
            supportsIPv6: coarseContext.supportsIPv6,
            environmentIdentity: environmentIdentity,
            identitySource: environmentIdentity.preferredSource
        )
    }

    var hasExactEnvironmentIdentity: Bool {
        schemaVersion == Self.currentSchemaVersion
            && environmentIdentity.isEmpty == false
            && identitySource == environmentIdentity.preferredSource
    }

    /// The matching Build-8 coarse prior. No V2 record is fabricated by this
    /// projection; it returns the pre-existing V1 key shape.
    var matchingCoarseContext: NetworkContext {
        if schemaVersion == Self.coarseSchemaVersion {
            return self
        }
        return NetworkContext(
            interfaceClass: interfaceClass,
            isExpensive: isExpensive,
            isConstrained: isConstrained,
            supportsIPv4: supportsIPv4,
            supportsIPv6: supportsIPv6
        )
    }

    /// Physical identity is kept distinct from route capabilities so callers
    /// cannot mistake IPv4/IPv6 support for a network identifier.
    var physicalEnvironmentKey: String? {
        guard hasExactEnvironmentIdentity else {
            return nil
        }
        return [
            identitySource.rawValue,
            environmentIdentity.stableKey
        ].joined(separator: "|")
    }

    var routeCapabilitiesKey: String {
        [
            interfaceClass.rawValue,
            isExpensive ? "expensive" : "not-expensive",
            isConstrained ? "constrained" : "not-constrained",
            supportsIPv4 ? "ipv4" : "no-ipv4",
            supportsIPv6 ? "ipv6" : "no-ipv6"
        ].joined(separator: "|")
    }

    /// Stable, inspectable identity used only inside the local learning file.
    /// V1 remains byte-for-byte compatible with the Build-8 key format.
    var stableKey: String {
        if schemaVersion == Self.coarseSchemaVersion {
            return ["v1", routeCapabilitiesKey].joined(separator: "|")
        }
        return [
            "v2",
            physicalEnvironmentKey ?? "invalid-environment",
            routeCapabilitiesKey
        ].joined(separator: "|")
    }

    var isSupportedForLearning: Bool {
        switch schemaVersion {
        case Self.coarseSchemaVersion:
            environmentIdentity.isEmpty && identitySource == .coarseOnly
        case Self.currentSchemaVersion:
            hasExactEnvironmentIdentity
        default:
            false
        }
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case interfaceClass
        case isExpensive
        case isConstrained
        case supportsIPv4
        case supportsIPv6
        case environmentIdentity
        case identitySource
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedVersion = try container.decodeIfPresent(
            Int.self,
            forKey: .schemaVersion
        ) ?? Self.coarseSchemaVersion
        let interfaceClass = try container.decode(
            SmartConnectionInterfaceClass.self,
            forKey: .interfaceClass
        )
        let isExpensive = try container.decode(Bool.self, forKey: .isExpensive)
        let isConstrained = try container.decode(Bool.self, forKey: .isConstrained)
        let supportsIPv4 = try container.decode(Bool.self, forKey: .supportsIPv4)
        let supportsIPv6 = try container.decode(Bool.self, forKey: .supportsIPv6)

        switch decodedVersion {
        case Self.coarseSchemaVersion:
            self.init(
                interfaceClass: interfaceClass,
                isExpensive: isExpensive,
                isConstrained: isConstrained,
                supportsIPv4: supportsIPv4,
                supportsIPv6: supportsIPv6
            )
        case Self.currentSchemaVersion:
            let identity = try container.decode(
                SmartConnectionEnvironmentIdentity.self,
                forKey: .environmentIdentity
            )
            let source = try container.decode(
                SmartConnectionNetworkIdentitySource.self,
                forKey: .identitySource
            )
            guard identity.isEmpty == false,
                  source == identity.preferredSource else {
                throw DecodingError.dataCorruptedError(
                    forKey: .environmentIdentity,
                    in: container,
                    debugDescription: "V2 requires an observed, source-consistent identity."
                )
            }
            self.init(
                schemaVersion: decodedVersion,
                interfaceClass: interfaceClass,
                isExpensive: isExpensive,
                isConstrained: isConstrained,
                supportsIPv4: supportsIPv4,
                supportsIPv6: supportsIPv6,
                environmentIdentity: identity,
                identitySource: source
            )
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "Unsupported network-context schema version."
            )
        }
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(interfaceClass, forKey: .interfaceClass)
        try container.encode(isExpensive, forKey: .isExpensive)
        try container.encode(isConstrained, forKey: .isConstrained)
        try container.encode(supportsIPv4, forKey: .supportsIPv4)
        try container.encode(supportsIPv6, forKey: .supportsIPv6)
        if schemaVersion == Self.currentSchemaVersion {
            try container.encode(environmentIdentity, forKey: .environmentIdentity)
            try container.encode(identitySource, forKey: .identitySource)
        }
    }

    static let unknown = NetworkContext()
}

/// An inspectable Build-9 privacy/capability contract. The current target has
/// neither Access Wi-Fi Information nor Location permission, and the repository
/// contains no owned ASN service, so production identity remains coarse-only.
nonisolated enum SmartConnectionNetworkEnvironmentCapabilityContract {
    static let currentSSIDAvailable = false
    static let currentBSSIDAvailable = false
    static let localNetworkTaggingEnabled = false
    static let ownedUnderlyingASNEndpointAvailable = false
    static let permitsPublicThirdPartyASNService = false
}

nonisolated enum SmartConnectionLearningPrivacyContract {
    static let allowedPersistedIdentityFieldNames: Set<String> = [
        "localNetworkTag",
        "underlyingASN"
    ]

    static let forbiddenPersistedFieldNames: Set<String> = [
        "ssid",
        "bssid",
        "rawPublicIP",
        "publicIP",
        "privateIP",
        "localIP",
        "gatewayIP",
        "mac",
        "macAddress",
        "location",
        "deviceIdentifier",
        "credential",
        "credentials",
        "subscriptionURI",
        "providerConfiguration",
        "hmacSecret",
        "hmacKey",
        "localNetworkTagKey"
    ]
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

nonisolated struct SmartConnectionSessionQualityAggregate: Equatable, Sendable {
    var latencySum: Double
    var latencyCount: Int
    var tailLatencyMilliseconds: Double?
    var packetLossSum: Double
    var packetLossCount: Int
    var tailPacketLossPercent: Double?

    static let empty = SmartConnectionSessionQualityAggregate(
        latencySum: 0,
        latencyCount: 0,
        tailLatencyMilliseconds: nil,
        packetLossSum: 0,
        packetLossCount: 0,
        tailPacketLossPercent: nil
    )

    var latencyMeanMilliseconds: Double? {
        guard latencyCount > 0 else { return nil }
        return latencySum / Double(latencyCount)
    }

    var packetLossMeanPercent: Double? {
        guard packetLossCount > 0 else { return nil }
        return packetLossSum / Double(packetLossCount)
    }
}

nonisolated struct SmartConnectionSessionSummary: Equatable, Sendable {
    var additionalSuccessfulSessionSeconds: TimeInterval
    var latencyMilliseconds: Double?
    var packetLossPercent: Double?
    var sessionEnded: Bool
    var unexpectedDisconnect: Bool
    var sessionID: String?
    var tailLatencyMilliseconds: Double?
    var tailPacketLossPercent: Double?
    var qualityAggregate: SmartConnectionSessionQualityAggregate?
    var qualityAggregateIsCumulative: Bool

    init(
        additionalSuccessfulSessionSeconds: TimeInterval,
        latencyMilliseconds: Double?,
        packetLossPercent: Double?,
        sessionEnded: Bool,
        unexpectedDisconnect: Bool,
        sessionID: String? = nil,
        tailLatencyMilliseconds: Double? = nil,
        tailPacketLossPercent: Double? = nil,
        qualityAggregate: SmartConnectionSessionQualityAggregate? = nil,
        qualityAggregateIsCumulative: Bool = false
    ) {
        self.additionalSuccessfulSessionSeconds = additionalSuccessfulSessionSeconds
        self.latencyMilliseconds = latencyMilliseconds
        self.packetLossPercent = packetLossPercent
        self.sessionEnded = sessionEnded
        self.unexpectedDisconnect = unexpectedDisconnect
        self.sessionID = sessionID
        self.tailLatencyMilliseconds = tailLatencyMilliseconds
        self.tailPacketLossPercent = tailPacketLossPercent
        self.qualityAggregate = qualityAggregate
        self.qualityAggregateIsCumulative = qualityAggregateIsCumulative
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

    static let degradedStatusTitle = LocalizedStringResource(
        "connection.smart.quality.degraded",
        defaultValue: "Connection quality is degraded",
        comment: "Passive dashboard status shown when Smart Connection detects sustained tunnel degradation."
    )
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
