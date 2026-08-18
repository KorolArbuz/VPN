//
//  TransportHealthModels.swift
//  VPN
//
//  Phase F1 transport health probes for passive KVNCore recommendations.
//  These models intentionally carry no credentials, raw VPN URI, subscription
//  URL, private keys, tokens, or full backend configuration.
//

import Foundation

nonisolated enum TransportProbeKind: String, Codable, Equatable, Sendable {
    case tcpConnect
    case tlsHandshake
}

nonisolated enum ProbeRouteContext: String, Codable, Equatable, Sendable {
    case directSystemPath
    case currentSystemPath
}

nonisolated struct ProbeContext: Codable, Equatable, Sendable {
    var networkType: KVNNetworkType
    var routeContext: ProbeRouteContext

    init(networkType: KVNNetworkType = .unknown, routeContext: ProbeRouteContext = .directSystemPath) {
        self.networkType = networkType
        self.routeContext = routeContext
    }
}

nonisolated struct ProbeSeriesConfiguration: Equatable, Sendable {
    var attemptCount: Int
    var delayBetweenAttempts: Duration
    var perAttemptTimeout: Duration
    var maxConcurrentProbes: Int

    init(
        attemptCount: Int = 3,
        delayBetweenAttempts: Duration = .milliseconds(250),
        perAttemptTimeout: Duration = .seconds(3),
        maxConcurrentProbes: Int = 4
    ) {
        self.attemptCount = max(1, attemptCount)
        self.delayBetweenAttempts = delayBetweenAttempts
        self.perAttemptTimeout = perAttemptTimeout
        self.maxConcurrentProbes = max(1, maxConcurrentProbes)
    }
}

nonisolated struct TransportProbeRequest: Identifiable, Codable, Equatable, Sendable {
    var id: String { candidateID }

    var candidateID: String
    var profileID: String
    var displayName: String
    var protocolType: VPNProtocol
    var host: String
    var port: UInt16
    var transport: String?
    var security: String?
    var kind: TransportProbeKind
    var serverName: String?

    init(
        candidateID: String,
        profileID: String,
        displayName: String,
        protocolType: VPNProtocol,
        host: String,
        port: UInt16,
        transport: String?,
        security: String?,
        kind: TransportProbeKind,
        serverName: String? = nil
    ) {
        self.candidateID = candidateID
        self.profileID = profileID
        self.displayName = displayName
        self.protocolType = protocolType
        self.host = host
        self.port = port
        self.transport = transport
        self.security = security
        self.kind = kind
        self.serverName = serverName
    }
}

nonisolated enum TransportProbeFailure: String, Codable, Error, Equatable, Sendable {
    case invalidEndpoint
    case unsupportedProbe
    case dnsResolutionFailed
    case connectionTimedOut
    case connectionRefused
    case tlsHandshakeFailed
    case cancelled
    case noSuccessfulAttempts
    case staleResultDiscarded
    case connectionFailed
    case insufficientTelemetry
    case probingDisabled

    var localizationKey: String {
        switch self {
        case .invalidEndpoint:
            "diagnostics.probe.error.invalid_endpoint"
        case .unsupportedProbe, .insufficientTelemetry:
            "diagnostics.probe.error.unsupported"
        case .dnsResolutionFailed:
            "diagnostics.probe.error.dns"
        case .connectionTimedOut:
            "diagnostics.probe.error.timeout"
        case .connectionRefused:
            "diagnostics.probe.error.refused"
        case .tlsHandshakeFailed:
            "diagnostics.probe.error.tls"
        case .cancelled:
            "diagnostics.probe.error.cancelled"
        case .noSuccessfulAttempts:
            "diagnostics.probe.error.no_success"
        case .staleResultDiscarded:
            "diagnostics.probe.error.stale"
        case .connectionFailed:
            "diagnostics.probe.error.failed"
        case .probingDisabled:
            "diagnostics.probe.error.disabled"
        }
    }
}

nonisolated struct TransportProbeAttempt: Equatable, Sendable {
    var candidateID: String
    var attemptIndex: Int
    var startedAt: Date
    var finishedAt: Date
    var connectLatencyMs: Double?
    var handshakeLatencyMs: Double?
    var failure: TransportProbeFailure?

    var isReachable: Bool {
        failure == nil
    }
}

nonisolated struct TransportProbeSummary: Identifiable, Codable, Equatable, Sendable {
    var id: String { candidateID }

    var candidateID: String
    var profileID: String
    var displayName: String
    var protocolType: VPNProtocol
    var host: String
    var port: UInt16
    var kind: TransportProbeKind?
    var context: ProbeContext
    var checkedAt: Date
    var reachable: Bool
    var connectLatencyMs: Double?
    var jitterMs: Double?
    var handshakeMs: Double?
    var successfulAttempts: Int
    var failedAttempts: Int
    var failure: TransportProbeFailure?

    var healthSample: KVNHealthSampleDTO {
        KVNHealthSampleDTO(
            timestampMs: Self.milliseconds(checkedAt),
            reachable: reachable,
            latencyMs: connectLatencyMs,
            jitterMs: jitterMs,
            packetLossPercent: nil,
            handshakeMs: handshakeMs,
            failure: failure?.rawValue
        )
    }

    private static func milliseconds(_ date: Date) -> UInt64 {
        let interval = date.timeIntervalSince1970
        guard interval > 0 else { return 0 }
        return UInt64(interval * 1_000)
    }
}

nonisolated struct TransportHealthReport: Sendable {
    var generatedAt: Date
    var context: ProbeContext
    var summaries: [TransportProbeSummary]
    var recommendation: KVNSelectionDecisionDTO?
    var wasSkippedBecauseDisabled: Bool
}

nonisolated enum TransportProbePlanEntry: Equatable, Sendable {
    case request(TransportProbeRequest)
    case skipped(TransportProbeSummary)
}

nonisolated protocol ProbeSleeping: Sendable {
    func sleep(for duration: Duration) async throws
}

nonisolated struct TaskProbeSleeper: ProbeSleeping {
    func sleep(for duration: Duration) async throws {
        try await Task.sleep(for: duration)
    }
}

nonisolated struct ImmediateProbeSleeper: ProbeSleeping {
    func sleep(for duration: Duration) async throws {}
}
