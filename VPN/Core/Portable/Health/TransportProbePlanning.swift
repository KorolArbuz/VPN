//
//  TransportProbePlanning.swift
//  VPN
//
//  Converts existing VPNProfile values into safe transport probe requests.
//  Credentials and raw import payloads never cross this boundary.
//

import Foundation

nonisolated protocol ProbePlanning: Sendable {
    func plan(profile: VPNProfile, context: ProbeContext, now: Date) -> TransportProbePlanEntry
}

nonisolated struct DefaultProbePlanner: ProbePlanning {
    init() {}

    func plan(profile: VPNProfile, context: ProbeContext, now: Date = Date()) -> TransportProbePlanEntry {
        let candidate = KVNCoreMapper.candidate(from: profile)

        guard profile.isEnabled else {
            return .skipped(skippedSummary(profile: profile, candidateID: candidate.candidateID, context: context, now: now, failure: .unsupportedProbe))
        }

        guard profile.isComplete else {
            return .skipped(skippedSummary(profile: profile, candidateID: candidate.candidateID, context: context, now: now, failure: .invalidEndpoint))
        }

        guard let port = profile.port, (1...65535).contains(port), let safePort = UInt16(exactly: port) else {
            return .skipped(skippedSummary(profile: profile, candidateID: candidate.candidateID, context: context, now: now, failure: .invalidEndpoint))
        }

        let host = profile.serverAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard host.isEmpty == false else {
            return .skipped(skippedSummary(profile: profile, candidateID: candidate.candidateID, context: context, now: now, failure: .invalidEndpoint))
        }

        guard supportsGenericAppProbe(profile) else {
            return .skipped(skippedSummary(profile: profile, candidateID: candidate.candidateID, context: context, now: now, failure: .unsupportedProbe))
        }

        if profile.tlsSettings.isEnabled {
            guard profile.tlsSettings.allowInsecure == false,
                  isReality(profile) == false,
                  let serverName = safeServerName(profile.tlsSettings.serverName) else {
                return .skipped(skippedSummary(profile: profile, candidateID: candidate.candidateID, context: context, now: now, failure: .unsupportedProbe))
            }

            return .request(TransportProbeRequest(
                candidateID: candidate.candidateID,
                profileID: candidate.profileID,
                displayName: displayName(profile),
                protocolType: profile.protocolType,
                host: host,
                port: safePort,
                transport: normalized(profile.transportSettings.network),
                security: normalized(profile.transportSettings.security),
                kind: .tlsHandshake,
                serverName: serverName
            ))
        }

        return .request(TransportProbeRequest(
            candidateID: candidate.candidateID,
            profileID: candidate.profileID,
            displayName: displayName(profile),
            protocolType: profile.protocolType,
            host: host,
            port: safePort,
            transport: normalized(profile.transportSettings.network),
            security: normalized(profile.transportSettings.security),
            kind: .tcpConnect
        ))
    }

    private func supportsGenericAppProbe(_ profile: VPNProfile) -> Bool {
        switch profile.protocolType {
        case .vless, .trojan, .vmess, .shadowsocks:
            break
        case .hysteria2, .wireGuard, .amneziaWG, .tuic, .ikev2:
            return false
        }

        guard isReality(profile) == false else {
            return false
        }

        switch normalized(profile.transportSettings.network) {
        case nil, "tcp", "ws", "websocket":
            return true
        case "udp", "quic", "grpc", "xhttp", "httpupgrade", "http-upgrade":
            return false
        default:
            return false
        }
    }

    private func isReality(_ profile: VPNProfile) -> Bool {
        normalized(profile.transportSettings.security) == "reality" || profile.tlsSettings.realityPublicKey != nil || profile.tlsSettings.publicKeyReference != nil
    }

    private func safeServerName(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmed.isEmpty ? nil : trimmed
    }

    private func normalized(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        return trimmed.isEmpty ? nil : trimmed
    }

    private func displayName(_ profile: VPNProfile) -> String {
        let trimmed = (profile.customDisplayName ?? profile.name).trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? profile.protocolType.displayName : trimmed
    }

    private func skippedSummary(
        profile: VPNProfile,
        candidateID: String,
        context: ProbeContext,
        now: Date,
        failure: TransportProbeFailure
    ) -> TransportProbeSummary {
        TransportProbeSummary(
            candidateID: candidateID,
            profileID: profile.id.uuidString,
            displayName: displayName(profile),
            protocolType: profile.protocolType,
            host: profile.serverAddress,
            port: UInt16(clamping: profile.port ?? 0),
            kind: nil,
            context: context,
            checkedAt: now,
            reachable: false,
            connectLatencyMs: nil,
            jitterMs: nil,
            handshakeMs: nil,
            successfulAttempts: 0,
            failedAttempts: 0,
            failure: failure
        )
    }
}

nonisolated struct ProbeResultAggregator: Sendable {
    init() {}

    func summarize(
        request: TransportProbeRequest,
        attempts: [TransportProbeAttempt],
        context: ProbeContext,
        now: Date = Date()
    ) -> TransportProbeSummary {
        let successfulAttempts = attempts.filter(\.isReachable)
        let latencies = successfulAttempts.compactMap(\.connectLatencyMs)
        let handshakes = successfulAttempts.compactMap(\.handshakeLatencyMs)
        let medianLatency = Self.median(latencies)
        let medianHandshake = Self.median(handshakes)
        let jitter = medianLatency.flatMap { Self.medianAbsoluteDeviation(values: latencies, median: $0) }
        let failure = successfulAttempts.isEmpty ? failureForAllFailedAttempts(attempts) : nil

        return TransportProbeSummary(
            candidateID: request.candidateID,
            profileID: request.profileID,
            displayName: request.displayName,
            protocolType: request.protocolType,
            host: request.host,
            port: request.port,
            kind: request.kind,
            context: context,
            checkedAt: now,
            reachable: successfulAttempts.isEmpty == false,
            connectLatencyMs: medianLatency,
            jitterMs: jitter,
            handshakeMs: medianHandshake,
            successfulAttempts: successfulAttempts.count,
            failedAttempts: attempts.count - successfulAttempts.count,
            failure: failure
        )
    }

    static func median(_ values: [Double]) -> Double? {
        guard values.isEmpty == false else { return nil }

        let sorted = values.sorted()
        let middle = sorted.count / 2
        if sorted.count.isMultiple(of: 2) {
            return (sorted[middle - 1] + sorted[middle]) / 2
        }

        return sorted[middle]
    }

    static func medianAbsoluteDeviation(values: [Double], median: Double) -> Double? {
        let deviations = values.map { abs($0 - median) }
        return Self.median(deviations)
    }

    private func failureForAllFailedAttempts(_ attempts: [TransportProbeAttempt]) -> TransportProbeFailure {
        let failures = attempts.compactMap(\.failure)
        guard failures.isEmpty == false else {
            return .noSuccessfulAttempts
        }

        let grouped = Dictionary(grouping: failures) { $0 }
        if grouped.count == 1, let failure = failures.first {
            return failure
        }

        return .noSuccessfulAttempts
    }
}
