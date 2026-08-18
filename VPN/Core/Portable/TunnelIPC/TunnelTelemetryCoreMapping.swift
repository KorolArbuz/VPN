//
//  TunnelTelemetryCoreMapping.swift
//  VPN
//
//  Converts authoritative PacketTunnelExtension runtime telemetry into the
//  existing KVNCore health DTO. This never issues connection commands.
//

import Foundation

nonisolated enum TunnelTelemetryComparability: Equatable, Sendable {
    case notUpdated
    case authoritativeCurrentOnly
    case insufficientComparability
}

nonisolated struct TunnelTelemetryCoreUpdateResult: Sendable {
    var updatedCandidateID: String?
    var recommendation: KVNSelectionDecisionDTO?
    var comparability: TunnelTelemetryComparability
}

nonisolated struct TunnelTelemetryHealthMapper {
    init() {}

    func healthSample(from snapshot: TunnelRuntimeSnapshot) -> KVNHealthSampleDTO? {
        switch snapshot.health.state {
        case .healthy:
            return KVNHealthSampleDTO(
                timestampMs: milliseconds(snapshot.health.generatedAt),
                reachable: true,
                latencyMs: nil,
                jitterMs: nil,
                packetLossPercent: nil,
                handshakeMs: nil,
                downloadBps: nil,
                uploadBps: nil,
                failure: nil
            )
        case .failed:
            return KVNHealthSampleDTO(
                timestampMs: milliseconds(snapshot.health.generatedAt),
                reachable: false,
                latencyMs: nil,
                jitterMs: nil,
                packetLossPercent: nil,
                handshakeMs: nil,
                downloadBps: nil,
                uploadBps: nil,
                failure: snapshot.lastFailure?.category.rawValue ?? TunnelFailureCategory.unknown.rawValue
            )
        case .unknown, .starting, .degraded, .stopped:
            return nil
        }
    }

    private func milliseconds(_ date: Date) -> UInt64 {
        let interval = date.timeIntervalSince1970
        guard interval > 0 else { return 0 }
        return UInt64(interval * 1_000)
    }
}

actor TunnelTelemetryCoreUpdater {
    private let coreService: any PortableCoreHealthServicing
    private let mapper: TunnelTelemetryHealthMapper

    init(coreService: any PortableCoreHealthServicing, mapper: TunnelTelemetryHealthMapper = TunnelTelemetryHealthMapper()) {
        self.coreService = coreService
        self.mapper = mapper
    }

    func apply(
        runtime snapshot: TunnelRuntimeSnapshot,
        profiles: [VPNProfile],
        activeProfileID: UUID?,
        now: Date = Date()
    ) async throws -> TunnelTelemetryCoreUpdateResult {
        guard snapshot.origin == .packetTunnelExtension, snapshot.health.isLive else {
            return TunnelTelemetryCoreUpdateResult(updatedCandidateID: nil, recommendation: nil, comparability: .notUpdated)
        }

        let candidateID = snapshot.candidateID ?? snapshot.activeProfileID
        guard let candidateID, candidateID.isEmpty == false else {
            return TunnelTelemetryCoreUpdateResult(updatedCandidateID: nil, recommendation: nil, comparability: .notUpdated)
        }

        if let activeProfileID, candidateID != activeProfileID.uuidString {
            return TunnelTelemetryCoreUpdateResult(updatedCandidateID: nil, recommendation: nil, comparability: .notUpdated)
        }

        guard let sample = mapper.healthSample(from: snapshot) else {
            return TunnelTelemetryCoreUpdateResult(updatedCandidateID: nil, recommendation: nil, comparability: .notUpdated)
        }

        try await coreService.syncCandidates(from: profiles)
        try await coreService.updateHealth(candidateID: candidateID, sample: sample)
        let recommendation = try await coreService.selectBest(now: now)
        return TunnelTelemetryCoreUpdateResult(
            updatedCandidateID: candidateID,
            recommendation: recommendation,
            comparability: .insufficientComparability
        )
    }
}
