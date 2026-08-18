//
//  TunnelRuntimeAdapters.swift
//  VPN
//
//  Small mapping layer for real runtime telemetry when adapters become
//  available. No third-party runtime API is guessed here.
//

import Foundation

nonisolated struct Tun2SocksStatsSnapshot: Equatable, Sendable {
    var bytesUploaded: UInt64?
    var bytesDownloaded: UInt64?
    var packetsUploaded: UInt64?
    var packetsDownloaded: UInt64?

    func trafficCounters() -> TunnelTrafficCounters {
        TunnelTrafficCounters(
            bytesUploaded: bytesUploaded,
            bytesDownloaded: bytesDownloaded,
            packetsUploaded: packetsUploaded,
            packetsDownloaded: packetsDownloaded
        )
    }
}

nonisolated protocol Tun2SocksRuntimeStatsProviding: Sendable {
    func currentStats() async -> Tun2SocksStatsSnapshot?
}

nonisolated enum XrayRuntimeStateMapper {
    static func componentState(from rawState: String?) -> TunnelComponentState {
        switch rawState?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "running", "started", "ok":
            .running
        case "starting":
            .starting
        case "stopped", "stopped_ok":
            .stopped
        case "failed", "error":
            .failed
        case .none:
            .unavailable
        default:
            .unknown
        }
    }
}
