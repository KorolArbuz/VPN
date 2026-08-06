//
//  MockServerProber.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct MockServerProber: ServerProbing {
    private let packetLossByServerID: [UUID: Double]

    init(packetLossByServerID: [UUID: Double] = [:]) {
        self.packetLossByServerID = packetLossByServerID
    }

    func metrics(for server: VPNServer) async throws -> ConnectionMetrics {
        guard server.isAvailable else {
            throw MockVPNError.serverUnavailable
        }

        try await Task.sleep(for: .milliseconds(80))

        return ConnectionMetrics(
            latency: server.latency,
            packetLoss: packetLossByServerID[server.id] ?? defaultPacketLoss(for: server),
            serverLoad: server.load,
            connectionTime: 0
        )
    }

    private func defaultPacketLoss(for server: VPNServer) -> Double {
        switch server.countryCode {
        case "DE":
            0.025
        case "FI":
            0.006
        case "US":
            0.011
        default:
            0.01
        }
    }
}
