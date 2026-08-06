//
//  ServerSelectionPolicy.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct ServerSelectionPolicy: Codable, Hashable, Sendable {
    var latencyWeight: Double
    var packetLossWeight: Double
    var serverLoadWeight: Double
    var failurePenalty: Double
    var unavailablePenalty: Double

    static let `default` = ServerSelectionPolicy(
        latencyWeight: 1 / 120,
        packetLossWeight: 18,
        serverLoadWeight: 2.2,
        failurePenalty: 50,
        unavailablePenalty: 100
    )

    func score(metrics: ConnectionMetrics, isAvailable: Bool, didFail: Bool = false) -> Double {
        let availabilityPenalty = isAvailable ? 0 : unavailablePenalty
        let failureScore = didFail ? failurePenalty : 0

        return Double(metrics.latency) * latencyWeight
            + metrics.packetLoss * packetLossWeight
            + metrics.serverLoad * serverLoadWeight
            + availabilityPenalty
            + failureScore
    }
}
