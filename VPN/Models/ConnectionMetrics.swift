//
//  ConnectionMetrics.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct ConnectionMetrics: Codable, Hashable, Sendable {
    let latency: Int
    let packetLoss: Double
    let serverLoad: Double
    let connectionTime: TimeInterval
}
