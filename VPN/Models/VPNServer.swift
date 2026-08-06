//
//  VPNServer.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct VPNServer: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    let name: String
    let country: String
    let countryCode: String
    let city: String
    let hostname: String
    let supportedProtocols: [VPNProtocol]
    let latency: Int
    let load: Double
    let isAvailable: Bool
}
