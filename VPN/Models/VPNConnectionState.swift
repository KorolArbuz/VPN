//
//  VPNConnectionState.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum VPNConnectionState: String, Codable, Sendable {
    case disconnected
    case testing
    case connecting
    case connected
    case disconnecting
    case failed

    var displayName: String {
        switch self {
        case .disconnected:
            "Disconnected"
        case .testing:
            "Testing"
        case .connecting:
            "Connecting"
        case .connected:
            "Connected"
        case .disconnecting:
            "Disconnecting"
        case .failed:
            "Failed"
        }
    }
}
