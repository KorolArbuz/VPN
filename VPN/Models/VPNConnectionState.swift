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

    var localizationKey: String {
        switch self {
        case .disconnected:
            "home.status.disconnected"
        case .testing:
            "home.status.testing"
        case .connecting:
            "home.status.connecting"
        case .connected:
            "home.status.connected"
        case .disconnecting:
            "home.status.disconnecting"
        case .failed:
            "home.status.failed"
        }
    }
}
