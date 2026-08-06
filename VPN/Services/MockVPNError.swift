//
//  MockVPNError.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum MockVPNError: LocalizedError, Sendable {
    case noAvailableServers
    case protocolUnavailable
    case serverUnavailable
    case incompleteProfile([String])

    var errorDescription: String? {
        switch self {
        case .noAvailableServers:
            "No available servers found."
        case .protocolUnavailable:
            "Selected protocol is not supported by this server."
        case .serverUnavailable:
            "Selected server is not available."
        case .incompleteProfile(let fields):
            "Profile is incomplete. Missing: \(fields.joined(separator: ", "))."
        }
    }
}
