//
//  VPNProtocolSelection.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum VPNProtocolSelection: Identifiable, Hashable, Sendable {
    case automatic
    case manual(VPNProtocol)

    var id: String {
        switch self {
        case .automatic:
            "automatic"
        case .manual(let vpnProtocol):
            vpnProtocol.id
        }
    }

    var displayName: String {
        switch self {
        case .automatic:
            "Automatic"
        case .manual(let vpnProtocol):
            vpnProtocol.displayName
        }
    }
}
