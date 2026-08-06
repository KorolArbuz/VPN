//
//  VPNProtocol.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum VPNProtocol: String, CaseIterable, Codable, Identifiable, Sendable {
    case wireGuard
    case ikev2
    case vless
    case hysteria2
    case trojan
    case shadowsocks
    case tuic
    case vmess

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .wireGuard:
            "WireGuard"
        case .ikev2:
            "IKEv2"
        case .vless:
            "VLESS"
        case .hysteria2:
            "Hysteria 2"
        case .trojan:
            "Trojan"
        case .shadowsocks:
            "Shadowsocks"
        case .tuic:
            "TUIC"
        case .vmess:
            "VMess"
        }
    }

    var automaticPriority: Int {
        switch self {
        case .wireGuard:
            0
        case .ikev2:
            1
        case .hysteria2:
            2
        case .vless:
            3
        case .trojan:
            4
        case .shadowsocks:
            5
        case .tuic:
            6
        case .vmess:
            7
        }
    }

    var iconName: String {
        switch self {
        case .wireGuard:
            "bolt.shield"
        case .ikev2:
            "building.columns"
        case .vless, .vmess:
            "point.3.connected.trianglepath.dotted"
        case .hysteria2, .tuic:
            "hare"
        case .trojan:
            "lock"
        case .shadowsocks:
            "eye.slash"
        }
    }
}
