//
//  VPNProtocol.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum VPNProtocol: String, CaseIterable, Codable, Identifiable, Sendable {
    case wireGuard
    case amneziaWG
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
        case .amneziaWG:
            "AmneziaWG"
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
        case .amneziaWG:
            1
        case .ikev2:
            2
        case .hysteria2:
            3
        case .vless:
            4
        case .trojan:
            5
        case .shadowsocks:
            6
        case .tuic:
            7
        case .vmess:
            8
        }
    }

    var iconName: String {
        switch self {
        case .wireGuard, .amneziaWG:
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
