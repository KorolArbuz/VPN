//
//  MockServerCatalog.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum MockServerCatalog {
    static let servers: [VPNServer] = [
        VPNServer(
            id: stableID("11111111-1111-1111-1111-111111111111"),
            name: "NL Amsterdam 01",
            country: "Netherlands",
            countryCode: "NL",
            city: "Amsterdam",
            hostname: "ams-01.example.invalid",
            supportedProtocols: [.wireGuard, .ikev2, .shadowsocks],
            latency: 32,
            load: 0.42,
            isAvailable: true
        ),
        VPNServer(
            id: stableID("22222222-2222-2222-2222-222222222222"),
            name: "DE Frankfurt 01",
            country: "Germany",
            countryCode: "DE",
            city: "Frankfurt",
            hostname: "fra-01.example.invalid",
            supportedProtocols: [.wireGuard, .hysteria2, .vless],
            latency: 24,
            load: 0.73,
            isAvailable: true
        ),
        VPNServer(
            id: stableID("33333333-3333-3333-3333-333333333333"),
            name: "FI Helsinki 01",
            country: "Finland",
            countryCode: "FI",
            city: "Helsinki",
            hostname: "hel-01.example.invalid",
            supportedProtocols: [.ikev2, .trojan, .shadowsocks],
            latency: 41,
            load: 0.28,
            isAvailable: true
        ),
        VPNServer(
            id: stableID("44444444-4444-4444-4444-444444444444"),
            name: "PL Warsaw 01",
            country: "Poland",
            countryCode: "PL",
            city: "Warsaw",
            hostname: "waw-01.example.invalid",
            supportedProtocols: [.wireGuard, .vless, .trojan],
            latency: 18,
            load: 0.91,
            isAvailable: false
        ),
        VPNServer(
            id: stableID("55555555-5555-5555-5555-555555555555"),
            name: "US New York 01",
            country: "United States",
            countryCode: "US",
            city: "New York",
            hostname: "nyc-01.example.invalid",
            supportedProtocols: [.ikev2, .hysteria2, .shadowsocks],
            latency: 96,
            load: 0.35,
            isAvailable: true
        )
    ]

    private static func stableID(_ value: String) -> UUID {
        UUID(uuidString: value) ?? UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    }
}
