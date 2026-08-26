//
//  TunnelProviderRouting.swift
//  VPN
//
//  Central, exhaustive routing contract for the two packet-tunnel providers.
//

import Foundation

nonisolated enum PacketTunnelProviderKind: String, CaseIterable, Equatable, Sendable {
    case wireGuard
    case xray
}

nonisolated enum PacketTunnelProviderRouting {
    static let wireGuardBundleIdentifier = "su.24kvn.kvn-app.PacketTunnelExtension"
    static let xrayBundleIdentifier = "su.24kvn.kvn-app.PacketTunnelXrayExtension"

    static var knownBundleIdentifiers: Set<String> {
        [wireGuardBundleIdentifier, xrayBundleIdentifier]
    }

    static func provider(for protocolType: VPNProtocol) -> PacketTunnelProviderKind? {
        switch protocolType {
        case .wireGuard, .amneziaWG:
            .wireGuard
        case .vless, .hysteria2, .trojan, .shadowsocks, .vmess:
            .xray
        case .ikev2, .tuic:
            nil
        }
    }

    static func providerBundleIdentifier(for protocolType: VPNProtocol) -> String? {
        guard let provider = provider(for: protocolType) else {
            return nil
        }
        return bundleIdentifier(for: provider)
    }

    static func provider(forBundleIdentifier bundleIdentifier: String) -> PacketTunnelProviderKind? {
        if bundleIdentifier == wireGuardBundleIdentifier {
            return .wireGuard
        }
        if bundleIdentifier == xrayBundleIdentifier {
            return .xray
        }
        return nil
    }

    static func bundleIdentifier(for provider: PacketTunnelProviderKind) -> String {
        switch provider {
        case .wireGuard:
            wireGuardBundleIdentifier
        case .xray:
            xrayBundleIdentifier
        }
    }
}

nonisolated enum TunnelProviderManagerReconciler {
    static func canRetarget(
        savedBundleIdentifier: String?,
        savedConfiguration: RuntimeProviderConfiguration?,
        desiredBundleIdentifier: String,
        desiredConfiguration: RuntimeProviderConfiguration,
        status: TunnelProviderSessionStatus
    ) -> Bool {
        guard let savedBundleIdentifier,
              savedBundleIdentifier != desiredBundleIdentifier,
              PacketTunnelProviderRouting.knownBundleIdentifiers.contains(savedBundleIdentifier),
              savedConfiguration == desiredConfiguration else {
            return false
        }
        return status == .disconnected || status == .invalid
    }
}
