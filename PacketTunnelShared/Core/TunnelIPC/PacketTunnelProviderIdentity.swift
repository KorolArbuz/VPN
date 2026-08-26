//
//  PacketTunnelProviderIdentity.swift
//  PacketTunnelShared
//
//  Compile-time identity and fail-closed launch validation shared by both
//  packet-tunnel provider processes.
//

import Foundation
import NetworkExtension

nonisolated enum PacketTunnelProviderIdentity {
    static let wireGuardBundleIdentifier = "su.24kvn.kvn-app.PacketTunnelExtension"
    static let xrayBundleIdentifier = "su.24kvn.kvn-app.PacketTunnelXrayExtension"

    #if KVN_WIREGUARD_PROVIDER
    static let currentProcess: TunnelProviderProcessIdentity = .wireGuard
    static let currentBundleIdentifier = wireGuardBundleIdentifier
    #elseif KVN_XRAY_PROVIDER
    static let currentProcess: TunnelProviderProcessIdentity = .xray
    static let currentBundleIdentifier = xrayBundleIdentifier
    #else
    #error("Packet-tunnel targets must declare exactly one provider identity.")
    #endif

    static func validatesLaunch(
        executingBundleIdentifier: String?,
        configuredProviderBundleIdentifier: String?,
        optionKeys: Set<String>
    ) -> Bool {
        guard executingBundleIdentifier == currentBundleIdentifier,
              configuredProviderBundleIdentifier == currentBundleIdentifier else {
            return false
        }

        let containsNativeOptions = optionKeys.contains { $0.hasPrefix("kvn.native.") }
        let containsXrayOptions = optionKeys.contains {
            $0.hasPrefix("kvn.xray.") || $0.hasPrefix("kvn.debug.")
        }

        switch currentProcess {
        case .wireGuard:
            return containsNativeOptions && containsXrayOptions == false
        case .xray:
            return containsXrayOptions && containsNativeOptions == false
        case .unknown:
            return false
        }
    }

    static func validatesLaunch(
        provider: NEPacketTunnelProvider,
        options: [String: NSObject]?
    ) -> Bool {
        let configuredBundleIdentifier = (
            provider.protocolConfiguration as? NETunnelProviderProtocol
        )?.providerBundleIdentifier

        return validatesLaunch(
            executingBundleIdentifier: Bundle.main.bundleIdentifier,
            configuredProviderBundleIdentifier: configuredBundleIdentifier,
            optionKeys: Set(options?.keys.map { $0 } ?? [])
        )
    }

    static var wrongProviderError: NSError {
        NSError(
            domain: "su.24kvn.packet-tunnel.provider-routing",
            code: 1,
            userInfo: [
                NSLocalizedDescriptionKey: "The selected protocol was routed to the wrong packet-tunnel provider."
            ]
        )
    }
}
