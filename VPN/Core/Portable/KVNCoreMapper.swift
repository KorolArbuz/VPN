//
//  KVNCoreMapper.swift
//  VPN
//
//  Maps the existing (source-of-truth) VPNProfile into the portable, non-secret
//  KVNCandidateDTO. Only connectivity metadata crosses this boundary.
//
//  EXCLUDED (never mapped): VLESS UUID, passwords, tokens, private keys,
//  pre-shared keys, credentialReference, raw subscription URL, original VPN URI,
//  full Xray config, and any arbitrary metadata values. The candidate/profile
//  identity is the profile's record UUID — NOT a credential.
//

import Foundation

nonisolated enum KVNCoreMapper {
    /// Builds a portable candidate from a profile. Secret-free by construction.
    static func candidate(from profile: VPNProfile) -> KVNCandidateDTO {
        let identity = profile.id.uuidString
        let endpoint = KVNEndpointDTO(
            host: profile.serverAddress,
            port: portValue(profile.port),
            protocolKind: protocolKind(for: profile.protocolType),
            backend: backendKind(for: profile.protocolType),
            enabled: profile.isEnabled,
            tags: [],
            region: safeString(profile.metadata["region"]),
            country: safeString(profile.metadata["country"]),
            manualPriority: (profile.isFavorite == true) ? 10 : 0
        )
        return KVNCandidateDTO(candidateID: identity, profileID: identity, endpoint: endpoint)
    }

    /// Maps the app protocol enum to the portable protocol kind.
    static func protocolKind(for proto: VPNProtocol) -> KVNProtocolKind {
        switch proto {
        case .vless: .vless
        case .trojan: .trojan
        case .vmess: .vmess
        case .hysteria2: .hysteria2
        case .wireGuard, .amneziaWG: .wireguard
        case .shadowsocks: .shadowsocks
        case .tuic: .tuic
        case .ikev2: .ikev2
        }
    }

    /// Maps a protocol to the data-plane engine that would carry it in this app.
    /// Reflects actual/intended execution: Xray-family protocols run on Xray,
    /// Hysteria2 on the Hysteria backend, WireGuard/IKEv2 on the OS/native stack.
    static func backendKind(for proto: VPNProtocol) -> KVNBackendKind {
        switch proto {
        case .vless, .trojan, .vmess, .shadowsocks, .tuic: .xray
        case .hysteria2: .hysteria
        case .wireGuard, .amneziaWG: .wireguard
        case .ikev2: .system
        }
    }

    private static func portValue(_ port: Int?) -> UInt16 {
        guard let port, let value = UInt16(exactly: port) else { return 0 }
        return value
    }

    private static func safeString(_ value: String?) -> String? {
        guard let value, value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false else {
            return nil
        }
        return value
    }
}
