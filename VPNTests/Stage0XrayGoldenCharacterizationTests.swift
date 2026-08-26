//
//  Stage0XrayGoldenCharacterizationTests.swift
//  VPNTests
//
//  Focused final-Xray goldens. Credentials are conspicuously fake.
//

import Foundation
import Testing
@testable import VPN

struct Stage0XrayGoldenCharacterizationTests {
    @Test
    func vlessTCPTLSMatchesCommittedSortedJSON() throws {
        try stage0RequireXrayGolden(
            stage0ResolvedConfiguration(
                id: "10000000-0000-4000-8000-000000000001",
                kind: .vless,
                host: "vless-tcp.stage0.example.invalid",
                port: 443,
                transport: stage0Transport(.tcp),
                security: stage0TLS("vless-tcp-sni.stage0.example.invalid", alpn: ["h2", "http/1.1"]),
                credential: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                vless: SharedRuntimeVLESSParameters(flow: "xtls-rprx-vision", encryption: "none")
            ),
            fixture: "xray-vless-tcp-tls"
        )
    }

    @Test
    func vlessHTTPUpgradeTLSMatchesCommittedSortedJSON() throws {
        try stage0RequireXrayGolden(
            stage0ResolvedConfiguration(
                id: "10000000-0000-4000-8000-000000000002",
                kind: .vless,
                host: "vless-upgrade.stage0.example.invalid",
                port: 8443,
                transport: SharedRuntimeTransport(
                    kind: .httpUpgrade,
                    path: "/upgrade",
                    host: "Host.Stage0.Example.Invalid",
                    serviceName: nil,
                    mode: nil,
                    xhttp: nil
                ),
                security: stage0TLS("vless-upgrade-sni.stage0.example.invalid"),
                credential: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                vless: SharedRuntimeVLESSParameters(flow: nil, encryption: "none")
            ),
            fixture: "xray-vless-httpupgrade-tls"
        )
    }

    @Test
    func vlessXHTTPRealityMatchesCommittedSortedJSON() throws {
        try stage0RequireXrayGolden(
            stage0ResolvedConfiguration(
                id: "10000000-0000-4000-8000-000000000003",
                kind: .vless,
                host: "vless-reality.stage0.example.invalid",
                port: 443,
                transport: SharedRuntimeTransport(
                    kind: .xhttp,
                    path: nil,
                    host: nil,
                    serviceName: nil,
                    mode: nil,
                    xhttp: SharedRuntimeXHTTPParameters(
                        path: "/xhttp",
                        host: "xhttp.stage0.example.invalid",
                        mode: .streamOne
                    )
                ),
                security: SharedRuntimeSecurity(
                    kind: .reality,
                    serverName: "reality.stage0.example.invalid",
                    allowInsecure: false,
                    fingerprint: "chrome",
                    alpn: nil,
                    shortID: "abcd1234",
                    reality: SharedRuntimeRealityPublicParameters(
                        serverName: "reality.stage0.example.invalid",
                        publicKey: String(repeating: "A", count: 43),
                        shortID: "abcd1234",
                        fingerprint: "chrome",
                        spiderX: "/stage0"
                    )
                ),
                credential: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                vless: SharedRuntimeVLESSParameters(flow: "xtls-rprx-vision", encryption: "none")
            ),
            fixture: "xray-vless-xhttp-reality"
        )
    }

    @Test
    func vmessWebSocketTLSMatchesCommittedSortedJSON() throws {
        try stage0RequireXrayGolden(
            stage0ResolvedConfiguration(
                id: "20000000-0000-4000-8000-000000000001",
                kind: .vmess,
                host: "vmess.stage0.example.invalid",
                port: 443,
                transport: SharedRuntimeTransport(
                    kind: .websocket,
                    path: "/vmess",
                    host: "VMess-Host.Stage0.Example.Invalid",
                    serviceName: nil,
                    mode: nil,
                    xhttp: nil
                ),
                security: stage0TLS("vmess-sni.stage0.example.invalid", alpn: ["h2"]),
                credential: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                vmess: SharedRuntimeVMessParameters(alterID: 0, security: "auto")
            ),
            fixture: "xray-vmess-websocket-tls"
        )
    }

    @Test
    func trojanGRPCTLSAndALPNMatchCommittedSortedJSON() throws {
        try stage0RequireXrayGolden(
            stage0ResolvedConfiguration(
                id: "30000000-0000-4000-8000-000000000001",
                kind: .trojan,
                host: "trojan.stage0.example.invalid",
                port: 443,
                transport: SharedRuntimeTransport(
                    kind: .grpc,
                    path: nil,
                    host: nil,
                    serviceName: "stage0-trojan",
                    mode: nil,
                    xhttp: nil
                ),
                security: stage0TLS("trojan-sni.stage0.example.invalid"),
                credential: "stage0-trojan-password-DO-NOT-USE",
                trojan: SharedRuntimeTrojanParameters(alpn: ["h2", "http/1.1"])
            ),
            fixture: "xray-trojan-grpc-tls"
        )
    }

    @Test
    func outlineShadowsocksMatchesCommittedSortedJSONAndOutlineMetadataIsRuntimeNeutral() throws {
        let outline = stage0ResolvedConfiguration(
            id: "40000000-0000-4000-8000-000000000001",
            kind: .shadowsocks,
            host: "outline.stage0.example.invalid",
            port: 8388,
            transport: stage0Transport(.tcp),
            security: SharedRuntimeSecurity(kind: .none),
            credential: "stage0-outline-password-DO-NOT-USE",
            shadowsocks: SharedRuntimeShadowsocksParameters(
                method: "chacha20-ietf-poly1305",
                plugin: nil,
                isOutlineStaticKey: true
            )
        )
        try stage0RequireXrayGolden(outline, fixture: "xray-outline-shadowsocks")

        var ordinaryShadowsocks = outline
        ordinaryShadowsocks.shadowsocks?.isOutlineStaticKey = false
        try stage0RequireXrayGolden(ordinaryShadowsocks, fixture: "xray-outline-shadowsocks")
    }

    @Test
    func hysteria2H3TLSMatchesCommittedSortedJSON() throws {
        try stage0RequireXrayGolden(
            stage0ResolvedConfiguration(
                id: "50000000-0000-4000-8000-000000000001",
                kind: .hysteria2,
                host: "hy2.stage0.example.invalid",
                port: 443,
                transport: stage0Transport(.hysteria),
                security: stage0TLS("hy2-sni.stage0.example.invalid"),
                credential: "stage0-hysteria-auth-DO-NOT-USE",
                hysteria2: SharedRuntimeHysteria2Parameters(
                    obfs: nil,
                    bandwidthHint: nil,
                    obfsPasswordReference: nil
                )
            ),
            fixture: "xray-hysteria2-base"
        )
    }

    @Test
    func hysteria2SalamanderFinalMaskMatchesCommittedSortedJSON() throws {
        try stage0RequireXrayGolden(
            stage0ResolvedConfiguration(
                id: "50000000-0000-4000-8000-000000000002",
                kind: .hysteria2,
                host: "hy2-obfs.stage0.example.invalid",
                port: 8443,
                transport: stage0Transport(.hysteria),
                security: SharedRuntimeSecurity(
                    kind: .tls,
                    serverName: "hy2-obfs-sni.stage0.example.invalid",
                    allowInsecure: true,
                    fingerprint: "safari",
                    alpn: ["h3"]
                ),
                credential: "stage0-hysteria-auth-DO-NOT-USE",
                hysteria2: SharedRuntimeHysteria2Parameters(
                    obfs: "salamander",
                    bandwidthHint: nil,
                    obfsPasswordReference: "keychain://stage0.runtime/hysteria2-obfs"
                ),
                obfsPassword: "stage0-salamander-secret-DO-NOT-USE"
            ),
            fixture: "xray-hysteria2-salamander"
        )
    }

    @Test
    func finalXrayKeyCasingNetworkNamesAndNilOmissionRemainExact() throws {
        let websocket = try Stage0TestResources.fixtureText(named: "xray-vmess-websocket-tls")
        let upgrade = try Stage0TestResources.fixtureText(named: "xray-vless-httpupgrade-tls")
        let reality = try Stage0TestResources.fixtureText(named: "xray-vless-xhttp-reality")
        let hysteria = try Stage0TestResources.fixtureText(named: "xray-hysteria2-salamander")

        #expect(websocket.contains(#""network":"ws""#))
        #expect(websocket.contains(#""alterId":0"#))
        #expect(!websocket.contains(#""alterID""#))
        #expect(websocket.contains(#""headers":{"Host":"VMess-Host.Stage0.Example.Invalid"}"#))
        #expect(!websocket.contains(#""headers":{"host""#))

        #expect(upgrade.contains(#""network":"httpupgrade""#))
        #expect(upgrade.contains(#""httpUpgradeSettings""#))
        #expect(!upgrade.contains(#""httpupgradeSettings""#))
        #expect(!upgrade.contains(#""flow""#))
        #expect(!upgrade.contains(#""alpn""#))

        #expect(reality.contains(#""shortId":"abcd1234""#))
        #expect(!reality.contains(#""shortID""#))
        #expect(reality.contains(#""mode":"stream-one""#))
        #expect(reality.contains(#""protocol":"vless""#))
        #expect(!reality.contains(#""tlsSettings""#))

        #expect(hysteria.contains(#""finalmask""#))
        #expect(!hysteria.contains(#""finalMask""#))
        #expect(hysteria.contains(#""protocol":"hysteria""#))
    }
}

private func stage0RequireXrayGolden(
    _ configuration: ResolvedVLESSRuntimeConfiguration,
    fixture: String
) throws {
    let sensitive = try XrayConfigurationBuilder().build(from: configuration)
    let json = try sensitive.withJSONString { $0 }
    try Stage0TestResources.requireGoldenJSON(json, named: fixture)
}

func stage0ResolvedConfiguration(
    id: String,
    kind: SharedRuntimeProtocolKind,
    host: String,
    port: Int,
    transport: SharedRuntimeTransport,
    security: SharedRuntimeSecurity,
    credential: String,
    vless: SharedRuntimeVLESSParameters = SharedRuntimeVLESSParameters(flow: nil, encryption: nil),
    vmess: SharedRuntimeVMessParameters? = nil,
    trojan: SharedRuntimeTrojanParameters? = nil,
    shadowsocks: SharedRuntimeShadowsocksParameters? = nil,
    hysteria2: SharedRuntimeHysteria2Parameters? = nil,
    obfsPassword: String? = nil
) -> ResolvedVLESSRuntimeConfiguration {
    ResolvedVLESSRuntimeConfiguration(
        profileID: UUID(uuidString: id)!,
        recordRevision: "stage0-revision",
        protocolKind: kind,
        endpoint: ResolvedRuntimeEndpoint(host: host, port: port),
        transport: transport,
        security: security,
        vless: vless,
        vmess: vmess,
        trojan: trojan,
        shadowsocks: shadowsocks,
        hysteria2: hysteria2,
        credential: SensitiveRuntimeCredential(credential),
        hysteria2ObfsPassword: obfsPassword.map(SensitiveRuntimeCredential.init)
    )
}

func stage0Transport(_ kind: SharedRuntimeTransportKind) -> SharedRuntimeTransport {
    SharedRuntimeTransport(
        kind: kind,
        path: nil,
        host: nil,
        serviceName: nil,
        mode: nil,
        xhttp: nil
    )
}

func stage0TLS(_ serverName: String, alpn: [String]? = nil) -> SharedRuntimeSecurity {
    SharedRuntimeSecurity(
        kind: .tls,
        serverName: serverName,
        allowInsecure: false,
        fingerprint: "chrome",
        alpn: alpn
    )
}
