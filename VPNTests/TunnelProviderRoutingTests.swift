//
//  TunnelProviderRoutingTests.swift
//  VPNTests
//
//  Exhaustive routing, migration-safety, and provider-identity diagnostics.
//

import Foundation
import Testing
@testable import VPN

@Suite(.serialized)
struct TunnelProviderRoutingTests {
    @Test
    func everyProtocolHasAnExplicitProviderRoute() {
        for protocolType in VPNProtocol.allCases {
            let expectedProvider: PacketTunnelProviderKind?
            switch protocolType {
            case .wireGuard, .amneziaWG:
                expectedProvider = .wireGuard
            case .vless, .hysteria2, .trojan, .shadowsocks, .vmess:
                expectedProvider = .xray
            case .ikev2, .tuic:
                expectedProvider = nil
            }

            #expect(PacketTunnelProviderRouting.provider(for: protocolType) == expectedProvider)
            let expectedBundleIdentifier = expectedProvider.map {
                PacketTunnelProviderRouting.bundleIdentifier(for: $0)
            }
            #expect(
                PacketTunnelProviderRouting.providerBundleIdentifier(for: protocolType)
                    == expectedBundleIdentifier
            )
        }
    }

    @Test
    func providerBundleIdentifiersRemainStableAndDistinct() {
        #expect(
            PacketTunnelProviderRouting.wireGuardBundleIdentifier
                == "su.24kvn.kvn-app.PacketTunnelExtension"
        )
        #expect(
            PacketTunnelProviderRouting.xrayBundleIdentifier
                == "su.24kvn.kvn-app.PacketTunnelXrayExtension"
        )
        #expect(
            PacketTunnelProviderRouting.wireGuardBundleIdentifier
                != PacketTunnelProviderRouting.xrayBundleIdentifier
        )
        #expect(PacketTunnelProviderRouting.knownBundleIdentifiers.count == 2)
    }

    @Test
    func staleManagerCanOnlyBeRetargetedWhenExactAndInactive() {
        let desired = RuntimeProviderConfiguration(
            profileID: UUID(),
            recordRevision: 5
        )
        let different = RuntimeProviderConfiguration(
            profileID: UUID(),
            recordRevision: 5
        )

        #expect(
            TunnelProviderManagerReconciler.canRetarget(
                savedBundleIdentifier: PacketTunnelProviderRouting.wireGuardBundleIdentifier,
                savedConfiguration: desired,
                desiredBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier,
                desiredConfiguration: desired,
                status: .disconnected
            )
        )
        #expect(
            TunnelProviderManagerReconciler.canRetarget(
                savedBundleIdentifier: PacketTunnelProviderRouting.wireGuardBundleIdentifier,
                savedConfiguration: desired,
                desiredBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier,
                desiredConfiguration: desired,
                status: .invalid
            )
        )
        #expect(
            TunnelProviderManagerReconciler.canRetarget(
                savedBundleIdentifier: PacketTunnelProviderRouting.wireGuardBundleIdentifier,
                savedConfiguration: desired,
                desiredBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier,
                desiredConfiguration: desired,
                status: .connected
            ) == false
        )
        #expect(
            TunnelProviderManagerReconciler.canRetarget(
                savedBundleIdentifier: PacketTunnelProviderRouting.wireGuardBundleIdentifier,
                savedConfiguration: different,
                desiredBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier,
                desiredConfiguration: desired,
                status: .disconnected
            ) == false
        )
        #expect(
            TunnelProviderManagerReconciler.canRetarget(
                savedBundleIdentifier: "unrelated.provider",
                savedConfiguration: desired,
                desiredBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier,
                desiredConfiguration: desired,
                status: .disconnected
            ) == false
        )
        #expect(
            TunnelProviderManagerReconciler.canRetarget(
                savedBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier,
                savedConfiguration: desired,
                desiredBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier,
                desiredConfiguration: desired,
                status: .disconnected
            ) == false
        )
    }

    @Test
    func allSupportedXrayProtocolsUseOnlyTheXrayProductionService() async throws {
        let xray = RoutingTestConnectionManager()
        let fallback = RoutingTestConnectionManager()
        let manager = ProductionVPNConnectionManager(
            xrayService: xray,
            fallback: fallback
        )
        let xrayProtocols: [VPNProtocol] = [
            .vless,
            .hysteria2,
            .trojan,
            .shadowsocks,
            .vmess
        ]

        for protocolType in xrayProtocols {
            _ = try await manager.connect(using: profile(for: protocolType))
            #expect(await manager.currentState() == .connected)
        }
        await manager.disconnect()

        #expect(await xray.connectedProtocols() == xrayProtocols)
        #expect(await fallback.connectedProtocols().isEmpty)
    }

    @Test
    func unsupportedPacketTunnelProtocolsStayOnFallback() async throws {
        let xray = RoutingTestConnectionManager()
        let fallback = RoutingTestConnectionManager()
        let manager = ProductionVPNConnectionManager(
            xrayService: xray,
            fallback: fallback
        )

        _ = try await manager.connect(using: profile(for: .ikev2))
        _ = try await manager.connect(using: profile(for: .tuic))
        await manager.disconnect()

        #expect(await xray.connectedProtocols().isEmpty)
        #expect(await fallback.connectedProtocols() == [.ikev2, .tuic])
    }

    @Test
    func providerResponsesIdentifyAndConstrainTheirProcess() async throws {
        let wireGuardHandler = TunnelAppMessageHandler(providerProcess: .wireGuard)
        let xrayHandler = TunnelAppMessageHandler(providerProcess: .xray)

        let wireGuardPong = try await response(
            from: wireGuardHandler,
            request: TunnelMessageRequest(kind: .ping)
        )
        let xrayPong = try await response(
            from: xrayHandler,
            request: TunnelMessageRequest(kind: .ping)
        )
        guard case .pong(let wireGuardSnapshot)? = wireGuardPong.payload,
              case .pong(let xraySnapshot)? = xrayPong.payload else {
            Issue.record("Expected provider pong payloads")
            return
        }
        #expect(wireGuardSnapshot.providerProcess == .wireGuard)
        #expect(xraySnapshot.providerProcess == .xray)

        let wireGuardCapabilities = try await response(
            from: wireGuardHandler,
            request: TunnelMessageRequest(kind: .getCapabilities)
        )
        let xrayCapabilities = try await response(
            from: xrayHandler,
            request: TunnelMessageRequest(kind: .getCapabilities)
        )
        guard case .capabilities(let wireGuardSnapshot)? = wireGuardCapabilities.payload,
              case .capabilities(let xraySnapshot)? = xrayCapabilities.payload else {
            Issue.record("Expected provider capability payloads")
            return
        }

        #expect(wireGuardSnapshot.providerProcess == .wireGuard)
        #expect(wireGuardSnapshot.supportsXrayState == false)
        #expect(wireGuardSnapshot.supportsLiveTun2SocksStats == false)
        #expect(wireGuardSnapshot.supportedRequests.contains(.runXrayLifecycleSmokeTest) == false)
        #expect(xraySnapshot.providerProcess == .xray)
        #expect(xraySnapshot.supportsXrayState)
        #expect(xraySnapshot.supportsLiveTun2SocksStats)
        #expect(xraySnapshot.supportedRequests.contains(.runXrayLifecycleSmokeTest))
    }

    private func response(
        from handler: TunnelAppMessageHandler,
        request: TunnelMessageRequest
    ) async throws -> TunnelMessageResponse {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let data = await handler.handle(try encoder.encode(request))
        return try decoder.decode(TunnelMessageResponse.self, from: data)
    }

    private func profile(for protocolType: VPNProtocol) -> VPNProfile {
        let configuration: VPNProtocolConfiguration
        switch protocolType {
        case .wireGuard:
            configuration = .wireGuard(WireGuardProfileConfiguration())
        case .amneziaWG:
            configuration = .amneziaWG(WireGuardProfileConfiguration())
        case .ikev2:
            configuration = .ikev2(
                IKEv2ProfileConfiguration(
                    remoteIdentifier: nil,
                    localIdentifier: nil,
                    authenticationMethod: nil
                )
            )
        case .vless:
            configuration = .vless(VLESSProfileConfiguration(flow: nil, encryption: "none"))
        case .hysteria2:
            configuration = .hysteria2(Hysteria2ProfileConfiguration())
        case .trojan:
            configuration = .trojan(TrojanProfileConfiguration(alpn: []))
        case .shadowsocks:
            configuration = .shadowsocks(
                ShadowsocksProfileConfiguration(method: "aes-256-gcm", plugin: nil)
            )
        case .tuic:
            configuration = .tuic(
                TUICProfileConfiguration(congestionControl: nil, udpRelayMode: nil)
            )
        case .vmess:
            configuration = .vmess(VMessProfileConfiguration(alterID: 0, security: "auto"))
        }

        return VPNProfile.draft(
            name: protocolType.displayName,
            protocolType: protocolType,
            serverAddress: "routing.example.invalid",
            port: 443,
            credentialReference: "keychain://vpn.credentials/routing",
            protocolConfiguration: configuration,
            source: .manual
        )
    }
}

private actor RoutingTestConnectionManager: VPNConnectionManaging {
    private var state: VPNConnectionState = .disconnected
    private var protocols: [VPNProtocol] = []

    func currentState() async -> VPNConnectionState {
        state
    }

    nonisolated func stateUpdates() -> AsyncStream<VPNConnectionState> {
        AsyncStream { _ in }
    }

    func connect(using profile: VPNProfile) async throws {
        protocols.append(profile.protocolType)
        state = .connected
    }

    func disconnect() async {
        state = .disconnected
    }

    func connectedProtocols() -> [VPNProtocol] {
        protocols
    }
}
