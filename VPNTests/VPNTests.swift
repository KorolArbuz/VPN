//
//  VPNTests.swift
//  VPNTests
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation
import Testing
@testable import VPN

struct VPNTests {
    @Test
    func detectsSupportedURISchemes() async throws {
        let parser = VPNLinkParser()
        let result = try await parser.parse("vless://sample-user@example.com:443?type=ws#Demo")

        #expect(result.detectedScheme == "vless")
    }

    @Test
    func parsesVLESSLink() async throws {
        let parser = VPNLinkParser()
        let result = try await parser.parse("vless://sample-user@example.com:443?type=ws&security=tls&sni=example.com#VLESS%20Demo")

        guard case .profile(let profile) = result.kind else {
            Issue.record("Expected profile import result")
            return
        }

        #expect(profile.protocolType == .vless)
        #expect(profile.name == "VLESS Demo")
        #expect(profile.serverAddress == "example.com")
        #expect(profile.port == 443)
        #expect(profile.tlsSettings.isEnabled)
        #expect(profile.credentialReference != nil)
    }

    @Test
    func parsesTrojanLink() async throws {
        let parser = VPNLinkParser()
        let result = try await parser.parse("trojan://sample-password@trojan.example.com:443?sni=trojan.example.com#Trojan")

        guard case .profile(let profile) = result.kind else {
            Issue.record("Expected profile import result")
            return
        }

        #expect(profile.protocolType == .trojan)
        #expect(profile.serverAddress == "trojan.example.com")
        #expect(profile.credentialReference != nil)
    }

    @Test
    func parsesShadowsocksLink() async throws {
        let parser = VPNLinkParser()
        let result = try await parser.parse("ss://YWVzLTEyOC1nY206c2FtcGxlLXBhc3M@ss.example.com:8388#SS")

        guard case .profile(let profile) = result.kind else {
            Issue.record("Expected profile import result")
            return
        }

        #expect(profile.protocolType == .shadowsocks)
        #expect(profile.serverAddress == "ss.example.com")
        #expect(profile.port == 8388)
        #expect(profile.credentialReference != nil)
    }

    @Test
    func parsesHysteria2Link() async throws {
        let parser = VPNLinkParser()
        let result = try await parser.parse("hy2://sample-password@hy.example.com:443?sni=hy.example.com#HY2")

        guard case .profile(let profile) = result.kind else {
            Issue.record("Expected profile import result")
            return
        }

        #expect(profile.protocolType == .hysteria2)
        #expect(profile.serverAddress == "hy.example.com")
        #expect(profile.tlsSettings.isEnabled)
    }

    @Test
    func parsesVMessBase64Payload() async throws {
        let payload = """
        {"ps":"VMess Demo","add":"vmess.example.com","port":"443","id":"sample-user-id","aid":"0","scy":"auto","net":"ws","type":"none","host":"vmess.example.com","path":"/ws","tls":"tls","sni":"vmess.example.com"}
        """
        let encoded = Data(payload.utf8).base64EncodedString()
        let parser = VPNLinkParser()
        let result = try await parser.parse("vmess://\(encoded)")

        guard case .profile(let profile) = result.kind else {
            Issue.record("Expected profile import result")
            return
        }

        #expect(profile.protocolType == .vmess)
        #expect(profile.serverAddress == "vmess.example.com")
        #expect(profile.port == 443)
        #expect(profile.credentialReference != nil)
    }

    @Test
    func malformedURLThrowsValidationError() async {
        let parser = VPNLinkParser()

        await #expect(throws: VPNImportError.self) {
            _ = try await parser.parse("vless://sample-user@:443")
        }
    }

    @Test
    func unsupportedSchemeThrowsValidationError() async {
        let parser = VPNLinkParser()

        await #expect(throws: VPNImportError.self) {
            _ = try await parser.parse("ftp://example.com/profile")
        }
    }

    @Test
    func masksSecrets() {
        #expect(SecretMasker.masked("sample-secret") == "••••cret")
        let summary = SecretMasker.sanitizedQuerySummary(from: [
            URLQueryItem(name: "token", value: "sample-token"),
            URLQueryItem(name: "type", value: "ws")
        ])

        #expect(summary["token"] == "••••")
        #expect(summary["type"] == "ws")
    }

    @Test
    func savesProfileInRepository() async throws {
        let repository = InMemoryVPNProfileRepository()
        let profile = makeCompleteProfile(name: "Saved")

        try await repository.save(profile)

        let profiles = try await repository.profiles()
        #expect(profiles.count == 1)
        #expect(profiles.first?.name == "Saved")
    }

    @Test
    func deletesProfileFromRepository() async throws {
        let repository = InMemoryVPNProfileRepository()
        let profile = makeCompleteProfile(name: "Delete")

        try await repository.save(profile)
        try await repository.delete(id: profile.id)

        let profiles = try await repository.profiles()
        #expect(profiles.isEmpty)
    }

    @Test
    func recognizesSubscriptionURLWithoutDownloading() async throws {
        let parser = VPNLinkParser()
        let result = try await parser.parse("https://vpn.example.com/subscription")

        guard case .subscription(let subscription) = result.kind else {
            Issue.record("Expected subscription import result")
            return
        }

        #expect(subscription.url.host == "vpn.example.com")
        #expect(result.warnings.isEmpty == false)
    }

    @Test
    @MainActor
    func preventsConnectingIncompleteProfile() async {
        let viewModel = VPNDashboardViewModel()
        let profile = VPNProfile.draft(
            name: "Incomplete",
            protocolType: .vless,
            serverAddress: "incomplete.example.com",
            port: nil,
            protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
            source: .manual
        )

        viewModel.selectProfile(profile)
        await viewModel.connect()

        #expect(viewModel.connectionState != .connected)
        #expect(viewModel.errorMessage?.contains("incomplete") == true)
    }

    @Test
    @MainActor
    func cancelsStaleAsyncOperation() async throws {
        let provider = SlowServerProvider()
        let viewModel = VPNDashboardViewModel(serverProvider: provider)

        let task = Task {
            await viewModel.loadInitialData()
        }

        try await Task.sleep(for: .milliseconds(30))
        viewModel.cancelCurrentOperation()
        await task.value

        #expect(viewModel.servers.isEmpty)
        #expect(viewModel.connectionState == .disconnected)
    }

    @Test
    func configurableServerScoringPolicyAffectsSelection() async throws {
        let policy = ServerSelectionPolicy(
            latencyWeight: 0.01,
            packetLossWeight: 1,
            serverLoadWeight: 100,
            failurePenalty: 50,
            unavailablePenalty: 100
        )
        let selector = MockServerSelector(policy: policy)
        let selected = try await selector.bestServer(from: MockServerCatalog.servers, using: MockServerProber())

        #expect(selected.city == "Helsinki")
    }

    @Test
    @MainActor
    func automaticProtocolSelectsOnlyCompatibleProtocol() async {
        let viewModel = VPNDashboardViewModel()
        let helsinki = MockServerCatalog.servers.first { $0.city == "Helsinki" }

        guard let helsinki else {
            Issue.record("Missing Helsinki mock server")
            return
        }

        viewModel.selectServer(helsinki)
        viewModel.selectProtocol(.manual(.wireGuard))

        #expect(viewModel.effectiveProtocol == nil)
        #expect(viewModel.errorMessage?.contains("not supported") == true)

        viewModel.selectProtocol(.automatic)
        #expect(viewModel.effectiveProtocol == .ikev2)
    }

    @Test
    func bestServerUsesWeightedScore() async throws {
        let selector = MockServerSelector()
        let selected = try await selector.bestServer(from: MockServerCatalog.servers, using: MockServerProber())

        #expect(selected.city == "Helsinki")
    }

    @Test
    func bestServerExcludesUnavailableServers() async throws {
        let selector = MockServerSelector()
        let servers = [
            VPNServer(
                id: UUID(),
                name: "Unavailable Fast",
                country: "Poland",
                countryCode: "PL",
                city: "Warsaw",
                hostname: "waw-fast.example.invalid",
                supportedProtocols: [.wireGuard],
                latency: 1,
                load: 0.01,
                isAvailable: false
            ),
            VPNServer(
                id: UUID(),
                name: "Available Stable",
                country: "Netherlands",
                countryCode: "NL",
                city: "Amsterdam",
                hostname: "ams-stable.example.invalid",
                supportedProtocols: [.wireGuard],
                latency: 50,
                load: 0.4,
                isAvailable: true
            )
        ]

        let selected = try await selector.bestServer(from: servers, using: MockServerProber())

        #expect(selected.city == "Amsterdam")
    }

    @Test
    func automaticProtocolUsesBestSupportedProtocol() {
        let selector = MockServerSelector()
        let server = VPNServer(
            id: UUID(),
            name: "Mixed Protocols",
            country: "Germany",
            countryCode: "DE",
            city: "Frankfurt",
            hostname: "fra-mixed.example.invalid",
            supportedProtocols: [.trojan, .shadowsocks, .wireGuard],
            latency: 20,
            load: 0.2,
            isAvailable: true
        )

        #expect(selector.automaticProtocol(for: server) == .wireGuard)
    }

    @Test
    @MainActor
    func mockConnectionStateChanges() async {
        let viewModel = VPNDashboardViewModel()

        await viewModel.loadInitialData()
        await viewModel.connect()

        #expect(viewModel.connectionState == .connected)
        #expect(viewModel.currentMetrics != nil)

        await viewModel.disconnect()

        #expect(viewModel.connectionState == .disconnected)
        #expect(viewModel.currentMetrics == nil)
    }

    private func makeCompleteProfile(name: String) -> VPNProfile {
        VPNProfile.draft(
            name: name,
            protocolType: .vless,
            serverAddress: "profile.example.com",
            port: 443,
            credentialReference: "test-reference",
            protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
            source: .manual
        )
    }
}

private nonisolated struct SlowServerProvider: ServerProviding {
    func fetchServers() async throws -> [VPNServer] {
        try await Task.sleep(for: .milliseconds(120))
        return MockServerCatalog.servers
    }
}
