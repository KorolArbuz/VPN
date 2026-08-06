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
    func validVLESS() async throws {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("vless://sample-user-id@vless.example.com:443?type=ws&security=tls&sni=vless.example.com&path=%2Fws#VLESS%20Demo")
        let profile = try importedProfile(from: result)

        #expect(result.detectedScheme == "vless")
        #expect(profile.protocolType == .vless)
        #expect(profile.name == "VLESS Demo")
        #expect(profile.serverAddress == "vless.example.com")
        #expect(profile.port == 443)
        #expect(profile.transportSettings.network == "ws")
        #expect(profile.transportSettings.path == "/ws")
        #expect(profile.tlsSettings.isEnabled)
        #expect(profile.credentialReference != nil)
    }

    @Test
    func vlessReality() async throws {
        let store = InMemoryCredentialStore()
        let parser = VPNLinkParser(credentialStore: store)
        let result = try await parser.parse("vless://sample-user-id@reality.example.com:443?type=tcp&security=reality&sni=site.example&fp=chrome&pbk=sample-public-key&sid=abcd#Reality")
        let profile = try importedProfile(from: result)

        #expect(profile.tlsSettings.isEnabled)
        #expect(profile.tlsSettings.serverName == "site.example")
        #expect(profile.tlsSettings.fingerprint == "chrome")
        #expect(profile.tlsSettings.publicKeyReference != nil)
        #expect(profile.tlsSettings.shortID == "abcd")
    }

    @Test
    func validTrojan() async throws {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("trojan://sample-password@trojan.example.com:443?sni=trojan.example.com&type=tcp&alpn=h2,http/1.1#Trojan")
        let profile = try importedProfile(from: result)

        #expect(profile.protocolType == .trojan)
        #expect(profile.serverAddress == "trojan.example.com")
        #expect(profile.port == 443)
        #expect(profile.transportSettings.network == "tcp")
        #expect(profile.tlsSettings.isEnabled)
        #expect(profile.credentialReference != nil)
    }

    @Test
    func validHysteria2() async throws {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("hysteria2://sample-password@hy.example.com:8443?sni=hy.example.com&obfs=salamander&bandwidth=100mbps#Hysteria")
        let profile = try importedProfile(from: result)

        #expect(result.detectedScheme == "hysteria2")
        #expect(profile.protocolType == .hysteria2)
        #expect(profile.serverAddress == "hy.example.com")
        #expect(profile.port == 8443)
        #expect(profile.tlsSettings.isEnabled)
        #expect(profile.metadata["obfs"] == "salamander")
    }

    @Test
    func hy2Alias() async throws {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("hy2://sample-password@alias.example.com:443#HY2")
        let profile = try importedProfile(from: result)

        #expect(result.detectedScheme == "hy2")
        #expect(profile.protocolType == .hysteria2)
        #expect(profile.serverAddress == "alias.example.com")
    }

    @Test
    func validVMess() async throws {
        let payload = """
        {"ps":"VMess Demo","add":"vmess.example.invalid","port":"443","id":"sample-user-id","aid":"0","scy":"auto","net":"ws","type":"none","host":"vmess.example.invalid","path":"/ws","tls":"tls","sni":"vmess.example.invalid"}
        """
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("vmess://\(Data(payload.utf8).base64EncodedString())")
        let profile = try importedProfile(from: result)

        #expect(profile.protocolType == .vmess)
        #expect(profile.serverAddress == "vmess.example.invalid")
        #expect(profile.transportSettings.network == "ws")
        #expect(profile.credentialReference != nil)
    }

    @Test
    func validShadowsocks() async throws {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("ss://YWVzLTEyOC1nY206c2FtcGxlLXBhc3M@ss.example.invalid:8388#Shadowsocks")
        let profile = try importedProfile(from: result)

        #expect(profile.protocolType == .shadowsocks)
        #expect(profile.serverAddress == "ss.example.invalid")
        #expect(profile.port == 8388)
        #expect(profile.credentialReference != nil)
    }

    @Test
    func validTUIC() async throws {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("tuic://sample-token@tuic.example.invalid:443?congestion=bbr&udpRelayMode=native#TUIC")
        let profile = try importedProfile(from: result)

        #expect(profile.protocolType == .tuic)
        #expect(profile.serverAddress == "tuic.example.invalid")
        #expect(profile.credentialReference != nil)
    }

    @Test
    func subscriptionURLRecognition() async throws {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("https://subscriptions.example.invalid/list")

        guard case .subscription(let subscription) = result.kind else {
            Issue.record("Expected subscription result")
            return
        }

        #expect(subscription.url.host == "subscriptions.example.invalid")
    }

    @Test
    func plainTextSubscriptionParsing() async throws {
        let parser = SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        let content = """
        vless://sample-user-id@one.example.invalid:443?type=ws#One
        trojan://sample-password@two.example.invalid:443#Two
        """

        let profiles = try await parser.parse(content)

        #expect(profiles.count == 2)
        #expect(profiles.map(\.protocolType).contains(.vless))
        #expect(profiles.map(\.protocolType).contains(.trojan))
    }

    @Test
    func base64SubscriptionParsing() async throws {
        let parser = SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        let content = "hy2://sample-password@hy.example.invalid:443#HY"
        let encoded = Data(content.utf8).base64EncodedString()

        let profiles = try await parser.parse(encoded)

        #expect(profiles.count == 1)
        #expect(profiles.first?.protocolType == .hysteria2)
    }

    @Test
    @MainActor
    func saveProfileCallsCredentialStorage() async {
        let credentialStore = RecordingCredentialStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )

        let didSave = await viewModel.saveProfileDraft(makeIncompleteCredentialProfile(name: "Manual"), credentialValue: "sample-manual-secret")

        #expect(didSave)
        #expect(await credentialStore.storeCount == 1)
        #expect(viewModel.profiles.first?.credentialReference?.hasPrefix("recording://") == true)
    }

    @Test
    func profileJSONDoesNotContainCredentialSecret() async throws {
        let fileURL = temporaryProfilesURL()
        let repository = FileVPNProfileRepository(fileURL: fileURL)
        let profile = makeCompleteProfile(name: "JSON")

        try await repository.save(profile)

        let data = try Data(contentsOf: fileURL)
        let json = String(data: data, encoding: .utf8) ?? ""
        #expect(json.contains("sample-manual-secret") == false)
        #expect(json.contains("test-reference"))
    }

    @Test
    @MainActor
    func profileBecomesActiveAfterSave() async {
        let activeStore = InMemoryActiveProfileStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: activeStore
        )
        let profile = makeCompleteProfile(name: "Active")

        let didSave = await viewModel.saveProfileDraft(profile)

        #expect(didSave)
        #expect(viewModel.activeProfileID == profile.id)
        #expect(viewModel.selectedProfile?.id == profile.id)
        #expect(await activeStore.activeProfileID() == profile.id)
    }

    @Test
    @MainActor
    func incompleteProfileDoesNotSave() async {
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: InMemoryActiveProfileStore()
        )
        let profile = VPNProfile.draft(
            name: "Incomplete",
            protocolType: .vless,
            serverAddress: "missing.example.invalid",
            port: nil,
            protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
            source: .manual
        )

        let didSave = await viewModel.saveProfileDraft(profile)

        #expect(didSave == false)
        #expect(viewModel.profiles.isEmpty)
        #expect(viewModel.activeProfileID == nil)
    }

    @Test
    @MainActor
    func repeatedSaveDoesNotCreateDuplicateProfiles() async {
        let repository = SlowSaveProfileRepository()
        let viewModel = VPNDashboardViewModel(
            profileRepository: repository,
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: InMemoryActiveProfileStore()
        )
        let profile = makeCompleteProfile(name: "Single")

        async let first: Bool = viewModel.saveProfileDraft(profile)
        async let second: Bool = viewModel.saveProfileDraft(profile)
        _ = await (first, second)

        #expect((try? await repository.profiles().count) == 1)
    }

    @Test
    @MainActor
    func repositoryFailureDeletesCreatedCredential() async {
        let credentialStore = RecordingCredentialStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: FailingProfileRepository(),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )

        let didSave = await viewModel.saveProfileDraft(makeIncompleteCredentialProfile(name: "Rollback"), credentialValue: "sample-rollback-secret")

        #expect(didSave == false)
        #expect(await credentialStore.deletedReferences.count == 1)
    }

    @Test
    @MainActor
    func activeProfileRestoresAfterRecreation() async {
        let repository = InMemoryVPNProfileRepository()
        let activeStore = InMemoryActiveProfileStore()
        let profile = makeCompleteProfile(name: "Restore")
        try? await repository.save(profile)
        await activeStore.saveActiveProfileID(profile.id)

        let viewModel = VPNDashboardViewModel(
            profileRepository: repository,
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: activeStore
        )

        await viewModel.loadInitialData()

        #expect(viewModel.selectedProfile?.id == profile.id)
    }

    @Test
    @MainActor
    func deletingActiveProfileClearsActiveProfileID() async {
        let activeStore = InMemoryActiveProfileStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: activeStore
        )
        let profile = makeCompleteProfile(name: "Delete Active")

        _ = await viewModel.saveProfileDraft(profile)
        await viewModel.deleteProfile(profile)

        #expect(viewModel.activeProfileID == nil)
    }

    @Test
    @MainActor
    func manualSetupSavePipelineStoresCredentialAndActivatesProfile() async {
        let credentialStore = RecordingCredentialStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )
        let profile = makeIncompleteCredentialProfile(name: "Manual Pipeline")

        let didSave = await viewModel.saveProfileDraft(profile, credentialValue: "sample-manual-secret")

        #expect(didSave)
        #expect(await credentialStore.storeCount == 1)
        #expect(viewModel.selectedProfile?.name == "Manual Pipeline")
    }

    @Test
    @MainActor
    func subscriptionRecordSaves() async {
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: InMemoryActiveProfileStore()
        )

        await viewModel.addSubscription(name: "Provider", urlText: "https://subscription.example.invalid/list?token=sample-token")

        #expect(viewModel.subscriptions.count == 1)
        #expect(viewModel.subscriptions.first?.name == "Provider")
    }

    @Test
    @MainActor
    func savingProfileDoesNotMarkConnectionConnected() async {
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: InMemoryActiveProfileStore()
        )

        _ = await viewModel.saveProfileDraft(makeCompleteProfile(name: "No Connect"))

        #expect(viewModel.connectionState != .connected)
    }

    @Test
    func percentDecodedProfileName() async throws {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("trojan://sample-password@name.example.com:443#My%20Profile")
        let profile = try importedProfile(from: result)

        #expect(profile.name == "My Profile")
    }

    @Test
    func malformedPort() async {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())

        await #expect(throws: VPNImportError.invalidPort) {
            _ = try await parser.parse("vless://sample-user-id@example.com:bad?type=ws")
        }
    }

    @Test
    func missingHost() async {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())

        await #expect(throws: VPNImportError.missingRequiredComponent("host")) {
            _ = try await parser.parse("vless://sample-user-id@:443?type=ws")
        }
    }

    @Test
    func unsupportedScheme() async {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())

        await #expect(throws: VPNImportError.unsupportedScheme("ftp")) {
            _ = try await parser.parse("ftp://example.com/profile")
        }
    }

    @Test
    func unknownQueryParameterIsMetadata() async throws {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("vless://sample-user-id@meta.example.com:443?type=ws&unknown=value#Meta")
        let profile = try importedProfile(from: result)

        #expect(profile.metadata["unknown"] == "value")
        #expect(profile.transportSettings.metadata["unknown"] == "value")
    }

    @Test
    func secretMasking() {
        #expect(SecretMasker.masked("sample-password") == "••••word")
        #expect(SecretMasker.masked("11111111-2222-3333-4444-555555555555") == "••••••••-••••")
    }

    @Test
    func credentialStoredSeparatelyFromProfile() async throws {
        let store = InMemoryCredentialStore()
        let parser = VPNLinkParser(credentialStore: store)
        let result = try await parser.parse("trojan://sample-password@secret.example.com:443#Secret")
        let profile = try importedProfile(from: result)

        #expect(profile.credentialReference != nil)
        #expect(profile.credentialReference?.contains("sample-password") == false)
        #expect(profile.metadata.values.contains("sample-password") == false)
    }

    @Test
    func profileSaveLoad() async throws {
        let repository = FileVPNProfileRepository(fileURL: temporaryProfilesURL())
        let profile = makeCompleteProfile(name: "Saved")

        try await repository.save(profile)

        let profiles = try await repository.profiles()
        #expect(profiles.count == 1)
        #expect(profiles.first?.name == "Saved")
    }

    @Test
    func profileUpdate() async throws {
        let repository = FileVPNProfileRepository(fileURL: temporaryProfilesURL())
        let profile = makeCompleteProfile(name: "Original")

        try await repository.save(profile)
        try await repository.rename(id: profile.id, to: "Renamed")

        let profiles = try await repository.profiles()
        #expect(profiles.first?.name == "Renamed")
    }

    @Test
    func profileDeletion() async throws {
        let repository = FileVPNProfileRepository(fileURL: temporaryProfilesURL())
        let profile = makeCompleteProfile(name: "Delete")

        try await repository.save(profile)
        try await repository.delete(id: profile.id)

        let profiles = try await repository.profiles()
        #expect(profiles.isEmpty)
    }

    @Test
    func credentialDeletion() async throws {
        let store = InMemoryCredentialStore()
        let reference = try await store.store("sample-secret", label: "test")

        try await store.delete(reference: reference)

        let secret = await store.secret(for: reference)
        #expect(secret == nil)
    }

    @Test
    func persistenceAfterRepositoryRecreation() async throws {
        let fileURL = temporaryProfilesURL()
        let firstRepository = FileVPNProfileRepository(fileURL: fileURL)
        let profile = makeCompleteProfile(name: "Persistent")

        try await firstRepository.save(profile)

        let secondRepository = FileVPNProfileRepository(fileURL: fileURL)
        let profiles = try await secondRepository.profiles()
        #expect(profiles.first?.name == "Persistent")
    }

    @Test
    @MainActor
    func incompleteProfileCannotBeSelected() {
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore()
        )
        let profile = VPNProfile.draft(
            name: "Incomplete",
            protocolType: .vless,
            serverAddress: "incomplete.example.com",
            port: nil,
            protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
            source: .manual
        )

        viewModel.selectProfile(profile)

        #expect(viewModel.selectedProfile == nil)
        #expect(viewModel.errorMessage?.contains("incomplete") == true)
    }

    @Test
    @MainActor
    func preventsConnectingIncompleteProfile() async {
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore()
        )
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
        #expect(viewModel.errorMessage != nil)
    }

    @Test
    @MainActor
    func cancelsStaleAsyncOperation() async throws {
        let provider = SlowServerProvider()
        let viewModel = VPNDashboardViewModel(
            serverProvider: provider,
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore()
        )

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
    func automaticProtocolSelectsOnlyCompatibleProtocol() {
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore()
        )
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
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore()
        )

        await viewModel.loadInitialData()
        await viewModel.connect()

        #expect(viewModel.connectionState == .connected)
        #expect(viewModel.currentMetrics != nil)

        await viewModel.disconnect()

        #expect(viewModel.connectionState == .disconnected)
        #expect(viewModel.currentMetrics == nil)
    }

    private func importedProfile(from result: VPNImportResult) throws -> VPNProfile {
        guard case .profile(let profile) = result.kind else {
            throw TestError.expectedProfile
        }

        return profile
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

    private func makeIncompleteCredentialProfile(name: String) -> VPNProfile {
        VPNProfile.draft(
            name: name,
            protocolType: .vless,
            serverAddress: "manual.example.invalid",
            port: 443,
            credentialReference: nil,
            protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
            source: .manual
        )
    }

    private func temporaryProfilesURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("VPNTests-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("profiles.json")
    }
}

private nonisolated enum TestError: Error {
    case expectedProfile
    case forcedFailure
}

private actor InMemoryActiveProfileStore: ActiveProfileStoring {
    private var storedID: UUID?

    func activeProfileID() async -> UUID? {
        storedID
    }

    func saveActiveProfileID(_ id: UUID?) async {
        storedID = id
    }
}

private actor RecordingCredentialStore: CredentialStoring {
    private(set) var storeCount = 0
    private(set) var deletedReferences: [String] = []

    func store(_ secret: String, label: String) async throws -> String {
        storeCount += 1
        return "recording://credential/\(storeCount)"
    }

    func delete(reference: String) async throws {
        deletedReferences.append(reference)
    }
}

private actor FailingProfileRepository: VPNProfileRepository {
    func profiles() async throws -> [VPNProfile] {
        []
    }

    func save(_ profile: VPNProfile) async throws {
        throw TestError.forcedFailure
    }

    func delete(id: VPNProfile.ID) async throws {}
    func setEnabled(_ isEnabled: Bool, id: VPNProfile.ID) async throws {}
    func rename(id: VPNProfile.ID, to name: String) async throws {}
}

private actor SlowSaveProfileRepository: VPNProfileRepository {
    private var storedProfiles: [VPNProfile] = []

    func profiles() async throws -> [VPNProfile] {
        storedProfiles
    }

    func save(_ profile: VPNProfile) async throws {
        try await Task.sleep(for: .milliseconds(100))
        if let index = storedProfiles.firstIndex(where: { $0.id == profile.id }) {
            storedProfiles[index] = profile
        } else {
            storedProfiles.append(profile)
        }
    }

    func delete(id: VPNProfile.ID) async throws {
        storedProfiles.removeAll { $0.id == id }
    }

    func setEnabled(_ isEnabled: Bool, id: VPNProfile.ID) async throws {}
    func rename(id: VPNProfile.ID, to name: String) async throws {}
}

private nonisolated struct SlowServerProvider: ServerProviding {
    func fetchServers() async throws -> [VPNServer] {
        try await Task.sleep(for: .milliseconds(120))
        return MockServerCatalog.servers
    }
}
