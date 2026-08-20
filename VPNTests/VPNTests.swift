//
//  VPNTests.swift
//  VPNTests
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation
import Testing
import UIKit
@testable import VPN

// Serialized: several tests exercise a @MainActor view model with async state
// streams and process-global stores (UserDefaults/Keychain/file repositories).
// Running the suite serially removes in-process concurrency contamination
// without weakening any assertion.
@Suite(.serialized)
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
        #expect(profile.tlsSettings.realityPublicKey == "sample-public-key")
        #expect(profile.tlsSettings.publicKeyReference == nil)
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
    func trojanGRPCServiceNameMapsToRuntime() async throws {
        let credentialStore = RecordingCredentialStore()
        let result = try await VPNLinkParser(credentialStore: credentialStore).parse(
            "trojan://test-password@trojan-grpc.example.invalid:443?type=grpc&security=tls&sni=trojan-grpc.example.invalid&serviceName=current-service#Trojan%20gRPC"
        )
        let profile = try importedProfile(from: result)

        #expect(profile.transportSettings.serviceName == "current-service")
        let runtime = try SharedRuntimeProfileMapper().record(from: profile)
        #expect(runtime.transport.kind == .grpc)
        #expect(runtime.transport.serviceName == "current-service")
    }

    @Test
    func vmessGRPCPathMapsToRuntimeServiceName() async throws {
        let credentialStore = RecordingCredentialStore()
        let payload = """
        {"ps":"VMess gRPC","add":"vmess-grpc.example.invalid","port":"443","id":"11111111-1111-4111-8111-111111111111","aid":"0","scy":"auto","net":"grpc","type":"none","host":"","path":"current-service","tls":"tls","sni":"vmess-grpc.example.invalid"}
        """
        let result = try await VPNLinkParser(credentialStore: credentialStore).parse(
            "vmess://\(Data(payload.utf8).base64EncodedString())"
        )
        let profile = try importedProfile(from: result)

        #expect(profile.transportSettings.serviceName == "current-service")
        let runtime = try SharedRuntimeProfileMapper().record(from: profile)
        #expect(runtime.transport.kind == .grpc)
        #expect(runtime.transport.serviceName == "current-service")
    }

    @Test
    func trojanRealityPublicParametersMapToRuntime() async throws {
        let credentialStore = RecordingCredentialStore()
        let publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        let result = try await VPNLinkParser(credentialStore: credentialStore).parse(
            "trojan://test-password@trojan-reality.example.invalid:443?type=tcp&security=reality&sni=cover.example.invalid&fp=chrome&pbk=\(publicKey)&sid=abcd&spx=%2Fcurrent#Trojan%20Reality"
        )
        let profile = try importedProfile(from: result)

        #expect(profile.tlsSettings.fingerprint == "chrome")
        #expect(profile.tlsSettings.realityPublicKey == publicKey)
        #expect(profile.tlsSettings.shortID == "abcd")
        #expect(profile.tlsSettings.spiderX == "/current")
        let runtime = try SharedRuntimeProfileMapper().record(from: profile)
        #expect(runtime.security.kind == .reality)
        #expect(runtime.security.reality?.publicKey == publicKey)
        #expect(runtime.security.reality?.shortID == "abcd")
        #expect(runtime.security.reality?.spiderX == "/current")
    }

    @Test
    @MainActor
    func trojanALPNMapsToXrayTLSSettings() async throws {
        let credentialStore = RecordingCredentialStore()
        let result = try await VPNLinkParser(credentialStore: credentialStore).parse(
            "trojan://test-password@trojan-alpn.example.invalid:443?type=tcp&security=tls&sni=trojan-alpn.example.invalid&alpn=h2,http%2F1.1#Trojan%20ALPN"
        )
        let profile = try importedProfile(from: result)
        guard case .trojan(let configuration) = profile.protocolConfiguration else {
            Issue.record("Expected Trojan protocol configuration")
            return
        }
        #expect(configuration.alpn == ["h2", "http/1.1"])

        let record = try SharedRuntimeProfileMapper().record(from: profile)
        let json = try await xrayJSON(record: record, credentialStore: credentialStore)
        let data = try #require(json.data(using: .utf8))
        let root = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let outbounds = try #require(root["outbounds"] as? [[String: Any]])
        let outbound = try #require(outbounds.first)
        let streamSettings = try #require(outbound["streamSettings"] as? [String: Any])
        let tlsSettings = try #require(streamSettings["tlsSettings"] as? [String: Any])
        let alpn = try #require(tlsSettings["alpn"] as? [String])
        #expect(alpn == ["h2", "http/1.1"])
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

    @Test(arguments: ["password", "token", "privateKey"])
    func tuicQueryCredentialIsStoredOnlyByReference(queryName: String) async throws {
        let credential = "test-tuic-query-credential"
        let credentialStore = RecordingCredentialStore()
        let parser = VPNLinkParser(credentialStore: credentialStore)
        let result = try await parser.parse(
            "tuic://tuic.example.invalid:443?\(queryName)=\(credential)&congestion=bbr&udpRelayMode=native#TUIC"
        )
        let profile = try importedProfile(from: result)
        let reference = try #require(profile.credentialReference)

        #expect(try await credentialStore.secret(for: reference) == credential)
        #expect(profile.metadata[queryName] == nil)
        #expect(profile.transportSettings.metadata[queryName] == nil)
        #expect(profile.metadata.values.contains(credential) == false)
        #expect(profile.transportSettings.metadata.values.contains(credential) == false)
    }

    @Test
    func subscriptionURLRecognition() async throws {
        let parser = VPNLinkParser(credentialStore: InMemoryCredentialStore())
        let result = try await parser.parse("https://subscriptions.example.invalid/list")

        guard case .subscription(let subscription) = result.kind else {
            Issue.record("Expected subscription result")
            return
        }

        #expect(subscription.sanitizedHost == "subscriptions.example.invalid")
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
    func plainVLESSURISubscription() async throws {
        let parser = SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        let result = try await parser.parseResult(from: Data("vless://sample-user-id@sub.example.invalid:443?type=ws#One".utf8))

        #expect(result.format == .singleURI)
        #expect(result.profiles.count == 1)
        #expect(result.profiles.first?.protocolType == .vless)
    }

    @Test
    func mixedSubscriptionIgnoresBrokenLine() async throws {
        let parser = SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        let content = """
        vless://sample-user-id@one.example.invalid:443?type=ws#One
        not-a-profile
        trojan://sample-password@two.example.invalid:443#Two
        hy2://sample-password@three.example.invalid:443#Three
        """

        let result = try await parser.parseResult(from: Data(content.utf8))

        #expect(result.format == .plainURIList)
        #expect(result.profiles.count == 3)
        #expect(result.invalidEntries.isEmpty == false)
    }

    @Test
    func urlSafeBase64WithoutPaddingSubscription() async throws {
        let parser = SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        let content = "trojan://sample-password@safe.example.invalid:443#Safe"
        let encoded = Data(content.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        let result = try await parser.parseResult(from: Data(encoded.utf8))

        #expect(result.format == .base64URIList)
        #expect(result.profiles.first?.serverAddress == "safe.example.invalid")
    }

    @Test
    func invalidBase64Subscription() async {
        let parser = SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))

        await #expect(throws: VPNImportError.invalidBase64Payload) {
            _ = try await parser.parseResult(from: Data("abc".utf8))
        }
    }

    @Test
    func invalidUTF8SubscriptionResponse() async {
        let decoder = DefaultSubscriptionDecoder()

        #expect(throws: SubscriptionError.invalidUTF8) {
            _ = try decoder.decode(Data([0xff, 0xfe]))
        }
    }

    @Test
    func oversizedSubscriptionResponse() async {
        let decoder = DefaultSubscriptionDecoder(maxDecodedSize: 4)

        #expect(throws: SubscriptionError.responseTooLarge) {
            _ = try decoder.decode(Data("too-large".utf8))
        }
    }

    @Test
    func subscriptionHTTPStatusErrors() async {
        let client = StubSubscriptionClient(result: .failure(SubscriptionError.httpStatus(401)))
        let updater = URLSessionSubscriptionUpdater(client: client, parser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore())))
        let subscription = makeSubscription()
        guard let url = URL(string: "https://subscription.example.invalid/list") else {
            Issue.record("Invalid test URL")
            return
        }

        await #expect(throws: SubscriptionError.httpStatus(401)) {
            _ = try await updater.preview(subscription, url: url)
        }
    }

    @Test
    func clashYAMLRecognizedOnly() async {
        let parser = SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        guard let url = URL(string: "https://subscription.example.invalid/list") else {
            Issue.record("Invalid test URL")
            return
        }

        await #expect(throws: SubscriptionError.unsupportedFormat("Clash subscriptions are recognized but are not fully supported in this build.")) {
            _ = try await URLSessionSubscriptionUpdater(
                client: StubSubscriptionClient(result: .success(Data("proxies:\n  - name: demo".utf8))),
                parser: parser
            ).preview(makeSubscription(), url: url)
        }
    }

    @Test
    func stableIdentityMatchesExistingProfile() {
        let merger = DefaultSubscriptionMerger()
        let first = makeCompleteProfile(name: "First")
        var second = first
        second.name = "Renamed"

        #expect(merger.stableIdentity(for: first) == merger.stableIdentity(for: second))
    }

    @Test
    func subscriptionUpdatePlanClassifiesChanges() {
        let planner = DefaultSubscriptionUpdatePlanner()
        let subscription = makeSubscription()
        let existing = makeSubscriptionProfile(name: "Existing", host: "same.example.invalid", subscriptionID: subscription.id)
        var changed = existing
        changed.port = 8443
        changed.externalIdentity = existing.externalIdentity
        let added = makeSubscriptionProfile(name: "Added", host: "new.example.invalid", subscriptionID: subscription.id)

        let plan = planner.planUpdate(subscription: subscription, incoming: [changed, added], existing: [existing])

        #expect(plan.updatedCount == 1)
        #expect(plan.addedCount == 1)
    }

    @Test
    func subscriptionRefreshReclassifiesSupportedAndUnsupportedRuntimeCapabilities() throws {
        let subscription = makeSubscription()
        let merger = DefaultSubscriptionMerger()
        let planner = DefaultSubscriptionUpdatePlanner()
        let base = VPNProfile.draft(
            name: "Provider Shadowsocks",
            protocolType: .shadowsocks,
            serverAddress: "capability-refresh.example.invalid",
            port: 8388,
            credentialReference: "keychain://test.credentials/shared-capability-reference",
            protocolConfiguration: .shadowsocks(ShadowsocksProfileConfiguration(
                method: "aes-256-gcm",
                plugin: nil
            )),
            source: .subscription
        )
        let supported = merger.makeSubscriptionProfile(
            base,
            subscriptionID: subscription.id,
            now: Date(timeIntervalSince1970: 1_800_000_000)
        )
        var unsupported = supported
        unsupported.protocolConfiguration = .shadowsocks(ShadowsocksProfileConfiguration(
            method: "aes-256-gcm",
            plugin: "v2ray-plugin;obfs=http"
        ))
        unsupported.externalIdentity = supported.externalIdentity

        let becomingUnsupported = planner.planUpdate(
            subscription: subscription,
            incoming: [unsupported],
            existing: [supported]
        )
        let rejectedChange = try #require(becomingUnsupported.changes.first)
        #expect(rejectedChange.kind == .invalid)
        #expect(rejectedChange.existingProfile?.id == supported.id)
        #expect(rejectedChange.isSelected == false)
        #expect(rejectedChange.message?.contains("v2ray-plugin") == true)

        var becomingSupported = supported
        becomingSupported.externalIdentity = unsupported.externalIdentity
        let recovered = planner.planUpdate(
            subscription: subscription,
            incoming: [becomingSupported],
            existing: [unsupported]
        )
        let recoveredChange = try #require(recovered.changes.first)
        #expect(recoveredChange.kind == .updated)
        #expect(recoveredChange.incomingProfile?.runtimeCapability == .ready)
        #expect(recoveredChange.isSelected)
    }

    @Test
    func vlessPortOnlyRefreshMatchesExistingProviderEntry() async throws {
        let credentialStore = RecordingCredentialStore()
        let subscription = makeSubscription()
        let credential = "11111111-1111-4111-8111-111111111111"
        let oldURI = "vless://\(credential)@field-refresh.example.invalid:443?type=tcp&security=tls&sni=field-refresh.example.invalid&encryption=none#Field%20Refresh"
        let currentURI = "vless://\(credential)@field-refresh.example.invalid:8443?type=tcp&security=tls&sni=field-refresh.example.invalid&encryption=none#Field%20Refresh"
        let parsed = try await VPNLinkParser(credentialStore: credentialStore).parse(oldURI)
        let existing = DefaultSubscriptionMerger().makeSubscriptionProfile(
            try importedProfile(from: parsed),
            subscriptionID: subscription.id,
            now: Date(timeIntervalSince1970: 1_800_000_000)
        )
        let updater = URLSessionSubscriptionUpdater(
            client: StubSubscriptionClient(result: .success(Data(currentURI.utf8))),
            credentialStore: credentialStore
        )

        let plan = try await updater.planRefresh(
            subscription,
            existingProfiles: [existing],
            url: try #require(URL(string: "https://subscription.example.invalid/list"))
        )

        let change = try #require(plan.changes.first)
        #expect(plan.changes.count == 1)
        #expect(change.kind == .updated)
        #expect(change.existingProfile?.id == existing.id)
        #expect(change.incomingProfile?.port == 8443)
    }

    @Test(arguments: ProviderManagedNonSecretRefreshCase.cases)
    @MainActor
    func providerManagedNonSecretRefreshIsDetectedMergedAndPublished(
        fieldCase: ProviderManagedNonSecretRefreshCase
    ) async throws {
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let existing = try await makeSubscriptionProfile(
            uri: fieldCase.oldURI,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        try await profileRepository.save(existing)
        try await subscriptionRepository.save(subscription)
        let oldReference = try #require(existing.credentialReference)
        let activeReferencesBeforeRefresh = await credentialStore.activeReferenceCount
        let runtimeSynchronizer = ReferenceTrackingRuntimeProfileSynchronizer()
        _ = try await runtimeSynchronizer.profileSaved(existing)
        let viewModel = makeCredentialRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: runtimeSynchronizer,
            refreshedURI: fieldCase.currentURI
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)

        let plan = try #require(viewModel.subscriptionUpdatePlan)
        let change = try #require(plan.changes.first)
        let prepared = try #require(change.incomingProfile)
        #expect(plan.changes.count == 1, Comment(rawValue: fieldCase.name))
        #expect(change.existingProfile?.id == existing.id, Comment(rawValue: fieldCase.name))
        #expect(prepared.credentialReference == oldReference, Comment(rawValue: fieldCase.name))
        #expect(
            ProviderManagedProfileSnapshot(existing) != ProviderManagedProfileSnapshot(prepared),
            Comment(rawValue: fieldCase.name)
        )
        #expect(
            await credentialStore.activeReferenceCount == activeReferencesBeforeRefresh,
            Comment(rawValue: fieldCase.name)
        )

        switch fieldCase.runtimeExpectation {
        case .builderSupported(let marker):
            #expect(change.kind == .updated, Comment(rawValue: fieldCase.name))
            await viewModel.applySubscriptionUpdate()

            let persisted = try #require(try await profileRepository.profiles().first)
            #expect(viewModel.subscriptionRefreshState == .completed, Comment(rawValue: fieldCase.name))
            #expect(persisted.id == existing.id, Comment(rawValue: fieldCase.name))
            #expect(
                ProviderManagedProfileSnapshot(persisted) == ProviderManagedProfileSnapshot(prepared),
                Comment(rawValue: fieldCase.name)
            )
            #expect(persisted.credentialReference == oldReference, Comment(rawValue: fieldCase.name))
            #expect(try await credentialStore.secret(for: oldReference) != nil, Comment(rawValue: fieldCase.name))
            #expect(
                await credentialStore.activeReferenceCount == activeReferencesBeforeRefresh,
                Comment(rawValue: fieldCase.name)
            )

            let mapper = SharedRuntimeProfileMapper(now: { Date(timeIntervalSince1970: 1_900_000_000) })
            let oldRecord = try mapper.record(from: existing)
            let currentRecord = try mapper.record(from: persisted)
            #expect(oldRecord.recordRevision != currentRecord.recordRevision, Comment(rawValue: fieldCase.name))
            let json = try await xrayJSON(
                record: currentRecord,
                credentialStore: credentialStore
            )
            if let marker {
                #expect(
                    try xrayJSON(json, containsSemanticMarker: marker),
                    Comment(rawValue: fieldCase.name)
                )
            }
        case .builderRejected, .mapperRejected, .runtimeUnsupported:
            #expect(change.kind == .invalid, Comment(rawValue: fieldCase.name))
            #expect(change.isSelected == false, Comment(rawValue: fieldCase.name))
            #expect(prepared.runtimeCapability.isReady == false, Comment(rawValue: fieldCase.name))

            await viewModel.applySubscriptionUpdate()

            let persisted = try #require(try await profileRepository.profiles().first)
            #expect(viewModel.subscriptionRefreshState == .completed, Comment(rawValue: fieldCase.name))
            #expect(persisted.id == existing.id, Comment(rawValue: fieldCase.name))
            #expect(
                ProviderManagedProfileSnapshot(persisted) == ProviderManagedProfileSnapshot(existing),
                Comment(rawValue: fieldCase.name)
            )
            #expect(persisted.credentialReference == oldReference, Comment(rawValue: fieldCase.name))
            #expect(try await credentialStore.secret(for: oldReference) != nil, Comment(rawValue: fieldCase.name))
            #expect(
                await credentialStore.activeReferenceCount == activeReferencesBeforeRefresh,
                Comment(rawValue: fieldCase.name)
            )
        }
    }

    @Test
    @MainActor
    func providerRefreshPreservesUserManagedProfileState() async throws {
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let credential = "11111111-1111-4111-8111-111111111111"
        let oldURI = "vless://\(credential)@local-state.example.invalid:443?type=tcp&security=tls&sni=local-state.example.invalid&encryption=none#Provider%20Name"
        let currentURI = "vless://\(credential)@local-state.example.invalid:8443?type=tcp&security=tls&sni=local-state.example.invalid&encryption=none#Renamed%20By%20Provider"
        var existing = try await makeSubscriptionProfile(
            uri: oldURI,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        existing.name = "Local Name"
        existing.customDisplayName = "Local Name"
        existing.isFavorite = true
        existing.localNotes = "Local notes"
        existing.routingSettings = VPNRoutingSettings(
            routeAllTraffic: false,
            dnsServers: ["192.0.2.53"],
            excludedRoutes: ["198.51.100.0/24"]
        )
        try await profileRepository.save(existing)
        try await subscriptionRepository.save(subscription)
        let viewModel = makeCredentialRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: nil,
            refreshedURI: currentURI
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)
        #expect(viewModel.subscriptionUpdatePlan?.changes.first?.kind == .updated)
        await viewModel.applySubscriptionUpdate()

        let persisted = try #require(try await profileRepository.profiles().first)
        #expect(persisted.id == existing.id)
        #expect(persisted.name == "Local Name")
        #expect(persisted.customDisplayName == "Local Name")
        #expect(persisted.isFavorite == true)
        #expect(persisted.localNotes == "Local notes")
        #expect(persisted.routingSettings == existing.routingSettings)
        #expect(persisted.port == 8443)
    }

    @Test
    func removedProviderProfileClassifiedAsMissing() {
        let planner = DefaultSubscriptionUpdatePlanner()
        let subscription = makeSubscription()
        let existing = makeSubscriptionProfile(name: "Missing", host: "missing.example.invalid", subscriptionID: subscription.id)

        let plan = planner.planUpdate(subscription: subscription, incoming: [], existing: [existing])

        #expect(plan.missingCount == 1)
    }

    @Test
    @MainActor
    func subscriptionURLAbsentFromRepositoryJSON() async throws {
        let fileURL = temporarySubscriptionsURL()
        let repository = FileSubscriptionRepository(fileURL: fileURL)
        let credentialStore = RecordingCredentialStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            subscriptionRepository: repository,
            subscriptionUpdater: URLSessionSubscriptionUpdater(client: StubSubscriptionClient(result: .success(Data("vless://sample-user-id@one.example.invalid:443#One".utf8)))),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )

        await viewModel.addSubscription(name: "Provider", urlText: "https://subscription.example.invalid/list?token=sample-token")

        let json = String(data: try Data(contentsOf: fileURL), encoding: .utf8) ?? ""
        #expect(json.contains("sample-token") == false)
        #expect(json.contains("credentialReference"))
    }

    @Test
    func corruptedProfileAndSubscriptionStoresFailClosed() async throws {
        let profileURL = temporaryProfilesURL()
        let subscriptionURL = temporarySubscriptionsURL()
        defer {
            try? FileManager.default.removeItem(at: profileURL.deletingLastPathComponent())
            try? FileManager.default.removeItem(at: subscriptionURL.deletingLastPathComponent())
        }
        try FileManager.default.createDirectory(
            at: profileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: subscriptionURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data("not-json".utf8).write(to: profileURL, options: .atomic)
        try Data("not-json".utf8).write(to: subscriptionURL, options: .atomic)

        var profileReadFailed = false
        do {
            _ = try await FileVPNProfileRepository(fileURL: profileURL).profiles()
        } catch {
            profileReadFailed = true
        }
        var subscriptionReadFailed = false
        do {
            _ = try await FileSubscriptionRepository(fileURL: subscriptionURL).subscriptions()
        } catch {
            subscriptionReadFailed = true
        }

        #expect(profileReadFailed)
        #expect(subscriptionReadFailed)
    }

    @Test
    @MainActor
    func subscriptionPreviewAndSaveCreatesProfiles() async {
        let credentialStore = RecordingCredentialStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            subscriptionRepository: InMemorySubscriptionRepository(),
            subscriptionUpdater: URLSessionSubscriptionUpdater(
                client: StubSubscriptionClient(result: .success(Data("trojan://sample-password@sub.example.invalid:443?security=tls&sni=sub.example.invalid#Sub".utf8))),
                credentialStore: credentialStore
            ),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )

        await viewModel.previewSubscription(urlText: "https://subscription.example.invalid/list", name: "Provider")
        let saved = await viewModel.saveSubscriptionPreview()

        #expect(saved != nil)
        #expect(viewModel.subscriptions.count == 1)
        #expect(viewModel.profiles.count == 1)
        #expect(viewModel.profiles.first?.source == .subscription)
    }

    @Test
    @MainActor
    func repeatedRefreshDoesNotCreateDuplicates() async {
        let repository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let credentialStore = RecordingCredentialStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: repository,
            subscriptionRepository: subscriptionRepository,
            subscriptionUpdater: URLSessionSubscriptionUpdater(
                client: StubSubscriptionClient(result: .success(Data("vless://sample-user-id@dup.example.invalid:443?type=tcp&security=tls&sni=dup.example.invalid&encryption=none#Dup".utf8))),
                credentialStore: credentialStore
            ),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )

        await viewModel.previewSubscription(urlText: "https://subscription.example.invalid/list", name: "Provider")
        guard let subscription = await viewModel.saveSubscriptionPreview() else {
            Issue.record("Subscription was not saved")
            return
        }
        await viewModel.refreshSubscription(subscription)
        await viewModel.applySubscriptionUpdate()

        #expect((try? await repository.profiles().count) == 1)
    }

    @Test
    @MainActor
    func vlessCredentialOnlyRefreshAdoptsCommittedCredentialInXray() async throws {
        try await assertPrimaryCredentialRefresh(
            protocolUnderTest: .vless,
            oldCredential: "00000000-0000-4000-8000-000000000001",
            currentCredential: "00000000-0000-4000-8000-000000000002"
        )
    }

    @Test
    @MainActor
    func identicalVLESSCredentialRefreshIsSemanticNoOp() async throws {
        try await assertIdenticalPrimaryCredentialRefresh(
            protocolUnderTest: .vless,
            credential: "00000000-0000-4000-8000-000000000003"
        )
    }

    @Test
    @MainActor
    func vmessCredentialOnlyRefreshAdoptsCommittedCredentialInXray() async throws {
        try await assertPrimaryCredentialRefresh(
            protocolUnderTest: .vmess,
            oldCredential: "10000000-0000-4000-8000-000000000001",
            currentCredential: "10000000-0000-4000-8000-000000000002"
        )
    }

    @Test
    @MainActor
    func identicalVMessCredentialRefreshIsSemanticNoOp() async throws {
        try await assertIdenticalPrimaryCredentialRefresh(
            protocolUnderTest: .vmess,
            credential: "10000000-0000-4000-8000-000000000003"
        )
    }

    @Test
    @MainActor
    func trojanCredentialOnlyRefreshAdoptsCommittedCredentialInXray() async throws {
        try await assertPrimaryCredentialRefresh(
            protocolUnderTest: .trojan,
            oldCredential: "test-old-trojan-password",
            currentCredential: "test-current-trojan-password"
        )
    }

    @Test
    @MainActor
    func identicalTrojanCredentialRefreshIsSemanticNoOp() async throws {
        try await assertIdenticalPrimaryCredentialRefresh(
            protocolUnderTest: .trojan,
            credential: "test-same-trojan-password"
        )
    }

    @Test
    @MainActor
    func shadowsocksCredentialOnlyRefreshAdoptsCommittedCredentialInXray() async throws {
        try await assertPrimaryCredentialRefresh(
            protocolUnderTest: .shadowsocks,
            oldCredential: "test-old-shadowsocks-password",
            currentCredential: "test-current-shadowsocks-password"
        )
    }

    @Test
    @MainActor
    func identicalShadowsocksCredentialRefreshIsSemanticNoOp() async throws {
        try await assertIdenticalPrimaryCredentialRefresh(
            protocolUnderTest: .shadowsocks,
            credential: "test-same-shadowsocks-password"
        )
    }

    @Test
    @MainActor
    func tuicUserCredentialRefreshIsRejectedBeforeAdoption() async throws {
        try await assertPrimaryCredentialRefresh(
            protocolUnderTest: .tuic,
            oldCredential: "test-old-tuic-user-credential",
            currentCredential: "test-current-tuic-user-credential"
        )
    }

    @Test
    @MainActor
    func identicalTUICUserCredentialRefreshIsRejectedWithoutOrphan() async throws {
        try await assertIdenticalPrimaryCredentialRefresh(
            protocolUnderTest: .tuic,
            credential: "test-same-tuic-user-credential"
        )
    }

    @Test(arguments: ["password", "token", "privateKey"])
    @MainActor
    func tuicQueryCredentialRefreshIsRejectedBeforeAdoption(queryName: String) async throws {
        let oldCredential = "test-old-tuic-query-credential"
        let currentCredential = "test-current-tuic-query-credential"
        try await assertPrimaryCredentialRefresh(
            protocolUnderTest: .tuic,
            oldCredential: oldCredential,
            currentCredential: currentCredential,
            oldURI: tuicQueryCredentialURI(queryName: queryName, credential: oldCredential),
            currentURI: tuicQueryCredentialURI(queryName: queryName, credential: currentCredential)
        )
    }

    @Test(arguments: ["password", "token", "privateKey"])
    @MainActor
    func identicalTUICQueryCredentialRefreshIsRejectedWithoutOrphan(queryName: String) async throws {
        let credential = "test-same-tuic-query-credential"
        let uri = tuicQueryCredentialURI(queryName: queryName, credential: credential)
        try await assertIdenticalPrimaryCredentialRefresh(
            protocolUnderTest: .tuic,
            credential: credential,
            oldURI: uri,
            currentURI: uri
        )
    }

    @Test
    func subscriptionPlannerObservesSupportedSecondaryCredentialSlotsAndRejectsUnsupportedProtocols() {
        let subscription = makeSubscription()
        let merger = DefaultSubscriptionMerger()
        let planner = DefaultSubscriptionUpdatePlanner()
        let secondarySlots = VPNProfileCredentialSlot.allCases.filter { $0 != .primary }

        #expect(Set(secondarySlots) == Set([
            .tlsPublicKey,
            .wireGuardPeerPublicKey,
            .wireGuardPresharedKey,
            .hysteria2ObfsPassword
        ]))

        for slot in secondarySlots {
            let existing = merger.makeSubscriptionProfile(
                makeProfile(for: slot, reference: "keychain://test.credentials/secondary-old"),
                subscriptionID: subscription.id,
                now: Date(timeIntervalSince1970: 1_800_000_000)
            )
            var changed = existing
            changed.setCredentialReference("keychain://test.credentials/secondary-current", for: slot)

            let changedPlan = planner.planUpdate(
                subscription: subscription,
                incoming: [changed],
                existing: [existing]
            )
            let identicalPlan = planner.planUpdate(
                subscription: subscription,
                incoming: [existing],
                existing: [existing]
            )

            switch slot {
            case .tlsPublicKey, .wireGuardPeerPublicKey, .wireGuardPresharedKey:
                #expect(changedPlan.changes.first?.kind == .invalid, "Changed unsupported slot: \(slot)")
                #expect(identicalPlan.changes.first?.kind == .invalid, "Identical unsupported slot: \(slot)")
            case .hysteria2ObfsPassword:
                #expect(changedPlan.changes.first?.kind == .updated, "Changed slot: \(slot)")
                #expect(identicalPlan.changes.first?.kind == .unchanged, "Identical slot: \(slot)")
            case .primary:
                Issue.record("Primary credential must not appear in the secondary-slot matrix")
            }
            #expect(merger.stableIdentity(for: changed) == merger.stableIdentity(for: existing))
        }
    }

    @Test
    @MainActor
    func hysteriaAuthOnlyRefreshAdoptsCredentialPublishesRuntimeAndBuildsCurrentAuth() async throws {
        let oldAuth = "test-old-auth"
        let currentAuth = "test-current-auth"
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let oldProfile = try await makeHysteriaSubscriptionProfile(
            auth: oldAuth,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        try await profileRepository.save(oldProfile)
        try await subscriptionRepository.save(subscription)
        let committedProfiles = try await profileRepository.profiles()
        let committedOldProfile = try #require(committedProfiles.first)
        let oldReference = try #require(committedOldProfile.credentialReference)

        let runtimeStore = RefreshRuntimeProfileStore()
        let runtimeSynchronizer = RuntimeProfileSynchronizer(
            profileRepository: profileRepository,
            store: runtimeStore,
            credentialStore: credentialStore
        )
        _ = try await runtimeSynchronizer.profileSaved(committedOldProfile)
        let viewModel = makeSubscriptionRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: runtimeSynchronizer,
            refreshedAuth: currentAuth
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)

        let change = try #require(viewModel.subscriptionUpdatePlan?.changes.first)
        #expect(change.kind == .updated)
        let preparedReference = try #require(change.incomingProfile?.credentialReference)
        #expect(preparedReference != oldReference)

        await viewModel.applySubscriptionUpdate()

        let persistedProfiles = try await profileRepository.profiles()
        let persistedProfile = try #require(persistedProfiles.first)
        let currentReference = try #require(persistedProfile.credentialReference)
        let currentSecret = try await credentialStore.secret(for: currentReference)
        let supersededSecret = try await credentialStore.secret(for: oldReference)
        let activeReferenceCount = await credentialStore.activeReferenceCount
        #expect(currentReference == preparedReference)
        #expect(currentSecret == currentAuth)
        #expect(supersededSecret == nil)
        #expect(activeReferenceCount == 3)

        let runtimeRecord = try await runtimeStore.read(profileID: persistedProfile.id)
        #expect(runtimeRecord.credentialReference == currentReference)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: runtimeRecord.profileID,
            sharedRecordRevision: runtimeRecord.recordRevision
        )
        let resolved = try await RuntimeConfigurationLoader(
            store: runtimeStore,
            credentialResolver: CredentialStoreRuntimeCredentialResolver(credentialStore: credentialStore)
        ).load(providerConfiguration: providerConfiguration.propertyList)
        let json = try XrayConfigurationBuilder()
            .build(from: resolved, options: XrayBuildOptions())
            .withJSONString { $0 }
        #expect(try hysteriaAuth(fromXrayJSON: json) == currentAuth)
    }

    @Test
    @MainActor
    func identicalHysteriaAuthRefreshReusesCommittedReferenceWithoutProfileRevisionOrOrphan() async throws {
        let unchangedAuth = "test-same-auth"
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let profile = try await makeHysteriaSubscriptionProfile(
            auth: unchangedAuth,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        try await profileRepository.save(profile)
        try await subscriptionRepository.save(subscription)
        let committedProfiles = try await profileRepository.profiles()
        let committedProfile = try #require(committedProfiles.first)
        let committedReference = try #require(committedProfile.credentialReference)
        let activeReferenceCountBeforeRefresh = await credentialStore.activeReferenceCount
        let viewModel = makeSubscriptionRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: nil,
            refreshedAuth: unchangedAuth
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)

        let change = try #require(viewModel.subscriptionUpdatePlan?.changes.first)
        let activeReferenceCountAfterRefresh = await credentialStore.activeReferenceCount
        #expect(change.kind == .unchanged)
        #expect(change.incomingProfile?.credentialReference == committedReference)
        #expect(activeReferenceCountAfterRefresh == activeReferenceCountBeforeRefresh)

        await viewModel.applySubscriptionUpdate()

        let persistedProfiles = try await profileRepository.profiles()
        let persistedProfile = try #require(persistedProfiles.first)
        let activeReferenceCountAfterApply = await credentialStore.activeReferenceCount
        let persistedSecret = try await credentialStore.secret(for: committedReference)
        #expect(persistedProfile.credentialReference == committedReference)
        #expect(persistedProfile.updatedAt == committedProfile.updatedAt)
        #expect(persistedSecret == unchangedAuth)
        #expect(activeReferenceCountAfterApply == activeReferenceCountBeforeRefresh)
    }

    @Test
    @MainActor
    func hysteriaObfsPasswordOnlyRefreshAdoptsCommittedCredentialInXray() async throws {
        let auth = "test-stable-hysteria-auth"
        let oldObfsPassword = "test-old-hysteria-obfs-password"
        let currentObfsPassword = "test-current-hysteria-obfs-password"
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let oldProfile = try await makeHysteriaSubscriptionProfile(
            auth: auth,
            obfsPassword: oldObfsPassword,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        try await profileRepository.save(oldProfile)
        try await subscriptionRepository.save(subscription)
        let committedOldProfile = try #require(try await profileRepository.profiles().first)
        let primaryReference = try #require(committedOldProfile.credentialReference)
        let oldObfsReference = try hysteriaObfsPasswordReference(from: committedOldProfile)
        let runtimeStore = RefreshRuntimeProfileStore()
        let runtimeSynchronizer = RuntimeProfileSynchronizer(
            profileRepository: profileRepository,
            store: runtimeStore,
            credentialStore: credentialStore
        )
        _ = try await runtimeSynchronizer.profileSaved(committedOldProfile)
        let oldRuntimeRecord = try await runtimeStore.read(profileID: committedOldProfile.id)
        let viewModel = makeSubscriptionRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: runtimeSynchronizer,
            refreshedAuth: auth,
            refreshedObfsPassword: currentObfsPassword
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)

        let change = try #require(viewModel.subscriptionUpdatePlan?.changes.first)
        let preparedProfile = try #require(change.incomingProfile)
        let preparedObfsReference = try hysteriaObfsPasswordReference(from: preparedProfile)
        #expect(change.kind == .updated)
        #expect(preparedProfile.credentialReference == primaryReference)
        #expect(preparedObfsReference != oldObfsReference)

        await viewModel.applySubscriptionUpdate()

        let persistedProfile = try #require(try await profileRepository.profiles().first)
        let currentObfsReference = try hysteriaObfsPasswordReference(from: persistedProfile)
        let persistedAuth = try await credentialStore.secret(for: primaryReference)
        let currentObfsSecret = try await credentialStore.secret(for: currentObfsReference)
        let supersededObfsSecret = try await credentialStore.secret(for: oldObfsReference)
        #expect(viewModel.subscriptionRefreshState == .completed)
        #expect(persistedProfile.credentialReference == primaryReference)
        #expect(currentObfsReference == preparedObfsReference)
        #expect(persistedAuth == auth)
        #expect(currentObfsSecret == currentObfsPassword)
        #expect(supersededObfsSecret == nil)
        #expect(await credentialStore.activeReferenceCount == 3)

        let runtimeRecord = try await runtimeStore.read(profileID: persistedProfile.id)
        #expect(runtimeRecord.credentialReference == primaryReference)
        #expect(runtimeRecord.hysteria2?.obfsPasswordReference == currentObfsReference)
        #expect(runtimeRecord.recordRevision != oldRuntimeRecord.recordRevision)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: runtimeRecord.profileID,
            sharedRecordRevision: runtimeRecord.recordRevision
        )
        let resolved = try await RuntimeConfigurationLoader(
            store: runtimeStore,
            credentialResolver: CredentialStoreRuntimeCredentialResolver(credentialStore: credentialStore)
        ).load(providerConfiguration: providerConfiguration.propertyList)
        let json = try XrayConfigurationBuilder()
            .build(from: resolved, options: XrayBuildOptions())
            .withJSONString { $0 }
        #expect(try hysteriaObfsPassword(fromXrayJSON: json) == currentObfsPassword)
    }

    @Test
    @MainActor
    func identicalHysteriaObfsPasswordRefreshIsSemanticNoOp() async throws {
        let auth = "test-stable-hysteria-auth"
        let obfsPassword = "test-same-hysteria-obfs-password"
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let profile = try await makeHysteriaSubscriptionProfile(
            auth: auth,
            obfsPassword: obfsPassword,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        try await profileRepository.save(profile)
        try await subscriptionRepository.save(subscription)
        let committedProfile = try #require(try await profileRepository.profiles().first)
        let committedPrimaryReference = try #require(committedProfile.credentialReference)
        let committedObfsReference = try hysteriaObfsPasswordReference(from: committedProfile)
        let activeReferenceCountBeforeRefresh = await credentialStore.activeReferenceCount
        let runtimeStore = RefreshRuntimeProfileStore()
        let runtimeSynchronizer = RuntimeProfileSynchronizer(
            profileRepository: profileRepository,
            store: runtimeStore,
            credentialStore: credentialStore
        )
        _ = try await runtimeSynchronizer.profileSaved(committedProfile)
        let committedRuntimeRecord = try await runtimeStore.read(profileID: committedProfile.id)
        let viewModel = makeSubscriptionRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: runtimeSynchronizer,
            refreshedAuth: auth,
            refreshedObfsPassword: obfsPassword
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)

        let change = try #require(viewModel.subscriptionUpdatePlan?.changes.first)
        let incomingProfile = try #require(change.incomingProfile)
        #expect(change.kind == .unchanged)
        #expect(incomingProfile.credentialReference == committedPrimaryReference)
        #expect(try hysteriaObfsPasswordReference(from: incomingProfile) == committedObfsReference)
        #expect(await credentialStore.activeReferenceCount == activeReferenceCountBeforeRefresh)

        await viewModel.applySubscriptionUpdate()

        let persistedProfile = try #require(try await profileRepository.profiles().first)
        let persistedRuntimeRecord = try await runtimeStore.read(profileID: persistedProfile.id)
        #expect(persistedProfile.credentialReference == committedPrimaryReference)
        #expect(try hysteriaObfsPasswordReference(from: persistedProfile) == committedObfsReference)
        #expect(persistedProfile.updatedAt == committedProfile.updatedAt)
        #expect(persistedRuntimeRecord.recordRevision == committedRuntimeRecord.recordRevision)
        #expect(try await credentialStore.secret(for: committedObfsReference) == obfsPassword)
        #expect(await credentialStore.activeReferenceCount == activeReferenceCountBeforeRefresh)
    }

    @Test
    @MainActor
    func discardedHysteriaAuthRefreshRemovesPreparedCredential() async throws {
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let oldProfile = try await makeHysteriaSubscriptionProfile(
            auth: "test-old-auth",
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        try await profileRepository.save(oldProfile)
        try await subscriptionRepository.save(subscription)
        let oldReference = try #require(oldProfile.credentialReference)
        let viewModel = makeSubscriptionRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: nil,
            refreshedAuth: "test-current-auth"
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)
        let preparedReference = try #require(
            viewModel.subscriptionUpdatePlan?.changes.first?.incomingProfile?.credentialReference
        )

        await viewModel.discardSubscriptionUpdate(for: subscription.id)

        let preparedSecret = try await credentialStore.secret(for: preparedReference)
        let committedSecret = try await credentialStore.secret(for: oldReference)
        let activeReferenceCount = await credentialStore.activeReferenceCount
        #expect(viewModel.subscriptionUpdatePlan == nil)
        #expect(preparedSecret == nil)
        #expect(committedSecret != nil)
        #expect(activeReferenceCount == 3)
    }

    @Test
    @MainActor
    func leavingDuringHysteriaRefreshDiscardsEventuallyPreparedCredential() async throws {
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let oldProfile = try await makeHysteriaSubscriptionProfile(
            auth: "test-old-auth",
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        try await profileRepository.save(oldProfile)
        try await subscriptionRepository.save(subscription)
        let oldReference = try #require(oldProfile.credentialReference)
        let client = SuspendedSubscriptionClient()
        let viewModel = VPNDashboardViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            subscriptionUpdater: URLSessionSubscriptionUpdater(
                client: client,
                credentialStore: credentialStore
            ),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )

        await viewModel.loadInitialData()
        let refreshTask = Task {
            await viewModel.refreshSubscription(subscription)
        }
        await client.waitUntilFetchStarts()
        await viewModel.discardSubscriptionUpdate(for: subscription.id)
        await client.complete(
            with: Data(hysteriaSubscriptionURI(auth: "test-current-auth").utf8)
        )
        await refreshTask.value

        let committedSecret = try await credentialStore.secret(for: oldReference)
        let activeReferenceCount = await credentialStore.activeReferenceCount
        #expect(viewModel.subscriptionUpdatePlan == nil)
        #expect(viewModel.subscriptionRefreshState == .cancelled)
        #expect(committedSecret != nil)
        #expect(activeReferenceCount == 3)
    }

    @Test
    @MainActor
    func changedHysteriaCredentialRollsBackWhenProfilePersistenceFails() async throws {
        let oldAuth = "test-old-auth"
        let currentAuth = "test-current-auth"
        let credentialStore = RecordingCredentialStore()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let oldProfile = try await makeHysteriaSubscriptionProfile(
            auth: oldAuth,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        let profileRepository = SeededFailingProfileRepository(profile: oldProfile)
        try await subscriptionRepository.save(subscription)
        let oldReference = try #require(oldProfile.credentialReference)
        let runtimeStore = RefreshRuntimeProfileStore()
        let runtimeSynchronizer = RuntimeProfileSynchronizer(
            profileRepository: profileRepository,
            store: runtimeStore,
            credentialStore: credentialStore
        )
        _ = try await runtimeSynchronizer.profileSaved(oldProfile)
        let oldRuntimeRecord = try await runtimeStore.read(profileID: oldProfile.id)
        let viewModel = makeSubscriptionRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: runtimeSynchronizer,
            refreshedAuth: currentAuth
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)
        let preparedReference = try #require(
            viewModel.subscriptionUpdatePlan?.changes.first?.incomingProfile?.credentialReference
        )
        #expect(preparedReference != oldReference)

        await viewModel.applySubscriptionUpdate()

        let persistedProfiles = try await profileRepository.profiles()
        let persistedProfile = try #require(persistedProfiles.first)
        let committedSecret = try await credentialStore.secret(for: oldReference)
        let preparedSecret = try await credentialStore.secret(for: preparedReference)
        let currentRuntimeRecord = try await runtimeStore.read(profileID: oldProfile.id)
        let activeReferenceCount = await credentialStore.activeReferenceCount
        #expect(persistedProfile.credentialReference == oldReference)
        #expect(committedSecret == oldAuth)
        #expect(preparedSecret == nil)
        #expect(currentRuntimeRecord == oldRuntimeRecord)
        #expect(activeReferenceCount == 3)
        #expect(viewModel.subscriptionRefreshState == .failed)
    }

    @Test
    @MainActor
    func runtimePublicationFailureKeepsCommittedProfileAndBothRequiredCredentials() async throws {
        let oldAuth = "test-old-auth"
        let currentAuth = "test-current-auth"
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let oldProfile = try await makeHysteriaSubscriptionProfile(
            auth: oldAuth,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        try await profileRepository.save(oldProfile)
        try await subscriptionRepository.save(subscription)
        let oldReference = try #require(oldProfile.credentialReference)
        let runtimeSynchronizer = FailingRefreshRuntimeProfileSynchronizer()
        let viewModel = makeSubscriptionRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: runtimeSynchronizer,
            refreshedAuth: currentAuth
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)
        await viewModel.applySubscriptionUpdate()

        let persistedProfiles = try await profileRepository.profiles()
        let persistedProfile = try #require(persistedProfiles.first)
        let currentReference = try #require(persistedProfile.credentialReference)
        let currentSecret = try await credentialStore.secret(for: currentReference)
        let retainedOldSecret = try await credentialStore.secret(for: oldReference)
        let persistedSubscriptions = try await subscriptionRepository.subscriptions()
        let persistedSubscription = try #require(persistedSubscriptions.first)
        let activeReferenceCount = await credentialStore.activeReferenceCount
        #expect(currentReference != oldReference)
        #expect(currentSecret == currentAuth)
        #expect(retainedOldSecret == oldAuth)
        #expect(persistedSubscription.refreshState == .failed)
        #expect(viewModel.subscriptionRefreshState == .failed)
        #expect(activeReferenceCount == 4)
    }

    @Test
    @MainActor
    func successfulHysteriaAuthRefreshRetainsSupersededCredentialWhenAnotherProfileReferencesIt() async throws {
        let oldAuth = "test-shared-old-auth"
        let currentAuth = "test-current-auth"
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let oldProfile = try await makeHysteriaSubscriptionProfile(
            auth: oldAuth,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        let oldReference = try #require(oldProfile.credentialReference)
        var sharingProfile = oldProfile
        sharingProfile.id = UUID()
        sharingProfile.name = "Shared credential owner"
        sharingProfile.source = .manual
        sharingProfile.sourceSubscriptionID = nil
        sharingProfile.externalIdentity = nil
        try await profileRepository.save(oldProfile)
        try await profileRepository.save(sharingProfile)
        try await subscriptionRepository.save(subscription)
        let runtimeStore = RefreshRuntimeProfileStore()
        let runtimeSynchronizer = RuntimeProfileSynchronizer(
            profileRepository: profileRepository,
            store: runtimeStore,
            credentialStore: credentialStore
        )
        _ = try await runtimeSynchronizer.profileSaved(oldProfile)
        _ = try await runtimeSynchronizer.profileSaved(sharingProfile)
        let viewModel = makeSubscriptionRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: runtimeSynchronizer,
            refreshedAuth: currentAuth
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)
        await viewModel.applySubscriptionUpdate()

        let storedProfiles = try await profileRepository.profiles()
        let refreshedProfile = try #require(storedProfiles.first { $0.id == oldProfile.id })
        let sharedSecret = try await credentialStore.secret(for: oldReference)
        let sharedRuntimeRecord = try await runtimeStore.read(profileID: sharingProfile.id)
        let activeReferenceCount = await credentialStore.activeReferenceCount
        #expect(refreshedProfile.credentialReference != oldReference)
        #expect(storedProfiles.first { $0.id == sharingProfile.id }?.credentialReference == oldReference)
        #expect(sharedSecret == oldAuth)
        #expect(sharedRuntimeRecord.credentialReference == oldReference)
        #expect(activeReferenceCount == 4)
    }

    @Test
    func scanQRCodeRouteOpensScanner() {
        #expect(AddProfileRoute.scanQRCode.destinationKind == .scanner)
    }

    @Test
    func chooseQRImageRouteOpensImagePicker() {
        #expect(AddProfileRoute.chooseQRImage.destinationKind == .imagePicker)
    }

    @Test
    func qrRoutesAreDistinct() {
        #expect(AddProfileRoute.scanQRCode.destinationKind != AddProfileRoute.chooseQRImage.destinationKind)
    }

    @Test
    func simulatorFallbackBelongsOnlyToScannerRoute() {
        #expect(AddProfileNavigationPolicy.destinationKind(for: .scanQRCode, isLiveScannerAvailable: false) == .scannerFallback)
        #expect(AddProfileNavigationPolicy.destinationKind(for: .chooseQRImage, isLiveScannerAvailable: false) == .imagePicker)
    }

    @Test
    func cancelledQRImageSelectionProducesNoErrorRoute() async throws {
        let processor = QRCodeImageImportProcessor(
            detector: RecordingQRCodeDetector(payload: "vless://sample-user-id@qr.example.invalid:443#QR"),
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        )

        let route = try await processor.processOptionalData(nil, title: "Cancelled")

        #expect(route == nil)
    }

    @Test
    func selectedQRImageDataIsPassedToDetector() async throws {
        let detector = RecordingQRCodeDetector(payload: "trojan://sample-password@qr.example.invalid:443#QR")
        let processor = QRCodeImageImportProcessor(
            detector: detector,
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        )
        let data = Data("fake-image-data".utf8)

        _ = try await processor.process(data: data, title: "QR")

        #expect(await detector.lastDataCount == data.count)
    }

    @Test
    func qrPayloadUsesReviewProfilePipeline() async throws {
        let processor = QRCodeImageImportProcessor(
            detector: RecordingQRCodeDetector(payload: "hy2://sample-password@qr.example.invalid:443#QR"),
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        )

        let route = try await processor.process(data: Data("fake-image-data".utf8), title: "QR")

        guard case .single(let result) = route,
              case .profile(let profile) = result.kind else {
            Issue.record("Expected single profile review route")
            return
        }
        #expect(profile.protocolType == .hysteria2)
        #expect(profile.serverAddress == "qr.example.invalid")
    }

    @Test
    func pasteURLVLESSRoutesToProfileReview() async throws {
        let router = ImportPayloadRouter(
            importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
            subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        )

        let route = try await router.route(text: "vless://sample-user-id@paste.example.invalid:443?encryption=none#Paste", title: "Paste")

        guard case .single(let result) = route,
              case .profile(let profile) = result.kind else {
            Issue.record("Expected a profile review route")
            return
        }
        #expect(profile.protocolType == .vless)
        #expect(profile.serverAddress == "paste.example.invalid")
    }

    @Test
    func pasteURLTrojanRoutesToProfileReview() async throws {
        let router = ImportPayloadRouter(
            importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
            subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        )

        let route = try await router.route(text: "trojan://sample-password@paste.example.invalid:443#Trojan", title: "Paste")

        guard case .single(let result) = route,
              case .profile(let profile) = result.kind else {
            Issue.record("Expected a profile review route")
            return
        }
        #expect(profile.protocolType == .trojan)
    }

    @Test
    func pasteURLHysteriaRoutesToProfileReview() async throws {
        let router = ImportPayloadRouter(
            importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
            subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        )

        let route = try await router.route(text: "hy2://sample-password@paste.example.invalid:443#Hysteria", title: "Paste")

        guard case .single(let result) = route,
              case .profile(let profile) = result.kind else {
            Issue.record("Expected a profile review route")
            return
        }
        #expect(profile.protocolType == .hysteria2)
    }

    @Test
    @MainActor
    func outlineSingleReviewSavesExactRoutedResult() async throws {
        let credential = "test-outline-review-password"
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let activeProfileStore = InMemoryActiveProfileStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: credentialStore,
            activeProfileStore: activeProfileStore
        )
        let userInfo = Data("aes-256-gcm:\(credential)".utf8).base64EncodedString()
        let route = try await viewModel.routeImportPayload(
            text: "ss://\(userInfo)@outline.example.invalid:443?outline=1#Outline",
            title: "Paste"
        )

        guard case .single(let reviewedResult) = route,
              case .profile(let reviewedProfile) = reviewedResult.kind else {
            Issue.record("Expected a single Shadowsocks profile review")
            return
        }
        let parserReference = try #require(reviewedProfile.credentialReference)
        #expect(reviewedProfile.isComplete)
        #expect(reviewedProfile.runtimeCapability == .ready)
        #expect(reviewedProfile.metadata["outline"] == "1")
        #expect(viewModel.importResult == nil)

        let didSave = await viewModel.saveImportResultAndSelect(reviewedResult)

        let persistedProfile = try #require((try await profileRepository.profiles()).first)
        #expect(didSave)
        #expect(persistedProfile.id == reviewedProfile.id)
        #expect(persistedProfile.credentialReference == parserReference)
        #expect(try await credentialStore.secret(for: parserReference) == credential)
        #expect(await credentialStore.storeCount == 1)
        #expect(viewModel.activeProfileID == reviewedProfile.id)
        #expect(await activeProfileStore.activeProfileID() == reviewedProfile.id)

        let runtimeRecord = try SharedRuntimeProfileMapper().record(from: persistedProfile)
        #expect(runtimeRecord.shadowsocks?.isOutlineStaticKey == true)
        let json = try await xrayJSON(record: runtimeRecord, credentialStore: credentialStore)
        let object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let outbounds = try #require(object["outbounds"] as? [[String: Any]])
        let outbound = try #require(outbounds.first)
        let settings = try #require(outbound["settings"] as? [String: Any])
        let servers = try #require(settings["servers"] as? [[String: Any]])
        let server = try #require(servers.first)
        let streamSettings = try #require(outbound["streamSettings"] as? [String: Any])
        #expect(outbound["protocol"] as? String == "shadowsocks")
        #expect(server["method"] as? String == "aes-256-gcm")
        #expect(server["password"] as? String == credential)
        #expect(streamSettings["network"] as? String == "tcp")
        #expect(streamSettings["security"] as? String == "none")
    }

    @Test
    @MainActor
    func unsupportedShadowsocksPluginIsRejectedBeforeSaveAndPreparedCredentialIsCompensated() async throws {
        let credential = "test-plugin-review-password"
        let hiddenPluginOption = "test-hidden-plugin-option"
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let viewModel = VPNDashboardViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )
        let userInfo = Data("aes-256-gcm:\(credential)".utf8).base64EncodedString()
        let plugin = "v2ray-plugin;obfs=http;obfs-host=\(hiddenPluginOption)"
        var components = URLComponents()
        components.scheme = "ss"
        components.user = userInfo
        components.host = "plugin-outline.example.invalid"
        components.port = 443
        components.queryItems = [
            URLQueryItem(name: "outline", value: "1"),
            URLQueryItem(name: "plugin", value: plugin)
        ]
        components.fragment = "Unsupported plugin"
        let uri = try #require(components.string)

        let route = try await viewModel.routeImportPayload(text: uri, title: "Paste")
        guard case .single(let reviewedResult) = route,
              case .profile(let reviewedProfile) = reviewedResult.kind else {
            Issue.record("Expected a single Shadowsocks profile review")
            return
        }
        let preparedReference = try #require(reviewedProfile.credentialReference)
        let status = reviewedProfile.runtimeCapability.statusText
        #expect(reviewedProfile.isComplete)
        #expect(reviewedProfile.runtimeCapability.isReady == false)
        #expect(status.contains("v2ray-plugin"))
        #expect(status.contains(hiddenPluginOption) == false)

        let didSave = await viewModel.saveImportResultAndSelect(reviewedResult)

        #expect(didSave == false)
        #expect((try await profileRepository.profiles()).isEmpty)
        #expect(try await credentialStore.secret(for: preparedReference) == nil)
        #expect(await credentialStore.activeReferenceCount == 0)
        #expect(await credentialStore.storeCount == 1)
    }

    @Test
    @MainActor
    func abandoningSingleReviewDeletesEveryPreparedCredentialSlot() async throws {
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let viewModel = VPNDashboardViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )
        let route = try await viewModel.routeImportPayload(
            text: "hy2://test-review-auth@review-hy2.example.invalid:443?obfs=salamander&obfs-password=test-review-obfs#Review",
            title: "Paste"
        )
        guard case .single(let reviewedResult) = route,
              case .profile(let reviewedProfile) = reviewedResult.kind else {
            Issue.record("Expected a single Hysteria 2 profile review")
            return
        }
        let preparedReferences = reviewedProfile.credentialReferences
        #expect(preparedReferences.count == 2)

        let didDiscard = await viewModel.discardImportResult(reviewedResult)

        #expect(didDiscard)
        #expect((try await profileRepository.profiles()).isEmpty)
        #expect(await credentialStore.activeReferenceCount == 0)
        for reference in preparedReferences {
            #expect(try await credentialStore.secret(for: reference) == nil)
        }
    }

    @Test
    @MainActor
    func supersededSingleImportRouteCompensatesPreparedCredential() async throws {
        let credentialStore = RecordingCredentialStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )
        let userInfo = Data("aes-256-gcm:test-superseded-outline-password".utf8).base64EncodedString()
        let route = try await viewModel.routeImportPayload(
            text: "ss://\(userInfo)@superseded-outline.example.invalid:443#Superseded",
            title: "Paste"
        )
        guard case .single(let reviewedResult) = route,
              case .profile(let reviewedProfile) = reviewedResult.kind else {
            Issue.record("Expected a single Shadowsocks profile review")
            return
        }
        let preparedReference = try #require(reviewedProfile.credentialReference)

        let didDiscard = await viewModel.discardImportRoute(route)

        #expect(didDiscard)
        #expect(try await credentialStore.secret(for: preparedReference) == nil)
        #expect(await credentialStore.activeReferenceCount == 0)
    }

    @Test
    @MainActor
    func failedOutlineSingleReviewSaveCompensatesPreparedCredential() async throws {
        let credentialStore = RecordingCredentialStore()
        let activeProfileStore = InMemoryActiveProfileStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: FailingProfileRepository(),
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: credentialStore,
            activeProfileStore: activeProfileStore
        )
        let userInfo = Data("aes-256-gcm:test-outline-failure-password".utf8).base64EncodedString()
        let route = try await viewModel.routeImportPayload(
            text: "ss://\(userInfo)@failure-outline.example.invalid:443#Failure",
            title: "Paste"
        )
        guard case .single(let reviewedResult) = route,
              case .profile(let reviewedProfile) = reviewedResult.kind else {
            Issue.record("Expected a single Shadowsocks profile review")
            return
        }
        let preparedReference = try #require(reviewedProfile.credentialReference)

        let didSave = await viewModel.saveImportResultAndSelect(reviewedResult)

        #expect(didSave == false)
        #expect(try await credentialStore.secret(for: preparedReference) == nil)
        #expect(await credentialStore.activeReferenceCount == 0)
        #expect(viewModel.activeProfileID == nil)
        #expect(await activeProfileStore.activeProfileID() == nil)
    }

    @Test
    @MainActor
    func abandoningSingleReviewRetainsCredentialReferencedByCommittedProfile() async throws {
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let viewModel = VPNDashboardViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )
        let userInfo = Data("aes-256-gcm:test-shared-outline-password".utf8).base64EncodedString()
        let route = try await viewModel.routeImportPayload(
            text: "ss://\(userInfo)@shared-outline.example.invalid:443#Shared",
            title: "Paste"
        )
        guard case .single(let reviewedResult) = route,
              case .profile(let reviewedProfile) = reviewedResult.kind else {
            Issue.record("Expected a single Shadowsocks profile review")
            return
        }
        let sharedReference = try #require(reviewedProfile.credentialReference)
        var committedProfile = reviewedProfile
        committedProfile.id = UUID()
        committedProfile.name = "Committed owner"
        try await profileRepository.save(committedProfile)

        let didDiscard = await viewModel.discardImportResult(reviewedResult)

        #expect(didDiscard)
        #expect(try await credentialStore.secret(for: sharedReference) == "test-shared-outline-password")
        #expect(await credentialStore.activeReferenceCount == 1)
        #expect(await credentialStore.deletedReferences.contains(sharedReference) == false)
    }

    @Test
    @MainActor
    func leavingDuringSingleReviewSaveCannotDeleteInFlightCredential() async throws {
        let credentialStore = RecordingCredentialStore()
        let profileRepository = SlowSaveProfileRepository()
        let viewModel = VPNDashboardViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )
        let userInfo = Data("aes-256-gcm:test-in-flight-outline-password".utf8).base64EncodedString()
        let route = try await viewModel.routeImportPayload(
            text: "ss://\(userInfo)@in-flight-outline.example.invalid:443#InFlight",
            title: "Paste"
        )
        guard case .single(let reviewedResult) = route,
              case .profile(let reviewedProfile) = reviewedResult.kind else {
            Issue.record("Expected a single Shadowsocks profile review")
            return
        }
        let preparedReference = try #require(reviewedProfile.credentialReference)

        let saveTask = Task { @MainActor in
            await viewModel.saveImportResultAndSelect(reviewedResult)
        }
        try await Task.sleep(for: .milliseconds(20))
        _ = await viewModel.discardImportResult(reviewedResult)
        let didSave = await saveTask.value

        #expect(didSave)
        #expect(try await credentialStore.secret(for: preparedReference) == "test-in-flight-outline-password")
        #expect((try await profileRepository.profiles()).first?.credentialReference == preparedReference)
    }

    @Test
    func pasteURLHTTPSRoutesToSubscriptionReview() async throws {
        let credentialStore = InMemoryCredentialStore()
        let router = ImportPayloadRouter(
            importer: VPNLinkParser(credentialStore: credentialStore),
            subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: credentialStore))
        )

        let route = try await router.route(text: "https://provider.example.invalid/sub?token=sample-token", title: "Paste")

        guard case .single(let result) = route,
              case .subscription(let subscription) = result.kind else {
            Issue.record("Expected a subscription review route")
            return
        }
        #expect(subscription.sanitizedHost == "provider.example.invalid")
        #expect(subscription.sanitizedURLDisplay.contains("sample-token") == false)
        #expect(subscription.credentialReference != nil)
    }

    @Test
    func invalidPasteInputThrowsTypedError() async {
        let router = ImportPayloadRouter(
            importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
            subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        )

        await #expect(throws: VPNImportError.invalidPayload("No supported VPN profiles were found.")) {
            _ = try await router.route(text: "not a vpn link", title: "Paste")
        }
    }

    @Test
    func emptyPasteInputThrowsValidationError() async {
        let router = ImportPayloadRouter(
            importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
            subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
        )

        await #expect(throws: VPNImportError.emptyInput) {
            _ = try await router.route(text: "   \n", title: "Paste")
        }
    }

    @Test
    @MainActor
    func subscriptionFromPasteURLUsesExistingSubscriptionImporter() async throws {
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let credentialStore = InMemoryCredentialStore()
        let profile = makeCompleteProfile(name: "Subscription Profile")
        let viewModel = VPNDashboardViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            subscriptionUpdater: StubSubscriptionUpdater(profile: profile),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )
        let importResult = try await VPNLinkParser(credentialStore: credentialStore)
            .parse("https://provider.example.invalid/sub?token=sample-token")

        guard case .subscription(let subscription) = importResult.kind else {
            Issue.record("Expected subscription result")
            return
        }

        let didSave = await viewModel.saveSubscriptionImportResult(subscription)

        #expect(didSave)
        #expect((try await subscriptionRepository.subscriptions()).count == 1)
        #expect((try await profileRepository.profiles()).count == 1)
        #expect(viewModel.connectionState == .disconnected)
    }

    @Test
    func iPhoneOrientationPolicyIsPortraitOnly() {
        #expect(AppOrientationPolicy.supportedInterfaceOrientations(for: .phone) == .portrait)
    }

    @Test
    func iPadOrientationPolicyPreservesAllOrientations() {
        #expect(AppOrientationPolicy.supportedInterfaceOrientations(for: .pad) == .all)
    }

    @Test
    func qrVisionErrorCompletesOnce() async {
        let detector = FailingQRCodeDetector(error: QRCodeImageImportError.recognitionUnavailable)
        let processor = QRCodeImageImportProcessor(
            detector: detector,
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        )

        await #expect(throws: QRCodeImageImportError.recognitionUnavailable) {
            _ = try await processor.payloads(in: Data("image".utf8))
        }
        #expect(await detector.callCount == 1)
    }

    @Test
    func invalidQRImageDoesNotCrash() async {
        let processor = QRCodeImageImportProcessor(
            detector: FailingQRCodeDetector(error: QRCodeImageImportError.invalidImage),
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        )

        await #expect(throws: QRCodeImageImportError.invalidImage) {
            _ = try await processor.payloads(in: Data("not-image".utf8))
        }
    }

    @Test
    func noQRCodeReturnsTypedError() async {
        let processor = QRCodeImageImportProcessor(
            detector: FailingQRCodeDetector(error: QRCodeImageImportError.noQRCodeFound),
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        )

        await #expect(throws: QRCodeImageImportError.noQRCodeFound) {
            _ = try await processor.payloads(in: Data("image".utf8))
        }
    }

    @Test
    func oneQRCodeReturnedOnce() async throws {
        let detector = RecordingQRCodeDetector(payloads: ["vless://sample-user-id@one.example.invalid:443#One"])
        let processor = QRCodeImageImportProcessor(
            detector: detector,
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        )

        let payloads = try await processor.payloads(in: Data("image".utf8))

        #expect(payloads.count == 1)
        #expect(await detector.callCount == 1)
    }

    @Test
    func multipleQRCodesReturnedAsArray() async throws {
        let detector = RecordingQRCodeDetector(payloads: [
            "vless://sample-user-id@one.example.invalid:443#One",
            "trojan://sample-password@two.example.invalid:443#Two"
        ])
        let processor = QRCodeImageImportProcessor(
            detector: detector,
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        )

        let payloads = try await processor.payloads(in: Data("image".utf8))

        #expect(payloads.count == 2)
    }

    @Test
    func repeatedQRImageSelectionCancelsStaleProcessing() async {
        let detector = ControllableQRCodeDetector()
        let coordinator = makeQRImageImportCoordinator(detector: detector)

        let firstTask = Task { await coordinator.start(data: Data("first".utf8), title: "First") }
        await detector.waitForRequest("first")
        let secondTask = Task { await coordinator.start(data: Data("second".utf8), title: "Second") }
        await detector.waitForRequest("second")

        await detector.succeed("second", payload: "vless://sample-user-id@second.example.invalid:443#Second")
        await detector.succeed("first", payload: "vless://sample-user-id@first.example.invalid:443#First")
        let results = await (firstTask.value, secondTask.value)

        #expect(results.0 == nil)
        #expect(singleProfileName(from: results.1) == "Second")
        #expect(await detector.callCount == 2)
    }

    @Test
    func staleQRResultIsDiscardedAfterNewerSelectionStarts() async {
        let detector = ControllableQRCodeDetector()
        let coordinator = makeQRImageImportCoordinator(detector: detector)

        let firstTask = Task { await coordinator.start(data: Data("first".utf8), title: "First") }
        await detector.waitForRequest("first")
        let secondTask = Task { await coordinator.start(data: Data("second".utf8), title: "Second") }
        await detector.waitForRequest("second")

        await detector.succeed("first", payload: "vless://sample-user-id@first.example.invalid:443#First")
        let staleResult = await firstTask.value

        #expect(staleResult == nil)
        #expect(await coordinator.isProcessing)

        await detector.succeed("second", payload: "vless://sample-user-id@second.example.invalid:443#Second")
        let latestResult = await secondTask.value

        #expect(singleProfileName(from: latestResult) == "Second")
        #expect(await coordinator.isProcessing == false)
    }

    @Test
    func staleQRImageErrorCannotOverwriteSuccessfulLatestSelection() async {
        let detector = ControllableQRCodeDetector()
        let coordinator = makeQRImageImportCoordinator(detector: detector)

        let firstTask = Task { await coordinator.start(data: Data("first".utf8), title: "First") }
        await detector.waitForRequest("first")
        let secondTask = Task { await coordinator.start(data: Data("second".utf8), title: "Second") }
        await detector.waitForRequest("second")

        await detector.fail("first", error: QRCodeImageImportError.noQRCodeFound)
        await detector.succeed("second", payload: "vless://sample-user-id@second.example.invalid:443#Second")
        let results = await (firstTask.value, secondTask.value)

        #expect(results.0 == nil)
        #expect(singleProfileName(from: results.1) == "Second")
        #expect(await coordinator.errorMessage == nil)
    }

    @Test
    func repeatedQRImageSelectionAppliesOnlyLatestRoute() async {
        let detector = ControllableQRCodeDetector()
        let coordinator = makeQRImageImportCoordinator(detector: detector)

        let firstTask = Task { await coordinator.start(data: Data("first".utf8), title: "First") }
        await detector.waitForRequest("first")
        let secondTask = Task { await coordinator.start(data: Data("second".utf8), title: "Second") }
        await detector.waitForRequest("second")

        await detector.succeed("first", payload: "vless://sample-user-id@first.example.invalid:443#First")
        await detector.succeed("second", payload: "vless://sample-user-id@second.example.invalid:443#Second")
        let routes = await [firstTask.value, secondTask.value].compactMap { $0 }

        #expect(routes.count == 1)
        #expect(singleProfileName(from: routes.first) == "Second")
    }

    @Test
    func staleQRResultDoesNotOpenReviewProfile() async {
        let coordinator = QRImageImportCoordinator(processor: QRCodeImageImportProcessor(
            detector: FailingQRCodeDetector(error: CancellationError()),
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        ))

        let route = await coordinator.start(data: Data("stale".utf8), title: "Stale")

        #expect(route == nil)
    }

    @Test
    func simultaneousDoubleQRProcessingKeepsSingleActiveResult() async {
        let coordinator = QRImageImportCoordinator(processor: QRCodeImageImportProcessor(
            detector: RecordingQRCodeDetector(payload: "vless://sample-user-id@single.example.invalid:443#Single"),
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        ))

        async let first: ImportPayloadRoute? = coordinator.start(data: Data("one".utf8), title: "One")
        async let second: ImportPayloadRoute? = coordinator.start(data: Data("two".utf8), title: "Two")
        let pair = await (first, second)
        let results = [pair.0, pair.1].compactMap { $0 }

        #expect(results.count <= 1)
    }

    @Test
    func qrProcessingErrorResetsIsProcessing() async {
        let coordinator = QRImageImportCoordinator(processor: QRCodeImageImportProcessor(
            detector: FailingQRCodeDetector(error: QRCodeImageImportError.noQRCodeFound),
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        ))

        _ = await coordinator.start(data: Data("image".utf8), title: "Image")

        #expect(await coordinator.isProcessing == false)
        #expect(await coordinator.errorMessage?.contains("No QR") == true)
    }

    @Test
    func qrErrorsDoNotExposeRawPayload() async {
        let secretPayload = "vless://sample-secret-user-id@secret.example.invalid:443?token=sample-token#Secret"
        let coordinator = QRImageImportCoordinator(processor: QRCodeImageImportProcessor(
            detector: RecordingQRCodeDetector(payload: secretPayload),
            router: ImportPayloadRouter(
                importer: FailingImporter(),
                subscriptionParser: SubscriptionContentParser(linkParser: FailingImporter())
            )
        ))

        _ = await coordinator.start(data: Data("image".utf8), title: "Image")

        #expect(await coordinator.errorMessage?.contains("sample-token") != true)
        #expect(await coordinator.errorMessage?.contains("sample-secret-user-id") != true)
    }

    @Test
    @MainActor
    func saveProfileCallsCredentialStorage() async {
        let credentialValue = "sample-manual-secret"
        let credentialStore = RecordingCredentialStore()
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore()
        )

        let didSave = await viewModel.saveProfileDraft(
            makeIncompleteCredentialProfile(name: "Manual"),
            credentialValue: credentialValue
        )

        #expect(didSave)
        #expect(await credentialStore.storeCount == 1)
        let savedReference = viewModel.profiles.first?.credentialReference
        #expect(savedReference != nil)
        guard let savedReference else { return }
        let savedReferenceResolves = (try? await credentialStore.secret(for: savedReference)) != nil
        #expect(savedReferenceResolves)
        #expect(savedReference != credentialValue)
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
            subscriptionRepository: InMemorySubscriptionRepository(),
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
    func portValidHostnameNumeric() throws {
        let components = try ParserSupport.components(from: "vless://user@example.com:443")
        #expect(try ParserSupport.requiredPort(from: components) == 443)
    }

    @Test
    func portAlphabeticRejected() {
        #expect(throws: VPNImportError.invalidPort) {
            _ = try ParserSupport.components(from: "vless://user@example.com:bad")
        }
    }

    @Test
    func portZeroRejected() {
        #expect(throws: VPNImportError.invalidPort) {
            _ = try ParserSupport.components(from: "vless://user@example.com:0")
        }
    }

    @Test
    func portUpperBoundAccepted() throws {
        let components = try ParserSupport.components(from: "vless://user@example.com:65535")
        #expect(try ParserSupport.requiredPort(from: components) == 65535)
    }

    @Test
    func portAboveUpperBoundRejected() {
        #expect(throws: VPNImportError.invalidPort) {
            _ = try ParserSupport.components(from: "vless://user@example.com:65536")
        }
    }

    @Test
    func portFarAboveUpperBoundRejected() {
        #expect(throws: VPNImportError.invalidPort) {
            _ = try ParserSupport.components(from: "vless://user@example.com:99999")
        }
    }

    @Test
    func bracketedIPv6NumericPortAccepted() throws {
        let components = try ParserSupport.components(from: "vless://user@[2001:db8::1]:443")
        #expect(try ParserSupport.requiredPort(from: components) == 443)
    }

    @Test
    func bracketedIPv6MalformedPortRejected() {
        #expect(throws: VPNImportError.invalidPort) {
            _ = try ParserSupport.components(from: "vless://user@[2001:db8::1]:bad")
        }
    }

    @Test
    func userinfoColonNotMistakenForPort() throws {
        let components = try ParserSupport.components(from: "vless://user:pass@example.com:443")
        #expect(try ParserSupport.requiredPort(from: components) == 443)
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
        // A plain secret reveals only its last 4 characters. (A hyphenated,
        // UUID-like value takes the dedicated identifier-mask branch below.)
        #expect(SecretMasker.masked("samplepassword") == "••••word")
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

        let secret = try await store.secret(for: reference)
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
    func persistedUnsupportedProfileRemainsStoredButCannotBecomeActive() async throws {
        let manager = RecordingConnectionManager()
        let repository = InMemoryVPNProfileRepository()
        let activeStore = InMemoryActiveProfileStore()
        let profile = VPNProfile.draft(
            name: "Legacy plugin profile",
            protocolType: .shadowsocks,
            serverAddress: "legacy-plugin.example.invalid",
            port: 8388,
            credentialReference: "keychain://test.credentials/legacy-plugin",
            protocolConfiguration: .shadowsocks(ShadowsocksProfileConfiguration(
                method: "aes-256-gcm",
                plugin: "v2ray-plugin;obfs=http"
            )),
            source: .importedURL
        )
        try await repository.save(profile)
        await activeStore.saveActiveProfileID(profile.id)
        let viewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: repository,
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: activeStore
        )

        await viewModel.loadInitialData()
        #expect(viewModel.profiles.contains(where: { $0.id == profile.id }))
        #expect(viewModel.activeProfileID == nil)

        viewModel.selectProfile(profile)

        #expect(viewModel.selectedProfile == nil)
        #expect(viewModel.errorMessage?.contains("v2ray-plugin") == true)
        #expect(await manager.connectCount == 0)
        #expect(await manager.currentState() == .disconnected)
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

        // Structured cancellation: loadInitialData awaits a cancellable
        // fetch, so cancelling the task deterministically aborts the load
        // before servers are populated (no timing assumptions).
        task.cancel()
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
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: InMemoryActiveProfileStore()
        )

        await viewModel.loadInitialData()
        await viewModel.connect()

        #expect(viewModel.connectionState == .connected)
        #expect(viewModel.currentMetrics != nil)

        await viewModel.disconnect()

        #expect(viewModel.connectionState == .disconnected)
        #expect(viewModel.currentMetrics == nil)
    }

    @Test
    @MainActor
    func connectionInitialStateIsDisconnected() async {
        let manager = RecordingConnectionManager()
        let viewModel = VPNDashboardViewModel(connectionManager: manager)

        #expect(viewModel.connectionState == .disconnected)
        #expect(await manager.currentState() == .disconnected)
    }

    @Test
    @MainActor
    func connectionStateSurvivesInitialLoadAfterReturningHome() async {
        let manager = RecordingConnectionManager()
        let viewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: InMemoryVPNProfileRepository(),
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: InMemoryActiveProfileStore()
        )

        await viewModel.loadInitialData()
        await viewModel.connect()
        await viewModel.loadInitialData()

        #expect(viewModel.connectionState == .connected)
        #expect(await manager.currentState() == .connected)
        #expect(await manager.disconnectCount == 0)
    }

    @Test
    @MainActor
    func recreatingHomeViewModelDoesNotResetSharedManagerState() async {
        let manager = RecordingConnectionManager()
        let repository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let credentialStore = InMemoryCredentialStore()
        let activeStore = InMemoryActiveProfileStore()
        let firstViewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: repository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            activeProfileStore: activeStore
        )

        await firstViewModel.loadInitialData()
        await firstViewModel.connect()

        let recreatedViewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: repository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            activeProfileStore: activeStore
        )
        await recreatedViewModel.loadInitialData()

        #expect(recreatedViewModel.connectionState == .connected)
        #expect(await manager.connectCount == 1)
        #expect(await manager.disconnectCount == 0)
    }

    @Test
    @MainActor
    func settingsNavigationDoesNotDisconnectSharedManager() async {
        let manager = RecordingConnectionManager()
        let viewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: InMemoryVPNProfileRepository(),
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: InMemoryActiveProfileStore()
        )

        await viewModel.loadInitialData()
        await viewModel.connect()
        _ = SettingsView()
        await viewModel.loadInitialData()

        #expect(viewModel.connectionState == .connected)
        #expect(await manager.disconnectCount == 0)
    }

    @Test
    @MainActor
    func disconnectUpdatesSameSharedManager() async {
        let manager = RecordingConnectionManager()
        let viewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: InMemoryVPNProfileRepository(),
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: InMemoryActiveProfileStore()
        )

        await viewModel.loadInitialData()
        await viewModel.connect()
        await viewModel.disconnect()

        #expect(viewModel.connectionState == .disconnected)
        #expect(await manager.currentState() == .disconnected)
        #expect(await manager.connectCount == 1)
        #expect(await manager.disconnectCount == 1)
    }

    @Test
    @MainActor
    func selectingProfileDoesNotResetActiveConnectionState() async {
        let manager = RecordingConnectionManager()
        let repository = InMemoryVPNProfileRepository()
        let profile = makeCompleteProfile(name: "Switch Profile")
        try? await repository.save(profile)
        let viewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: repository,
            subscriptionRepository: InMemorySubscriptionRepository(),
            credentialStore: InMemoryCredentialStore(),
            activeProfileStore: InMemoryActiveProfileStore()
        )

        await viewModel.loadInitialData()
        await viewModel.connect()
        viewModel.selectProfile(profile)

        #expect(viewModel.connectionState == .connected)
        #expect(await manager.currentState() == .connected)
    }

    @Test
    func cameraDeniedStateShowsSettingsAction() {
        #expect(QRScannerCameraAccessState.denied.fallbackTitle == "qr.camera_permission_required")
        #expect(QRScannerCameraAccessState.denied.showsSettingsAction)
    }

    @Test
    func cameraUnavailableStateKeepsImageFallbackAvailable() {
        #expect(QRScannerCameraAccessState.unavailable.fallbackTitle == "qr.camera_unavailable")
        #expect(QRScannerCameraAccessState.unavailable.showsSettingsAction == false)
    }

    @Test
    func appLanguageDefaultsToSystemForUnsupportedPersistedValue() {
        #expect(AppLanguage.persistedValue("unsupported") == .system)
    }

    @Test
    func appLanguageUsesStableStorageValues() {
        #expect(AppLanguage.storageKey == "app.language")
        #expect(AppLanguage.system.rawValue == "system")
        #expect(AppLanguage.english.rawValue == "english")
        #expect(AppLanguage.russian.rawValue == "russian")
    }

    @Test
    func appLanguageMapsToExpectedLocales() {
        #expect(AppLanguage.english.locale.identifier == "en")
        #expect(AppLanguage.russian.locale.identifier == "ru")
    }

    @Test
    func keyEnglishLocalizationsExist() throws {
        let strings = try localizableStrings()
        let keys = [
            "app.name",
            "settings.language",
            "home.status.connected",
            "profiles.add",
            "qr.camera_permission_required",
            "import.success.title",
            "import.success.profile",
            "import.success.subscription",
            "import.error.subscription_failed",
            "import.progress.importing"
        ]

        for key in keys {
            let localization = try #require(strings[key] as? [String: Any])
            let localizations = try #require(localization["localizations"] as? [String: Any])
            #expect(localizations["en"] != nil)
        }
    }

    @Test
    func keyRussianLocalizationsExist() throws {
        let strings = try localizableStrings()
        let keys = [
            "app.name",
            "settings.language",
            "home.status.connected",
            "profiles.add",
            "qr.camera_permission_required",
            "import.success.title",
            "import.success.profile",
            "import.success.subscription",
            "import.error.subscription_failed",
            "import.progress.importing"
        ]

        for key in keys {
            let localization = try #require(strings[key] as? [String: Any])
            let localizations = try #require(localization["localizations"] as? [String: Any])
            #expect(localizations["ru"] != nil)
        }
    }

    @Test
    @MainActor
    func changingLanguageDoesNotChangeConnectionStateOrActiveProfile() async {
        let manager = RecordingConnectionManager()
        let activeStore = InMemoryActiveProfileStore()
        let repository = InMemoryVPNProfileRepository()
        let profile = makeCompleteProfile(name: "Localized")
        try? await repository.save(profile)
        await activeStore.saveActiveProfileID(profile.id)
        let viewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: repository,
            activeProfileStore: activeStore
        )

        await viewModel.loadInitialData()
        await viewModel.connect()
        let language = AppLanguage.persistedValue(AppLanguage.russian.rawValue)

        #expect(language == .russian)
        #expect(viewModel.connectionState == .connected)
        #expect(viewModel.activeProfileID == profile.id)
    }

    @Test
    func vlessProfileCompilesToCoreConfiguration() throws {
        let profile = makeCompleteProfile(name: "Core VLESS")
        let configuration = try VLESSProfileConfigurationCompiler().compile(profile: profile)

        #expect(configuration.protocolType == .vless)
        #expect(configuration.endpoint.host == "profile.example.com")
        #expect(configuration.endpoint.port == 443)
        #expect(configuration.credentialReference == "keychain://test.credentials/test-reference")
    }

    @Test
    func vlessRealityRequiresFields() {
        var profile = makeCompleteProfile(name: "Reality")
        profile.transportSettings.security = "reality"
        profile.tlsSettings = VPNTLSSettings(isEnabled: true, serverName: "site.example.invalid", realityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", shortID: nil)

        #expect(throws: CoreError.invalidConfiguration("Reality requires short ID.")) {
            _ = try VLESSProfileConfigurationCompiler().compile(profile: profile)
        }
    }

    @Test
    func coreInvalidPortRejected() {
        var profile = makeCompleteProfile(name: "Bad Port")
        profile.port = 70_000

        #expect(throws: CoreError.invalidConfiguration("Port must be in range 1...65535.")) {
            _ = try VLESSProfileConfigurationCompiler().compile(profile: profile)
        }
    }

    @Test
    func coreMissingCredentialRejected() {
        var profile = makeCompleteProfile(name: "Missing Credential")
        profile.credentialReference = nil

        #expect(throws: CoreError.missingCredential) {
            _ = try VLESSProfileConfigurationCompiler().compile(profile: profile)
        }
    }

    @Test
    func backendSelectedByProtocol() throws {
        let registry = VPNCoreBackendRegistry(factories: [MockCoreBackendFactory(supportedProtocols: [.vless])])
        let backend = try registry.backend(for: .vless)

        #expect(backend.identifier == "mock-core-backend")
    }

    @Test
    func unsupportedBackendReturnsTypedError() {
        let registry = VPNCoreBackendRegistry(factories: [])

        #expect(throws: CoreError.unsupportedProtocol(.vless)) {
            _ = try registry.backend(for: .vless)
        }
    }

    @Test
    func repeatedCoreStartIsBlocked() async {
        let coordinator = makeCoreCoordinator(delay: .milliseconds(120))
        let profile = makeCompleteProfile(name: "Repeated")

        let task = Task {
            try? await coordinator.start(profile: profile)
        }
        await waitUntilCoreBusy(coordinator)

        await #expect(throws: CoreError.alreadyRunning) {
            try await coordinator.start(profile: profile)
        }

        await coordinator.stop()
        await task.value
    }

    @Test
    func startDuringPrepareDoesNotStartTwice() async {
        let coordinator = makeCoreCoordinator(delay: .milliseconds(120))
        let profile = makeCompleteProfile(name: "Prepare")

        async let first: Void = coordinator.start(profile: profile)
        await waitUntilCoreBusy(coordinator)
        await #expect(throws: CoreError.alreadyRunning) {
            try await coordinator.start(profile: profile)
        }
        _ = try? await first
        await coordinator.stop()
    }

    @Test
    func stopCancelsPendingStartState() async {
        let coordinator = makeCoreCoordinator(delay: .milliseconds(200))
        let profile = makeCompleteProfile(name: "Stop Pending")
        let task = Task {
            try? await coordinator.start(profile: profile)
        }

        await waitUntilCoreBusy(coordinator)
        await coordinator.stop()
        await task.value

        #expect(await coordinator.currentState() == .stopped)
    }

    @Test
    func backendErrorMovesCoordinatorToFailed() async {
        let coordinator = makeCoreCoordinator(shouldFail: true)

        await #expect(throws: CoreError.startupFailed("Mock backend configured to fail.")) {
            try await coordinator.start(profile: makeCompleteProfile(name: "Failure"))
        }

        #expect(await coordinator.currentState() == .failed)
    }

    @Test
    func stopAfterFailureReturnsStopped() async {
        let coordinator = makeCoreCoordinator(shouldFail: true)
        try? await coordinator.start(profile: makeCompleteProfile(name: "Failure"))

        await coordinator.stop()

        #expect(await coordinator.currentState() == .stopped)
    }

    @Test
    func coreEventStreamEmitsStateOrder() async {
        let coordinator = makeCoreCoordinator(delay: .milliseconds(20))
        let stream = coordinator.events
        let collector = Task<[CoreState], Never> {
            var states: [CoreState] = []
            for await event in stream {
                if case .stateChanged(let state) = event {
                    states.append(state)
                    if state == .running { break }
                }
            }
            return states
        }

        try? await coordinator.start(profile: makeCompleteProfile(name: "Events"))
        let states = await collector.value
        await coordinator.stop()

        #expect(states.contains(.preparing))
        #expect(states.contains(.starting))
        #expect(states.contains(.running))
    }

    @Test
    func mockCoreStatisticsUpdate() async throws {
        let backend = MockCoreBackend(delay: .milliseconds(10))
        let configuration = try VLESSProfileConfigurationCompiler().compile(profile: makeCompleteProfile(name: "Stats"))

        try await backend.prepare(configuration: configuration)
        try await backend.start()
        try? await Task.sleep(for: .milliseconds(180))
        let statistics = await backend.statistics()
        await backend.stop()

        #expect(statistics.bytesReceived > 0)
    }

    @Test
    func coreLoggerMasksCredentials() throws {
        let configuration = try VLESSProfileConfigurationCompiler().compile(profile: makeCompleteProfile(name: "Logs"))
        let message = SanitizedCoreLogger(isDeveloperMode: true).sanitizedMessage(.startupFailed("sample"), configuration: configuration)

        #expect(message.contains("test-reference") == false)
        #expect(message.contains("credential="))
    }

    @Test
    func coreConfigurationCodableDoesNotContainRawSecret() throws {
        var profile = makeCompleteProfile(name: "Codable")
        profile.credentialReference = "keychain://service/account"
        let configuration = try VLESSProfileConfigurationCompiler().compile(profile: profile)
        let data = try JSONEncoder().encode(configuration)
        let json = String(data: data, encoding: .utf8) ?? ""

        #expect(json.contains("sample-password") == false)
    }

    @Test
    func homeDemoModeUsesMockCoreBackendPath() async throws {
        let manager = MockVPNConnectionManager()
        let metrics = try await manager.connect(using: makeCompleteProfile(name: "Demo"))

        #expect(await manager.currentState() == .connected)
        #expect(metrics.latency > 0)
        await manager.disconnect()
    }

    @Test
    @MainActor
    func selectingProfileDoesNotStartCore() {
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            credentialStore: InMemoryCredentialStore()
        )
        let profile = makeCompleteProfile(name: "Select Only")

        viewModel.profiles = [profile]
        viewModel.selectProfile(profile)

        #expect(viewModel.connectionState == .disconnected)
    }

    private enum PrimaryCredentialProtocol {
        case vless
        case vmess
        case trojan
        case shadowsocks
        case tuic

        var supportsSharedRuntime: Bool {
            self != .tuic
        }
    }

    @MainActor
    private func assertPrimaryCredentialRefresh(
        protocolUnderTest: PrimaryCredentialProtocol,
        oldCredential: String,
        currentCredential: String,
        oldURI suppliedOldURI: String? = nil,
        currentURI suppliedCurrentURI: String? = nil
    ) async throws {
        let oldURI = suppliedOldURI ?? subscriptionCredentialURI(
            protocolUnderTest: protocolUnderTest,
            credential: oldCredential
        )
        let currentURI = suppliedCurrentURI ?? subscriptionCredentialURI(
            protocolUnderTest: protocolUnderTest,
            credential: currentCredential
        )
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let oldProfile = try await makeSubscriptionProfile(
            uri: oldURI,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        try await profileRepository.save(oldProfile)
        try await subscriptionRepository.save(subscription)
        let committedOldProfile = try #require(try await profileRepository.profiles().first)
        let oldReference = try #require(committedOldProfile.credentialReference)
        let runtimeStore = RefreshRuntimeProfileStore()
        let runtimeSynchronizer: any RuntimeProfileSynchronizing
        var oldRuntimeRecord: SharedRuntimeProfileRecord?
        if protocolUnderTest.supportsSharedRuntime {
            let synchronizer = RuntimeProfileSynchronizer(
                profileRepository: profileRepository,
                store: runtimeStore,
                credentialStore: credentialStore
            )
            _ = try await synchronizer.profileSaved(committedOldProfile)
            oldRuntimeRecord = try await runtimeStore.read(profileID: committedOldProfile.id)
            runtimeSynchronizer = synchronizer
        } else {
            let synchronizer = ReferenceTrackingRuntimeProfileSynchronizer()
            _ = try await synchronizer.profileSaved(committedOldProfile)
            runtimeSynchronizer = synchronizer
        }
        let viewModel = makeCredentialRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: runtimeSynchronizer,
            refreshedURI: currentURI
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)

        let change = try #require(viewModel.subscriptionUpdatePlan?.changes.first)
        let preparedProfile = try #require(change.incomingProfile)
        let preparedReference = try #require(preparedProfile.credentialReference)
        if case .tuic = protocolUnderTest {
            #expect(change.kind == .invalid)
            #expect(change.isSelected == false)
            #expect(preparedProfile.runtimeCapability == .unsupported(.unsupportedProtocol(.tuic)))
            #expect(preparedReference != oldReference)

            await viewModel.applySubscriptionUpdate()

            let persistedProfile = try #require(try await profileRepository.profiles().first)
            let runtimeReferences = try await runtimeSynchronizer.credentialReferences()
            let deletedReferences = await credentialStore.deletedReferences
            #expect(viewModel.subscriptionRefreshState == .completed)
            #expect(persistedProfile.id == committedOldProfile.id)
            #expect(persistedProfile.credentialReference == oldReference)
            #expect(try await credentialStore.secret(for: oldReference) == oldCredential)
            #expect(try await credentialStore.secret(for: preparedReference) == nil)
            #expect(deletedReferences.contains(preparedReference))
            #expect(deletedReferences.contains(oldReference) == false)
            #expect(runtimeReferences.contains(oldReference))
            #expect(await credentialStore.activeReferenceCount == 2)
            return
        }
        #expect(change.kind == .updated)
        #expect(preparedProfile.protocolType == committedOldProfile.protocolType)
        #expect(preparedReference != oldReference)

        await viewModel.applySubscriptionUpdate()

        let persistedProfile = try #require(try await profileRepository.profiles().first)
        let currentReference = try #require(persistedProfile.credentialReference)
        let runtimeReferences = try await runtimeSynchronizer.credentialReferences()
        let deletedReferences = await credentialStore.deletedReferences
        #expect(viewModel.subscriptionRefreshState == .completed)
        #expect(persistedProfile.id == committedOldProfile.id)
        #expect(currentReference == preparedReference)
        #expect(try await credentialStore.secret(for: currentReference) == currentCredential)
        #expect(try await credentialStore.secret(for: oldReference) == nil)
        #expect(deletedReferences.contains(oldReference))
        #expect(runtimeReferences.contains(currentReference))
        #expect(runtimeReferences.contains(oldReference) == false)
        #expect(await credentialStore.activeReferenceCount == 2)

        guard protocolUnderTest.supportsSharedRuntime else { return }

        let previousRuntimeRecord = try #require(oldRuntimeRecord)
        let runtimeRecord = try await runtimeStore.read(profileID: persistedProfile.id)
        #expect(runtimeRecord.credentialReference == currentReference)
        #expect(runtimeRecord.recordRevision != previousRuntimeRecord.recordRevision)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: runtimeRecord.profileID,
            sharedRecordRevision: runtimeRecord.recordRevision
        )
        let resolved = try await RuntimeConfigurationLoader(
            store: runtimeStore,
            credentialResolver: CredentialStoreRuntimeCredentialResolver(credentialStore: credentialStore)
        ).load(providerConfiguration: providerConfiguration.propertyList)
        let json = try XrayConfigurationBuilder()
            .build(from: resolved, options: XrayBuildOptions())
            .withJSONString { $0 }
        #expect(try primaryCredential(fromXrayJSON: json, protocolUnderTest: protocolUnderTest) == currentCredential)
    }

    @MainActor
    private func assertIdenticalPrimaryCredentialRefresh(
        protocolUnderTest: PrimaryCredentialProtocol,
        credential: String,
        oldURI suppliedOldURI: String? = nil,
        currentURI suppliedCurrentURI: String? = nil
    ) async throws {
        let oldURI = suppliedOldURI ?? subscriptionCredentialURI(
            protocolUnderTest: protocolUnderTest,
            credential: credential
        )
        let currentURI = suppliedCurrentURI ?? oldURI
        let credentialStore = RecordingCredentialStore()
        let profileRepository = InMemoryVPNProfileRepository()
        let subscriptionRepository = InMemorySubscriptionRepository()
        let subscriptionReference = try await credentialStore.store(
            "https://subscription.example.invalid/list",
            label: "Subscription URL"
        )
        var subscription = makeSubscription()
        subscription.credentialReference = subscriptionReference
        let profile = try await makeSubscriptionProfile(
            uri: oldURI,
            subscriptionID: subscription.id,
            credentialStore: credentialStore
        )
        try await profileRepository.save(profile)
        try await subscriptionRepository.save(subscription)
        let committedProfile = try #require(try await profileRepository.profiles().first)
        let committedReference = try #require(committedProfile.credentialReference)
        let activeReferenceCountBeforeRefresh = await credentialStore.activeReferenceCount
        let runtimeStore = RefreshRuntimeProfileStore()
        let runtimeSynchronizer: any RuntimeProfileSynchronizing
        var committedRuntimeRecord: SharedRuntimeProfileRecord?
        if protocolUnderTest.supportsSharedRuntime {
            let synchronizer = RuntimeProfileSynchronizer(
                profileRepository: profileRepository,
                store: runtimeStore,
                credentialStore: credentialStore
            )
            _ = try await synchronizer.profileSaved(committedProfile)
            committedRuntimeRecord = try await runtimeStore.read(profileID: committedProfile.id)
            runtimeSynchronizer = synchronizer
        } else {
            let synchronizer = ReferenceTrackingRuntimeProfileSynchronizer()
            _ = try await synchronizer.profileSaved(committedProfile)
            runtimeSynchronizer = synchronizer
        }
        let viewModel = makeCredentialRefreshViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            credentialStore: credentialStore,
            runtimeSynchronizer: runtimeSynchronizer,
            refreshedURI: currentURI
        )

        await viewModel.loadInitialData()
        await viewModel.refreshSubscription(subscription)

        let change = try #require(viewModel.subscriptionUpdatePlan?.changes.first)
        if case .tuic = protocolUnderTest {
            #expect(change.kind == .invalid)
            #expect(change.isSelected == false)
            #expect(change.incomingProfile?.runtimeCapability == .unsupported(.unsupportedProtocol(.tuic)))
            #expect(change.incomingProfile?.credentialReference == committedReference)
            #expect(await credentialStore.activeReferenceCount == activeReferenceCountBeforeRefresh)

            await viewModel.applySubscriptionUpdate()

            let persistedProfile = try #require(try await profileRepository.profiles().first)
            let runtimeReferences = try await runtimeSynchronizer.credentialReferences()
            let deletedReferences = await credentialStore.deletedReferences
            #expect(viewModel.subscriptionRefreshState == .completed)
            #expect(persistedProfile.credentialReference == committedReference)
            #expect(persistedProfile.updatedAt == committedProfile.updatedAt)
            #expect(try await credentialStore.secret(for: committedReference) == credential)
            #expect(deletedReferences.contains(committedReference) == false)
            #expect(runtimeReferences.contains(committedReference))
            #expect(await credentialStore.activeReferenceCount == activeReferenceCountBeforeRefresh)
            return
        }
        #expect(change.kind == .unchanged)
        #expect(change.incomingProfile?.credentialReference == committedReference)
        #expect(await credentialStore.activeReferenceCount == activeReferenceCountBeforeRefresh)

        await viewModel.applySubscriptionUpdate()

        let persistedProfile = try #require(try await profileRepository.profiles().first)
        let runtimeReferences = try await runtimeSynchronizer.credentialReferences()
        let deletedReferences = await credentialStore.deletedReferences
        #expect(viewModel.subscriptionRefreshState == .completed)
        #expect(persistedProfile.credentialReference == committedReference)
        #expect(persistedProfile.updatedAt == committedProfile.updatedAt)
        #expect(try await credentialStore.secret(for: committedReference) == credential)
        #expect(deletedReferences.contains(committedReference) == false)
        #expect(runtimeReferences.contains(committedReference))
        #expect(await credentialStore.activeReferenceCount == activeReferenceCountBeforeRefresh)

        guard protocolUnderTest.supportsSharedRuntime else { return }

        let originalRuntimeRecord = try #require(committedRuntimeRecord)
        let persistedRuntimeRecord = try await runtimeStore.read(profileID: persistedProfile.id)
        #expect(persistedRuntimeRecord.recordRevision == originalRuntimeRecord.recordRevision)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: persistedRuntimeRecord.profileID,
            sharedRecordRevision: persistedRuntimeRecord.recordRevision
        )
        let resolved = try await RuntimeConfigurationLoader(
            store: runtimeStore,
            credentialResolver: CredentialStoreRuntimeCredentialResolver(credentialStore: credentialStore)
        ).load(providerConfiguration: providerConfiguration.propertyList)
        let json = try XrayConfigurationBuilder()
            .build(from: resolved, options: XrayBuildOptions())
            .withJSONString { $0 }
        #expect(try primaryCredential(fromXrayJSON: json, protocolUnderTest: protocolUnderTest) == credential)
    }

    private func makeSubscriptionProfile(
        uri: String,
        subscriptionID: UUID,
        credentialStore: any CredentialStoring
    ) async throws -> VPNProfile {
        let result = try await VPNLinkParser(credentialStore: credentialStore).parse(uri)
        let profile = try importedProfile(from: result)
        return DefaultSubscriptionMerger().makeSubscriptionProfile(
            profile,
            subscriptionID: subscriptionID,
            now: Date(timeIntervalSince1970: 1_800_000_000)
        )
    }

    @MainActor
    private func makeCredentialRefreshViewModel(
        profileRepository: any VPNProfileRepository,
        subscriptionRepository: any SubscriptionRepository,
        credentialStore: RecordingCredentialStore,
        runtimeSynchronizer: (any RuntimeProfileSynchronizing)?,
        refreshedURI: String
    ) -> VPNDashboardViewModel {
        VPNDashboardViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            subscriptionUpdater: URLSessionSubscriptionUpdater(
                client: StubSubscriptionClient(result: .success(Data(refreshedURI.utf8))),
                credentialStore: credentialStore
            ),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore(),
            runtimeProfileSynchronizer: runtimeSynchronizer
        )
    }

    private func subscriptionCredentialURI(
        protocolUnderTest: PrimaryCredentialProtocol,
        credential: String
    ) -> String {
        switch protocolUnderTest {
        case .vless:
            return "vless://\(credential)@refresh-vless.example.invalid:443?type=tcp&security=tls&sni=refresh-vless.example.invalid&encryption=none#Credential%20Refresh"
        case .vmess:
            let payload = """
            {"ps":"Credential Refresh","add":"refresh-vmess.example.invalid","port":"443","id":"\(credential)","aid":"0","scy":"auto","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"refresh-vmess.example.invalid"}
            """
            return "vmess://\(Data(payload.utf8).base64EncodedString())"
        case .trojan:
            return "trojan://\(credential)@refresh-trojan.example.invalid:443?type=tcp&security=tls&sni=refresh-trojan.example.invalid#Credential%20Refresh"
        case .shadowsocks:
            let user = Data("aes-256-gcm:\(credential)".utf8).base64EncodedString()
            return "ss://\(user)@refresh-shadowsocks.example.invalid:8388#Credential%20Refresh"
        case .tuic:
            return "tuic://\(credential)@refresh-tuic.example.invalid:443?congestion=bbr&udpRelayMode=native#Credential%20Refresh"
        }
    }

    private func tuicQueryCredentialURI(queryName: String, credential: String) -> String {
        "tuic://refresh-tuic.example.invalid:443?\(queryName)=\(credential)&congestion=bbr&udpRelayMode=native#Credential%20Refresh"
    }

    private func primaryCredential(
        fromXrayJSON json: String,
        protocolUnderTest: PrimaryCredentialProtocol
    ) throws -> String {
        let object = try #require(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        let outbounds = try #require(object["outbounds"] as? [[String: Any]])
        let outbound = try #require(outbounds.first)
        let settings = try #require(outbound["settings"] as? [String: Any])

        switch protocolUnderTest {
        case .vless, .vmess:
            let servers = try #require(settings["vnext"] as? [[String: Any]])
            let server = try #require(servers.first)
            let users = try #require(server["users"] as? [[String: Any]])
            return try #require(users.first?["id"] as? String)
        case .trojan, .shadowsocks:
            let servers = try #require(settings["servers"] as? [[String: Any]])
            return try #require(servers.first?["password"] as? String)
        case .tuic:
            throw TestError.expectedProfile
        }
    }

    private func makeProfile(for slot: VPNProfileCredentialSlot, reference: String) -> VPNProfile {
        switch slot {
        case .primary:
            return VPNProfile.draft(
                name: "Primary",
                protocolType: .vless,
                serverAddress: "primary.example.invalid",
                port: 443,
                credentialReference: reference,
                protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
                source: .importedURL
            )
        case .tlsPublicKey:
            return VPNProfile.draft(
                name: "Legacy Reality Public Key",
                protocolType: .vless,
                serverAddress: "reality.example.invalid",
                port: 443,
                credentialReference: "keychain://test.credentials/primary",
                transportSettings: VPNTransportSettings(network: "tcp", security: "reality"),
                tlsSettings: VPNTLSSettings(
                    isEnabled: true,
                    serverName: "reality.example.invalid",
                    publicKeyReference: reference,
                    shortID: "abcd"
                ),
                protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
                source: .importedURL
            )
        case .wireGuardPeerPublicKey, .wireGuardPresharedKey:
            return VPNProfile.draft(
                name: "WireGuard",
                protocolType: .wireGuard,
                serverAddress: "wireguard.example.invalid",
                port: 51820,
                credentialReference: "keychain://test.credentials/wireguard-private-key",
                protocolConfiguration: .wireGuard(WireGuardProfileConfiguration(
                    peerPublicKeyReference: slot == .wireGuardPeerPublicKey
                        ? reference
                        : "keychain://test.credentials/wireguard-peer-public-key",
                    presharedKeyReference: slot == .wireGuardPresharedKey
                        ? reference
                        : "keychain://test.credentials/wireguard-preshared-key",
                    allowedIPs: ["0.0.0.0/0"]
                )),
                source: .importedURL
            )
        case .hysteria2ObfsPassword:
            return VPNProfile.draft(
                name: "Hysteria 2",
                protocolType: .hysteria2,
                serverAddress: "hysteria.example.invalid",
                port: 443,
                credentialReference: "keychain://test.credentials/hysteria-auth",
                transportSettings: VPNTransportSettings(network: "udp", security: "tls"),
                tlsSettings: VPNTLSSettings(isEnabled: true, serverName: "hysteria.example.invalid"),
                protocolConfiguration: .hysteria2(Hysteria2ProfileConfiguration(
                    obfs: "salamander",
                    bandwidthHint: nil,
                    obfsPasswordReference: reference
                )),
                source: .importedURL
            )
        }
    }

    private func makeHysteriaSubscriptionProfile(
        auth: String,
        obfsPassword: String = "test-static-obfs",
        subscriptionID: UUID,
        credentialStore: any CredentialStoring
    ) async throws -> VPNProfile {
        let result = try await Hysteria2LinkParser(credentialStore: credentialStore)
            .parse(hysteriaSubscriptionURI(auth: auth, obfsPassword: obfsPassword))
        let profile = try importedProfile(from: result)
        return DefaultSubscriptionMerger().makeSubscriptionProfile(
            profile,
            subscriptionID: subscriptionID,
            now: Date(timeIntervalSince1970: 1_800_000_000)
        )
    }

    @MainActor
    private func makeSubscriptionRefreshViewModel(
        profileRepository: any VPNProfileRepository,
        subscriptionRepository: any SubscriptionRepository,
        credentialStore: RecordingCredentialStore,
        runtimeSynchronizer: (any RuntimeProfileSynchronizing)?,
        refreshedAuth: String,
        refreshedObfsPassword: String = "test-static-obfs"
    ) -> VPNDashboardViewModel {
        VPNDashboardViewModel(
            profileRepository: profileRepository,
            subscriptionRepository: subscriptionRepository,
            subscriptionUpdater: URLSessionSubscriptionUpdater(
                client: StubSubscriptionClient(
                    result: .success(Data(hysteriaSubscriptionURI(
                        auth: refreshedAuth,
                        obfsPassword: refreshedObfsPassword
                    ).utf8))
                ),
                credentialStore: credentialStore
            ),
            credentialStore: credentialStore,
            activeProfileStore: InMemoryActiveProfileStore(),
            runtimeProfileSynchronizer: runtimeSynchronizer
        )
    }

    private func hysteriaSubscriptionURI(
        auth: String,
        obfsPassword: String = "test-static-obfs"
    ) -> String {
        "hy2://\(auth)@refresh-hy2.example.invalid:443?sni=refresh-hy2.example.invalid&obfs=salamander&obfs-password=\(obfsPassword)#Credential%20Refresh"
    }

    private func hysteriaAuth(fromXrayJSON json: String) throws -> String {
        let object = try #require(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        let outbounds = try #require(object["outbounds"] as? [[String: Any]])
        let outbound = try #require(outbounds.first)
        let streamSettings = try #require(outbound["streamSettings"] as? [String: Any])
        let hysteriaSettings = try #require(streamSettings["hysteriaSettings"] as? [String: Any])
        return try #require(hysteriaSettings["auth"] as? String)
    }

    private func hysteriaObfsPasswordReference(from profile: VPNProfile) throws -> String {
        guard case .hysteria2(let configuration) = profile.protocolConfiguration else {
            throw TestError.expectedProfile
        }
        return try #require(configuration.obfsPasswordReference)
    }

    private func hysteriaObfsPassword(fromXrayJSON json: String) throws -> String {
        let object = try #require(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
        let outbounds = try #require(object["outbounds"] as? [[String: Any]])
        let outbound = try #require(outbounds.first)
        let streamSettings = try #require(outbound["streamSettings"] as? [String: Any])
        let finalMask = try #require(streamSettings["finalmask"] as? [String: Any])
        let udpLayers = try #require(finalMask["udp"] as? [[String: Any]])
        let layer = try #require(udpLayers.first)
        let settings = try #require(layer["settings"] as? [String: Any])
        return try #require(settings["password"] as? String)
    }

    @MainActor
    private func xrayJSON(
        record: SharedRuntimeProfileRecord,
        credentialStore: any CredentialStoring
    ) async throws -> String {
        let runtimeStore = RefreshRuntimeProfileStore()
        try await runtimeStore.write(record)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: record.profileID,
            sharedRecordRevision: record.recordRevision
        )
        let resolved = try await RuntimeConfigurationLoader(
            store: runtimeStore,
            credentialResolver: CredentialStoreRuntimeCredentialResolver(credentialStore: credentialStore)
        ).load(providerConfiguration: providerConfiguration.propertyList)
        return try XrayConfigurationBuilder()
            .build(from: resolved, options: XrayBuildOptions())
            .withJSONString { $0 }
    }

    private func xrayJSON(_ json: String, containsSemanticMarker marker: String) throws -> Bool {
        let object = try JSONSerialization.jsonObject(with: Data(json.utf8))
        return jsonValue(object, containsSemanticMarker: marker)
    }

    private func jsonValue(_ value: Any, containsSemanticMarker marker: String) -> Bool {
        if let dictionary = value as? [String: Any] {
            return dictionary.contains { key, nestedValue in
                key.contains(marker) || jsonValue(nestedValue, containsSemanticMarker: marker)
            }
        }
        if let array = value as? [Any] {
            return array.contains { jsonValue($0, containsSemanticMarker: marker) }
        }
        if let string = value as? String {
            return string.contains(marker)
        }
        if let number = value as? NSNumber {
            return number.stringValue.contains(marker)
        }
        return false
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
            credentialReference: "keychain://test.credentials/test-reference",
            transportSettings: VPNTransportSettings(network: "tcp", security: "tls"),
            tlsSettings: VPNTLSSettings(isEnabled: true, serverName: "profile.example.com"),
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
            transportSettings: VPNTransportSettings(network: "tcp", security: "tls"),
            tlsSettings: VPNTLSSettings(isEnabled: true, serverName: "manual.example.invalid"),
            protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
            source: .manual
        )
    }

    private func temporaryProfilesURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("VPNTests-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("profiles.json")
    }

    private func temporarySubscriptionsURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("VPNTests-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("subscriptions.json")
    }

    private func makeSubscription() -> VPNSubscription {
        VPNSubscription(
            name: "Provider",
            sanitizedHost: "subscription.example.invalid",
            sanitizedURLDisplay: "https://subscription.example.invalid/list",
            credentialReference: "test-subscription-url"
        )
    }

    private func makeSubscriptionProfile(name: String, host: String, subscriptionID: UUID) -> VPNProfile {
        let merger = DefaultSubscriptionMerger()
        let profile = VPNProfile.draft(
            name: name,
            protocolType: .vless,
            serverAddress: host,
            port: 443,
            credentialReference: "keychain://test.credentials/test-reference",
            transportSettings: VPNTransportSettings(network: "tcp", security: "tls"),
            tlsSettings: VPNTLSSettings(isEnabled: true, serverName: host),
            protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
            source: .subscription
        )
        return merger.makeSubscriptionProfile(profile, subscriptionID: subscriptionID, now: Date())
    }

    /// Deterministically awaits until the coordinator has left idle (reached
    /// preparing/starting/running) via its event stream — replaces fixed
    /// `Task.sleep` interleaving in concurrency tests.
    private func waitUntilCoreBusy(_ coordinator: VPNCoreCoordinator) async {
        // Poll the actor's authoritative state directly (no fixed sleep, no
        // event-stream registration race): yield until it leaves idle.
        while await coordinator.currentState() == .idle {
            await Task.yield()
        }
    }

    private func makeCoreCoordinator(shouldFail: Bool = false, delay: Duration = .milliseconds(20)) -> VPNCoreCoordinator {
        VPNCoreCoordinator(
            compiler: CompositeProfileConfigurationCompiler(),
            registry: VPNCoreBackendRegistry(factories: [
                MockCoreBackendFactory(shouldFail: shouldFail, delay: delay)
            ]),
            credentialResolver: NonSecretReferenceCredentialResolver()
        )
    }

    private func localizableStrings() throws -> [String: Any] {
        let testsURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let projectURL = testsURL.deletingLastPathComponent()
        let catalogURL = projectURL.appendingPathComponent("VPN/Resources/Localizable.xcstrings")
        let data = try Data(contentsOf: catalogURL)
        let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        return try #require(object?["strings"] as? [String: Any])
    }

    private func makeQRImageImportCoordinator(detector: QRCodeImageDetecting) -> QRImageImportCoordinator {
        QRImageImportCoordinator(processor: QRCodeImageImportProcessor(
            detector: detector,
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        ))
    }

    private func singleProfileName(from route: ImportPayloadRoute?) -> String? {
        guard case .single(let result)? = route,
              case .profile(let profile) = result.kind else {
            return nil
        }

        return profile.name
    }
}

private nonisolated struct ProviderManagedProfileSnapshot: Equatable {
    let protocolType: VPNProtocol
    let serverAddress: String
    let port: Int?
    let username: String?
    let transportSettings: VPNTransportSettings
    let tlsSettings: VPNTLSSettings
    let protocolConfiguration: VPNProtocolConfiguration
    let metadata: [String: String]

    init(_ profile: VPNProfile) {
        protocolType = profile.protocolType
        serverAddress = profile.serverAddress
        port = profile.port
        username = profile.username
        transportSettings = profile.transportSettings
        tlsSettings = profile.tlsSettings
        protocolConfiguration = profile.protocolConfiguration
        metadata = profile.metadata
    }
}

nonisolated enum ProviderFieldRuntimeExpectation: Sendable {
    case builderSupported(marker: String?)
    case builderRejected
    case mapperRejected
    case runtimeUnsupported
}

nonisolated struct ProviderManagedNonSecretRefreshCase: Sendable, CustomTestStringConvertible {
    let name: String
    let oldURI: String
    let currentURI: String
    let runtimeExpectation: ProviderFieldRuntimeExpectation

    var testDescription: String { name }

    static var cases: [ProviderManagedNonSecretRefreshCase] {
        vlessCases + trojanCases + vmessCases + shadowsocksCases + hysteria2Cases + tuicCases
    }

    private static var vlessCases: [ProviderManagedNonSecretRefreshCase] {
        let user = "11111111-1111-4111-8111-111111111111"
        let host = "vless-field.example.invalid"
        let tlsQuery = [
            "type": "tcp",
            "security": "tls",
            "sni": "vless-cover.example.invalid",
            "encryption": "none"
        ]
        let xhttpQuery = [
            "type": "xhttp",
            "security": "tls",
            "sni": "vless-cover.example.invalid",
            "encryption": "none",
            "path": "/old-path",
            "host": "old-cdn.example.invalid",
            "mode": "auto"
        ]
        let realityQuery = [
            "type": "tcp",
            "security": "reality",
            "sni": "vless-cover.example.invalid",
            "encryption": "none",
            "fp": "chrome",
            "pbk": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sid": "abcd",
            "spx": "/old-spider"
        ]

        return [
            endpointCase(
                name: "VLESS server",
                scheme: "vless",
                user: user,
                oldHost: host,
                currentHost: "current-vless.example.invalid",
                oldPort: 443,
                currentPort: 443,
                query: tlsQuery,
                runtime: .builderSupported(marker: "current-vless.example.invalid")
            ),
            endpointCase(
                name: "VLESS port",
                scheme: "vless",
                user: user,
                oldHost: host,
                currentHost: host,
                oldPort: 443,
                currentPort: 8443,
                query: tlsQuery,
                runtime: .builderSupported(marker: "8443")
            ),
            queryCase(
                name: "VLESS transport type",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: xhttpQuery,
                key: "type",
                oldValue: "tcp",
                currentValue: "xhttp",
                runtime: .builderSupported(marker: "xhttp")
            ),
            queryCase(
                name: "VLESS transport path",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: xhttpQuery,
                key: "path",
                oldValue: "/old-path",
                currentValue: "/current-path",
                runtime: .builderSupported(marker: "/current-path")
            ),
            queryCase(
                name: "VLESS transport host",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: xhttpQuery,
                key: "host",
                oldValue: "old-cdn.example.invalid",
                currentValue: "current-cdn.example.invalid",
                runtime: .builderSupported(marker: "current-cdn.example.invalid")
            ),
            queryCase(
                name: "VLESS gRPC service name",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery.merging(["type": "grpc", "serviceName": "old-service"]) { _, current in current },
                key: "serviceName",
                oldValue: "old-service",
                currentValue: "current-service",
                runtime: .builderSupported(marker: "current-service")
            ),
            queryCase(
                name: "VLESS XHTTP mode",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: xhttpQuery,
                key: "mode",
                oldValue: "auto",
                currentValue: "stream-one",
                runtime: .builderSupported(marker: "stream-one")
            ),
            queryCase(
                name: "VLESS security mode",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "security",
                oldValue: "tls",
                currentValue: "none",
                runtime: .builderRejected
            ),
            queryCase(
                name: "VLESS TLS SNI",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "sni",
                oldValue: "old-cover.example.invalid",
                currentValue: "current-cover.example.invalid",
                runtime: .builderSupported(marker: "current-cover.example.invalid")
            ),
            queryCase(
                name: "VLESS allow insecure",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "allowInsecure",
                oldValue: "0",
                currentValue: "1",
                runtime: .builderRejected
            ),
            queryCase(
                name: "VLESS TLS fingerprint",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "fp",
                oldValue: "chrome",
                currentValue: "firefox",
                runtime: .builderSupported(marker: "firefox")
            ),
            queryCase(
                name: "VLESS Reality public key",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: realityQuery,
                key: "pbk",
                oldValue: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                currentValue: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                runtime: .builderSupported(marker: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
            ),
            queryCase(
                name: "VLESS Reality short ID",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: realityQuery,
                key: "sid",
                oldValue: "abcd",
                currentValue: "ef01",
                runtime: .builderSupported(marker: "ef01")
            ),
            queryCase(
                name: "VLESS Reality spider X",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: realityQuery,
                key: "spx",
                oldValue: "/old-spider",
                currentValue: "/current-spider",
                runtime: .builderSupported(marker: "/current-spider")
            ),
            queryCase(
                name: "VLESS flow",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "flow",
                oldValue: nil,
                currentValue: "xtls-rprx-vision",
                runtime: .builderSupported(marker: "xtls-rprx-vision")
            ),
            queryCase(
                name: "VLESS encryption",
                scheme: "vless",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "encryption",
                oldValue: "none",
                currentValue: "zero",
                runtime: .builderRejected
            )
        ]
    }

    private static var trojanCases: [ProviderManagedNonSecretRefreshCase] {
        let user = "test-trojan-password"
        let host = "trojan-field.example.invalid"
        let tlsQuery = [
            "type": "tcp",
            "security": "tls",
            "sni": "trojan-cover.example.invalid"
        ]
        let websocketQuery = [
            "type": "ws",
            "security": "tls",
            "sni": "trojan-cover.example.invalid",
            "path": "/old-path",
            "host": "old-cdn.example.invalid"
        ]
        let xhttpQuery = [
            "type": "xhttp",
            "security": "tls",
            "sni": "trojan-cover.example.invalid",
            "path": "/xhttp",
            "host": "cdn.example.invalid",
            "mode": "auto"
        ]
        let realityQuery = [
            "type": "tcp",
            "security": "reality",
            "sni": "trojan-cover.example.invalid",
            "fp": "chrome",
            "pbk": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sid": "abcd",
            "spx": "/old-spider"
        ]

        return [
            endpointCase(
                name: "Trojan server",
                scheme: "trojan",
                user: user,
                oldHost: host,
                currentHost: "current-trojan.example.invalid",
                oldPort: 443,
                currentPort: 443,
                query: tlsQuery,
                runtime: .builderSupported(marker: "current-trojan.example.invalid")
            ),
            endpointCase(
                name: "Trojan port",
                scheme: "trojan",
                user: user,
                oldHost: host,
                currentHost: host,
                oldPort: 443,
                currentPort: 8443,
                query: tlsQuery,
                runtime: .builderSupported(marker: "8443")
            ),
            queryCase(
                name: "Trojan transport type",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery.merging(["serviceName": "stable-service"]) { _, current in current },
                key: "type",
                oldValue: "tcp",
                currentValue: "grpc",
                runtime: .builderSupported(marker: "stable-service")
            ),
            queryCase(
                name: "Trojan transport path",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: websocketQuery,
                key: "path",
                oldValue: "/old-path",
                currentValue: "/current-path",
                runtime: .builderSupported(marker: "/current-path")
            ),
            queryCase(
                name: "Trojan transport host",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: websocketQuery,
                key: "host",
                oldValue: "old-cdn.example.invalid",
                currentValue: "current-cdn.example.invalid",
                runtime: .builderSupported(marker: "current-cdn.example.invalid")
            ),
            queryCase(
                name: "Trojan gRPC service name",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery.merging(["type": "grpc", "serviceName": "old-service"]) { _, current in current },
                key: "serviceName",
                oldValue: "old-service",
                currentValue: "current-service",
                runtime: .builderSupported(marker: "current-service")
            ),
            queryCase(
                name: "Trojan XHTTP mode",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: xhttpQuery,
                key: "mode",
                oldValue: "auto",
                currentValue: "stream-one",
                runtime: .builderSupported(marker: "stream-one")
            ),
            queryCase(
                name: "Trojan security mode",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "security",
                oldValue: "tls",
                currentValue: "reality",
                runtime: .mapperRejected
            ),
            queryCase(
                name: "Trojan TLS SNI",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "sni",
                oldValue: "old-cover.example.invalid",
                currentValue: "current-cover.example.invalid",
                runtime: .builderSupported(marker: "current-cover.example.invalid")
            ),
            queryCase(
                name: "Trojan allow insecure",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "allowInsecure",
                oldValue: "0",
                currentValue: "1",
                runtime: .builderSupported(marker: "allowInsecure")
            ),
            queryCase(
                name: "Trojan TLS fingerprint",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "fp",
                oldValue: "chrome",
                currentValue: "firefox",
                runtime: .builderSupported(marker: "firefox")
            ),
            queryCase(
                name: "Trojan Reality public key",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: realityQuery,
                key: "pbk",
                oldValue: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                currentValue: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                runtime: .builderSupported(marker: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
            ),
            queryCase(
                name: "Trojan Reality short ID",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: realityQuery,
                key: "sid",
                oldValue: "abcd",
                currentValue: "ef01",
                runtime: .builderSupported(marker: "ef01")
            ),
            queryCase(
                name: "Trojan Reality spider X",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: realityQuery,
                key: "spx",
                oldValue: "/old-spider",
                currentValue: "/current-spider",
                runtime: .builderSupported(marker: "/current-spider")
            ),
            queryCase(
                name: "Trojan ALPN",
                scheme: "trojan",
                user: user,
                host: host,
                port: 443,
                baseQuery: tlsQuery,
                key: "alpn",
                oldValue: "h2",
                currentValue: "h2,http/1.1",
                runtime: .builderSupported(marker: "http/1.1")
            )
        ]
    }

    private static var vmessCases: [ProviderManagedNonSecretRefreshCase] {
        let base = [
            "ps": "VMess Field",
            "add": "vmess-field.example.invalid",
            "port": "443",
            "id": "11111111-1111-4111-8111-111111111111",
            "aid": "0",
            "scy": "auto",
            "net": "tcp",
            "type": "none",
            "host": "",
            "path": "",
            "tls": "tls",
            "sni": "vmess-cover.example.invalid"
        ]

        return [
            vmessCase(name: "VMess server", base: base, key: "add", oldValue: "vmess-field.example.invalid", currentValue: "current-vmess.example.invalid", runtime: .builderSupported(marker: "current-vmess.example.invalid")),
            vmessCase(name: "VMess port", base: base, key: "port", oldValue: "443", currentValue: "8443", runtime: .builderSupported(marker: "8443")),
            vmessCase(
                name: "VMess transport type",
                base: base.merging(["path": "/ws", "host": "cdn.example.invalid"]) { _, current in current },
                key: "net",
                oldValue: "tcp",
                currentValue: "ws",
                runtime: .builderSupported(marker: "ws")
            ),
            vmessCase(
                name: "VMess transport path",
                base: base.merging(["net": "ws", "path": "/old-path", "host": "cdn.example.invalid"]) { _, current in current },
                key: "path",
                oldValue: "/old-path",
                currentValue: "/current-path",
                runtime: .builderSupported(marker: "/current-path")
            ),
            vmessCase(
                name: "VMess transport host",
                base: base.merging(["net": "ws", "path": "/ws", "host": "old-cdn.example.invalid"]) { _, current in current },
                key: "host",
                oldValue: "old-cdn.example.invalid",
                currentValue: "current-cdn.example.invalid",
                runtime: .builderSupported(marker: "current-cdn.example.invalid")
            ),
            vmessCase(
                name: "VMess gRPC service path",
                base: base.merging(["net": "grpc", "path": "old-service"]) { _, current in current },
                key: "path",
                oldValue: "old-service",
                currentValue: "current-service",
                runtime: .builderSupported(marker: "current-service")
            ),
            vmessCase(
                name: "VMess TLS mode",
                base: base,
                key: "tls",
                oldValue: "",
                currentValue: "tls",
                runtime: .builderSupported(marker: "tls")
            ),
            vmessCase(name: "VMess TLS SNI", base: base, key: "sni", oldValue: "old-cover.example.invalid", currentValue: "current-cover.example.invalid", runtime: .builderSupported(marker: "current-cover.example.invalid")),
            vmessCase(name: "VMess alter ID", base: base, key: "aid", oldValue: "0", currentValue: "1", runtime: .builderSupported(marker: "alterId")),
            vmessCase(name: "VMess cipher", base: base, key: "scy", oldValue: "auto", currentValue: "aes-128-gcm", runtime: .builderSupported(marker: "aes-128-gcm"))
        ]
    }

    private static var shadowsocksCases: [ProviderManagedNonSecretRefreshCase] {
        let password = "test-shadowsocks-password"
        let host = "shadowsocks-field.example.invalid"
        return [
            ProviderManagedNonSecretRefreshCase(
                name: "Shadowsocks server",
                oldURI: shadowsocksURI(method: "aes-256-gcm", password: password, host: host, port: 8388),
                currentURI: shadowsocksURI(method: "aes-256-gcm", password: password, host: "current-shadowsocks.example.invalid", port: 8388),
                runtimeExpectation: .builderSupported(marker: "current-shadowsocks.example.invalid")
            ),
            ProviderManagedNonSecretRefreshCase(
                name: "Shadowsocks port",
                oldURI: shadowsocksURI(method: "aes-256-gcm", password: password, host: host, port: 8388),
                currentURI: shadowsocksURI(method: "aes-256-gcm", password: password, host: host, port: 8389),
                runtimeExpectation: .builderSupported(marker: "8389")
            ),
            ProviderManagedNonSecretRefreshCase(
                name: "Shadowsocks method",
                oldURI: shadowsocksURI(method: "aes-128-gcm", password: password, host: host, port: 8388),
                currentURI: shadowsocksURI(method: "chacha20-ietf-poly1305", password: password, host: host, port: 8388),
                runtimeExpectation: .builderSupported(marker: "chacha20-ietf-poly1305")
            ),
            ProviderManagedNonSecretRefreshCase(
                name: "Shadowsocks plugin and options",
                oldURI: shadowsocksURI(method: "aes-256-gcm", password: password, host: host, port: 8388),
                currentURI: shadowsocksURI(
                    method: "aes-256-gcm",
                    password: password,
                    host: host,
                    port: 8388,
                    query: ["plugin": "v2ray-plugin;tls;host=current-plugin.example.invalid"]
                ),
                runtimeExpectation: .mapperRejected
            ),
            ProviderManagedNonSecretRefreshCase(
                name: "Shadowsocks Outline marker",
                oldURI: shadowsocksURI(method: "aes-256-gcm", password: password, host: host, port: 8388, query: ["outline": "0"]),
                currentURI: shadowsocksURI(method: "aes-256-gcm", password: password, host: host, port: 8388, query: ["outline": "1"]),
                runtimeExpectation: .builderSupported(marker: nil)
            )
        ]
    }

    private static var hysteria2Cases: [ProviderManagedNonSecretRefreshCase] {
        let user = "test-hysteria-auth"
        let host = "hysteria-field.example.invalid"
        let base = ["sni": "hysteria-cover.example.invalid"]
        return [
            endpointCase(name: "Hysteria2 server", scheme: "hy2", user: user, oldHost: host, currentHost: "current-hysteria.example.invalid", oldPort: 443, currentPort: 443, query: base, runtime: .builderSupported(marker: "current-hysteria.example.invalid")),
            endpointCase(name: "Hysteria2 port", scheme: "hy2", user: user, oldHost: host, currentHost: host, oldPort: 443, currentPort: 8443, query: base, runtime: .builderSupported(marker: "8443")),
            queryCase(name: "Hysteria2 TLS SNI", scheme: "hy2", user: user, host: host, port: 443, baseQuery: base, key: "sni", oldValue: "old-cover.example.invalid", currentValue: "current-cover.example.invalid", runtime: .builderSupported(marker: "current-cover.example.invalid")),
            queryCase(name: "Hysteria2 insecure TLS", scheme: "hy2", user: user, host: host, port: 443, baseQuery: base, key: "insecure", oldValue: "0", currentValue: "1", runtime: .builderSupported(marker: "allowInsecure")),
            queryCase(
                name: "Hysteria2 obfuscation type",
                scheme: "hy2",
                user: user,
                host: host,
                port: 443,
                baseQuery: base.merging(["obfs-password": "test-static-obfs"]) { _, current in current },
                key: "obfs",
                oldValue: nil,
                currentValue: "salamander",
                runtime: .builderSupported(marker: "salamander")
            ),
            queryCase(name: "Hysteria2 bandwidth hint", scheme: "hy2", user: user, host: host, port: 443, baseQuery: base, key: "bandwidth", oldValue: nil, currentValue: "100mbps", runtime: .builderRejected),
            queryCase(name: "Hysteria2 certificate pin", scheme: "hy2", user: user, host: host, port: 443, baseQuery: base, key: "pinSHA256", oldValue: nil, currentValue: "test-public-pin", runtime: .mapperRejected),
            queryCase(name: "Hysteria2 ECH", scheme: "hy2", user: user, host: host, port: 443, baseQuery: base, key: "ech", oldValue: nil, currentValue: "test-public-ech-config", runtime: .mapperRejected),
            queryCase(name: "Hysteria2 port hopping", scheme: "hy2", user: user, host: host, port: 443, baseQuery: base, key: "mport", oldValue: nil, currentValue: "20000-30000", runtime: .mapperRejected)
        ]
    }

    private static var tuicCases: [ProviderManagedNonSecretRefreshCase] {
        let user = "test-tuic-credential"
        let host = "tuic-field.example.invalid"
        let base = [
            "username": "stable-user",
            "type": "tcp",
            "security": "tls",
            "tls": "1",
            "sni": "tuic-cover.example.invalid",
            "congestion": "bbr",
            "udpRelayMode": "native"
        ]
        return [
            endpointCase(name: "TUIC server", scheme: "tuic", user: user, oldHost: host, currentHost: "current-tuic.example.invalid", oldPort: 443, currentPort: 443, query: base, runtime: .runtimeUnsupported),
            endpointCase(name: "TUIC port", scheme: "tuic", user: user, oldHost: host, currentHost: host, oldPort: 443, currentPort: 8443, query: base, runtime: .runtimeUnsupported),
            queryCase(name: "TUIC username", scheme: "tuic", user: user, host: host, port: 443, baseQuery: base, key: "username", oldValue: "old-user", currentValue: "current-user", runtime: .runtimeUnsupported),
            queryCase(name: "TUIC transport type", scheme: "tuic", user: user, host: host, port: 443, baseQuery: base, key: "type", oldValue: "tcp", currentValue: "udp", runtime: .runtimeUnsupported),
            queryCase(name: "TUIC security mode", scheme: "tuic", user: user, host: host, port: 443, baseQuery: base, key: "security", oldValue: "tls", currentValue: "none", runtime: .runtimeUnsupported),
            queryCase(name: "TUIC TLS flag", scheme: "tuic", user: user, host: host, port: 443, baseQuery: base.merging(["security": "none"]) { _, current in current }, key: "tls", oldValue: "0", currentValue: "1", runtime: .runtimeUnsupported),
            queryCase(name: "TUIC TLS SNI", scheme: "tuic", user: user, host: host, port: 443, baseQuery: base, key: "sni", oldValue: "old-cover.example.invalid", currentValue: "current-cover.example.invalid", runtime: .runtimeUnsupported),
            queryCase(name: "TUIC allow insecure", scheme: "tuic", user: user, host: host, port: 443, baseQuery: base, key: "allowInsecure", oldValue: "0", currentValue: "1", runtime: .runtimeUnsupported),
            queryCase(name: "TUIC congestion control", scheme: "tuic", user: user, host: host, port: 443, baseQuery: base, key: "congestion", oldValue: "bbr", currentValue: "cubic", runtime: .runtimeUnsupported),
            queryCase(name: "TUIC UDP relay mode", scheme: "tuic", user: user, host: host, port: 443, baseQuery: base, key: "udpRelayMode", oldValue: "native", currentValue: "quic", runtime: .runtimeUnsupported)
        ]
    }

    private static func endpointCase(
        name: String,
        scheme: String,
        user: String,
        oldHost: String,
        currentHost: String,
        oldPort: Int,
        currentPort: Int,
        query: [String: String],
        runtime: ProviderFieldRuntimeExpectation
    ) -> ProviderManagedNonSecretRefreshCase {
        ProviderManagedNonSecretRefreshCase(
            name: name,
            oldURI: standardURI(scheme: scheme, user: user, host: oldHost, port: oldPort, query: query),
            currentURI: standardURI(scheme: scheme, user: user, host: currentHost, port: currentPort, query: query),
            runtimeExpectation: runtime
        )
    }

    private static func queryCase(
        name: String,
        scheme: String,
        user: String,
        host: String,
        port: Int,
        baseQuery: [String: String],
        key: String,
        oldValue: String?,
        currentValue: String?,
        runtime: ProviderFieldRuntimeExpectation
    ) -> ProviderManagedNonSecretRefreshCase {
        var oldQuery = baseQuery
        var currentQuery = baseQuery
        oldQuery[key] = oldValue
        currentQuery[key] = currentValue
        return ProviderManagedNonSecretRefreshCase(
            name: name,
            oldURI: standardURI(scheme: scheme, user: user, host: host, port: port, query: oldQuery),
            currentURI: standardURI(scheme: scheme, user: user, host: host, port: port, query: currentQuery),
            runtimeExpectation: runtime
        )
    }

    private static func vmessCase(
        name: String,
        base: [String: String],
        key: String,
        oldValue: String,
        currentValue: String,
        runtime: ProviderFieldRuntimeExpectation
    ) -> ProviderManagedNonSecretRefreshCase {
        var oldPayload = base
        var currentPayload = base
        oldPayload[key] = oldValue
        currentPayload[key] = currentValue
        return ProviderManagedNonSecretRefreshCase(
            name: name,
            oldURI: vmessURI(payload: oldPayload),
            currentURI: vmessURI(payload: currentPayload),
            runtimeExpectation: runtime
        )
    }

    private static func standardURI(
        scheme: String,
        user: String,
        host: String,
        port: Int,
        query: [String: String]
    ) -> String {
        var components = URLComponents()
        components.scheme = scheme
        components.user = user
        components.host = host
        components.port = port
        components.queryItems = query.sorted { $0.key < $1.key }.map {
            URLQueryItem(name: $0.key, value: $0.value)
        }
        components.fragment = "Field Refresh"
        guard let uri = components.string else {
            preconditionFailure("Invalid provider field test URI")
        }
        return uri
    }

    private static func shadowsocksURI(
        method: String,
        password: String,
        host: String,
        port: Int,
        query: [String: String] = [:]
    ) -> String {
        let user = Data("\(method):\(password)".utf8).base64EncodedString()
        return standardURI(scheme: "ss", user: user, host: host, port: port, query: query)
    }

    private static func vmessURI(payload: [String: String]) -> String {
        let fields = payload.sorted { $0.key < $1.key }.map { key, value in
            "\"\(key)\":\"\(value)\""
        }.joined(separator: ",")
        return "vmess://\(Data("{\(fields)}".utf8).base64EncodedString())"
    }
}

private nonisolated enum TestError: Error {
    case expectedProfile
    case forcedFailure
}

private nonisolated struct StubSubscriptionClient: SubscriptionClient {
    let result: Result<Data, Error>

    func fetch(url: URL) async throws -> Data {
        try result.get()
    }
}

private nonisolated struct StubSubscriptionUpdater: SubscriptionUpdating {
    let profile: VPNProfile

    func preview(_ subscription: VPNSubscription, url: URL) async throws -> SubscriptionPreview {
        SubscriptionPreview(
            id: UUID(),
            subscription: subscription,
            providerURLReference: subscription.credentialReference ?? "",
            detectedFormat: .plainURIList,
            profiles: [
                SubscriptionProfilePreview(profile: profile, state: .valid, isSelected: true)
            ],
            warnings: []
        )
    }

    func planRefresh(_ subscription: VPNSubscription, existingProfiles: [VPNProfile], url: URL) async throws -> SubscriptionUpdatePlan {
        SubscriptionUpdatePlan(
            id: UUID(),
            subscription: subscription,
            providerURLReference: subscription.credentialReference ?? "",
            detectedFormat: .plainURIList,
            changes: [
                SubscriptionProfileChange(kind: .added, incomingProfile: profile)
            ]
        )
    }
}

private actor RecordingQRCodeDetector: QRCodeImageDetecting {
    private let payloads: [String]
    private(set) var lastDataCount: Int?
    private(set) var callCount = 0

    init(payload: String) {
        self.payloads = [payload]
    }

    init(payloads: [String]) {
        self.payloads = payloads
    }

    func detectPayloads(in data: Data) async throws -> [String] {
        callCount += 1
        lastDataCount = data.count
        return payloads
    }
}

private actor FailingQRCodeDetector: QRCodeImageDetecting {
    private let error: Error
    private(set) var callCount = 0

    init(error: Error) {
        self.error = error
    }

    func detectPayloads(in data: Data) async throws -> [String] {
        callCount += 1
        throw error
    }
}

private actor ControllableQRCodeDetector: QRCodeImageDetecting {
    private var continuations: [String: CheckedContinuation<[String], Error>] = [:]
    private var waiters: [String: [CheckedContinuation<Void, Never>]] = [:]
    private(set) var callCount = 0

    func detectPayloads(in data: Data) async throws -> [String] {
        callCount += 1
        let requestKey = key(for: data)

        return try await withCheckedThrowingContinuation { continuation in
            continuations[requestKey] = continuation
            let pendingWaiters = waiters.removeValue(forKey: requestKey) ?? []
            for waiter in pendingWaiters {
                waiter.resume()
            }
        }
    }

    func waitForRequest(_ requestKey: String) async {
        if continuations[requestKey] != nil {
            return
        }

        await withCheckedContinuation { continuation in
            waiters[requestKey, default: []].append(continuation)
        }
    }

    func succeed(_ requestKey: String, payload: String) {
        continuations.removeValue(forKey: requestKey)?.resume(returning: [payload])
    }

    func fail(_ requestKey: String, error: Error) {
        continuations.removeValue(forKey: requestKey)?.resume(throwing: error)
    }

    private nonisolated func key(for data: Data) -> String {
        String(data: data, encoding: .utf8) ?? data.base64EncodedString()
    }
}

private nonisolated struct FailingImporter: VPNProfileImporting {
    func parse(_ text: String) async throws -> VPNImportResult {
        throw VPNImportError.invalidPayload("Unsupported QR content.")
    }
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
    private var secrets: [String: String] = [:]

    var activeReferenceCount: Int {
        secrets.count
    }

    func store(_ secret: String, label: String) async throws -> String {
        storeCount += 1
        let reference = "keychain://test.credentials/account-\(storeCount)"
        secrets[reference] = secret
        return reference
    }

    func secret(for reference: String) async throws -> String? {
        secrets[reference]
    }

    func delete(reference: String) async throws {
        deletedReferences.append(reference)
        secrets[reference] = nil
    }
}

private actor SuspendedSubscriptionClient: SubscriptionClient {
    private var fetchContinuation: CheckedContinuation<Data, Never>?
    private var startWaiters: [CheckedContinuation<Void, Never>] = []

    func fetch(url: URL) async throws -> Data {
        await withCheckedContinuation { continuation in
            fetchContinuation = continuation
            let waiters = startWaiters
            startWaiters.removeAll()
            for waiter in waiters {
                waiter.resume()
            }
        }
    }

    func waitUntilFetchStarts() async {
        guard fetchContinuation == nil else { return }
        await withCheckedContinuation { continuation in
            startWaiters.append(continuation)
        }
    }

    func complete(with data: Data) {
        let continuation = fetchContinuation
        fetchContinuation = nil
        continuation?.resume(returning: data)
    }
}

private actor SeededFailingProfileRepository: VPNProfileRepository {
    private var storedProfiles: [VPNProfile]

    init(profile: VPNProfile) {
        self.storedProfiles = [profile]
    }

    func profiles() async throws -> [VPNProfile] {
        storedProfiles
    }

    func save(_ profile: VPNProfile) async throws {
        throw TestError.forcedFailure
    }

    func delete(id: VPNProfile.ID) async throws {
        storedProfiles.removeAll { $0.id == id }
    }

    func setEnabled(_ isEnabled: Bool, id: VPNProfile.ID) async throws {}
    func rename(id: VPNProfile.ID, to name: String) async throws {}
}

private actor RefreshRuntimeProfileStore: SharedRuntimeProfileStoring {
    private var storedRecords: [UUID: SharedRuntimeProfileRecord] = [:]

    func write(_ record: SharedRuntimeProfileRecord) async throws {
        storedRecords[record.profileID] = record
    }

    func read(profileID: UUID) async throws -> SharedRuntimeProfileRecord {
        guard let record = storedRecords[profileID] else {
            throw RuntimeConfigurationError.profileRecordNotFound
        }
        return record
    }

    func records() async throws -> [SharedRuntimeProfileRecord] {
        storedRecords.values.sorted { lhs, rhs in
            lhs.profileID.uuidString < rhs.profileID.uuidString
        }
    }

    func replaceAll(_ records: [SharedRuntimeProfileRecord]) async throws {
        storedRecords = Dictionary(uniqueKeysWithValues: records.map { ($0.profileID, $0) })
    }

    func delete(profileID: UUID) async throws {
        storedRecords[profileID] = nil
    }
}

private actor ReferenceTrackingRuntimeProfileSynchronizer: RuntimeProfileSynchronizing {
    private var referencesByProfileID: [UUID: Set<String>] = [:]

    func profileSaved(_ profile: VPNProfile) async throws -> RuntimeProfileSynchronizationSummary {
        referencesByProfileID[profile.id] = profile.credentialReferences
        return RuntimeProfileSynchronizationSummary(
            publishedProfileIDs: [profile.id],
            omissions: []
        )
    }

    func profileDeleted(id: UUID) async throws {
        referencesByProfileID[id] = nil
    }

    func credentialReferences() async throws -> Set<String> {
        referencesByProfileID.values.reduce(into: Set<String>()) { references, profileReferences in
            references.formUnion(profileReferences)
        }
    }
}

private actor FailingRefreshRuntimeProfileSynchronizer: RuntimeProfileSynchronizing {
    func profileSaved(_ profile: VPNProfile) async throws -> RuntimeProfileSynchronizationSummary {
        throw TestError.forcedFailure
    }

    func profileDeleted(id: UUID) async throws {
        throw TestError.forcedFailure
    }

    func credentialReferences() async throws -> Set<String> {
        throw TestError.forcedFailure
    }
}

private actor RecordingConnectionManager: VPNConnectionManaging {
    private var state: VPNConnectionState = .disconnected
    private var continuations: [UUID: AsyncStream<VPNConnectionState>.Continuation] = [:]
    private(set) var connectCount = 0
    private(set) var disconnectCount = 0

    func currentState() async -> VPNConnectionState {
        state
    }

    nonisolated func stateUpdates() -> AsyncStream<VPNConnectionState> {
        AsyncStream { continuation in
            Task {
                let id = UUID()
                await self.addContinuation(continuation, id: id)
                continuation.onTermination = { _ in
                    Task {
                        await self.removeContinuation(id: id)
                    }
                }
            }
        }
    }

    func connect(using profile: VPNProfile) async throws -> ConnectionMetrics {
        connectCount += 1
        publish(.connecting)
        publish(.connected)
        return ConnectionMetrics(latency: 24, packetLoss: 0, serverLoad: 0.2, connectionTime: 0.1)
    }

    func disconnect() async {
        disconnectCount += 1
        publish(.disconnecting)
        publish(.disconnected)
    }

    private func addContinuation(_ continuation: AsyncStream<VPNConnectionState>.Continuation, id: UUID) {
        continuations[id] = continuation
        continuation.yield(state)
    }

    private func removeContinuation(id: UUID) {
        continuations[id] = nil
    }

    private func publish(_ newState: VPNConnectionState) {
        state = newState
        for continuation in continuations.values {
            continuation.yield(newState)
        }
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
