//
//  RuntimeConfigurationTests.swift
//  VPNTests
//
//  Phase F2B-K2: secret-free shared runtime profile and read-only
//  configuration validation tests. These tests never start VPN runtime.
//

import Foundation
import Testing
@testable import VPN

struct RuntimeConfigurationRecordTests {
    @Test
    func realisticVLESSXHTTPURICompilesToTypedXHTTPTransport() async throws {
        let uri = [
            "vless://\(TestSecrets().vlessUUID)@xhttp.example.com:443",
            "?type=splithttp",
            "&security=reality",
            "&pbk=\(TestSecrets().realityPublicKey)",
            "&sid=abcd",
            "&sni=site.example.com",
            "&fp=chrome",
            "&path=%2Fxhttp",
            "&host=cdn.example.com",
            "&mode=stream-one",
            "#XHTTP"
        ].joined()
        let parser = VLESSLinkParser(credentialStore: InMemoryCredentialStore())

        let result = try await parser.parse(uri)

        guard case .profile(let profile) = result.kind else {
            Issue.record("Expected VLESS profile import")
            return
        }
        #expect(profile.transportSettings.network == "splithttp")
        let configuration = try VLESSProfileConfigurationCompiler().compile(profile: profile)
        guard case .xhttp(let path, let host, let mode, _) = configuration.transport else {
            Issue.record("Expected splithttp to normalize into CoreTransportConfiguration.xhttp")
            return
        }
        #expect(path == "/xhttp")
        #expect(host == "cdn.example.com")
        #expect(mode == "stream-one")
    }

    @Test
    func validVLESSProfileMapsToRuntimeRecord() throws {
        let profile = makeVLESSProfile()
        let mapper = SharedRuntimeProfileMapper(now: fixedDate)

        let record = try mapper.record(from: profile)

        #expect(record.schemaVersion == RuntimeConfigurationProtocol.profileSchemaVersion)
        #expect(record.profileID == profile.id)
        #expect(record.enabled)
        #expect(record.completeness == .complete)
        #expect(record.credentialReference == profile.credentialReference)
        #expect(record.protocolKind == .vless)
        #expect(record.backendKind == .xray)
        #expect(record.endpoint == SharedRuntimeEndpoint(host: "example.com", port: 443))
        #expect(record.transport.kind == .websocket)
        #expect(record.transport.path == "/ws")
        #expect(record.transport.host == "cdn.example.com")
        #expect(record.security.kind == .tls)
        #expect(record.security.serverName == "sni.example.com")
        #expect(record.vless.flow == "xtls-rprx-vision")
        #expect(record.vless.encryption == "none")
        #expect(record.recordRevision.isEmpty == false)
    }

    @Test
    func vlessRealityProfileMapsToRuntimeRecord() throws {
        let profile = makeRealityProfile()
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: profile)
        let reality = try #require(record.security.reality)

        #expect(record.protocolKind == .vless)
        #expect(record.transport.kind == .tcp)
        #expect(record.security.kind == .reality)
        #expect(reality.serverName == "site.example.com")
        #expect(reality.publicKey == TestSecrets().realityPublicKey)
        #expect(reality.shortID == "abcd")
        #expect(reality.fingerprint == "chrome")
        #expect(reality.spiderX == "/")
        #expect(record.vless.flow == "xtls-rprx-vision")
    }

    @Test
    func nonVLESSProfilesMapToTypedRuntimeRecordsWithoutCredentialValues() throws {
        let vmess = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVMessProfile())
        let trojan = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeTrojanProfile())
        let shadowsocks = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeShadowsocksProfile(outline: true))
        let hysteria2 = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeHysteria2Profile())

        #expect(vmess.protocolKind == .vmess)
        #expect(vmess.vmess == SharedRuntimeVMessParameters(alterID: 0, security: "auto"))
        #expect(vmess.transport.kind == .websocket)
        #expect(vmess.security.kind == .tls)

        #expect(trojan.protocolKind == .trojan)
        #expect(trojan.trojan == SharedRuntimeTrojanParameters(alpn: ["h2", "http/1.1"]))
        #expect(trojan.transport.kind == .xhttp)
        #expect(trojan.security.kind == .tls)

        #expect(shadowsocks.protocolKind == .shadowsocks)
        #expect(shadowsocks.shadowsocks == SharedRuntimeShadowsocksParameters(method: "chacha20-ietf-poly1305", plugin: nil, isOutlineStaticKey: true))
        #expect(shadowsocks.security.kind == .none)

        #expect(hysteria2.protocolKind == .hysteria2)
        #expect(hysteria2.transport.kind == .hysteria)
        #expect(hysteria2.security.kind == .tls)

        let encoded = try encodedJSONString(SharedRuntimeProfileCollection(records: [vmess, trojan, shadowsocks, hysteria2]))
        #expect(!encoded.contains(TestSecrets().vlessUUID))
        #expect(!encoded.contains(TestSecrets().password))
        #expect(!encoded.contains(TestSecrets().token))
        #expect(!encoded.contains(TestSecrets().privateKey))
        #expect(!encoded.contains("SECRET-RAW"))
    }

    @Test
    func hysteria2URIAuthPercentDecodingRoundTripsIntoKeychainOnly() async throws {
        let cases = [
            ("hysteria2://simple-auth@hy2.example.com:443?sni=hy2.example.com#HY2", "simple-auth"),
            ("hysteria2://user%3Apassword@hy2.example.com:443?sni=hy2.example.com#HY2", "user:password"),
            ("hysteria2://alice%3Asecret@example.com:443/", "alice:secret"),
            ("hysteria2://alice:secret@example.com:443/", "alice:secret"),
            ("hysteria2://abc%40123@hy2.example.com:443?sni=hy2.example.com#HY2", "abc@123"),
            ("hysteria2://literal%2525@hy2.example.com:443?sni=hy2.example.com#HY2", "literal%25")
        ]

        for (uri, expectedSecret) in cases {
            let store = CanonicalInMemoryCredentialStore()
            let parser = Hysteria2LinkParser(credentialStore: store)

            let result = try await parser.parse(uri)

            guard case .profile(let profile) = result.kind else {
                Issue.record("Expected Hysteria2 profile import")
                return
            }
            let reference = try #require(profile.credentialReference)
            #expect(try await store.secret(for: reference) == expectedSecret)
            #expect(CredentialReferenceValidator.isValid(reference))
            #expect(profile.metadata.values.contains(expectedSecret) == false)
            #expect(result.sanitizedSummary.values.contains(expectedSecret) == false)

            let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: profile)
            let recordJSON = try encodedJSONString(record)
            #expect(record.credentialReference == reference)
            #expect(!recordJSON.contains(expectedSecret))

            let runtimeStore = InMemoryRuntimeProfileStore(records: [record.profileID: record])
            let credentialResolver = StaticRuntimeCredentialResolver(secrets: [reference: expectedSecret])
            let loader = RuntimeConfigurationLoader(store: runtimeStore, credentialResolver: credentialResolver)
            let providerConfiguration = try RuntimeProviderConfiguration(
                profileID: record.profileID,
                sharedRecordRevision: record.recordRevision
            )
            let resolved = try await loader.load(providerConfiguration: providerConfiguration.propertyList)
            #expect(resolved.protocolKind == .hysteria2)

            let json = try await MainActor.run {
                try XrayConfigurationBuilder()
                    .build(from: resolved, options: XrayBuildOptions())
                    .withJSONString { $0 }
            }
            let outbound = try firstXrayOutbound(from: json)
            let streamSettings = try #require(outbound["streamSettings"] as? [String: Any])
            let hysteriaSettings = try #require(streamSettings["hysteriaSettings"] as? [String: Any])
            #expect(hysteriaSettings["auth"] as? String == expectedSecret)
        }
    }

    @Test
    func hysteria2EmptyAuthRejects() async throws {
        let store = InMemoryCredentialStore()
        let parser = Hysteria2LinkParser(credentialStore: store)

        await #expect(throws: VPNImportError.missingRequiredComponent("password")) {
            _ = try await parser.parse("hysteria2://@hy2.example.com:443/")
        }
    }

    @Test
    func hysteria2InsecureAndUnsupportedTLSFeaturesMapExplicitly() async throws {
        let store = CanonicalInMemoryCredentialStore()
        let parser = Hysteria2LinkParser(credentialStore: store)
        let insecure = try await parser.parse("hy2://secret@hy2.example.com?insecure=1&sni=hy2.example.com")
        let explicitSecure = try await parser.parse("hy2://secret@hy2.example.com?insecure=0&sni=hy2.example.com")
        let defaultSecure = try await parser.parse("hy2://secret@hy2.example.com?sni=hy2.example.com")

        guard case .profile(let insecureProfile) = insecure.kind,
              case .profile(let explicitSecureProfile) = explicitSecure.kind,
              case .profile(let defaultSecureProfile) = defaultSecure.kind else {
            Issue.record("Expected Hysteria2 profile imports")
            return
        }

        #expect(insecureProfile.tlsSettings.allowInsecure == true)
        #expect(explicitSecureProfile.tlsSettings.allowInsecure == false)
        #expect(defaultSecureProfile.tlsSettings.allowInsecure == false)
        #expect(CredentialReferenceValidator.isValid(try #require(insecureProfile.credentialReference)))
        #expect(CredentialReferenceValidator.isValid(try #require(explicitSecureProfile.credentialReference)))
        #expect(CredentialReferenceValidator.isValid(try #require(defaultSecureProfile.credentialReference)))

        let insecureRecord = try SharedRuntimeProfileMapper(now: fixedDate).record(from: insecureProfile)
        let explicitSecureRecord = try SharedRuntimeProfileMapper(now: fixedDate).record(from: explicitSecureProfile)
        let defaultSecureRecord = try SharedRuntimeProfileMapper(now: fixedDate).record(from: defaultSecureProfile)

        #expect(insecureRecord.security.allowInsecure == true)
        #expect(explicitSecureRecord.security.allowInsecure == false)
        #expect(defaultSecureRecord.security.allowInsecure == false)
        #expect(try firstXrayOutboundTLSSettings(from: xrayJSONString(from: insecureProfile, credential: "secret"))["allowInsecure"] as? Bool == true)
        #expect(try firstXrayOutboundTLSSettings(from: xrayJSONString(from: explicitSecureProfile, credential: "secret"))["allowInsecure"] as? Bool == false)
        #expect(try firstXrayOutboundTLSSettings(from: xrayJSONString(from: defaultSecureProfile, credential: "secret"))["allowInsecure"] as? Bool == false)

        #expect(throws: RuntimeConfigurationError.unsupportedProtocol) {
            _ = try SharedRuntimeProfileMapper(now: fixedDate).record(
                from: makeHysteria2Profile(metadata: ["pinSHA256": "pin-value"])
            )
        }
        #expect(throws: RuntimeConfigurationError.unsupportedProtocol) {
            _ = try SharedRuntimeProfileMapper(now: fixedDate).record(
                from: makeHysteria2Profile(metadata: ["ech": "ech-value"])
            )
        }
        await #expect(throws: VPNImportError.invalidPort) {
            _ = try await parser.parse("hy2://secret@hy2.example.com:123,5000-6000?sni=hy2.example.com")
        }
    }

    @Test
    func xhttpRealityProfileMapsToRuntimeRecord() throws {
        let profile = makeRealityProfile(network: "splithttp", path: "/xhttp", host: "cdn.example.com", mode: "stream-one")
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: profile)

        #expect(record.transport.kind == .xhttp)
        #expect(record.transport.path == "/xhttp")
        #expect(record.transport.host == "cdn.example.com")
        #expect(record.transport.mode == "stream-one")
        #expect(record.transport.xhttp == SharedRuntimeXHTTPParameters(path: "/xhttp", host: "cdn.example.com", mode: .streamOne))
        #expect(record.security.kind == .reality)
        #expect(record.security.reality?.publicKey == TestSecrets().realityPublicKey)
    }

    @Test
    func xhttpTLSProfileMapsToRuntimeRecord() throws {
        let profile = makeXHTTPTLSProfile(network: "xhttp", path: "/xhttp", host: "cdn.example.com", mode: "auto")
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: profile)

        #expect(record.transport.kind == .xhttp)
        #expect(record.transport.xhttp?.path == "/xhttp")
        #expect(record.transport.xhttp?.host == "cdn.example.com")
        #expect(record.transport.xhttp?.mode == .auto)
        #expect(record.security.kind == .tls)
        #expect(record.security.serverName == "sni.example.com")
    }

    @Test
    func xhttpRecordUsesCanonicalWireValuesAndDoesNotLeakTransportDetailsThroughProviderConfig() throws {
        let profile = makeRealityProfile(network: "splithttp", path: "/xhttp", host: "cdn.example.com", mode: "stream-one")
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: profile)
        let providerConfiguration = try RuntimeProviderConfiguration(profileID: record.profileID, sharedRecordRevision: record.recordRevision)
        let recordJSON = try encodedJSONString(record)
        let collectionJSON = try encodedJSONString(SharedRuntimeProfileCollection(records: [record]))
        let providerJSON = try propertyListJSONString(providerConfiguration.propertyList)

        #expect(recordJSON.contains(#""kind":"xhttp""#))
        #expect(recordJSON.contains(#""mode":"stream-one""#))
        #expect(!recordJSON.contains("splithttp"))
        #expect(collectionJSON.contains(#""xhttp""#))
        #expect(Set(providerConfiguration.propertyList.keys) == RuntimeProviderConfiguration.allowedKeys)
        #expect(!providerJSON.contains("xhttp"))
        #expect(!providerJSON.contains("/xhttp"))
        #expect(!providerJSON.contains("cdn.example.com"))
        #expect(!providerJSON.contains("credentialReference"))
    }

    @Test
    func malformedXHTTPParametersAreRejectedWithTypedErrors() throws {
        let invalidMode = makeRealityProfile(network: "xhttp", path: "/xhttp", host: "cdn.example.com", mode: "invalid-mode")
        let invalidPath = makeRealityProfile(network: "xhttp", path: "not-a-path", host: "cdn.example.com", mode: "auto")
        let invalidHost = makeRealityProfile(network: "xhttp", path: "/xhttp", host: "bad host", mode: "auto")
        let malformedXHTTPTransport = makeRealityProfile(network: "not-xhttp", path: "/xhttp", host: "cdn.example.com", mode: "auto")
        let unknownTransport = makeRealityProfile(network: "not-a-supported-transport", path: "/xhttp", host: "cdn.example.com", mode: "auto")
        let mapper = SharedRuntimeProfileMapper(now: fixedDate)

        #expect(throws: RuntimeConfigurationError.invalidXHTTPMode) {
            _ = try mapper.record(from: invalidMode)
        }
        #expect(throws: RuntimeConfigurationError.invalidXHTTPPath) {
            _ = try mapper.record(from: invalidPath)
        }
        #expect(throws: RuntimeConfigurationError.invalidXHTTPHost) {
            _ = try mapper.record(from: invalidHost)
        }
        #expect(throws: RuntimeConfigurationError.invalidXHTTPConfiguration) {
            _ = try mapper.record(from: malformedXHTTPTransport)
        }
        #expect(throws: RuntimeConfigurationError.unsupportedTransport) {
            _ = try mapper.record(from: unknownTransport)
        }
    }

    @Test
    func malformedRealityPublicParametersAreRejected() throws {
        let missingPublicKey = makeRealityProfile(publicKey: nil)
        let malformedPublicKey = makeRealityProfile(publicKey: "bad-key")
        let missingServerName = makeRealityProfile(serverName: nil)
        let malformedShortID = makeRealityProfile(shortID: "not-hex")

        let mapper = SharedRuntimeProfileMapper(now: fixedDate)

        #expect(throws: RuntimeConfigurationError.invalidSecurityConfiguration) {
            _ = try mapper.record(from: missingPublicKey)
        }
        #expect(throws: RuntimeConfigurationError.invalidSecurityConfiguration) {
            _ = try mapper.record(from: malformedPublicKey)
        }
        #expect(throws: RuntimeConfigurationError.invalidSecurityConfiguration) {
            _ = try mapper.record(from: missingServerName)
        }
        #expect(throws: RuntimeConfigurationError.invalidSecurityConfiguration) {
            _ = try mapper.record(from: malformedShortID)
        }
    }

    @Test
    func recordEncodesAndDecodesWithExplicitSchema() throws {
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVLESSProfile())
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(record)

        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["schemaVersion"] as? Int == Int(RuntimeConfigurationProtocol.profileSchemaVersion))
        #expect(object["profileID"] as? String == record.profileID.uuidString)
        #expect(object["recordRevision"] as? String == record.recordRevision)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        #expect(try decoder.decode(SharedRuntimeProfileRecord.self, from: data) == record)
    }

    @Test
    func serializedRecordContainsNoSecretMaterial() throws {
        let secrets = TestSecrets()
        let profile = makeVLESSProfile(
            credentialReference: "keychain://vpn.credentials/account-1",
            metadata: [
                "vlessUUID": secrets.vlessUUIDCanary,
                "rawURI": secrets.rawURI,
                "subscriptionURL": secrets.subscriptionURL,
                "token": secrets.token,
                "password": secrets.password,
                "privateKey": secrets.privateKey,
                "arbitrary": secrets.arbitraryMetadataSecret
            ]
        )

        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: profile)
        let collection = SharedRuntimeProfileCollection(records: [record])
        let json = try encodedJSONString(record)
        let collectionJSON = try encodedJSONString(collection)

        #expect(record.credentialReference == "keychain://vpn.credentials/account-1")
        #expect(json.contains("credentialReference"))
        assertNoSecretMaterial(in: json, secrets: secrets)
        assertNoSecretMaterial(in: collectionJSON, secrets: secrets)
        #expect(!json.contains("rawURI"))
        #expect(!json.contains("subscriptionURL"))
        #expect(!json.contains("arbitrary"))
        #expect(!collectionJSON.contains("rawURI"))
        #expect(!collectionJSON.contains("subscriptionURL"))
        #expect(!collectionJSON.contains("arbitrary"))
    }

    @Test
    func serializedRealityRecordContainsNoSecretMaterialOrLegacyReference() throws {
        let secrets = TestSecrets()
        let profile = makeRealityProfile(
            metadata: [
                "uuid": secrets.vlessUUIDCanary,
                "privateKey": secrets.privateKey,
                "token": secrets.token,
                "rawURI": secrets.rawURI,
                "subscriptionURL": secrets.subscriptionURL,
                "arbitrary": secrets.arbitraryMetadataSecret
            ]
        )

        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: profile)
        let json = try encodedJSONString(record)

        #expect(json.contains(secrets.realityPublicKey))
        #expect(json.contains("reality"))
        #expect(!json.contains("publicKeyReference"))
        assertNoSecretMaterial(in: json, secrets: secrets)
        #expect(!json.contains("rawURI"))
        #expect(!json.contains("subscriptionURL"))
        #expect(!json.contains("privateKey"))
        #expect(!json.contains("arbitrary"))
    }

    @Test
    func recordRejectsUnsupportedAndIncompleteProfiles() throws {
        let unsupported = VPNProfile.draft(
            name: "WG",
            protocolType: .wireGuard,
            serverAddress: "example.com",
            port: 443,
            credentialReference: "keychain://vpn.credentials/account-1",
            protocolConfiguration: .wireGuard(WireGuardProfileConfiguration(peerPublicKeyReference: nil, presharedKeyReference: nil, allowedIPs: [])),
            source: .manual
        )
        var incomplete = makeVLESSProfile(credentialReference: nil)
        var disabled = makeVLESSProfile()
        disabled.isEnabled = false

        let mapper = SharedRuntimeProfileMapper(now: fixedDate)

        #expect(throws: RuntimeConfigurationError.unsupportedProtocol) {
            _ = try mapper.record(from: unsupported)
        }
        #expect(throws: RuntimeConfigurationError.profileIncomplete) {
            _ = try mapper.record(from: incomplete)
        }
        #expect(throws: RuntimeConfigurationError.profileDisabled) {
            _ = try mapper.record(from: disabled)
        }
        incomplete.serverAddress = "bad host"
        incomplete.credentialReference = "keychain://vpn.credentials/account-1"
        #expect(throws: RuntimeConfigurationError.invalidEndpoint) {
            _ = try mapper.record(from: incomplete)
        }
    }

    @Test
    func debugDescriptionsAreRedacted() throws {
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVLESSProfile())
        let description = String(reflecting: record)

        #expect(description.contains("credentialReference: <redacted>"))
        #expect(description.contains("endpoint: <redacted>"))
        #expect(!description.contains(record.credentialReference))
        #expect(!description.contains(record.endpoint.host))
    }
}

struct RuntimeProfileStoreTests {
    @Test
    func recordWriteReadAndDeleteUseExactProfileID() async throws {
        let root = temporaryDirectory()
        let store = FileSharedRuntimeProfileStore(rootDirectory: root)
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVLESSProfile())

        try await store.write(record)
        #expect(try await store.read(profileID: record.profileID) == record)

        try await store.delete(profileID: record.profileID)
        await #expect(throws: RuntimeConfigurationError.profileRecordNotFound) {
            _ = try await store.read(profileID: record.profileID)
        }
    }

    @Test
    func recordReadRejectsOversizedAndMalformedFiles() async throws {
        let oversizedRoot = temporaryDirectory()
        let oversizedStore = FileSharedRuntimeProfileStore(rootDirectory: oversizedRoot, maximumRecordBytes: 8)
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVLESSProfile())

        await #expect(throws: RuntimeConfigurationError.profileRecordTooLarge) {
            try await oversizedStore.write(record)
        }

        let malformedRoot = temporaryDirectory()
        let malformedStore = FileSharedRuntimeProfileStore(rootDirectory: malformedRoot)
        try FileManager.default.createDirectory(at: malformedRoot, withIntermediateDirectories: true)
        let fileURL = runtimeProfileCollectionURL(root: malformedRoot)
        try Data("not-json".utf8).write(to: fileURL, options: [.atomic])

        await #expect(throws: RuntimeConfigurationError.profileRecordMalformed) {
            _ = try await malformedStore.read(profileID: record.profileID)
        }
    }

    @Test
    func recordFileIsExcludedFromBackupWhereAvailable() async throws {
        let root = temporaryDirectory()
        let store = FileSharedRuntimeProfileStore(rootDirectory: root)
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVLESSProfile())

        try await store.write(record)

        let fileURL = runtimeProfileCollectionURL(root: root)
        let values = try fileURL.resourceValues(forKeys: [.isExcludedFromBackupKey])
        #expect(values.isExcludedFromBackup == true)
    }

    @Test
    func collectionStoresMultipleProfilesDeterministicallyAndReplacesSameProfile() async throws {
        let root = temporaryDirectory()
        let store = FileSharedRuntimeProfileStore(rootDirectory: root)
        let first = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVLESSProfile())
        let second = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVLESSProfile(credentialReference: "keychain://vpn.credentials/account-2"))
        var updatedFirst = first
        updatedFirst.recordRevision = "v1-updated"

        try await store.write(second)
        try await store.write(first)
        try await store.write(updatedFirst)

        let records = try await store.records()
        #expect(records.map(\.profileID) == [first.profileID, second.profileID].sorted { $0.uuidString < $1.uuidString })
        #expect(try await store.read(profileID: first.profileID).recordRevision == "v1-updated")
    }

    @Test
    func wrongCollectionSchemaIsRejected() async throws {
        let root = temporaryDirectory()
        let store = FileSharedRuntimeProfileStore(rootDirectory: root)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let data = Data(#"{"schemaVersion":999,"records":[]}"#.utf8)
        try data.write(to: runtimeProfileCollectionURL(root: root), options: [.atomic])

        await #expect(throws: RuntimeConfigurationError.profileSchemaMismatch) {
            _ = try await store.records()
        }
    }
}

struct RuntimeProfileSynchronizerTests {
    @Test
    func synchronizingExistingProfilesIsIdempotentAndOmitsUnsupportedProfiles() async throws {
        let valid = makeVLESSProfile()
        let unsupported = VPNProfile.draft(
            name: "WG",
            protocolType: .wireGuard,
            serverAddress: "example.com",
            port: 443,
            credentialReference: "keychain://vpn.credentials/wg",
            protocolConfiguration: .wireGuard(WireGuardProfileConfiguration(peerPublicKeyReference: nil, presharedKeyReference: nil, allowedIPs: [])),
            source: .manual
        )
        let repository = InMemoryVPNProfileRepository()
        try await repository.save(valid)
        try await repository.save(unsupported)
        let store = InMemoryRuntimeProfileStore()
        let synchronizer = RuntimeProfileSynchronizer(
            profileRepository: repository,
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: store,
            credentialStore: StaticCredentialStore(secrets: [valid.credentialReference!: TestSecrets().vlessUUID])
        )

        let first = try await synchronizer.synchronizeExistingProfiles()
        let firstRecords = try await store.records()
        let second = try await synchronizer.synchronizeExistingProfiles()
        let secondRecords = try await store.records()

        #expect(first.publishedProfileIDs == [valid.id])
        #expect(first.omissions == [RuntimeProfileSynchronizationOmission(profileID: unsupported.id, reason: .unsupportedProtocol)])
        #expect(second == first)
        #expect(secondRecords == firstRecords)
        #expect(try await store.read(profileID: valid.id).credentialReference == valid.credentialReference)
    }

    @Test
    func profileSavedUpdatesAndProfileDeletedRemovesOnlyThatRecord() async throws {
        let first = makeVLESSProfile()
        let second = makeVLESSProfile(credentialReference: "keychain://vpn.credentials/account-2")
        let repository = InMemoryVPNProfileRepository()
        let store = InMemoryRuntimeProfileStore()
        let synchronizer = RuntimeProfileSynchronizer(
            profileRepository: repository,
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: store,
            credentialStore: StaticCredentialStore(
                secrets: [
                    first.credentialReference!: TestSecrets().vlessUUID,
                    second.credentialReference!: TestSecrets().vlessUUID
                ]
            )
        )

        _ = try await synchronizer.profileSaved(first)
        _ = try await synchronizer.profileSaved(second)
        try await synchronizer.profileDeleted(id: first.id)

        await #expect(throws: RuntimeConfigurationError.profileRecordNotFound) {
            _ = try await store.read(profileID: first.id)
        }
        #expect(try await store.read(profileID: second.id).profileID == second.id)
    }

    @Test
    func publisherMigratesLegacyRealityPublicKeyReferenceWithoutSerializingIt() async throws {
        let legacyReference = "keychain://vpn.credentials/reality-public-key"
        var profile = makeRealityProfile(publicKey: nil)
        profile.tlsSettings.publicKeyReference = legacyReference
        let store = InMemoryRuntimeProfileStore()
        let publisher = SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: store,
            credentialStore: StaticCredentialStore(
                secrets: [
                    profile.credentialReference!: TestSecrets().vlessUUID,
                    legacyReference: TestSecrets().realityPublicKey
                ]
            )
        )

        let record = try await publisher.publish(profile)
        let json = try encodedJSONString(record)

        #expect(record.security.kind == .reality)
        #expect(record.security.reality?.publicKey == TestSecrets().realityPublicKey)
        #expect(!json.contains(legacyReference))
        #expect(!json.contains("publicKeyReference"))
    }
}

struct RuntimeProviderConfigurationTests {
    @Test
    func providerConfigurationContainsIdentitySchemaAndRevisionOnly() throws {
        let profileID = UUID()
        let configuration = try RuntimeProviderConfiguration(profileID: profileID, sharedRecordRevision: "rev-1")
        let propertyList = configuration.propertyList

        #expect(Set(propertyList.keys) == RuntimeProviderConfiguration.allowedKeys)
        #expect(propertyList["schemaVersion"] is NSNumber)
        #expect(propertyList["profileID"] as? String == profileID.uuidString)
        #expect(propertyList["recordRevision"] is NSNumber)
        #expect(propertyList["credentialReference"] == nil)
        #expect(propertyList["host"] == nil)
        #expect(propertyList["port"] == nil)
        #expect(propertyList["credential"] == nil)
    }

    @Test
    func providerConfigurationStrictlyRejectsUnknownKeysAndWrongTypes() throws {
        let profileID = UUID()
        let valid = try RuntimeProviderConfiguration(profileID: profileID, sharedRecordRevision: "rev-1").propertyList
        #expect(try RuntimeProviderConfiguration.parse(valid).profileID == profileID)

        var unknown = valid
        unknown["host"] = "example.com" as NSString
        #expect(throws: RuntimeConfigurationError.providerConfigurationUnknownKey) {
            _ = try RuntimeProviderConfiguration.parse(unknown)
        }

        var wrongSchemaType = valid
        wrongSchemaType["schemaVersion"] = "1" as NSString
        #expect(throws: RuntimeConfigurationError.providerConfigurationWrongSchemaVersionType) {
            _ = try RuntimeProviderConfiguration.parse(wrongSchemaType)
        }

        var wrongProfileType = valid
        wrongProfileType["profileID"] = NSNumber(value: 1)
        #expect(throws: RuntimeConfigurationError.providerConfigurationWrongProfileIDType) {
            _ = try RuntimeProviderConfiguration.parse(wrongProfileType)
        }
    }

    @Test
    func providerConfigurationAcceptsFoundationBridgeTypes() throws {
        let profileID = UUID()
        let revision = try RuntimeProviderConfiguration.revisionToken(for: "rev-bridge")
        let propertyList: [String: Any] = [
            "schemaVersion": NSNumber(value: RuntimeConfigurationProtocol.providerConfigurationSchemaVersion),
            "profileID": profileID.uuidString as NSString,
            "recordRevision": NSNumber(value: revision)
        ]

        let parsed = try RuntimeProviderConfiguration.parse(propertyList)

        #expect(parsed.profileID == profileID)
        #expect(parsed.recordRevision == revision)
    }

    @Test
    func providerConfigurationRejectsBoolFractionalAndMissingKeysGranularly() throws {
        let profileID = UUID()
        let valid = try RuntimeProviderConfiguration(profileID: profileID, sharedRecordRevision: "rev-1").propertyList

        var boolSchema = valid
        boolSchema["schemaVersion"] = NSNumber(value: true)
        #expect(throws: RuntimeConfigurationError.providerConfigurationWrongSchemaVersionType) {
            _ = try RuntimeProviderConfiguration.parse(boolSchema)
        }

        var boolRevision = valid
        boolRevision["recordRevision"] = NSNumber(value: false)
        #expect(throws: RuntimeConfigurationError.providerConfigurationWrongRecordRevisionType) {
            _ = try RuntimeProviderConfiguration.parse(boolRevision)
        }

        var fractionalRevision = valid
        fractionalRevision["recordRevision"] = NSNumber(value: 1.25)
        #expect(throws: RuntimeConfigurationError.providerConfigurationWrongRecordRevisionType) {
            _ = try RuntimeProviderConfiguration.parse(fractionalRevision)
        }

        var invalidRevision = valid
        invalidRevision["recordRevision"] = NSNumber(value: 0)
        #expect(throws: RuntimeConfigurationError.providerConfigurationInvalidRecordRevision) {
            _ = try RuntimeProviderConfiguration.parse(invalidRevision)
        }

        var missingSchema = valid
        missingSchema.removeValue(forKey: "schemaVersion")
        #expect(throws: RuntimeConfigurationError.providerConfigurationMissingSchemaVersion) {
            _ = try RuntimeProviderConfiguration.parse(missingSchema)
        }

        var missingRevision = valid
        missingRevision.removeValue(forKey: "recordRevision")
        #expect(throws: RuntimeConfigurationError.providerConfigurationMissingRecordRevision) {
            _ = try RuntimeProviderConfiguration.parse(missingRevision)
        }
    }

    @Test
    func providerConfigurationDiagnosticsExposeOnlySafeKeysAndTypes() throws {
        let diagnostic = RuntimeProviderConfiguration.diagnostic(
            for: [
                "schemaVersion": NSNumber(value: RuntimeConfigurationProtocol.providerConfigurationSchemaVersion),
                "profileID": "not-a-uuid" as NSString,
                "recordRevision": NSNumber(value: 1),
                "diagnosticPurpose": "sharedKeychainSentinel" as NSString
            ],
            category: .providerConfigurationUnknownKey
        )
        let json = try encodedJSONString(diagnostic)

        #expect(diagnostic.keyCount == 4)
        #expect(diagnostic.keyNames == ["diagnosticPurpose", "profileID", "recordRevision", "schemaVersion"])
        #expect(diagnostic.valueTypesByKey?["schemaVersion"] == "Number")
        #expect(diagnostic.valueTypesByKey?["profileID"] == "String")
        #expect(!json.contains("not-a-uuid"))
        #expect(!json.contains("sharedKeychainSentinel"))
    }

    @Test
    func revisionTokenUsesStableCrossProcessFixture() throws {
        let first = try RuntimeProviderConfiguration.revisionToken(for: "rev-stable-cross-process")
        let second = try RuntimeProviderConfiguration.revisionToken(for: "rev-stable-cross-process")

        #expect(first == 6_875_115_447_722_027_723)
        #expect(second == first)
        #expect(try RuntimeProviderConfiguration.revisionToken(for: "rev-stable-cross-process-2") != first)
    }
}

struct RuntimeConfigurationLoaderTests {
    @Test
    func loaderResolvesCanonicalCredentialIntoRedactedInMemoryModel() async throws {
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVLESSProfile())
        let store = InMemoryRuntimeProfileStore(records: [record.profileID: record])
        let resolver = StaticRuntimeCredentialResolver(secrets: [record.credentialReference: TestSecrets().vlessUUID])
        let loader = RuntimeConfigurationLoader(store: store, credentialResolver: resolver)
        let providerConfiguration = try RuntimeProviderConfiguration(profileID: record.profileID, sharedRecordRevision: record.recordRevision)

        let resolved = try await loader.load(providerConfiguration: providerConfiguration.propertyList)

        #expect(resolved.profileID == record.profileID)
        #expect(resolved.recordRevision == record.recordRevision)
        #expect(resolved.endpoint.host == record.endpoint.host)
        #expect(String(describing: resolved.credential) == "<redacted>")
        #expect(String(reflecting: resolved).contains("credential: <redacted>"))
        #expect(!String(reflecting: resolved).contains(TestSecrets().vlessUUID))
    }

    @Test
    func loaderResolvesRealityConfigurationWithoutExposingPublicValues() async throws {
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeRealityProfile())
        let store = InMemoryRuntimeProfileStore(records: [record.profileID: record])
        let resolver = StaticRuntimeCredentialResolver(secrets: [record.credentialReference: TestSecrets().vlessUUID])
        let loader = RuntimeConfigurationLoader(store: store, credentialResolver: resolver)
        let providerConfiguration = try RuntimeProviderConfiguration(profileID: record.profileID, sharedRecordRevision: record.recordRevision)

        let resolved = try await loader.load(providerConfiguration: providerConfiguration.propertyList)
        let validation = await loader.validateRuntimeConfiguration(
            providerConfiguration: providerConfiguration.propertyList,
            correlationID: UUID(),
            expectedProfileID: record.profileID
        )
        let validationJSON = try encodedJSONString(validation)

        #expect(resolved.security.kind == .reality)
        #expect(resolved.security.reality?.publicKey == TestSecrets().realityPublicKey)
        #expect(String(reflecting: resolved).contains("credential: <redacted>"))
        #expect(!String(reflecting: resolved).contains(TestSecrets().vlessUUID))
        #expect(validation.success)
        #expect(validation.securityName == "reality")
        #expect(!validationJSON.contains(TestSecrets().realityPublicKey))
        #expect(!validationJSON.contains("site.example.com"))
        #expect(!validationJSON.contains("abcd"))
    }

    @Test
    func loaderResolvesXHTTPConfigurationWithoutReturningTransportParameters() async throws {
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(
            from: makeRealityProfile(network: "splithttp", path: "/xhttp", host: "cdn.example.com", mode: "stream-one")
        )
        let store = InMemoryRuntimeProfileStore(records: [record.profileID: record])
        let resolver = StaticRuntimeCredentialResolver(secrets: [record.credentialReference: TestSecrets().vlessUUID])
        let loader = RuntimeConfigurationLoader(store: store, credentialResolver: resolver)
        let providerConfiguration = try RuntimeProviderConfiguration(profileID: record.profileID, sharedRecordRevision: record.recordRevision)

        let resolved = try await loader.load(providerConfiguration: providerConfiguration.propertyList)
        let validation = await loader.validateRuntimeConfiguration(
            providerConfiguration: providerConfiguration.propertyList,
            correlationID: UUID(),
            expectedProfileID: record.profileID
        )
        let validationJSON = try encodedJSONString(validation)

        #expect(resolved.transport.kind == .xhttp)
        #expect(resolved.transport.xhttp?.path == "/xhttp")
        #expect(resolved.transport.xhttp?.host == "cdn.example.com")
        #expect(resolved.transport.xhttp?.mode == .streamOne)
        #expect(String(reflecting: resolved).contains("credential: <redacted>"))
        #expect(!String(reflecting: resolved).contains(TestSecrets().vlessUUID))
        #expect(validation.success)
        #expect(validation.transportName == "xhttp")
        #expect(validation.securityName == "reality")
        #expect(!validationJSON.contains("/xhttp"))
        #expect(!validationJSON.contains("cdn.example.com"))
        #expect(!validationJSON.contains("stream-one"))
        #expect(!validationJSON.contains(TestSecrets().realityPublicKey))
        #expect(!validationJSON.contains(TestSecrets().vlessUUID))
    }

    @Test
    func loaderRejectsProviderRecordAndCredentialMismatches() async throws {
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVLESSProfile())
        let store = InMemoryRuntimeProfileStore(records: [record.profileID: record])
        let resolver = StaticRuntimeCredentialResolver(secrets: [record.credentialReference: TestSecrets().vlessUUID])
        let loader = RuntimeConfigurationLoader(store: store, credentialResolver: resolver)

        await #expect(throws: RuntimeConfigurationError.profileRevisionMismatch) {
            _ = try await loader.load(providerConfiguration: RuntimeProviderConfiguration(profileID: record.profileID, recordRevision: 1).propertyList)
        }
        await #expect(throws: RuntimeConfigurationError.profileRecordNotFound) {
            _ = try await loader.load(providerConfiguration: RuntimeProviderConfiguration(profileID: UUID(), recordRevision: 1).propertyList)
        }

        var disabled = record
        disabled.enabled = false
        let disabledStore = InMemoryRuntimeProfileStore(records: [disabled.profileID: disabled])
        let disabledLoader = RuntimeConfigurationLoader(store: disabledStore, credentialResolver: resolver)
        await #expect(throws: RuntimeConfigurationError.profileDisabled) {
            _ = try await disabledLoader.load(providerConfiguration: RuntimeProviderConfiguration(profileID: disabled.profileID, sharedRecordRevision: disabled.recordRevision).propertyList)
        }

        var unsupportedSecurity = record
        unsupportedSecurity.security = SharedRuntimeSecurity(kind: .reality, serverName: nil, allowInsecure: false, fingerprint: nil, shortID: nil)
        let unsupportedSecurityStore = InMemoryRuntimeProfileStore(records: [unsupportedSecurity.profileID: unsupportedSecurity])
        let unsupportedSecurityLoader = RuntimeConfigurationLoader(store: unsupportedSecurityStore, credentialResolver: resolver)
        await #expect(throws: RuntimeConfigurationError.invalidSecurityConfiguration) {
            _ = try await unsupportedSecurityLoader.load(providerConfiguration: RuntimeProviderConfiguration(profileID: unsupportedSecurity.profileID, sharedRecordRevision: unsupportedSecurity.recordRevision).propertyList)
        }

        let missingCredentialLoader = RuntimeConfigurationLoader(
            store: store,
            credentialResolver: StaticRuntimeCredentialResolver(secrets: [:])
        )
        await #expect(throws: RuntimeConfigurationError.credentialUnavailable) {
            _ = try await missingCredentialLoader.load(providerConfiguration: RuntimeProviderConfiguration(profileID: record.profileID, sharedRecordRevision: record.recordRevision).propertyList)
        }

        let malformedCredentialLoader = RuntimeConfigurationLoader(
            store: store,
            credentialResolver: StaticRuntimeCredentialResolver(secrets: [record.credentialReference: "not-a-uuid"])
        )
        await #expect(throws: RuntimeConfigurationError.credentialMalformed) {
            _ = try await malformedCredentialLoader.load(providerConfiguration: RuntimeProviderConfiguration(profileID: record.profileID, sharedRecordRevision: record.recordRevision).propertyList)
        }
    }

    @Test
    func loaderValidatesCredentialsByRuntimeProtocol() async throws {
        let profiles = [makeVMessProfile(), makeTrojanProfile(), makeShadowsocksProfile(), makeHysteria2Profile()]
        let records = try profiles.map { try SharedRuntimeProfileMapper(now: fixedDate).record(from: $0) }
        let secrets = Dictionary(uniqueKeysWithValues: records.map { record in
            let secret = record.protocolKind == .vmess ? TestSecrets().vlessUUID : TestSecrets().password
            return (record.credentialReference, secret)
        })
        let store = InMemoryRuntimeProfileStore(records: Dictionary(uniqueKeysWithValues: records.map { ($0.profileID, $0) }))
        let loader = RuntimeConfigurationLoader(store: store, credentialResolver: StaticRuntimeCredentialResolver(secrets: secrets))

        for record in records {
            let resolved = try await loader.load(
                providerConfiguration: RuntimeProviderConfiguration(
                    profileID: record.profileID,
                    sharedRecordRevision: record.recordRevision
                ).propertyList
            )
            #expect(resolved.protocolKind == record.protocolKind)
            #expect(String(reflecting: resolved).contains("credential: <redacted>"))
            #expect(!String(reflecting: resolved).contains(TestSecrets().password))
            #expect(!String(reflecting: resolved).contains(TestSecrets().vlessUUID))
        }

        let vmess = try #require(records.first { $0.protocolKind == .vmess })
        let malformedVMessLoader = RuntimeConfigurationLoader(
            store: store,
            credentialResolver: StaticRuntimeCredentialResolver(secrets: [vmess.credentialReference: TestSecrets().password])
        )
        await #expect(throws: RuntimeConfigurationError.credentialMalformed) {
            _ = try await malformedVMessLoader.load(
                providerConfiguration: RuntimeProviderConfiguration(
                    profileID: vmess.profileID,
                    sharedRecordRevision: vmess.recordRevision
                ).propertyList
            )
        }

        let obfsProfile = makeHysteria2Profile(
            obfs: "salamander",
            obfsPasswordReference: "keychain://vpn.credentials/hysteria2-obfs"
        )
        let obfsRecord = try SharedRuntimeProfileMapper(now: fixedDate).record(from: obfsProfile)
        let obfsStore = InMemoryRuntimeProfileStore(records: [obfsRecord.profileID: obfsRecord])
        let obfsLoader = RuntimeConfigurationLoader(
            store: obfsStore,
            credentialResolver: StaticRuntimeCredentialResolver(secrets: [
                obfsRecord.credentialReference: TestSecrets().password,
                "keychain://vpn.credentials/hysteria2-obfs": TestSecrets().privateKey
            ])
        )
        let resolvedObfs = try await obfsLoader.load(
            providerConfiguration: RuntimeProviderConfiguration(
                profileID: obfsRecord.profileID,
                sharedRecordRevision: obfsRecord.recordRevision
            ).propertyList
        )
        #expect(resolvedObfs.protocolKind == .hysteria2)
        #expect(!String(reflecting: resolvedObfs).contains(TestSecrets().privateKey))

        let missingObfsLoader = RuntimeConfigurationLoader(
            store: obfsStore,
            credentialResolver: StaticRuntimeCredentialResolver(secrets: [
                obfsRecord.credentialReference: TestSecrets().password
            ])
        )
        await #expect(throws: RuntimeConfigurationError.credentialUnavailable) {
            _ = try await missingObfsLoader.load(
                providerConfiguration: RuntimeProviderConfiguration(
                    profileID: obfsRecord.profileID,
                    sharedRecordRevision: obfsRecord.recordRevision
                ).propertyList
            )
        }
    }

    @Test
    func validationResponseIsSafeAndReportsMismatches() async throws {
        let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeVLESSProfile())
        let loader = RuntimeConfigurationLoader(
            store: InMemoryRuntimeProfileStore(records: [record.profileID: record]),
            credentialResolver: StaticRuntimeCredentialResolver(secrets: [record.credentialReference: TestSecrets().vlessUUID])
        )
        let correlationID = UUID()

        let providerConfiguration = try RuntimeProviderConfiguration(profileID: record.profileID, sharedRecordRevision: record.recordRevision)
        let success = await loader.validateRuntimeConfiguration(
            providerConfiguration: providerConfiguration.propertyList,
            correlationID: correlationID,
            expectedProfileID: record.profileID
        )

        #expect(success.success)
        #expect(success.correlationID == correlationID)
        #expect(success.providerConfigurationValid)
        #expect(success.profileFound)
        #expect(success.credentialFound)
        #expect(success.credentialFormatValid)
        #expect(success.protocolName == "vless")
        let responseJSON = try encodedJSONString(success)
        assertNoSecretMaterial(in: responseJSON, secrets: TestSecrets())
        #expect(!responseJSON.contains(record.credentialReference))
        #expect(!responseJSON.contains(record.endpoint.host))

        let mismatch = await loader.validateRuntimeConfiguration(
            providerConfiguration: providerConfiguration.propertyList,
            correlationID: UUID(),
            expectedProfileID: UUID()
        )
        #expect(!mismatch.success)
        #expect(mismatch.diagnostic?.category == .profileIdentityMismatch)

        let revisionMismatch = await loader.validateRuntimeConfiguration(
            providerConfiguration: providerConfiguration.propertyList,
            correlationID: UUID(),
            expectedProfileID: record.profileID,
            expectedRevisionToken: providerConfiguration.recordRevision + 1
        )
        #expect(!revisionMismatch.success)
        #expect(revisionMismatch.diagnostic?.stage == .providerConfiguration)
        #expect(revisionMismatch.diagnostic?.category == .profileRevisionMismatch)
    }
}

struct RuntimeConfigurationValidationIPCTests {
    @Test
    func validationRequestAndResponseContainNoSecretMaterial() throws {
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .validateRuntimeConfiguration,
            payload: .runtimeConfigurationValidation(
                TunnelRuntimeConfigurationValidationRequest(correlationID: correlationID, expectedProfileID: UUID())
            )
        )
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .runtimeConfigurationValidation(
                .success(
                    correlationID: correlationID,
                    protocolName: "vless",
                    transportName: "websocket",
                    securityName: "tls"
                )
            )
        )

        let requestJSON = try encodedJSONString(request)
        let responseJSON = try encodedJSONString(response)
        let secrets = TestSecrets()

        assertNoSecretMaterial(in: requestJSON, secrets: secrets)
        assertNoSecretMaterial(in: responseJSON, secrets: secrets)
        #expect(!requestJSON.contains("keychain://"))
        #expect(!responseJSON.contains("keychain://"))
        #expect(!responseJSON.contains("example.com"))
        #expect(!responseJSON.contains("raw"))
    }

    @Test
    func handlerRespondsExactlyOnceWithValidationPayload() async throws {
        let correlationID = UUID()
        let loader = MockValidationLoader(
            response: .success(correlationID: correlationID, protocolName: "vless")
        )
        let handler = TunnelAppMessageHandler(runtimeValidationLoader: loader)
        let request = TunnelMessageRequest(
            kind: .validateRuntimeConfiguration,
            payload: .runtimeConfigurationValidation(
                TunnelRuntimeConfigurationValidationRequest(correlationID: correlationID, expectedProfileID: UUID())
            )
        )

        let data = await handler.handle(try encode(request))
        let response = try tunnelMessageDecoder().decode(TunnelMessageResponse.self, from: data)

        #expect(response.requestID == request.requestID)
        #expect(response.success)
        guard case .runtimeConfigurationValidation(let validation)? = response.payload else {
            Issue.record("Expected runtime configuration validation payload")
            return
        }
        #expect(validation.success)
        #expect(validation.correlationID == correlationID)
        #expect(await loader.callCount == 1)
    }

    @Test
    func validationServiceRejectsStaleOrInvalidResponses() async throws {
        let profile = makeVLESSProfile()
        let publisher = SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: InMemoryRuntimeProfileStore(),
            credentialStore: StaticCredentialStore(secrets: [profile.credentialReference!: TestSecrets().vlessUUID])
        )

        let staleMessenger = StaticValidationMessenger(
            responseBuilder: { request in
                TunnelMessageResponse.success(
                    request: request,
                    payload: .runtimeConfigurationValidation(.success(correlationID: UUID(), protocolName: "vless"))
                )
            }
        )
        let staleService = RuntimeConfigurationValidationService(publisher: publisher, messenger: staleMessenger)
        await expectValidationFailure {
            _ = try await staleService.validate(profile: profile)
        }

        let invalidMessenger = StaticValidationMessenger(
            responseBuilder: { request in
                TunnelMessageResponse.success(
                    request: request,
                    payload: .pong(TunnelPongSnapshot(extensionProcessAlive: true, schemaVersion: TunnelMessageProtocol.schemaVersion))
                )
            }
        )
        let invalidService = RuntimeConfigurationValidationService(publisher: publisher, messenger: invalidMessenger)
        await expectValidationFailure {
            _ = try await invalidService.validate(profile: profile)
        }
        #expect(await staleMessenger.sentRequests.count == 1)
        #expect(await invalidMessenger.sentRequests.count == 1)
    }

    @Test
    func validationServiceMarksExtensionProviderParseFailureAsContractMismatch() async throws {
        let profile = makeVLESSProfile()
        let publisher = SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: InMemoryRuntimeProfileStore(),
            credentialStore: StaticCredentialStore(secrets: [profile.credentialReference!: TestSecrets().vlessUUID])
        )
        let messenger = StaticValidationMessenger(
            responseBuilder: { request in
                guard case .runtimeConfigurationValidation(let payload)? = request.payload else {
                    return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
                }
                let providerDiagnostic = TunnelProviderConfigurationDiagnostic(
                    keyCount: 4,
                    keyNames: ["diagnosticPurpose", "profileID", "recordRevision", "schemaVersion"],
                    valueTypesByKey: [
                        "diagnosticPurpose": "String",
                        "profileID": "String",
                        "recordRevision": "Number",
                        "schemaVersion": "Number"
                    ],
                    parseSubreason: .providerConfigurationUnknownKey
                )
                return TunnelMessageResponse.success(
                    request: request,
                    payload: .runtimeConfigurationValidation(
                        .failure(
                            correlationID: payload.correlationID,
                            stage: .providerConfiguration,
                            category: .providerConfigurationUnknownKey,
                            providerConfigurationDiagnostic: providerDiagnostic
                        )
                    )
                )
            }
        )
        let service = RuntimeConfigurationValidationService(publisher: publisher, messenger: messenger)

        let result = try await service.validate(profile: profile)

        #expect(!result.success)
        #expect(result.diagnostic?.category == .providerConfigurationContractMismatch)
        #expect(result.diagnostic?.providerConfiguration?.parseSubreason == .providerConfigurationUnknownKey)
        #expect(await messenger.sentProviderConfigurations.count == 1)
    }

    @Test
    func validationServiceSendsExpectedRevisionAndGeneration() async throws {
        let profile = makeVLESSProfile()
        let publisher = SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: InMemoryRuntimeProfileStore(),
            credentialStore: StaticCredentialStore(secrets: [profile.credentialReference!: TestSecrets().vlessUUID])
        )
        let messenger = StaticValidationMessenger(
            responseBuilder: { request in
                guard case .runtimeConfigurationValidation(let payload)? = request.payload else {
                    return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
                }
                return TunnelMessageResponse.success(
                    request: request,
                    payload: .runtimeConfigurationValidation(.success(correlationID: payload.correlationID, protocolName: "vless"))
                )
            }
        )
        let service = RuntimeConfigurationValidationService(publisher: publisher, messenger: messenger)

        _ = try await service.validate(profile: profile)
        _ = try await service.validate(profile: profile)

        let requests = await messenger.sentRequests
        let providerConfigurations = await messenger.sentProviderConfigurations
        #expect(requests.count == 2)
        #expect(providerConfigurations.count == 2)
        guard case .runtimeConfigurationValidation(let firstPayload)? = requests.first?.payload,
              case .runtimeConfigurationValidation(let secondPayload)? = requests.last?.payload else {
            Issue.record("Expected runtime validation payloads")
            return
        }
        #expect(firstPayload.expectedProfileID == profile.id)
        #expect(firstPayload.expectedRevisionToken == providerConfigurations[0].recordRevision)
        #expect(firstPayload.requestGeneration == 1)
        #expect(secondPayload.expectedProfileID == profile.id)
        #expect(secondPayload.expectedRevisionToken == providerConfigurations[1].recordRevision)
        #expect(secondPayload.requestGeneration == 2)

        let requestJSON = try encodedJSONString(requests[0])
        assertNoSecretMaterial(in: requestJSON, secrets: TestSecrets())
        #expect(!requestJSON.contains("keychain://"))
        #expect(!requestJSON.contains("example.com"))
    }
}

struct XrayConfigurationBuilderTests {
    @Test
    func tcpTLSProducesDeterministicValidStructure() throws {
        let first = try xrayJSONString(from: makeTCPTLSProfile())
        let second = try xrayJSONString(from: makeTCPTLSProfile())

        #expect(first == second)
        #expect(first.contains(#""protocol":"vless""#))
        #expect(first.contains(#""network":"tcp""#))
        #expect(first.contains(#""security":"tls""#))
        #expect(first.contains(#""serverName":"sni.example.com""#))
        #expect(first.contains(#""fingerprint":"chrome""#))
        #expect(first.contains(#""encryption":"none""#))
        #expect(first.contains(TestSecrets().vlessUUID))
        #expect(!first.contains(#""xhttpSettings""#))
        #expect(!first.contains(#""flow""#))
    }

    @Test
    func packetTunnelDataPlaneXraySocksInboundEnablesUDPOnLoopbackOnly() throws {
        let json = try xrayJSONString(
            from: makeTCPTLSProfile(),
            options: XrayBuildOptions(
                localSocksListenAddress: "127.0.0.1",
                localSocksPort: 20_480,
                localSocksUDPEnabled: true
            )
        )
        let object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let inbounds = try #require(object["inbounds"] as? [[String: Any]])
        let inbound = try #require(inbounds.first)
        let settings = try #require(inbound["settings"] as? [String: Any])

        #expect(inbound["listen"] as? String == "127.0.0.1")
        #expect(inbound["port"] as? Int == 20_480)
        #expect(inbound["protocol"] as? String == "socks")
        #expect(settings["auth"] as? String == "noauth")
        #expect(settings["udp"] as? Bool == true)
    }

    @Test
    func defaultXraySocksInboundKeepsUDPDisabledForValidationAndSmokeModes() throws {
        let json = try xrayJSONString(from: makeTCPTLSProfile())
        let object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let inbounds = try #require(object["inbounds"] as? [[String: Any]])
        let inbound = try #require(inbounds.first)
        let settings = try #require(inbound["settings"] as? [String: Any])

        #expect(inbound["listen"] as? String == "127.0.0.1")
        #expect(settings["udp"] as? Bool == false)
    }

    @Test
    func tcpRealityProducesDeterministicValidStructure() throws {
        let json = try xrayJSONString(from: makeRealityProfile())

        #expect(json.contains(#""network":"tcp""#))
        #expect(json.contains(#""security":"reality""#))
        #expect(json.contains(#""serverName":"site.example.com""#))
        #expect(json.contains(#""publicKey":"\#(TestSecrets().realityPublicKey)""#))
        #expect(json.contains(#""shortId":"abcd""#))
        #expect(json.contains(#""spiderX":"\/""#))
        #expect(json.contains(#""flow":"xtls-rprx-vision""#))
        #expect(!json.contains(#""tlsSettings""#))
    }

    @Test
    func xhttpTLSProducesCanonicalXHTTPStructure() throws {
        let json = try xrayJSONString(from: makeXHTTPTLSProfile(mode: "stream-one"))

        #expect(json.contains(#""network":"xhttp""#))
        #expect(!json.contains("splithttp"))
        #expect(json.contains(#""xhttpSettings":{"host":"cdn.example.com","mode":"stream-one","path":"\/xhttp"}"#))
        #expect(json.contains(#""security":"tls""#))
        #expect(!json.contains(#""realitySettings""#))
    }

    @Test
    func xhttpRealityProducesCanonicalXHTTPStructure() throws {
        let json = try xrayJSONString(
            from: makeRealityProfile(network: "splithttp", path: "/xhttp", host: "cdn.example.com", mode: "packet-up")
        )

        #expect(json.contains(#""network":"xhttp""#))
        #expect(!json.contains("splithttp"))
        #expect(json.contains(#""mode":"packet-up""#))
        #expect(json.contains(#""security":"reality""#))
        #expect(json.contains(#""publicKey":"\#(TestSecrets().realityPublicKey)""#))
    }

    @Test
    func vmessOutboundUsesTypedRuntimeConfiguration() throws {
        let json = try xrayJSONString(from: makeVMessProfile(), credential: TestSecrets().vlessUUID)

        #expect(json.contains(#""protocol":"vmess""#))
        #expect(json.contains(#""network":"ws""#))
        #expect(json.contains(#""wsSettings":{"headers":{"Host":"cdn.example.com"},"path":"\/vmess"}"#))
        #expect(json.contains(#""security":"tls""#))
        #expect(json.contains(#""alterId":0"#))
        #expect(json.contains(#""id":"\#(TestSecrets().vlessUUID)""#))
        #expect(!json.contains("keychain://"))
    }

    @Test
    func trojanOutboundUsesPasswordOnlyInsideSensitiveXrayJSON() throws {
        let json = try xrayJSONString(from: makeTrojanProfile(), credential: TestSecrets().password)

        #expect(json.contains(#""protocol":"trojan""#))
        #expect(json.contains(#""network":"xhttp""#))
        #expect(json.contains(#""xhttpSettings":{"host":"cdn.example.com","mode":"stream-one","path":"\/trojan"}"#))
        #expect(json.contains(#""security":"tls""#))
        #expect(json.contains(#""password":"\#(TestSecrets().password)""#))
        #expect(!json.contains("keychain://"))
    }

    @Test
    func shadowsocksAndOutlineUseShadowsocksOutboundWithUDPDataPlaneInbound() throws {
        let json = try xrayJSONString(
            from: makeShadowsocksProfile(outline: true),
            credential: TestSecrets().password,
            options: XrayBuildOptions(localSocksListenAddress: "127.0.0.1", localSocksPort: 20_481, localSocksUDPEnabled: true)
        )

        #expect(json.contains(#""protocol":"shadowsocks""#))
        #expect(!json.contains(#""protocol":"outline""#))
        #expect(json.contains(#""method":"chacha20-ietf-poly1305""#))
        #expect(json.contains(#""password":"\#(TestSecrets().password)""#))
        #expect(json.contains(#""security":"none""#))
        #expect(json.contains(#""udp":true"#))
        #expect(!json.contains("keychain://"))
    }

    @Test
    func hysteria2OutboundUsesXrayHysteriaTransportAndTLS() throws {
        let json = try xrayJSONString(from: makeHysteria2Profile(), credential: TestSecrets().password)
        let tlsSettings = try firstXrayOutboundTLSSettings(from: json)
        let object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        let outbounds = try #require(object["outbounds"] as? [[String: Any]])

        #expect(json.contains(#""protocol":"hysteria""#))
        #expect(json.contains(#""method":"hysteria""#))
        #expect(json.contains(#""network":"hysteria""#))
        #expect(json.contains(#""security":"tls""#))
        #expect(json.contains(#""version":2"#))
        #expect(json.contains(#""auth":"\#(TestSecrets().password)""#))
        #expect(tlsSettings["serverName"] as? String == "hy2-sni.example.com")
        #expect((tlsSettings["alpn"] as? [String]) == ["h3"])
        #expect(!json.contains("realitySettings"))
        #expect(!json.contains("finalmask"))
        #expect(!json.contains("keychain://"))
        #expect(outbounds.map { $0["protocol"] as? String } == ["hysteria"])
        #expect(!json.contains(#""protocol":"freedom""#))
    }

    @Test
    func hysteria2AllowInsecureMapsOnlyWhenRequested() throws {
        let insecureJSON = try xrayJSONString(
            from: makeHysteria2Profile(allowInsecure: true),
            credential: TestSecrets().password
        )
        let secureJSON = try xrayJSONString(
            from: makeHysteria2Profile(allowInsecure: false),
            credential: TestSecrets().password
        )

        #expect(try firstXrayOutboundTLSSettings(from: insecureJSON)["allowInsecure"] as? Bool == true)
        #expect(try firstXrayOutboundTLSSettings(from: secureJSON)["allowInsecure"] as? Bool == false)
    }

    @Test
    func hysteria2TLSUsesHostnameFallbackWhenSNIIsAbsent() throws {
        let json = try xrayJSONString(
            from: makeHysteria2Profile(serverName: nil, serverAddress: "hy2-fallback.example.com"),
            credential: TestSecrets().password
        )
        let tlsSettings = try firstXrayOutboundTLSSettings(from: json)

        #expect(tlsSettings["serverName"] as? String == "hy2-fallback.example.com")
        #expect((tlsSettings["alpn"] as? [String]) == ["h3"])
    }

    @Test
    func hysteria2IPServerKeepsExplicitSNI() throws {
        let json = try xrayJSONString(
            from: makeHysteria2Profile(serverName: "hy2-sni.example.com", serverAddress: "203.0.113.10"),
            credential: TestSecrets().password
        )
        let outbound = try firstXrayOutbound(from: json)
        let settings = try #require(outbound["settings"] as? [String: Any])
        let tlsSettings = try firstXrayOutboundTLSSettings(from: json)

        #expect(settings["address"] as? String == "203.0.113.10")
        #expect(tlsSettings["serverName"] as? String == "hy2-sni.example.com")
        #expect((tlsSettings["alpn"] as? [String]) == ["h3"])
    }

    @Test
    func nonHysteriaTLSDoesNotEmitH3ALPN() throws {
        for profile in [makeTCPTLSProfile(), makeVMessProfile(), makeTrojanProfile()] {
            let tlsSettings = try firstXrayOutboundTLSSettings(
                from: xrayJSONString(from: profile, credential: TestSecrets().vlessUUID)
            )
            #expect(tlsSettings["alpn"] == nil)
        }
    }

    @Test
    func malformedHysteria2TLSConfigurationFailsClosed() throws {
        #expect(throws: XrayConfigurationBuilderError.invalidTLSConfiguration) {
            _ = try xrayJSONString(
                from: makeHysteria2Profile(serverName: "bad sni.example.com"),
                credential: TestSecrets().password
            )
        }
    }

    @Test
    func hysteria2SalamanderUsesFinalMaskWithSecondaryCredentialOnlyInSensitiveJSON() throws {
        let reference = "keychain://vpn.credentials/hysteria2-obfs"
        let json = try xrayJSONString(
            from: makeHysteria2Profile(obfs: "salamander", obfsPasswordReference: reference),
            credential: TestSecrets().password,
            hysteria2ObfsPassword: TestSecrets().privateKey
        )

        #expect(json.contains(#""finalmask":{"udp":[{"settings":{"password":"\#(TestSecrets().privateKey)"},"type":"salamander"}]}"#))
        #expect(!json.contains(reference))
        #expect(!json.contains("obfs-password"))
    }

    @Test
    func unsupportedAdvancedProtocolFeaturesFailBeforeRuntime() throws {
        #expect(throws: RuntimeConfigurationError.unsupportedProtocol) {
            _ = try xrayJSONString(from: makeShadowsocksProfile(plugin: "v2ray-plugin"), credential: TestSecrets().password)
        }
        #expect(throws: XrayConfigurationBuilderError.unsupportedProtocol) {
            _ = try xrayJSONString(from: makeHysteria2Profile(obfs: "salamander"), credential: TestSecrets().password)
        }
        #expect(throws: RuntimeConfigurationError.invalidSecurityConfiguration) {
            _ = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeHysteria2Profile(security: "reality"))
        }
        #expect(throws: RuntimeConfigurationError.unsupportedProtocol) {
            _ = try SharedRuntimeProfileMapper(now: fixedDate).record(from: makeHysteria2Profile(metadata: ["echConfig": "unsupported"]))
        }
    }

    @Test
    func socksRemoteConnectRequestAndResponseParsingAreSanitized() throws {
        #expect([UInt8](XraySOCKS5RemoteConnect.requestBytes) == [0x05, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x50])
        #expect(XraySOCKS5RemoteConnect.targetHost == "1.1.1.1")
        #expect(XraySOCKS5RemoteConnect.targetPort == 80)

        #expect(XraySOCKS5RemoteConnect.parseReply(Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])) == .success)
        #expect(XraySOCKS5RemoteConnect.parseReply(Data([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])) == .socksConnectRejected)
        #expect(XraySOCKS5RemoteConnect.parseReply(Data([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])) == .socksConnectRejected)
        #expect(XraySOCKS5RemoteConnect.parseReply(Data([0x05, 0x00, 0x00])) == .timeout)
        #expect(XraySOCKS5RemoteConnect.parseReply(Data([0x04, 0x00, 0x00, 0x01])) == .unknown)
        #expect(String(decoding: XrayRemoteEgressHTTPProbe.requestBytes, as: UTF8.self) == "GET / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
        #expect(XrayRemoteEgressHTTPProbe.maximumResponseBytes == 16 * 1_024)
    }

    @Test
    func remoteEgressPayloadProbeRequiresRemoteResponseBytes() throws {
        let ackOnly = XrayRemoteEgressHTTPProbe.evaluate(
            socksConnectRequested: true,
            socksConnectCategory: .success,
            payloadWriteSucceeded: false,
            responseData: nil
        )
        #expect(ackOnly.socksConnectAccepted)
        #expect(ackOnly.success == false)
        #expect(ackOnly.category == .payloadWriteFailed)

        let noResponse = XrayRemoteEgressHTTPProbe.evaluate(
            socksConnectRequested: true,
            socksConnectCategory: .success,
            payloadWriteSucceeded: true,
            responseData: nil
        )
        #expect(noResponse.socksConnectAccepted)
        #expect(noResponse.payloadWriteSucceeded)
        #expect(noResponse.success == false)
        #expect(noResponse.category == .remoteFirstByteTimeout)

        let readFailure = XrayRemoteEgressHTTPProbe.evaluate(
            socksConnectRequested: true,
            socksConnectCategory: .success,
            payloadWriteSucceeded: true,
            responseData: nil,
            responseReadFailed: true
        )
        #expect(readFailure.category == .remoteReadFailed)

        let malformed = XrayRemoteEgressHTTPProbe.evaluate(
            socksConnectRequested: true,
            socksConnectCategory: .success,
            payloadWriteSucceeded: true,
            responseData: Data("SSH-2.0\r\n".utf8)
        )
        #expect(malformed.remoteFirstByteReceived)
        #expect(malformed.remoteResponseValidated == false)
        #expect(malformed.success == false)
        #expect(malformed.category == .remoteResponseInvalid)

        let http = XrayRemoteEgressHTTPProbe.evaluate(
            socksConnectRequested: true,
            socksConnectCategory: .success,
            payloadWriteSucceeded: true,
            responseData: Data("HTTP/1.1 301 Moved Permanently\r\n".utf8)
        )
        #expect(http.success)
        #expect(http.socksConnectAccepted)
        #expect(http.payloadWriteSucceeded)
        #expect(http.remoteFirstByteReceived)
        #expect(http.remoteResponseValidated)
        #expect(http.category == .success)
    }

    @Test
    func udpControlDNSProbeRequiresMatchingResponseDatagram() throws {
        let requestBytes = [UInt8](UDPControlDNSProbe.requestBytes)
        #expect(UDPControlDNSProbe.targetHost == "1.1.1.1")
        #expect(UDPControlDNSProbe.targetPort == 53)
        #expect(UDPControlDNSProbe.maximumResponseBytes == 512)
        #expect(Array(requestBytes.prefix(2)) == [0x4B, 0x4E])
        #expect(Array(requestBytes.suffix(4)) == [0x00, 0x01, 0x00, 0x01])

        let readyOnly = UDPControlDNSProbe.evaluate(
            connectionReady: true,
            writeSucceeded: false,
            responseData: nil
        )
        #expect(readyOnly.success == false)
        #expect(readyOnly.category == .writeFailed)
        #expect(readyOnly.udpConnectionReady)
        #expect(readyOnly.udpWriteSucceeded == false)

        let writeOnly = UDPControlDNSProbe.evaluate(
            connectionReady: true,
            writeSucceeded: true,
            responseData: nil
        )
        #expect(writeOnly.success == false)
        #expect(writeOnly.category == .readTimeout)
        #expect(writeOnly.udpWriteSucceeded)
        #expect(writeOnly.udpResponseReceived == false)

        let readFailure = UDPControlDNSProbe.evaluate(
            connectionReady: true,
            writeSucceeded: true,
            responseData: nil,
            responseReadFailed: true
        )
        #expect(readFailure.category == .readFailed)

        let malformed = UDPControlDNSProbe.evaluate(
            connectionReady: true,
            writeSucceeded: true,
            responseData: Data([0x4B, 0x4E, 0x01])
        )
        #expect(malformed.success == false)
        #expect(malformed.category == .invalidResponse)
        #expect(malformed.udpResponseReceived)

        let mismatched = UDPControlDNSProbe.evaluate(
            connectionReady: true,
            writeSucceeded: true,
            responseData: dnsResponse(transactionID: 0x1234)
        )
        #expect(mismatched.success == false)
        #expect(mismatched.category == .invalidResponse)

        let valid = UDPControlDNSProbe.evaluate(
            connectionReady: true,
            writeSucceeded: true,
            responseData: dnsResponse(transactionID: UDPControlDNSProbe.transactionID)
        )
        #expect(valid.success)
        #expect(valid.udpConnectionReady)
        #expect(valid.udpWriteSucceeded)
        #expect(valid.udpResponseReceived)
        #expect(valid.udpResponseValidated)
        #expect(valid.category == .success)

        let cancelled = UDPControlDNSProbe.evaluate(
            connectionReady: false,
            writeSucceeded: false,
            responseData: nil,
            cancelled: true
        )
        #expect(cancelled.category == .cancelled)

        let pathUnsatisfied = UDPControlDNSProbe.evaluate(
            connectionReady: false,
            writeSucceeded: false,
            responseData: nil,
            pathUnsatisfied: true
        )
        #expect(pathUnsatisfied.category == .pathUnsatisfied)
    }

    @Test
    func xhttpModesArePreservedThroughSettings() throws {
        for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
            let json = try xrayJSONString(from: makeXHTTPTLSProfile(mode: mode))
            #expect(json.contains(#""mode":"\#(mode)""#))
        }
    }

    @Test
    func builderRejectsUnsupportedTransportAndMalformedInputs() throws {
        #expect(throws: XrayConfigurationBuilderError.unsupportedTransport) {
            _ = try XrayConfigurationBuilder().build(from: resolvedConfiguration(from: makeVLESSProfile()), options: XrayBuildOptions())
        }

        var malformedXHTTP = try resolvedConfiguration(from: makeXHTTPTLSProfile())
        malformedXHTTP.transport = SharedRuntimeTransport(
            kind: .xhttp,
            path: "not-a-path",
            host: "cdn.example.com",
            serviceName: nil,
            mode: "auto",
            xhttp: SharedRuntimeXHTTPParameters(path: "not-a-path", host: "cdn.example.com", mode: .auto)
        )
        #expect(throws: XrayConfigurationBuilderError.invalidXHTTPPath) {
            _ = try XrayConfigurationBuilder().build(from: malformedXHTTP, options: XrayBuildOptions())
        }

        var malformedReality = try resolvedConfiguration(from: makeRealityProfile())
        malformedReality.security.reality?.publicKey = "bad-key"
        #expect(throws: XrayConfigurationBuilderError.invalidRealityConfiguration) {
            _ = try XrayConfigurationBuilder().build(from: malformedReality, options: XrayBuildOptions())
        }

        var invalidEndpoint = try resolvedConfiguration(from: makeTCPTLSProfile())
        invalidEndpoint.endpoint = ResolvedRuntimeEndpoint(host: "bad host", port: 443)
        #expect(throws: XrayConfigurationBuilderError.invalidEndpoint) {
            _ = try XrayConfigurationBuilder().build(from: invalidEndpoint, options: XrayBuildOptions())
        }
    }

    @Test
    func sensitiveConfigurationAndBuilderErrorsAreRedacted() throws {
        let secrets = TestSecrets()
        let json = try xrayJSONString(from: makeTCPTLSProfile(), credential: secrets.vlessUUID)
        let configuration = try xrayConfiguration(from: makeTCPTLSProfile(), credential: secrets.vlessUUID)

        #expect(json.contains(secrets.vlessUUID))
        #expect(!json.contains("keychain://"))
        #expect(!json.contains(secrets.rawURI))
        #expect(!json.contains(secrets.password))
        #expect(!json.contains(secrets.token))
        #expect(!json.contains(secrets.privateKey))
        #expect(!json.contains(secrets.arbitraryMetadataSecret))
        #expect(String(describing: configuration) == "<redacted>")
        #expect(String(reflecting: configuration) == "<redacted>")
        #expect(!String(describing: XrayConfigurationBuilderError.invalidCredential).contains(secrets.vlessUUID))
    }

    @Test
    func generatedConfigurationHasNoRandomFieldsOrDiskLogs() throws {
        let json = try xrayJSONString(from: makeXHTTPTLSProfile())

        #expect(!json.contains("generatedAt"))
        #expect(!json.contains("timestamp"))
        #expect(!json.contains(#""accessLog""#))
        #expect(!json.contains(#""errorLog""#))
        #expect(json.contains(#""access":"none""#))
        #expect(json.contains(#""error":"none""#))
        #expect(json.contains(#""listen":"127.0.0.1""#))
        #expect(json.contains(#""port":10808"#))
        #expect(!json.contains("0.0.0.0"))
    }
}

struct LibXrayAdapterTests {
    @Test
    func supportedAPIVersionBuildsTestXrayEnvelopeAndInvokesOnce() async throws {
        let invoker = RecordingLibXrayRawInvoker(response: #"{"success":true,"data":{}}"#)
        let adapter = LibXrayTestAdapterCore(invoker: invoker)
        let configuration = try xrayConfiguration(from: makeTCPTLSProfile())

        let result = await adapter.test(configuration)

        #expect(result.success)
        #expect(result.apiVersionSupported)
        #expect(result.invoked)
        #expect(result.category == .none)
        #expect(invoker.requestCount == 1)

        let request = try #require(invoker.lastRequest)
        #expect(request.contains(#""apiVersion":2"#))
        #expect(request.contains(#""method":"testXray""#))
        #expect(request.contains(#""xrayJson":"#))
        #expect(!request.contains("runXray"))
        #expect(!request.contains("stopXray"))
    }

    @Test
    func generatedHysteria2ConfigurationCanPassTestXrayBoundary() async throws {
        let invoker = RecordingLibXrayRawInvoker(response: #"{"success":true,"data":{},"error":""}"#)
        let adapter = LibXrayTestAdapterCore(invoker: invoker)
        let configuration = try xrayConfiguration(from: makeHysteria2Profile(), credential: TestSecrets().password)

        let result = await adapter.test(configuration)

        #expect(result.success)
        #expect(result.category == .none)
        #expect(invoker.requestCount == 1)
        let request = try #require(invoker.lastRequest)
        #expect(request.contains(#""method":"testXray""#))
        #expect(request.contains(#""xrayJson":"#))
        #expect(!request.contains("runXray"))
        #expect(!request.contains("stopXray"))
    }

    @Test
    func unsupportedAPIVersionIsRejectedBeforeInvocation() async throws {
        let invoker = RecordingLibXrayRawInvoker(apiVersion: 1, response: #"{"success":true,"data":{}}"#)
        let adapter = LibXrayTestAdapterCore(invoker: invoker)

        let result = await adapter.test(try xrayConfiguration(from: makeTCPTLSProfile()))

        #expect(!result.success)
        #expect(!result.apiVersionSupported)
        #expect(!result.invoked)
        #expect(result.category == .unsupportedLibXrayAPIVersion)
        #expect(invoker.requestCount == 0)
    }

    @Test
    func adapterMapsFailureResponsesWithoutExposingRawText() async throws {
        let rawSecret = TestSecrets().vlessUUID
        let invoker = RecordingLibXrayRawInvoker(response: #"{"success":false,"error":"\#(rawSecret)"}"#)
        let adapter = LibXrayTestAdapterCore(invoker: invoker)

        let result = await adapter.test(try xrayConfiguration(from: makeTCPTLSProfile()))
        let resultText = String(describing: result)

        #expect(!result.success)
        #expect(result.invoked)
        #expect(result.category == .configurationRejected)
        #expect(!resultText.contains(rawSecret))
    }

    @Test
    func adapterRejectsMalformedAndEmptyResponses() async throws {
        let empty = LibXrayTestAdapterCore(invoker: RecordingLibXrayRawInvoker(response: ""))
        let malformed = LibXrayTestAdapterCore(invoker: RecordingLibXrayRawInvoker(response: "not-json"))
        let configuration = try xrayConfiguration(from: makeTCPTLSProfile())

        let emptyResult = await empty.test(configuration)
        let malformedResult = await malformed.test(configuration)

        #expect(emptyResult.category == .emptyResponse)
        #expect(malformedResult.category == .malformedResponse)
    }

    @Test
    func concurrentAdapterCallsAreSerializedByDedicatedExecutor() async throws {
        let invoker = RecordingLibXrayRawInvoker(response: #"{"success":true,"data":{}}"#)
        let adapter = LibXrayTestAdapterCore(invoker: invoker)
        let configuration = try xrayConfiguration(from: makeTCPTLSProfile())

        async let first = adapter.test(configuration)
        async let second = adapter.test(configuration)
        async let third = adapter.test(configuration)
        _ = await [first, second, third]

        #expect(invoker.requestCount == 3)
        #expect(invoker.maximumConcurrentInvocations == 1)
    }
}

struct XrayConfigurationValidationIPCTests {
    @Test
    func xrayValidationRequestAndResponseContainNoSecretMaterial() throws {
        let secrets = TestSecrets()
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .validateXrayConfiguration,
            payload: .xrayConfigurationValidation(
                TunnelXrayConfigurationValidationRequest(
                    correlationID: correlationID,
                    expectedProfileID: UUID(),
                    expectedRevisionToken: 12_345,
                    requestGeneration: 1
                )
            )
        )
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .xrayConfigurationValidation(
                .success(
                    correlationID: correlationID,
                    protocolName: "vless",
                    transportName: "xhttp",
                    securityName: "reality"
                )
            )
        )

        let requestJSON = try encodedJSONString(request)
        let responseJSON = try encodedJSONString(response)

        assertNoSecretMaterial(in: requestJSON, secrets: secrets)
        assertNoSecretMaterial(in: responseJSON, secrets: secrets)
        #expect(!requestJSON.contains("keychain://"))
        #expect(!responseJSON.contains("keychain://"))
        #expect(!responseJSON.contains(secrets.realityPublicKey))
        #expect(!responseJSON.contains("/xhttp"))
        #expect(!responseJSON.contains("cdn.example.com"))
        #expect(!responseJSON.contains("site.example.com"))
        #expect(responseJSON.contains("xhttp"))
        #expect(responseJSON.contains("reality"))
    }

    @Test
    func handlerRespondsExactlyOnceWithXrayValidationPayload() async throws {
        let correlationID = UUID()
        let validator = await MockXrayConfigurationValidator(
            response: .success(
                correlationID: correlationID,
                protocolName: "vless",
                transportName: "tcp",
                securityName: "tls"
            )
        )
        let handler = TunnelAppMessageHandler(xrayConfigurationValidator: validator)
        let request = TunnelMessageRequest(
            kind: .validateXrayConfiguration,
            payload: .xrayConfigurationValidation(
                TunnelXrayConfigurationValidationRequest(correlationID: correlationID, expectedProfileID: UUID())
            )
        )

        let data = await handler.handle(try encode(request))
        let response = try tunnelMessageDecoder().decode(TunnelMessageResponse.self, from: data)

        #expect(response.requestID == request.requestID)
        #expect(response.success)
        guard case .xrayConfigurationValidation(let validation)? = response.payload else {
            Issue.record("Expected Xray configuration validation payload")
            return
        }
        #expect(validation.success)
        #expect(validation.correlationID == correlationID)
        #expect(await validator.callCount == 1)
    }

    @Test
    func xrayValidationServiceSendsIdentityOnlyAndRejectsStaleResponses() async throws {
        let profile = makeTCPTLSProfile()
        let publisher = SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: InMemoryRuntimeProfileStore(),
            credentialStore: StaticCredentialStore(secrets: [profile.credentialReference!: TestSecrets().vlessUUID])
        )
        let messenger = StaticXrayValidationMessenger(
            responseBuilder: { request in
                guard case .xrayConfigurationValidation(let payload)? = request.payload else {
                    return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
                }
                return TunnelMessageResponse.success(
                    request: request,
                    payload: .xrayConfigurationValidation(
                        .success(
                            correlationID: payload.correlationID,
                            protocolName: "vless",
                            transportName: "tcp",
                            securityName: "tls"
                        )
                    )
                )
            }
        )
        let service = XrayConfigurationValidationService(publisher: publisher, messenger: messenger)

        let result = try await service.validate(profile: profile)

        #expect(result.success)
        #expect(await messenger.sentRequests.count == 1)
        #expect(await messenger.sentProviderConfigurations.count == 1)
        guard case .xrayConfigurationValidation(let payload)? = await messenger.sentRequests.first?.payload else {
            Issue.record("Expected Xray validation request")
            return
        }
        #expect(payload.expectedProfileID == profile.id)
        #expect(payload.requestGeneration == 1)

        let requestJSON = try encodedJSONString(try #require(await messenger.sentRequests.first))
        assertNoSecretMaterial(in: requestJSON, secrets: TestSecrets())
        #expect(!requestJSON.contains("keychain://"))
        #expect(!requestJSON.contains("example.com"))

        let staleMessenger = StaticXrayValidationMessenger(
            responseBuilder: { request in
                TunnelMessageResponse.success(
                    request: request,
                    payload: .xrayConfigurationValidation(
                        .success(correlationID: UUID(), protocolName: "vless", transportName: "tcp", securityName: "tls")
                    )
                )
            }
        )
        let staleService = XrayConfigurationValidationService(publisher: publisher, messenger: staleMessenger)
        await expectXrayValidationFailure {
            _ = try await staleService.validate(profile: profile)
        }
    }
}

struct XrayLifecycleSmokeTestIPCTests {
    @Test
    func xrayLifecycleRequestAndResponseContainNoSecretMaterial() throws {
        let secrets = TestSecrets()
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .runXrayLifecycleSmokeTest,
            payload: .xrayLifecycleSmokeTest(
                TunnelXrayLifecycleSmokeTestRequest(
                    correlationID: correlationID,
                    expectedProfileID: UUID(),
                    expectedRevisionToken: 12_345,
                    requestGeneration: 1
                )
            )
        )
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .xrayLifecycleSmokeTest(
                .success(
                    correlationID: correlationID,
                    protocolName: "vless",
                    transportName: "tcp",
                    securityName: "tls",
                    startDurationMs: 4,
                    readinessDurationMs: 12,
                    stopDurationMs: 3,
                    totalDurationMs: 20
                )
            )
        )

        let requestData = try encode(request)
        let responseData = try encode(response)
        let requestJSON = String(decoding: requestData, as: UTF8.self)
        let responseJSON = String(decoding: responseData, as: UTF8.self)
        let decodedRequest = try tunnelMessageDecoder().decode(TunnelMessageRequest.self, from: requestData)
        let decodedResponse = try tunnelMessageDecoder().decode(TunnelMessageResponse.self, from: responseData)

        #expect(decodedRequest.kind == .runXrayLifecycleSmokeTest)
        guard case .xrayLifecycleSmokeTest(let decodedRequestPayload)? = decodedRequest.payload else {
            Issue.record("Expected Xray lifecycle smoke-test request payload")
            return
        }
        #expect(decodedRequestPayload.correlationID == correlationID)

        guard case .xrayLifecycleSmokeTest(let decodedResponsePayload)? = decodedResponse.payload else {
            Issue.record("Expected Xray lifecycle smoke-test response payload")
            return
        }
        #expect(decodedResponsePayload.correlationID == correlationID)
        #expect(decodedResponsePayload.success)
        #expect(decodedResponsePayload.protocolName == "vless")
        #expect(decodedResponsePayload.transportName == "tcp")
        #expect(decodedResponsePayload.securityName == "tls")
        #expect(decodedResponsePayload.localPortClosed)
        try assertJSONDoesNotContainForbiddenKeys(in: requestData, forbiddenKeys: lifecycleForbiddenJSONKeys)
        try assertJSONDoesNotContainForbiddenKeys(in: responseData, forbiddenKeys: lifecycleForbiddenJSONKeys)

        assertNoSecretMaterial(in: requestJSON, secrets: secrets)
        assertNoSecretMaterial(in: responseJSON, secrets: secrets)
        #expect(!requestJSON.contains(secrets.xrayCredentialReference))
        #expect(!responseJSON.contains(secrets.xrayCredentialReference))
        #expect(!requestJSON.contains("keychain://"))
        #expect(!responseJSON.contains("keychain://"))
        #expect(!requestJSON.contains("LibXray"))
        #expect(!responseJSON.contains("LibXray"))
        #expect(!requestJSON.contains("example.com"))
        #expect(!responseJSON.contains("example.com"))
        #expect(!requestJSON.contains(secrets.realityPublicKey))
        #expect(!responseJSON.contains(secrets.realityPublicKey))
        #expect(!requestJSON.contains("sni.example.com"))
        #expect(!responseJSON.contains("sni.example.com"))
        #expect(!requestJSON.contains("/xhttp"))
        #expect(!responseJSON.contains("/xhttp"))
        #expect(!requestJSON.contains("stream-one"))
        #expect(!responseJSON.contains("stream-one"))
        #expect(responseJSON.contains("tcp"))
        #expect(responseJSON.contains("tls"))
    }

    @Test
    func jsonPrivacyKeyCheckAllowsLocalPortClosedAndRejectsExactLocalPortKeys() throws {
        let allowed = Data(#"{"payload":{"data":{"localPortClosed":true},"kind":"xrayLifecycleSmokeTest"}}"#.utf8)
        let forbidden = Data(#"{"payload":{"data":{"localPort":20480},"kind":"xrayLifecycleSmokeTest"}}"#.utf8)
        let nestedForbidden = Data(#"{"payload":{"data":{"checks":[{"localPort":20480}]}}}"#.utf8)

        #expect(try forbiddenJSONKeyPaths(in: allowed, forbiddenKeys: lifecycleForbiddenJSONKeys).isEmpty)
        #expect(try forbiddenJSONKeyPaths(in: forbidden, forbiddenKeys: lifecycleForbiddenJSONKeys) == ["payload.data.localPort"])
        #expect(try forbiddenJSONKeyPaths(in: nestedForbidden, forbiddenKeys: lifecycleForbiddenJSONKeys) == ["payload.data.checks.[0].localPort"])
    }

    @Test
    func xrayLifecycleCommandAndPayloadWireNamesRoundTripSeparately() throws {
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .runXrayLifecycleSmokeTest,
            payload: .xrayLifecycleSmokeTest(
                TunnelXrayLifecycleSmokeTestRequest(
                    correlationID: correlationID,
                    expectedProfileID: UUID(),
                    expectedRevisionToken: 12_345,
                    requestGeneration: 1
                )
            )
        )
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .xrayLifecycleSmokeTest(
                .success(
                    correlationID: correlationID,
                    protocolName: "vless",
                    transportName: "tcp",
                    securityName: "tls",
                    startDurationMs: 4,
                    readinessDurationMs: 12,
                    stopDurationMs: 3,
                    totalDurationMs: 20
                )
            )
        )

        let decoder = tunnelMessageDecoder()
        let decodedRequest = try decoder.decode(TunnelMessageRequest.self, from: encode(request))
        let decodedResponse = try decoder.decode(TunnelMessageResponse.self, from: encode(response))

        #expect(decodedRequest.kind == .runXrayLifecycleSmokeTest)
        guard case .xrayLifecycleSmokeTest(let decodedRequestPayload)? = decodedRequest.payload else {
            Issue.record("Expected Xray lifecycle smoke-test request payload")
            return
        }
        #expect(decodedRequestPayload.correlationID == correlationID)

        guard case .xrayLifecycleSmokeTest(let decodedResponsePayload)? = decodedResponse.payload else {
            Issue.record("Expected Xray lifecycle smoke-test response payload")
            return
        }
        #expect(decodedResponsePayload.correlationID == correlationID)
        #expect(decodedResponsePayload.success)
        #expect(decodedResponsePayload.protocolName == "vless")
        #expect(decodedResponsePayload.transportName == "tcp")
        #expect(decodedResponsePayload.securityName == "tls")
    }

    @Test
    func appAndExtensionLifecycleWireContractsStayInSync() throws {
        let appModels = try projectFileContents("VPN/Core/Portable/TunnelIPC/TunnelMessageModels.swift")
        let extensionModels = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/TunnelMessageModels.swift")
        let extensionHandler = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/TunnelTelemetryIPC.swift")

        #expect(TunnelMessageKind.runXrayLifecycleSmokeTest.rawValue == "runXrayLifecycleSmokeTest")
        #expect(appModels.contains("\"runXrayLifecycleSmokeTest\""))
        #expect(extensionModels.contains("\"runXrayLifecycleSmokeTest\""))
        #expect(appModels.contains("xrayLifecycleSmokeTest"))
        #expect(extensionModels.contains("xrayLifecycleSmokeTest"))
        #expect(extensionHandler.contains("case .runXrayLifecycleSmokeTest:"))
        #expect(extensionHandler.contains("guard case .xrayLifecycleSmokeTest(let payload)? = request.payload"))
        #expect(extensionHandler.contains("return .success(request: request, payload: .xrayLifecycleSmokeTest(validation))"))
        #expect(!extensionHandler.contains("payload: .runXrayLifecycleSmokeTest"))
    }

    @Test
    func xrayRemoteEgressRequestAndResponseContainNoSecretMaterial() throws {
        let secrets = TestSecrets()
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .runXrayRemoteEgressProbe,
            payload: .xrayRemoteEgressProbe(
                TunnelXrayRemoteEgressProbeRequest(
                    correlationID: correlationID,
                    expectedProfileID: UUID(),
                    expectedRevisionToken: 12_345,
                    requestGeneration: 1
                )
            )
        )
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .xrayRemoteEgressProbe(
                .success(
                    correlationID: correlationID,
                    protocolName: "hysteria2",
                    transportName: "hysteria",
                    securityName: "tls",
                    h3ALPNConfigured: true,
                    sniConfigured: true,
                    allowInsecureConfigured: true,
                    startDurationMs: 4,
                    readinessDurationMs: 12,
                    remoteConnectDurationMs: 80,
                    stopDurationMs: 3,
                    totalDurationMs: 100
                )
            )
        )

        let requestData = try encode(request)
        let responseData = try encode(response)
        let requestJSON = String(decoding: requestData, as: UTF8.self)
        let responseJSON = String(decoding: responseData, as: UTF8.self)
        let decodedRequest = try tunnelMessageDecoder().decode(TunnelMessageRequest.self, from: requestData)
        let decodedResponse = try tunnelMessageDecoder().decode(TunnelMessageResponse.self, from: responseData)

        #expect(decodedRequest.kind == .runXrayRemoteEgressProbe)
        guard case .xrayRemoteEgressProbe(let decodedRequestPayload)? = decodedRequest.payload else {
            Issue.record("Expected Xray remote egress request payload")
            return
        }
        #expect(decodedRequestPayload.correlationID == correlationID)

        guard case .xrayRemoteEgressProbe(let decodedResponsePayload)? = decodedResponse.payload else {
            Issue.record("Expected Xray remote egress response payload")
            return
        }
        #expect(decodedResponsePayload.correlationID == correlationID)
        #expect(decodedResponsePayload.success)
        #expect(decodedResponsePayload.protocolName == "hysteria2")
        #expect(decodedResponsePayload.transportName == "hysteria")
        #expect(decodedResponsePayload.securityName == "tls")
        #expect(decodedResponsePayload.remoteConnectAttempted)
        #expect(decodedResponsePayload.remoteConnectSucceeded)
        #expect(decodedResponsePayload.remoteConnectCategory == .success)
        #expect(decodedResponsePayload.socksConnectRequested)
        #expect(decodedResponsePayload.socksConnectAccepted)
        #expect(decodedResponsePayload.payloadWriteSucceeded)
        #expect(decodedResponsePayload.remoteFirstByteReceived)
        #expect(decodedResponsePayload.remoteResponseValidated)
        #expect(decodedResponsePayload.remoteEgressSucceeded)
        #expect(decodedResponsePayload.cleanupSucceeded)
        #expect(decodedResponsePayload.allowInsecureConfigured == true)

        try assertJSONDoesNotContainForbiddenKeys(in: requestData, forbiddenKeys: lifecycleForbiddenJSONKeys)
        try assertJSONDoesNotContainForbiddenKeys(in: responseData, forbiddenKeys: lifecycleForbiddenJSONKeys)
        assertNoSecretMaterial(in: requestJSON, secrets: secrets)
        assertNoSecretMaterial(in: responseJSON, secrets: secrets)
        #expect(!requestJSON.contains("keychain://"))
        #expect(!responseJSON.contains("keychain://"))
        #expect(!requestJSON.contains("hy2-sni.example.com"))
        #expect(!responseJSON.contains("hy2-sni.example.com"))
        #expect(!requestJSON.contains("1.1.1.1"))
        #expect(!responseJSON.contains("1.1.1.1"))
        #expect(!responseJSON.contains("one.one.one.one"))
        #expect(!responseJSON.contains("HTTP/"))
        #expect(responseJSON.contains("hysteria2"))
        #expect(responseJSON.contains("hysteria"))
        #expect(responseJSON.contains("tls"))
    }

    @Test
    func udpControlProbeRequestAndResponseContainOnlySanitizedFields() throws {
        let secrets = TestSecrets()
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .runUDPControlProbe,
            payload: .udpControlProbe(
                TunnelUDPControlProbeRequest(
                    correlationID: correlationID,
                    requestGeneration: 1
                )
            )
        )
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .udpControlProbe(
                .success(
                    correlationID: correlationID,
                    pathSnapshot: TunnelUDPControlProbePathSnapshot(
                        pathStatus: .satisfied,
                        usesWiFi: true,
                        usesCellular: false,
                        usesWiredEthernet: false,
                        supportsIPv4: true,
                        supportsIPv6: true,
                        supportsDNS: true
                    ),
                    durationMs: 24
                )
            )
        )

        let requestData = try encode(request)
        let responseData = try encode(response)
        let requestJSON = String(decoding: requestData, as: UTF8.self)
        let responseJSON = String(decoding: responseData, as: UTF8.self)
        let decodedRequest = try tunnelMessageDecoder().decode(TunnelMessageRequest.self, from: requestData)
        let decodedResponse = try tunnelMessageDecoder().decode(TunnelMessageResponse.self, from: responseData)

        #expect(decodedRequest.kind == .runUDPControlProbe)
        guard case .udpControlProbe(let decodedRequestPayload)? = decodedRequest.payload else {
            Issue.record("Expected UDP control request payload")
            return
        }
        #expect(decodedRequestPayload.correlationID == correlationID)

        guard case .udpControlProbe(let decodedResponsePayload)? = decodedResponse.payload else {
            Issue.record("Expected UDP control response payload")
            return
        }
        #expect(decodedResponsePayload.correlationID == correlationID)
        #expect(decodedResponsePayload.success)
        #expect(decodedResponsePayload.udpConnectionReady)
        #expect(decodedResponsePayload.udpWriteSucceeded)
        #expect(decodedResponsePayload.udpResponseReceived)
        #expect(decodedResponsePayload.udpResponseValidated)
        #expect(decodedResponsePayload.udpControlSucceeded)
        #expect(decodedResponsePayload.failureCategory == .success)
        #expect(decodedResponsePayload.pathSnapshot?.pathStatus == .satisfied)
        #expect(decodedResponsePayload.pathSnapshot?.usesWiFi == true)

        try assertJSONDoesNotContainForbiddenKeys(in: requestData, forbiddenKeys: lifecycleForbiddenJSONKeys)
        try assertJSONDoesNotContainForbiddenKeys(in: responseData, forbiddenKeys: lifecycleForbiddenJSONKeys)
        assertNoSecretMaterial(in: requestJSON, secrets: secrets)
        assertNoSecretMaterial(in: responseJSON, secrets: secrets)
        #expect(!requestJSON.contains("1.1.1.1"))
        #expect(!responseJSON.contains("1.1.1.1"))
        #expect(!requestJSON.contains("one.one.one.one"))
        #expect(!responseJSON.contains("one.one.one.one"))
        #expect(!responseJSON.contains("raw"))
        #expect(!responseJSON.contains("packet"))
        #expect(!responseJSON.contains("responseBytes"))
    }

    @Test
    func libXrayPingProbeRequestAndResponseContainOnlySanitizedFields() throws {
        let secrets = TestSecrets()
        let correlationID = UUID()
        let nativeErrorSecret = "x509 certificate failed for \(secrets.password) at hy2-sni.example.com"
        let request = TunnelMessageRequest(
            kind: .runLibXrayPingProbe,
            payload: .libXrayPingProbe(
                TunnelLibXrayPingProbeRequest(
                    correlationID: correlationID,
                    expectedProfileID: UUID(),
                    expectedRevisionToken: 12_345,
                    requestGeneration: 1
                )
            )
        )
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .libXrayPingProbe(
                .failure(
                    correlationID: correlationID,
                    stage: .libXrayPing,
                    category: .certificateFailure,
                    xrayConfigurationBuilt: true,
                    pingAccepted: true,
                    pingCompleted: true,
                    delayMs: 10_000,
                    nativeErrorPresent: true,
                    protocolName: "hysteria2",
                    transportName: "hysteria",
                    securityName: "tls",
                    h3ALPNConfigured: true,
                    sniConfigured: true,
                    allowInsecureConfigured: false,
                    durationMs: 5_000
                )
            )
        )

        let requestData = try encode(request)
        let responseData = try encode(response)
        let requestJSON = String(decoding: requestData, as: UTF8.self)
        let responseJSON = String(decoding: responseData, as: UTF8.self)
        let decodedRequest = try tunnelMessageDecoder().decode(TunnelMessageRequest.self, from: requestData)
        let decodedResponse = try tunnelMessageDecoder().decode(TunnelMessageResponse.self, from: responseData)

        #expect(decodedRequest.kind == .runLibXrayPingProbe)
        guard case .libXrayPingProbe(let decodedRequestPayload)? = decodedRequest.payload else {
            Issue.record("Expected LibXray ping request payload")
            return
        }
        #expect(decodedRequestPayload.correlationID == correlationID)

        guard case .libXrayPingProbe(let decodedResponsePayload)? = decodedResponse.payload else {
            Issue.record("Expected LibXray ping response payload")
            return
        }
        #expect(decodedResponsePayload.correlationID == correlationID)
        #expect(!decodedResponsePayload.success)
        #expect(decodedResponsePayload.xrayConfigurationBuilt)
        #expect(decodedResponsePayload.pingAccepted)
        #expect(decodedResponsePayload.pingCompleted)
        #expect(!decodedResponsePayload.pingSucceeded)
        #expect(decodedResponsePayload.nativeErrorPresent)
        #expect(decodedResponsePayload.sanitizedFailureCategory == .certificateFailure)
        #expect(decodedResponsePayload.protocolName == "hysteria2")
        #expect(decodedResponsePayload.transportName == "hysteria")
        #expect(decodedResponsePayload.securityName == "tls")
        #expect(decodedResponsePayload.h3ALPNConfigured == true)

        try assertJSONDoesNotContainForbiddenKeys(in: requestData, forbiddenKeys: lifecycleForbiddenJSONKeys)
        try assertJSONDoesNotContainForbiddenKeys(in: responseData, forbiddenKeys: lifecycleForbiddenJSONKeys)
        assertNoSecretMaterial(in: requestJSON, secrets: secrets)
        assertNoSecretMaterial(in: responseJSON, secrets: secrets)
        #expect(!requestJSON.contains("keychain://"))
        #expect(!responseJSON.contains("keychain://"))
        #expect(!requestJSON.contains("hy2-sni.example.com"))
        #expect(!responseJSON.contains("hy2-sni.example.com"))
        #expect(!requestJSON.contains("HY2.Example.COM"))
        #expect(!responseJSON.contains("HY2.Example.COM"))
        #expect(!responseJSON.contains(nativeErrorSecret))
        #expect(!responseJSON.contains("x509"))
        #expect(!responseJSON.contains("certificate failed for"))
        #expect(!responseJSON.contains("raw"))
        #expect(!responseJSON.contains("errorString"))
        #expect(!responseJSON.contains("nativeErrorMessage"))
        #expect(responseJSON.contains("nativeErrorPresent"))
        #expect(responseJSON.contains("certificateFailure"))
    }

    @Test
    func appAndExtensionLibXrayPingWireContractsStayInSync() throws {
        let appModels = try projectFileContents("VPN/Core/Portable/TunnelIPC/TunnelMessageModels.swift")
        let extensionModels = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/TunnelMessageModels.swift")
        let extensionHandler = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/TunnelTelemetryIPC.swift")
        let runtimeModels = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/RuntimeConfigurationModels.swift")
        let provider = try projectFileContents("PacketTunnelExtension/PacketTunnelProvider.swift")

        #expect(TunnelMessageKind.runLibXrayPingProbe.rawValue == "runLibXrayPingProbe")
        #expect(TunnelLibXrayPingProbeCategory.timeout.rawValue == "timeout")
        #expect(TunnelLibXrayPingProbeCategory.quicFailure.rawValue == "quicFailure")
        #expect(appModels.contains("\"runLibXrayPingProbe\""))
        #expect(extensionModels.contains("\"runLibXrayPingProbe\""))
        #expect(appModels.contains("libXrayPingProbe"))
        #expect(extensionModels.contains("libXrayPingProbe"))
        #expect(extensionHandler.contains("case .runLibXrayPingProbe:"))
        #expect(extensionHandler.contains("guard case .libXrayPingProbe(let payload)? = request.payload"))
        #expect(extensionHandler.contains("return .success(request: request, payload: .libXrayPingProbe(validation))"))
        #expect(runtimeModels.contains("protocol LibXrayPingBatchInvoking"))
        #expect(runtimeModels.contains("protocol LibXrayPingProbing"))
        #expect(runtimeModels.contains("LibXrayPingBatchItemResponsePayload"))
        #expect(runtimeModels.contains("LibXrayPingErrorClassifier.category(for: item.error)"))
        #expect(runtimeModels.contains(#"normalized.contains("quic") || normalized.contains("hysteria")"#))
        #expect(runtimeModels.contains(#"normalized.contains("tls") || normalized.contains("handshake failure")"#))
        #expect(runtimeModels.contains(#"normalized.contains("x509") || normalized.contains("certificate")"#))
        #expect(runtimeModels.contains(#"normalized.contains("auth") || normalized.contains("unauthorized")"#))
        #expect(runtimeModels.contains(#"normalized.contains("timeout") || normalized.contains("deadline exceeded")"#))
        #expect(runtimeModels.contains(#"return .unknown"#))
        #expect(runtimeModels.contains("nativeErrorPresent: item.error?.isEmpty == false"))
        #expect(!appModels.contains("nativeErrorMessage"))
        #expect(!extensionModels.contains("nativeErrorMessage"))
        #expect(!appModels.contains("rawLibXrayError"))
        #expect(!extensionModels.contains("rawLibXrayError"))
        #expect(provider.contains("LibXrayPingOnlyPacketTunnelStartOptions"))
        #expect(provider.contains("xrayRuntimeController.startPacketTunnelLibXrayPingOnly"))
        #expect(provider.contains("PacketTunnelLibXrayPingProbeService(controller: xrayRuntimeController)"))
        #expect(!extensionHandler.contains("payload: .runLibXrayPingProbe"))
    }

    @Test
    func appAndExtensionRemoteEgressWireContractsStayInSync() throws {
        let appModels = try projectFileContents("VPN/Core/Portable/TunnelIPC/TunnelMessageModels.swift")
        let extensionModels = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/TunnelMessageModels.swift")
        let extensionHandler = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/TunnelTelemetryIPC.swift")
        let runtimeModels = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/RuntimeConfigurationModels.swift")

        #expect(TunnelMessageKind.runXrayRemoteEgressProbe.rawValue == "runXrayRemoteEgressProbe")
        #expect(TunnelMessageKind.probeActiveXrayEgress.rawValue == "probeActiveXrayEgress")
        #expect(TunnelXrayRemoteEgressProbeContext.runtimeOnly.rawValue == "runtimeOnly")
        #expect(TunnelXrayRemoteEgressProbeContext.dataPlane.rawValue == "dataPlane")
        #expect(appModels.contains("\"runXrayRemoteEgressProbe\""))
        #expect(appModels.contains("\"probeActiveXrayEgress\""))
        #expect(extensionModels.contains("\"runXrayRemoteEgressProbe\""))
        #expect(extensionModels.contains("\"probeActiveXrayEgress\""))
        #expect(appModels.contains("enum TunnelXrayRemoteEgressProbeContext"))
        #expect(extensionModels.contains("enum TunnelXrayRemoteEgressProbeContext"))
        #expect(appModels.contains("xrayRemoteEgressProbe"))
        #expect(extensionModels.contains("xrayRemoteEgressProbe"))
        #expect(extensionHandler.contains("case .runXrayRemoteEgressProbe:"))
        #expect(extensionHandler.contains("case .probeActiveXrayEgress:"))
        #expect(extensionHandler.contains("guard case .xrayRemoteEgressProbe(let payload)? = request.payload"))
        #expect(extensionHandler.contains("return .success(request: request, payload: .xrayRemoteEgressProbe(validation))"))
        #expect(runtimeModels.contains("remoteEgressProbe.probe(host: \"127.0.0.1\", port: port)"))
        #expect(runtimeModels.contains("remoteEgressProbe.probe(host: \"127.0.0.1\", port: session.port)"))
        #expect(!runtimeModels.contains("remoteEgressProbe.probe(host: XraySOCKS5RemoteConnect.targetHost"))
        #expect(runtimeModels.contains("XraySOCKS5RemoteConnect.requestBytes"))
        #expect(runtimeModels.contains("XrayRemoteEgressHTTPProbe.requestBytes"))
        let runtimeController = try sourceSlice(
            in: runtimeModels,
            from: "actor XrayRuntimeLifecycleController:",
            to: "final class PacketTunnelXrayLifecycleSmokeTestService"
        )
        #expect(runtimeController.contains("func probeActiveXrayEgress("))
        #expect(runtimeController.contains("private static func remoteProbeContext(for mode: XrayRuntimeLifecycleMode)"))
        #expect(runtimeController.contains("case .packetTunnelRuntimeOnly:"))
        #expect(runtimeController.contains("return .runtimeOnly"))
        #expect(runtimeController.contains("case .packetTunnelDataPlane:"))
        #expect(runtimeController.contains("return .dataPlane"))
        #expect(runtimeController.contains("case .oneShotSmoke, .libXrayPingOnly:"))
        #expect(runtimeController.contains("return nil"))
        let activeProbeBody = try sourceSlice(
            in: runtimeController,
            from: "func probeActiveXrayEgress(",
            to: "func startPacketTunnelRuntimeOnly("
        )
        #expect(activeProbeBody.contains("let probeContext = Self.remoteProbeContext(for: session.mode)"))
        #expect(activeProbeBody.contains("probeContext: probeContext"))
        #expect(!activeProbeBody.contains("libXray.test"))
        #expect(!activeProbeBody.contains("libXray.run"))
        #expect(!activeProbeBody.contains("libXray.stop"))
        #expect(!activeProbeBody.contains("tun2Socks.start"))
        #expect(!activeProbeBody.contains("tun2Socks.quit"))
        #expect(!activeProbeBody.contains("networkSettingsApplier.apply"))
        #expect(!activeProbeBody.contains("networkSettingsApplier.clear"))
        #expect(!extensionHandler.contains("payload: .runXrayRemoteEgressProbe"))
    }

    @Test
    func appAndExtensionUDPControlWireContractsStayInSync() throws {
        let appModels = try projectFileContents("VPN/Core/Portable/TunnelIPC/TunnelMessageModels.swift")
        let extensionModels = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/TunnelMessageModels.swift")
        let extensionHandler = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/TunnelTelemetryIPC.swift")
        let runtimeModels = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/RuntimeConfigurationModels.swift")
        let provider = try projectFileContents("PacketTunnelExtension/PacketTunnelProvider.swift")
        let settingsView = try projectFileContents("VPN/Views/SettingsView.swift")
        let diagnosticsViewModel = try projectFileContents("VPN/Core/Portable/TunnelIPC/TunnelTelemetryDiagnosticsViewModel.swift")

        #expect(TunnelMessageKind.runUDPControlProbe.rawValue == "runUDPControlProbe")
        #expect(TunnelUDPControlProbeCategory.notRuntimeOnly.rawValue == "notRuntimeOnly")
        #expect(TunnelUDPControlProbePathStatus.satisfied.rawValue == "satisfied")
        #expect(appModels.contains("\"runUDPControlProbe\""))
        #expect(extensionModels.contains("\"runUDPControlProbe\""))
        #expect(appModels.contains("udpControlProbe"))
        #expect(extensionModels.contains("udpControlProbe"))
        #expect(extensionHandler.contains("case .runUDPControlProbe:"))
        #expect(extensionHandler.contains("guard case .udpControlProbe(let payload)? = request.payload"))
        #expect(extensionHandler.contains("return .success(request: request, payload: .udpControlProbe(validation))"))
        #expect(provider.contains("PacketTunnelUDPControlProbeService(controller: xrayRuntimeController)"))
        #expect(settingsView.contains("diagnostics.udp_control.run"))
        #expect(diagnosticsViewModel.contains("func runUDPControlProbe()"))
        #expect(diagnosticsViewModel.contains("guard runtimeOnlyDiagnosticModeIsRunning else"))
        #expect(!diagnosticsViewModel.contains("runtimeOnlyTunnelResult?.success == true"))
        #expect(!diagnosticsViewModel.contains("dataPlaneTunnelResult?.success != true"))
        #expect(runtimeModels.contains("protocol PacketTunnelUDPControlProbing"))
        #expect(runtimeModels.contains("protocol UDPControlPathSnapshotProviding"))
        #expect(runtimeModels.contains("protocol UDPControlDatagramTransporting"))
        #expect(runtimeModels.contains("NetworkFrameworkUDPControlPathProvider"))
        #expect(runtimeModels.contains("NetworkFrameworkUDPControlDatagramTransport"))
        #expect(runtimeModels.contains("UDPControlDNSProbe.requestBytes"))
        #expect(runtimeModels.contains("UDPControlDNSProbe.maximumResponseBytes"))

        let runtimeController = try sourceSlice(
            in: runtimeModels,
            from: "actor XrayRuntimeLifecycleController:",
            to: "private static func remoteProbeContext(for mode: XrayRuntimeLifecycleMode)"
        )
        #expect(runtimeController.contains("PacketTunnelUDPControlProbing"))
        #expect(runtimeController.contains("func runUDPControlProbe("))
        #expect(runtimeController.contains("session.mode == .packetTunnelRuntimeOnly"))
        #expect(runtimeController.contains("category: .notRuntimeOnly"))

        let udpProbeBody = try sourceSlice(
            in: runtimeModels,
            from: """
            func runUDPControlProbe(
                    correlationID: UUID,
                    requestGeneration: UInt64?
                ) async -> TunnelUDPControlProbeResponse {
                    guard let session
            """,
            to: "private static func remoteProbeContext(for mode: XrayRuntimeLifecycleMode)"
        )
        #expect(!udpProbeBody.contains("libXray.test"))
        #expect(!udpProbeBody.contains("libXray.run"))
        #expect(!udpProbeBody.contains("libXray.stop"))
        #expect(!udpProbeBody.contains("remoteEgressProbe.probe"))
        #expect(!udpProbeBody.contains("readinessProbe.waitForReadiness"))
        #expect(!udpProbeBody.contains("tun2Socks"))
        #expect(!udpProbeBody.contains("networkSettingsApplier"))
        #expect(!udpProbeBody.contains("setTunnelNetworkSettings"))
        #expect(!udpProbeBody.contains("packetFlow"))
        #expect(!runtimeModels.contains("packetFlow.readPackets"))
        #expect(!runtimeModels.contains("packetFlow.writePackets"))
    }

    @Test
    func lifecycleServiceSendsIdentityOnlyAndRejectsStaleResponses() async throws {
        let profile = makeTCPTLSProfile()
        let publisher = SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: InMemoryRuntimeProfileStore(),
            credentialStore: StaticCredentialStore(secrets: [profile.credentialReference!: TestSecrets().vlessUUID])
        )
        let messenger = StaticXrayLifecycleSmokeTestMessenger(
            responseBuilder: { request in
                guard case .xrayLifecycleSmokeTest(let payload)? = request.payload else {
                    return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
                }
                return TunnelMessageResponse.success(
                    request: request,
                    payload: .xrayLifecycleSmokeTest(
                        .success(
                            correlationID: payload.correlationID,
                            protocolName: "vless",
                            transportName: "tcp",
                            securityName: "tls",
                            startDurationMs: 4,
                            readinessDurationMs: 12,
                            stopDurationMs: 3,
                            totalDurationMs: 20
                        )
                    )
                )
            }
        )
        let service = XrayLifecycleSmokeTestService(publisher: publisher, messenger: messenger)

        let result = try await service.run(profile: profile)

        #expect(result.success)
        #expect(await messenger.sentRequests.count == 1)
        #expect(await messenger.sentProviderConfigurations.count == 1)
        let request = try #require(await messenger.sentRequests.first)
        guard case .xrayLifecycleSmokeTest(let payload)? = request.payload else {
            Issue.record("Expected Xray lifecycle smoke-test request")
            return
        }
        #expect(payload.expectedProfileID == profile.id)
        #expect(payload.requestGeneration == 1)

        let requestJSON = try encodedJSONString(request)
        let providerConfiguration = try #require(await messenger.sentProviderConfigurations.first)
        let providerConfigurationData = try JSONSerialization.data(
            withJSONObject: providerConfiguration.propertyList,
            options: [.sortedKeys]
        )
        let providerConfigurationJSON = String(decoding: providerConfigurationData, as: UTF8.self)
        assertNoSecretMaterial(in: requestJSON, secrets: TestSecrets())
        assertNoSecretMaterial(in: providerConfigurationJSON, secrets: TestSecrets())
        #expect(!requestJSON.contains("keychain://"))
        #expect(!requestJSON.contains("example.com"))
        #expect(!providerConfigurationJSON.contains("keychain://"))
        #expect(!providerConfigurationJSON.contains("example.com"))

        let staleMessenger = StaticXrayLifecycleSmokeTestMessenger(
            responseBuilder: { request in
                TunnelMessageResponse.success(
                    request: request,
                    payload: .xrayLifecycleSmokeTest(
                        .success(
                            correlationID: UUID(),
                            protocolName: "vless",
                            transportName: "tcp",
                            securityName: "tls",
                            startDurationMs: 1,
                            readinessDurationMs: 1,
                            stopDurationMs: 1,
                            totalDurationMs: 3
                        )
                    )
                )
            }
        )
        let staleService = XrayLifecycleSmokeTestService(publisher: publisher, messenger: staleMessenger)
        await expectXrayLifecycleFailure {
            _ = try await staleService.run(profile: profile)
        }
    }

    @Test
    func remoteEgressServiceSendsIdentityOnlyAndRejectsStaleResponses() async throws {
        let profile = makeHysteria2Profile()
        let publisher = SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: InMemoryRuntimeProfileStore(),
            credentialStore: StaticCredentialStore(secrets: [profile.credentialReference!: TestSecrets().password])
        )
        let messenger = StaticXrayRemoteEgressProbeMessenger(
            responseBuilder: { request in
                guard case .xrayRemoteEgressProbe(let payload)? = request.payload else {
                    return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
                }
                return TunnelMessageResponse.success(
                    request: request,
                    payload: .xrayRemoteEgressProbe(
                        .success(
                            correlationID: payload.correlationID,
                            protocolName: "hysteria2",
                            transportName: "hysteria",
                            securityName: "tls",
                            h3ALPNConfigured: true,
                            sniConfigured: true,
                            allowInsecureConfigured: false,
                            startDurationMs: 4,
                            readinessDurationMs: 12,
                            remoteConnectDurationMs: 80,
                            stopDurationMs: 3,
                            totalDurationMs: 100
                        )
                    )
                )
            }
        )
        let service = XrayRemoteEgressProbeService(publisher: publisher, messenger: messenger)

        let result = try await service.run(profile: profile)

        #expect(result.success)
        #expect(await messenger.sentRequests.count == 1)
        #expect(await messenger.sentProviderConfigurations.count == 1)
        let request = try #require(await messenger.sentRequests.first)
        #expect(request.kind == .runXrayRemoteEgressProbe)
        guard case .xrayRemoteEgressProbe(let payload)? = request.payload else {
            Issue.record("Expected Xray remote egress request")
            return
        }
        #expect(payload.expectedProfileID == profile.id)
        #expect(payload.requestGeneration == 1)

        let requestJSON = try encodedJSONString(request)
        let providerConfiguration = try #require(await messenger.sentProviderConfigurations.first)
        let providerConfigurationData = try JSONSerialization.data(
            withJSONObject: providerConfiguration.propertyList,
            options: [.sortedKeys]
        )
        let providerConfigurationJSON = String(decoding: providerConfigurationData, as: UTF8.self)
        assertNoSecretMaterial(in: requestJSON, secrets: TestSecrets())
        assertNoSecretMaterial(in: providerConfigurationJSON, secrets: TestSecrets())
        #expect(!requestJSON.contains("keychain://"))
        #expect(!requestJSON.contains("example.com"))
        #expect(!providerConfigurationJSON.contains("keychain://"))
        #expect(!providerConfigurationJSON.contains("example.com"))

        let staleMessenger = StaticXrayRemoteEgressProbeMessenger(
            responseBuilder: { request in
                TunnelMessageResponse.success(
                    request: request,
                    payload: .xrayRemoteEgressProbe(
                        .success(
                            correlationID: UUID(),
                            protocolName: "hysteria2",
                            transportName: "hysteria",
                            securityName: "tls",
                            h3ALPNConfigured: true,
                            sniConfigured: true,
                            allowInsecureConfigured: false,
                            startDurationMs: 4,
                            readinessDurationMs: 12,
                            remoteConnectDurationMs: 80,
                            stopDurationMs: 3,
                            totalDurationMs: 100
                        )
                    )
                )
            }
        )
        let staleService = XrayRemoteEgressProbeService(publisher: publisher, messenger: staleMessenger)
        await expectXrayRemoteEgressFailure {
            _ = try await staleService.run(profile: profile)
        }

        let activeMessenger = StaticXrayRemoteEgressProbeMessenger(
            responseBuilder: { request in
                guard case .xrayRemoteEgressProbe(let payload)? = request.payload else {
                    return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
                }
                return TunnelMessageResponse.success(
                    request: request,
                    payload: .xrayRemoteEgressProbe(
                        .success(
                            correlationID: payload.correlationID,
                            protocolName: "hysteria2",
                            transportName: "hysteria",
                            securityName: "tls",
                            h3ALPNConfigured: true,
                            sniConfigured: true,
                            allowInsecureConfigured: false,
                            probeContext: .runtimeOnly,
                            cleanupSucceeded: false,
                            startDurationMs: nil,
                            readinessDurationMs: nil,
                            remoteConnectDurationMs: 80,
                            stopDurationMs: nil,
                            totalDurationMs: 85
                        )
                    )
                )
            }
        )
        let activeService = XrayRemoteEgressProbeService(publisher: publisher, messenger: activeMessenger)
        let active = try await activeService.probeActiveXrayEgress(profile: profile)
        let activeRequest = try #require(await activeMessenger.sentRequests.first)
        #expect(active.success)
        #expect(active.probeContext == .runtimeOnly)
        #expect(active.cleanupSucceeded == false)
        #expect(activeRequest.kind == .probeActiveXrayEgress)
        guard case .xrayRemoteEgressProbe(let activePayload)? = activeRequest.payload else {
            Issue.record("Expected active Xray egress request")
            return
        }
        #expect(activePayload.expectedProfileID == profile.id)
        #expect(activePayload.requestGeneration == 1)
    }

    @Test
    func appAndExtensionDiagnosticProviderModeWireContractsStayInSync() throws {
        let appModels = try projectFileContents("VPN/Core/Portable/TunnelIPC/TunnelMessageModels.swift")
        let extensionModels = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/TunnelMessageModels.swift")
        let extensionHandler = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/TunnelTelemetryIPC.swift")
        let provider = try projectFileContents("PacketTunnelExtension/PacketTunnelProvider.swift")

        #expect(TunnelMessageKind.getDiagnosticProviderMode.rawValue == "getDiagnosticProviderMode")
        #expect(TunnelDiagnosticProviderMode.idle.rawValue == "idle")
        #expect(TunnelDiagnosticProviderMode.runtimeOnly.rawValue == "runtimeOnly")
        #expect(TunnelDiagnosticProviderMode.dataPlane.rawValue == "dataPlane")
        #expect(TunnelDiagnosticProviderMode.libXrayPingOnly.rawValue == "libXrayPingOnly")
        #expect(TunnelDiagnosticProviderMode.lifecycleSmoke.rawValue == "lifecycleSmoke")
        #expect(TunnelDiagnosticProviderMode.unknown.rawValue == "unknown")
        #expect(appModels.contains("\"getDiagnosticProviderMode\""))
        #expect(extensionModels.contains("\"getDiagnosticProviderMode\""))
        #expect(appModels.contains("diagnosticProviderMode"))
        #expect(extensionModels.contains("diagnosticProviderMode"))
        #expect(extensionHandler.contains("case .getDiagnosticProviderMode:"))
        #expect(extensionHandler.contains("diagnosticProviderModeProvider?.diagnosticProviderMode() ?? .unknown"))
        #expect(provider.contains("diagnosticProviderModeProvider: xrayRuntimeController"))

        let request = TunnelMessageRequest(kind: .getDiagnosticProviderMode)
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .diagnosticProviderMode(TunnelDiagnosticProviderModeResponse(mode: .libXrayPingOnly))
        )
        let requestData = try JSONEncoder().encode(request)
        let responseData = try JSONEncoder().encode(response)
        let decodedResponse = try JSONDecoder().decode(TunnelMessageResponse.self, from: responseData)

        #expect(try JSONDecoder().decode(TunnelMessageRequest.self, from: requestData).kind == .getDiagnosticProviderMode)
        guard case .diagnosticProviderMode(let payload)? = decodedResponse.payload else {
            Issue.record("Expected diagnostic provider mode payload")
            return
        }
        #expect(payload.mode == .libXrayPingOnly)

        let requestJSON = try #require(String(data: requestData, encoding: .utf8))
        let responseJSON = try #require(String(data: responseData, encoding: .utf8))
        assertNoSecretMaterial(in: requestJSON, secrets: TestSecrets())
        assertNoSecretMaterial(in: responseJSON, secrets: TestSecrets())
        #expect(!responseJSON.contains("profileID"))
        #expect(!responseJSON.contains("localPort"))
        #expect(!responseJSON.contains("endpoint"))
        #expect(!responseJSON.contains("xrayJson"))
    }
}

struct RuntimeOnlyPacketTunnelTests {
    @Test
    func runtimeOnlyStartOptionsContainOnlyDebugMarker() throws {
        let options = RuntimeOnlyPacketTunnelStartOptions.propertyList
        let json = try propertyListJSONString(options)

        #expect(Set(options.keys) == RuntimeOnlyPacketTunnelStartOptions.allowedKeys)
        #expect((options[RuntimeOnlyPacketTunnelStartOptions.runtimeOnlyKey] as? NSNumber)?.boolValue == true)
        assertNoSecretMaterial(in: json, secrets: TestSecrets())
        #expect(!json.contains("keychain://"))
        #expect(!json.contains("example.com"))
        #expect(!json.contains("xrayJson"))
        #expect(!json.contains("xhttp"))
        #expect(!json.contains("/xhttp"))
        #expect(!json.contains("stream-one"))
    }

    @Test
    func runtimeOnlyStartPublishesCanonicalProviderConfigurationAndUsesMarkerOnly() async throws {
        let profile = makeXHTTPTLSProfile(mode: "stream-one")
        let profileStore = InMemoryRuntimeProfileStore()
        let publisher = SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: profileStore,
            credentialStore: StaticCredentialStore(secrets: [profile.credentialReference!: TestSecrets().vlessUUID])
        )
        let session = RecordingRuntimeOnlySession(initialStatus: .disconnected)
        let manager = RecordingDiagnosticTunnelProviderManager(session: session)
        let managerStore = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: managerStore)
        let service = RuntimeOnlyPacketTunnelService(
            publisher: publisher,
            bootstrapper: bootstrapper,
            sessionProvider: StaticTunnelProviderSessionProvider(session: session),
            statusTimeout: .milliseconds(50),
            statusPollInterval: .milliseconds(1)
        )

        let result = try await service.start(profile: profile)

        #expect(result.success)
        #expect(result.transportName == "xhttp")
        #expect(result.securityName == "tls")
        #expect(result.runXrayInvoked)
        #expect(result.runningStateObserved)
        #expect(result.socksListenerReady)
        #expect(result.socksGreetingAccepted)
        #expect(!result.stopXrayInvoked)
        #expect(!result.localPortClosed)

        let providerConfiguration = try #require(manager.providerConfiguration)
        #expect(Set(providerConfiguration.keys) == RuntimeProviderConfiguration.allowedKeys)
        #expect(try RuntimeProviderConfiguration.parse(providerConfiguration).profileID == profile.id)
        #expect(manager.sequence == ["configureRuntime", "save", "reload", "session"])

        let startOptions = try #require(session.startOptions.first)
        #expect(Set(startOptions.keys) == RuntimeOnlyPacketTunnelStartOptions.allowedKeys)
        let startOptionsJSON = try propertyListJSONString(startOptions)
        assertNoSecretMaterial(in: startOptionsJSON, secrets: TestSecrets())
        #expect(!startOptionsJSON.contains("keychain://"))
        #expect(!startOptionsJSON.contains("example.com"))
        #expect(!startOptionsJSON.contains("/xhttp"))
        #expect(!startOptionsJSON.contains("cdn.example.com"))
        #expect(!startOptionsJSON.contains("stream-one"))
    }

    @Test
    func runtimeOnlyStopCallsSessionStopAndWaitsForDisconnectedStatus() async throws {
        let profile = makeTCPTLSProfile()
        let session = RecordingRuntimeOnlySession(initialStatus: .connected)
        let service = RuntimeOnlyPacketTunnelService(
            publisher: SharedRuntimeProfilePublisher(
                mapper: SharedRuntimeProfileMapper(now: fixedDate),
                store: InMemoryRuntimeProfileStore(),
                credentialStore: StaticCredentialStore(secrets: [profile.credentialReference!: TestSecrets().vlessUUID])
            ),
            sessionProvider: StaticTunnelProviderSessionProvider(session: session),
            statusTimeout: .milliseconds(50),
            statusPollInterval: .milliseconds(1)
        )

        let result = try await service.stop()

        #expect(result.success)
        #expect(result.stopXrayInvoked)
        #expect(result.stoppedStateObserved)
        #expect(result.localPortClosed)
        #expect(session.stopCount == 1)
    }

    @Test
    func dataPlaneStartOptionsContainOnlyDebugMarker() throws {
        let options = DataPlanePacketTunnelStartOptions.propertyList
        let json = try propertyListJSONString(options)

        #expect(Set(options.keys) == DataPlanePacketTunnelStartOptions.allowedKeys)
        #expect((options[DataPlanePacketTunnelStartOptions.dataPlaneKey] as? NSNumber)?.boolValue == true)
        assertNoSecretMaterial(in: json, secrets: TestSecrets())
        #expect(!json.contains("keychain://"))
        #expect(!json.contains("example.com"))
        #expect(!json.contains("xrayJson"))
        #expect(!json.contains("xhttp"))
        #expect(!json.contains("/xhttp"))
        #expect(!json.contains("stream-one"))
        #expect(!json.contains("localPort"))
    }

    @Test
    func libXrayPingOnlyStartOptionsContainOnlyDebugMarker() throws {
        let options = LibXrayPingOnlyPacketTunnelStartOptions.propertyList
        let json = try propertyListJSONString(options)

        #expect(Set(options.keys) == LibXrayPingOnlyPacketTunnelStartOptions.allowedKeys)
        #expect((options[LibXrayPingOnlyPacketTunnelStartOptions.libXrayPingOnlyKey] as? NSNumber)?.boolValue == true)
        assertNoSecretMaterial(in: json, secrets: TestSecrets())
        #expect(!json.contains("keychain://"))
        #expect(!json.contains("example.com"))
        #expect(!json.contains("xrayJson"))
        #expect(!json.contains("hysteria"))
        #expect(!json.contains("localPort"))
        #expect(!json.contains("auth"))
    }

    @Test
    func libXrayPingOnlyStartPublishesCanonicalProviderConfigurationAndUsesMarkerOnly() async throws {
        let profile = makeHysteria2Profile()
        let publisher = SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: InMemoryRuntimeProfileStore(),
            credentialStore: StaticCredentialStore(secrets: [profile.credentialReference!: TestSecrets().password])
        )
        let session = RecordingRuntimeOnlySession(initialStatus: .disconnected)
        let manager = RecordingDiagnosticTunnelProviderManager(session: session)
        let managerStore = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: managerStore)
        let service = LibXrayPingOnlyPacketTunnelService(
            publisher: publisher,
            bootstrapper: bootstrapper,
            sessionProvider: StaticTunnelProviderSessionProvider(session: session),
            statusTimeout: .milliseconds(50),
            statusPollInterval: .milliseconds(1)
        )

        let result = try await service.start(profile: profile)

        #expect(result.success)
        #expect(result.protocolName == "libXrayPingOnly")
        #expect(result.transportName == "none")
        #expect(result.securityName == "none")
        #expect(!result.testXrayPassed)
        #expect(!result.runXrayInvoked)
        #expect(!result.runningStateObserved)
        #expect(!result.socksListenerReady)
        #expect(!result.socksGreetingAccepted)
        #expect(!result.stopXrayInvoked)
        #expect(!result.localPortClosed)

        let providerConfiguration = try #require(manager.providerConfiguration)
        #expect(Set(providerConfiguration.keys) == RuntimeProviderConfiguration.allowedKeys)
        #expect(try RuntimeProviderConfiguration.parse(providerConfiguration).profileID == profile.id)
        #expect(manager.sequence == ["configureRuntime", "save", "reload", "session"])

        let startOptions = try #require(session.startOptions.first)
        #expect(Set(startOptions.keys) == LibXrayPingOnlyPacketTunnelStartOptions.allowedKeys)
        let startOptionsJSON = try propertyListJSONString(startOptions)
        assertNoSecretMaterial(in: startOptionsJSON, secrets: TestSecrets())
        #expect(!startOptionsJSON.contains("keychain://"))
        #expect(!startOptionsJSON.contains("hy2-sni.example.com"))
        #expect(!startOptionsJSON.contains("HY2.Example.COM"))
        #expect(!startOptionsJSON.contains("hysteria"))
        #expect(!startOptionsJSON.contains("localPort"))
    }

    @Test
    func dataPlaneStartPublishesCanonicalProviderConfigurationAndUsesMarkerOnly() async throws {
        let profile = makeXHTTPTLSProfile(mode: "stream-one")
        let publisher = SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: InMemoryRuntimeProfileStore(),
            credentialStore: StaticCredentialStore(secrets: [profile.credentialReference!: TestSecrets().vlessUUID])
        )
        let session = RecordingRuntimeOnlySession(initialStatus: .disconnected)
        let manager = RecordingDiagnosticTunnelProviderManager(session: session)
        let managerStore = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: managerStore)
        let service = DataPlanePacketTunnelService(
            publisher: publisher,
            bootstrapper: bootstrapper,
            sessionProvider: StaticTunnelProviderSessionProvider(session: session),
            statusTimeout: .milliseconds(50),
            statusPollInterval: .milliseconds(1)
        )

        let result = try await service.start(profile: profile)

        #expect(result.success)
        #expect(result.transportName == "xhttp")
        #expect(result.securityName == "tls")
        let providerConfiguration = try #require(manager.providerConfiguration)
        #expect(Set(providerConfiguration.keys) == RuntimeProviderConfiguration.allowedKeys)
        #expect(try RuntimeProviderConfiguration.parse(providerConfiguration).profileID == profile.id)
        #expect(manager.sequence == ["configureRuntime", "save", "reload", "session"])

        let startOptions = try #require(session.startOptions.first)
        #expect(Set(startOptions.keys) == DataPlanePacketTunnelStartOptions.allowedKeys)
        let startOptionsJSON = try propertyListJSONString(startOptions)
        assertNoSecretMaterial(in: startOptionsJSON, secrets: TestSecrets())
        #expect(!startOptionsJSON.contains("keychain://"))
        #expect(!startOptionsJSON.contains("example.com"))
        #expect(!startOptionsJSON.contains("/xhttp"))
        #expect(!startOptionsJSON.contains("cdn.example.com"))
        #expect(!startOptionsJSON.contains("stream-one"))
        #expect(!startOptionsJSON.contains("localPort"))
    }

    @Test
    func tun2SocksConfigurationIsDeterministicLoopbackTCPOnlyAndRedacted() throws {
        let builder = Tun2SocksConfigurationBuilder()
        let first = try builder.build(localSocksHost: "127.0.0.1", localSocksPort: 20_480)
        let second = try builder.build(localSocksHost: "127.0.0.1", localSocksPort: 20_480)
        let firstString = first.withString { $0 }
        let secondString = second.withString { $0 }

        #expect(firstString == secondString)
        #expect(firstString.contains("tunnel:\n  mtu: 9000"))
        #expect(firstString.contains("socks5:\n  port: 20480\n  address: 127.0.0.1"))
        #expect(!firstString.contains("udp:"))
        #expect(!firstString.contains(TestSecrets().vlessUUID))
        #expect(!firstString.contains("keychain://"))
        #expect(!firstString.contains("example.com"))
        #expect(first.description == "<redacted tun2socks configuration>")
        #expect(first.debugDescription == "<redacted tun2socks configuration>")
    }

    @Test
    func tun2SocksDataPlaneConfigurationEnablesSupportedUDPMode() throws {
        let configuration = try Tun2SocksConfigurationBuilder().build(
            localSocksHost: "127.0.0.1",
            localSocksPort: 20_480,
            udpEnabled: true
        )
        let content = configuration.withString { $0 }

        #expect(content.contains("socks5:\n  port: 20480\n  address: 127.0.0.1\n  udp: 'udp'"))
        #expect(!content.contains("0.0.0.0"))
        #expect(!content.contains("::"))
        #expect(!content.contains(TestSecrets().vlessUUID))
        #expect(!content.contains("keychain://"))
        #expect(!content.contains("example.com"))
    }

    @Test
    func packetTunnelNetworkSettingsPlanDocumentsIPv4DNSIPv6AndUDPPolicy() {
        let plan = PacketTunnelNetworkSettingsPlan.k3b3aIPv4FullTunnel

        #expect(plan.tunnelRemoteAddress == "127.0.0.1")
        #expect(plan.ipv4Address == "10.24.0.2")
        #expect(plan.ipv4SubnetMask == "255.255.255.0")
        #expect(plan.mtu == 9_000)
        #expect(plan.dnsMatchDomains == [""])
        #expect(plan.ipv6Policy == "ipv4OnlyNoIPv6Settings")
        #expect(plan.udpPolicy == "enabledForDataPlaneDNSForwarding")
    }

    @Test
    func extensionRuntimeControllerKeepsRuntimeOnlySeparateAndEnablesK3B3ADataPlane() throws {
        let runtimeModels = try projectFileContents("PacketTunnelExtension/Core/TunnelIPC/RuntimeConfigurationModels.swift")
        let provider = try projectFileContents("PacketTunnelExtension/PacketTunnelProvider.swift")
        let settingsView = try projectFileContents("VPN/Views/SettingsView.swift")
        let diagnosticsViewModel = try projectFileContents("VPN/Core/Portable/TunnelIPC/TunnelTelemetryDiagnosticsViewModel.swift")

        #expect(runtimeModels.contains("[.tcp, .xhttp].contains(resolved.transport.kind)"))
        #expect(runtimeModels.contains("mode: .packetTunnelRuntimeOnly"))
        #expect(runtimeModels.contains("return .runtimeOnlyStarted("))
        let actorDeclaration = try sourceSlice(
            in: runtimeModels,
            from: "actor XrayRuntimeLifecycleController:",
            to: "private let runtimeConfigurationLoader"
        )
        #expect(actorDeclaration.contains("actor XrayRuntimeLifecycleController:"))
        #expect(actorDeclaration.contains("XrayConfigurationValidating"))
        #expect(actorDeclaration.contains("XrayRemoteEgressProbing"))
        #expect(actorDeclaration.contains("PacketTunnelUDPControlProbing"))
        #expect(actorDeclaration.contains("LibXrayPingProbing"))
        #expect(actorDeclaration.contains("DiagnosticProviderModeProviding"))
        #expect(actorDeclaration.contains("XrayRuntimeSessionControlling"))
        #expect(runtimeModels.contains("category: .runtimeAlreadyRunning"))
        #expect(!runtimeModels.contains("resolved.transport.kind == .tcp,"))
        let runtimeController = try sourceSlice(
            in: runtimeModels,
            from: "actor XrayRuntimeLifecycleController:",
            to: "final class PacketTunnelXrayLifecycleSmokeTestService"
        )
        let activeProbe = try sourceFunctionBody(
            in: runtimeController,
            from: "func probeActiveXrayEgress("
        )
        #expect(runtimeController.contains("private static func remoteProbeContext(for mode: XrayRuntimeLifecycleMode)"))
        #expect(runtimeController.contains("case .packetTunnelRuntimeOnly:"))
        #expect(runtimeController.contains("return .runtimeOnly"))
        #expect(runtimeController.contains("case .packetTunnelDataPlane:"))
        #expect(runtimeController.contains("return .dataPlane"))
        #expect(runtimeController.contains("case .oneShotSmoke, .libXrayPingOnly:"))
        #expect(runtimeController.contains("return nil"))
        #expect(runtimeController.contains("case .oneShotSmoke, .libXrayPingOnly:"))
        #expect(runtimeController.contains("func runLibXrayPingProbe("))
        #expect(runtimeController.contains("func diagnosticProviderMode() async -> TunnelDiagnosticProviderMode"))
        #expect(runtimeController.contains("func startPacketTunnelLibXrayPingOnly("))
        #expect(runtimeController.contains("mode: .libXrayPingOnly"))
        #expect(runtimeModels.contains("LibXrayPingBatchPayload"))
        #expect(runtimeModels.contains(#"encodedRuntimeRequest(method: "pingBatch""#))
        #expect(runtimeModels.contains(#"outboundTag: "proxy""#))
        #expect(runtimeModels.contains(#"url: "https://cp.cloudflare.com/""#))
        #expect(runtimeModels.contains("nativeErrorPresent: item.error?.isEmpty == false"))
        #expect(activeProbe.contains("remoteEgressProbe.probe(host: \"127.0.0.1\", port: session.port)"))
        #expect(activeProbe.contains("let probeContext = Self.remoteProbeContext(for: session.mode)"))
        #expect(activeProbe.contains("probeContext: probeContext"))
        #expect(!activeProbe.contains("testXray("))
        #expect(!activeProbe.contains("runXray("))
        #expect(!activeProbe.contains("stopXray("))
        #expect(!activeProbe.contains("tun2Socks"))
        #expect(!activeProbe.contains("networkSettingsApplier"))
        #expect(!activeProbe.contains("setTunnelNetworkSettings"))
        #expect(!activeProbe.contains("Socks5Tunnel.run"))
        #expect(!activeProbe.contains("Socks5Tunnel.quit"))
        let udpProbe = try sourceFunctionBody(
            in: runtimeController,
            from: "func runUDPControlProbe("
        )
        #expect(udpProbe.contains("session.mode == .packetTunnelRuntimeOnly"))
        #expect(udpProbe.contains("category: .notRuntimeOnly"))
        #expect(!udpProbe.contains("LibXrayInvoke"))
        #expect(!udpProbe.contains("testXray("))
        #expect(!udpProbe.contains("runXray("))
        #expect(!udpProbe.contains("stopXray("))
        #expect(!udpProbe.contains("Socks5Tunnel.run"))
        #expect(!udpProbe.contains("Socks5Tunnel.quit"))
        #expect(!udpProbe.contains("tun2Socks.run"))
        #expect(!udpProbe.contains("tun2Socks.quit"))
        #expect(!udpProbe.contains("setTunnelNetworkSettings"))
        #expect(!udpProbe.contains("packetFlow"))
        let libXrayPingProbe = try sourceFunctionBody(
            in: runtimeController,
            from: "func runLibXrayPingProbe("
        )
        #expect(libXrayPingProbe.contains("session.mode == .libXrayPingOnly"))
        #expect(libXrayPingProbe.contains("libXrayPingBatch.pingBatch("))
        #expect(libXrayPingProbe.contains("builder.build("))
        #expect(!libXrayPingProbe.contains("testXray("))
        #expect(!libXrayPingProbe.contains("runXray("))
        #expect(!libXrayPingProbe.contains("stopXray("))
        #expect(!libXrayPingProbe.contains("readinessProbe.waitForReadiness"))
        #expect(!libXrayPingProbe.contains("remoteEgressProbe.probe"))
        #expect(!libXrayPingProbe.contains("tun2Socks"))
        #expect(!libXrayPingProbe.contains("networkSettingsApplier"))
        #expect(!libXrayPingProbe.contains("setTunnelNetworkSettings"))
        #expect(!libXrayPingProbe.contains("packetFlow"))
        let pingOnlyStart = try sourceFunctionBody(
            in: runtimeController,
            from: "func startPacketTunnelLibXrayPingOnly("
        )
        #expect(pingOnlyStart.contains("mode: .libXrayPingOnly"))
        #expect(pingOnlyStart.contains("tun2SocksStarted: false"))
        #expect(pingOnlyStart.contains("networkSettingsApplied: false"))
        #expect(pingOnlyStart.contains("runXrayInvoked: false"))
        #expect(pingOnlyStart.contains("socksListenerReady: false"))
        #expect(!pingOnlyStart.contains("testXray("))
        #expect(!pingOnlyStart.contains("runXray("))
        #expect(!pingOnlyStart.contains("stopXray("))
        #expect(!pingOnlyStart.contains("readinessProbe"))
        #expect(!pingOnlyStart.contains("Socks5Tunnel.run"))
        #expect(!pingOnlyStart.contains("Socks5Tunnel.quit"))
        #expect(!pingOnlyStart.contains("tun2Socks.run"))
        #expect(!pingOnlyStart.contains("tun2Socks.quit"))
        #expect(!pingOnlyStart.contains("networkSettingsApplier"))
        #expect(!pingOnlyStart.contains("setTunnelNetworkSettings"))
        #expect(!pingOnlyStart.contains("packetFlow"))
        #expect(provider.contains("private lazy var xrayConfigurationValidator: (any XrayConfigurationValidating)? = {"))
        #expect(provider.contains("xrayRuntimeController"))
        #expect(provider.contains("PacketTunnelUDPControlProbeService(controller: xrayRuntimeController)"))
        #expect(provider.contains("PacketTunnelLibXrayPingProbeService(controller: xrayRuntimeController)"))
        #expect(provider.contains("diagnosticProviderModeProvider: xrayRuntimeController"))
        #expect(!provider.contains("return PacketTunnelXrayConfigurationValidationService(runtimeConfigurationLoader: runtimeValidationLoader)"))
        #expect(provider.contains("RuntimeOnlyPacketTunnelStartOptions"))
        #expect(provider.contains("DataPlanePacketTunnelStartOptions"))
        #expect(provider.contains("LibXrayPingOnlyPacketTunnelStartOptions"))
        #expect(provider.contains("xrayRuntimeController.startPacketTunnelRuntimeOnly"))
        #expect(provider.contains("xrayRuntimeController.startPacketTunnelDataPlane"))
        #expect(provider.contains("xrayRuntimeController.startPacketTunnelLibXrayPingOnly"))
        #expect(provider.contains("xrayRuntimeController.stopActivePacketTunnelSession"))
        #expect(runtimeModels.contains("Socks5Tunnel.run(withConfig: .string(content: content))"))
        #expect(runtimeModels.contains("Socks5Tunnel.quit()"))
        #expect(runtimeModels.contains("Socks5Tunnel.stats"))
        #expect(runtimeModels.contains("provider.setTunnelNetworkSettings(settings)"))
        #expect(runtimeModels.contains("provider.setTunnelNetworkSettings(nil)"))
        #expect(runtimeModels.contains("ipv4.includedRoutes = [NEIPv4Route.default()]"))
        #expect(runtimeModels.contains("dns.matchDomains = plan.dnsMatchDomains"))
        #expect(runtimeModels.contains("localSocksUDPEnabled: mode == .packetTunnelDataPlane"))
        #expect(runtimeModels.contains("udpEnabled: true"))
        #expect(!provider.contains("localPort"))
        #expect(!provider.contains("20_480"))
        #expect(!settingsView.contains("20_480"))
        #expect(!settingsView.contains("selectedPort"))
        #expect(!settingsView.contains("socksPort"))
        #expect(settingsView.contains("diagnostics.active_xray_egress.context"))
        #expect(settingsView.contains("diagnostics.udp_control.run"))
        #expect(settingsView.contains("diagnostics.libxray_ping.run"))
        #expect(settingsView.contains("diagnostics.libxray_ping_only.start"))
        #expect(settingsView.contains("diagnostics.provider_mode.label"))
        #expect(settingsView.contains("diagnostics.provider_mode.recover"))
        #expect(settingsView.contains("tunnelTelemetry.reconcileDiagnosticProviderState()"))
        #expect(settingsView.contains("tunnelTelemetry.recoverDiagnosticProvider()"))
        #expect(settingsView.contains("tunnelTelemetry.runUDPControlProbe()"))
        #expect(settingsView.contains("tunnelTelemetry.runLibXrayPingProbe("))
        #expect(settingsView.contains("profile: viewModel?.selectedProfile"))
        #expect(settingsView.contains("tunnelTelemetry.persistentDiagnosticStartIsEligible"))
        #expect(settingsView.contains("tunnelTelemetry.runtimeOnlyDiagnosticModeIsRunning"))
        #expect(settingsView.contains("tunnelTelemetry.dataPlaneDiagnosticModeIsRunning"))
        #expect(settingsView.contains("tunnelTelemetry.libXrayPingOnlyDiagnosticModeIsRunning"))
        #expect(!settingsView.contains("runtimeOnlyTunnelResult?.success != true"))
        #expect(!settingsView.contains("dataPlaneTunnelResult?.success != true"))
        #expect(!settingsView.contains("libXrayPingOnlyTunnelResult?.success == true"))
        #expect(!settingsView.contains("libXrayPingOnlyTunnelResult?.success != true"))
        #expect(!diagnosticsViewModel.contains("20_480"))
        #expect(!diagnosticsViewModel.contains("selectedPort"))
        #expect(!diagnosticsViewModel.contains("socksPort"))
        #expect(diagnosticsViewModel.contains("var diagnosticProviderMode: TunnelDiagnosticProviderMode = .idle"))
        #expect(diagnosticsViewModel.contains("func reconcileDiagnosticProviderState()"))
        #expect(diagnosticsViewModel.contains("func recoverDiagnosticProvider()"))
        #expect(diagnosticsViewModel.contains("var persistentDiagnosticStartIsEligible: Bool"))
        #expect(diagnosticsViewModel.contains("var diagnosticProviderIsOccupied: Bool"))
        #expect(diagnosticsViewModel.contains("let persistentXrayModeIsRunning = runtimeOnlyDiagnosticModeIsRunning"))
        #expect(diagnosticsViewModel.contains("|| dataPlaneDiagnosticModeIsRunning"))
        #expect(diagnosticsViewModel.contains("probeActiveXrayEgress(profile: profile)"))
        #expect(diagnosticsViewModel.contains("func runUDPControlProbe()"))
        #expect(diagnosticsViewModel.contains("func runLibXrayPingProbe(profile: VPNProfile?)"))
        #expect(diagnosticsViewModel.contains("func startLibXrayPingOnlyTunnel(profile: VPNProfile?)"))
        #expect(diagnosticsViewModel.contains("guard runtimeOnlyDiagnosticModeIsRunning else"))
        #expect(diagnosticsViewModel.contains("guard libXrayPingOnlyDiagnosticModeIsRunning else"))
        #expect(!diagnosticsViewModel.contains("runtimeOnlyTunnelResult?.success == true"))
        #expect(!diagnosticsViewModel.contains("dataPlaneTunnelResult?.success == true"))
        #expect(!diagnosticsViewModel.contains("libXrayPingOnlyTunnelResult?.success == true"))
        #expect(!provider.contains("packetFlow.readPackets"))
        #expect(!provider.contains("packetFlow.writePackets"))
        #expect(!runtimeModels.contains("packetFlow.readPackets"))
        #expect(!runtimeModels.contains("packetFlow.writePackets"))
        #expect(!provider.contains("Socks5Tunnel.run"))
        #expect(!provider.contains("Socks5Tunnel.quit"))
    }
}

struct K3B4DiagnosticAdmissionTests {
    @Test
    @MainActor
    func debugDiagnosticsAcceptEveryK3B4XrayBackedProtocol() async throws {
        for fixture in k3b4DiagnosticAdmissionFixtures() {
            let harness = try makeDiagnosticAdmissionHarness(
                profile: fixture.profile,
                credential: fixture.credential,
                expectedProtocolName: fixture.expectedProtocolName
            )

            harness.viewModel.validateRuntimeConfiguration(profile: fixture.profile)
            await waitForDiagnosticCondition { harness.viewModel.runtimeValidationResult != nil }
            #expect(harness.viewModel.runtimeValidationResult?.success == true)
            #expect(harness.viewModel.runtimeValidationResult?.protocolName == fixture.expectedProtocolName)
            #expect(harness.viewModel.runtimeValidationDiagnostic?.extensionRequestReached == true)
            #expect(await harness.runtimeMessenger.sentRequests.count == 1)

            harness.viewModel.validateXrayConfiguration(profile: fixture.profile)
            await waitForDiagnosticCondition { harness.viewModel.xrayValidationResult != nil }
            #expect(harness.viewModel.xrayValidationResult?.success == true)
            #expect(harness.viewModel.xrayValidationResult?.protocolName == fixture.expectedProtocolName)
            #expect(harness.viewModel.xrayValidationDiagnostic?.extensionRequestReached == true)
            #expect(await harness.xrayMessenger.sentRequests.count == 1)

            harness.viewModel.runXrayLifecycleSmokeTest(profile: fixture.profile)
            await waitForDiagnosticCondition { harness.viewModel.xrayLifecycleSmokeTestResult != nil }
            #expect(harness.viewModel.xrayLifecycleSmokeTestResult?.success == true)
            #expect(harness.viewModel.xrayLifecycleSmokeTestResult?.protocolName == fixture.expectedProtocolName)
            #expect(harness.viewModel.xrayLifecycleSmokeTestDiagnostic?.extensionRequestReached == true)
            #expect(await harness.lifecycleMessenger.sentRequests.count == 1)

            harness.viewModel.runXrayRemoteEgressProbe(profile: fixture.profile)
            await waitForDiagnosticCondition { harness.viewModel.xrayRemoteEgressProbeResult != nil }
            #expect(harness.viewModel.xrayRemoteEgressProbeResult?.success == true)
            #expect(harness.viewModel.xrayRemoteEgressProbeResult?.protocolName == fixture.expectedProtocolName)
            #expect(harness.viewModel.xrayRemoteEgressProbeDiagnostic?.extensionRequestReached == true)
            #expect(await harness.remoteEgressMessenger.sentRequests.count == 1)

            harness.viewModel.startRuntimeOnlyTunnel(profile: fixture.profile)
            await waitForDiagnosticCondition {
                harness.viewModel.runtimeOnlyTunnelResult != nil &&
                    harness.viewModel.diagnosticProviderMode == .runtimeOnly
            }
            #expect(harness.viewModel.runtimeOnlyTunnelResult?.success == true)
            #expect(harness.viewModel.runtimeOnlyTunnelResult?.protocolName == fixture.expectedProtocolName)
            #expect(harness.viewModel.runtimeOnlyTunnelDiagnostic?.extensionRequestReached == true)
            #expect(harness.viewModel.diagnosticProviderMode == .runtimeOnly)
            #expect(harness.runtimeOnlySession.runtimeOnlyStartOptions.count == 1)

            harness.viewModel.stopRuntimeOnlyTunnel()
            await waitForDiagnosticCondition { harness.viewModel.providerStatus == .disconnected }

            harness.viewModel.startDataPlaneTunnel(profile: fixture.profile)
            await waitForDiagnosticCondition {
                harness.viewModel.dataPlaneTunnelResult != nil &&
                    harness.viewModel.diagnosticProviderMode == .dataPlane
            }
            #expect(harness.viewModel.dataPlaneTunnelResult?.success == true)
            #expect(harness.viewModel.dataPlaneTunnelResult?.protocolName == fixture.expectedProtocolName)
            #expect(harness.viewModel.dataPlaneTunnelDiagnostic?.extensionRequestReached == true)
            #expect(harness.viewModel.diagnosticProviderMode == .dataPlane)
            #expect(harness.dataPlaneSession.dataPlaneStartOptions.count == 1)
        }
    }

    @Test
    @MainActor
    func outlineStaticAdmissionUsesShadowsocksRuntimeProtocol() async throws {
        let profile = makeShadowsocksProfile(outline: true)
        let harness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().password,
            expectedProtocolName: "shadowsocks"
        )

        harness.viewModel.validateRuntimeConfiguration(profile: profile)
        await waitForDiagnosticCondition { harness.viewModel.runtimeValidationResult != nil }
        harness.viewModel.validateXrayConfiguration(profile: profile)
        await waitForDiagnosticCondition { harness.viewModel.xrayValidationResult != nil }
        harness.viewModel.startDataPlaneTunnel(profile: profile)
        await waitForDiagnosticCondition {
            harness.viewModel.dataPlaneTunnelResult != nil &&
                harness.viewModel.diagnosticProviderMode == .dataPlane
        }

        #expect(harness.viewModel.runtimeValidationResult?.protocolName == "shadowsocks")
        #expect(harness.viewModel.xrayValidationResult?.protocolName == "shadowsocks")
        #expect(harness.viewModel.dataPlaneTunnelResult?.protocolName == "shadowsocks")
        #expect(harness.viewModel.diagnosticProviderMode == .dataPlane)
        #expect(harness.viewModel.dataPlaneTunnelResult?.protocolName != "outline")
        #expect(await harness.runtimeMessenger.sentRequests.count == 1)
        #expect(await harness.xrayMessenger.sentRequests.count == 1)
        #expect(await harness.remoteEgressMessenger.sentRequests.isEmpty)
        #expect(harness.dataPlaneSession.dataPlaneStartOptions.count == 1)
    }

    @Test
    @MainActor
    func activeXrayEgressProbeAdmitsRuntimeOnlyAndDataPlaneContexts() async throws {
        let profile = makeTCPTLSProfile()

        let idleHarness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless"
        )
        idleHarness.viewModel.probeActiveXrayEgress(profile: profile)
        #expect(idleHarness.viewModel.activeXrayEgressProbeResult == nil)
        #expect(idleHarness.viewModel.activeXrayEgressProbeDiagnostic?.category == .runtimeBusy)
        #expect(idleHarness.viewModel.activeXrayEgressProbeDiagnostic?.extensionRequestReached == false)
        #expect(await idleHarness.remoteEgressMessenger.sentRequests.isEmpty)

        let runtimeOnlyHarness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless",
            activeProbeContext: .runtimeOnly
        )
        runtimeOnlyHarness.viewModel.startRuntimeOnlyTunnel(profile: profile)
        await waitForDiagnosticCondition {
            runtimeOnlyHarness.viewModel.runtimeOnlyTunnelResult?.success == true &&
                runtimeOnlyHarness.viewModel.diagnosticProviderMode == .runtimeOnly
        }
        runtimeOnlyHarness.viewModel.probeActiveXrayEgress(profile: profile)
        await waitForDiagnosticCondition { runtimeOnlyHarness.viewModel.activeXrayEgressProbeResult != nil }
        #expect(runtimeOnlyHarness.viewModel.activeXrayEgressProbeResult?.success == true)
        #expect(runtimeOnlyHarness.viewModel.activeXrayEgressProbeResult?.probeContext == .runtimeOnly)
        #expect(runtimeOnlyHarness.dataPlaneSession.dataPlaneStartOptions.isEmpty)
        let runtimeOnlyRequests = await runtimeOnlyHarness.remoteEgressMessenger.sentRequests
        #expect(runtimeOnlyRequests.map(\.kind) == [.probeActiveXrayEgress])

        let dataPlaneHarness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless",
            activeProbeContext: .dataPlane
        )
        dataPlaneHarness.viewModel.startDataPlaneTunnel(profile: profile)
        await waitForDiagnosticCondition {
            dataPlaneHarness.viewModel.dataPlaneTunnelResult?.success == true &&
                dataPlaneHarness.viewModel.diagnosticProviderMode == .dataPlane
        }
        dataPlaneHarness.viewModel.probeActiveXrayEgress(profile: profile)
        await waitForDiagnosticCondition { dataPlaneHarness.viewModel.activeXrayEgressProbeResult != nil }
        #expect(dataPlaneHarness.viewModel.activeXrayEgressProbeResult?.success == true)
        #expect(dataPlaneHarness.viewModel.activeXrayEgressProbeResult?.probeContext == .dataPlane)
        #expect(dataPlaneHarness.runtimeOnlySession.runtimeOnlyStartOptions.isEmpty)
        let dataPlaneRequests = await dataPlaneHarness.remoteEgressMessenger.sentRequests
        #expect(dataPlaneRequests.map(\.kind) == [.probeActiveXrayEgress])
    }

    @Test
    @MainActor
    func udpControlProbeAdmitsOnlyRuntimeOnlyContext() async throws {
        let profile = makeTCPTLSProfile()

        let idleHarness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless"
        )
        idleHarness.viewModel.runUDPControlProbe()
        #expect(idleHarness.viewModel.udpControlProbeResult == nil)
        #expect(idleHarness.viewModel.udpControlProbeDiagnostic?.category == .notRuntimeOnly)
        #expect(idleHarness.viewModel.udpControlProbeDiagnostic?.extensionRequestReached == false)
        #expect(await idleHarness.udpControlMessenger.sentRequests.isEmpty)
        #expect(await idleHarness.remoteEgressMessenger.sentRequests.isEmpty)

        let runtimeOnlyHarness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless"
        )
        runtimeOnlyHarness.viewModel.startRuntimeOnlyTunnel(profile: profile)
        await waitForDiagnosticCondition {
            runtimeOnlyHarness.viewModel.runtimeOnlyTunnelResult?.success == true &&
                runtimeOnlyHarness.viewModel.diagnosticProviderMode == .runtimeOnly
        }
        runtimeOnlyHarness.viewModel.runUDPControlProbe()
        await waitForDiagnosticCondition { runtimeOnlyHarness.viewModel.udpControlProbeResult != nil }
        #expect(runtimeOnlyHarness.viewModel.udpControlProbeResult?.success == true)
        #expect(runtimeOnlyHarness.viewModel.udpControlProbeResult?.udpConnectionReady == true)
        #expect(runtimeOnlyHarness.viewModel.udpControlProbeResult?.udpWriteSucceeded == true)
        #expect(runtimeOnlyHarness.viewModel.udpControlProbeResult?.udpResponseReceived == true)
        #expect(runtimeOnlyHarness.viewModel.udpControlProbeResult?.udpResponseValidated == true)
        #expect(runtimeOnlyHarness.viewModel.udpControlProbeResult?.pathSnapshot?.pathStatus == .satisfied)
        #expect(runtimeOnlyHarness.dataPlaneSession.dataPlaneStartOptions.isEmpty)
        #expect(await runtimeOnlyHarness.remoteEgressMessenger.sentRequests.isEmpty)
        let runtimeOnlyRequests = await runtimeOnlyHarness.udpControlMessenger.sentRequests
        #expect(runtimeOnlyRequests.map(\.kind) == [.runUDPControlProbe])

        let dataPlaneHarness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless"
        )
        dataPlaneHarness.viewModel.startDataPlaneTunnel(profile: profile)
        await waitForDiagnosticCondition {
            dataPlaneHarness.viewModel.dataPlaneTunnelResult?.success == true &&
                dataPlaneHarness.viewModel.diagnosticProviderMode == .dataPlane
        }
        dataPlaneHarness.viewModel.runUDPControlProbe()
        #expect(dataPlaneHarness.viewModel.udpControlProbeResult == nil)
        #expect(dataPlaneHarness.viewModel.udpControlProbeDiagnostic?.category == .notRuntimeOnly)
        #expect(dataPlaneHarness.viewModel.udpControlProbeDiagnostic?.extensionRequestReached == false)
        #expect(dataPlaneHarness.runtimeOnlySession.runtimeOnlyStartOptions.isEmpty)
        #expect(await dataPlaneHarness.udpControlMessenger.sentRequests.isEmpty)
        #expect(await dataPlaneHarness.remoteEgressMessenger.sentRequests.isEmpty)
    }

    @Test
    @MainActor
    func isolatedLibXrayPingProbeAdmitsOnlyPingOnlyContext() async throws {
        let profile = makeHysteria2Profile()

        let idleHarness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().password,
            expectedProtocolName: "hysteria2"
        )
        idleHarness.viewModel.runLibXrayPingProbe(profile: profile)
        #expect(idleHarness.viewModel.libXrayPingProbeResult == nil)
        #expect(idleHarness.viewModel.libXrayPingProbeDiagnostic?.category == .runtimeBusy)
        #expect(idleHarness.viewModel.libXrayPingProbeDiagnostic?.extensionRequestReached == false)
        #expect(await idleHarness.libXrayPingMessenger.sentRequests.isEmpty)

        let runtimeOnlyHarness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().password,
            expectedProtocolName: "hysteria2"
        )
        runtimeOnlyHarness.viewModel.startRuntimeOnlyTunnel(profile: profile)
        await waitForDiagnosticCondition {
            runtimeOnlyHarness.viewModel.runtimeOnlyTunnelResult?.success == true &&
                runtimeOnlyHarness.viewModel.diagnosticProviderMode == .runtimeOnly
        }
        runtimeOnlyHarness.viewModel.runLibXrayPingProbe(profile: profile)
        #expect(runtimeOnlyHarness.viewModel.libXrayPingProbeResult == nil)
        #expect(runtimeOnlyHarness.viewModel.libXrayPingProbeDiagnostic?.category == .runtimeBusy)
        #expect(await runtimeOnlyHarness.libXrayPingMessenger.sentRequests.isEmpty)

        let dataPlaneHarness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().password,
            expectedProtocolName: "hysteria2"
        )
        dataPlaneHarness.viewModel.startDataPlaneTunnel(profile: profile)
        await waitForDiagnosticCondition {
            dataPlaneHarness.viewModel.dataPlaneTunnelResult?.success == true &&
                dataPlaneHarness.viewModel.diagnosticProviderMode == .dataPlane
        }
        dataPlaneHarness.viewModel.runLibXrayPingProbe(profile: profile)
        #expect(dataPlaneHarness.viewModel.libXrayPingProbeResult == nil)
        #expect(dataPlaneHarness.viewModel.libXrayPingProbeDiagnostic?.category == .runtimeBusy)
        #expect(await dataPlaneHarness.libXrayPingMessenger.sentRequests.isEmpty)

        let pingOnlyHarness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().password,
            expectedProtocolName: "hysteria2"
        )
        pingOnlyHarness.viewModel.startLibXrayPingOnlyTunnel(profile: profile)
        await waitForDiagnosticCondition {
            pingOnlyHarness.viewModel.libXrayPingOnlyTunnelResult?.success == true &&
                pingOnlyHarness.viewModel.diagnosticProviderMode == .libXrayPingOnly
        }
        #expect(pingOnlyHarness.viewModel.libXrayPingOnlyTunnelResult?.runXrayInvoked == false)
        #expect(pingOnlyHarness.viewModel.libXrayPingOnlyTunnelResult?.socksListenerReady == false)
        #expect(pingOnlyHarness.runtimeOnlySession.runtimeOnlyStartOptions.isEmpty)
        #expect(pingOnlyHarness.dataPlaneSession.dataPlaneStartOptions.isEmpty)

        pingOnlyHarness.viewModel.runLibXrayPingProbe(profile: profile)
        await waitForDiagnosticCondition { pingOnlyHarness.viewModel.libXrayPingProbeResult != nil }
        #expect(pingOnlyHarness.viewModel.libXrayPingProbeResult?.success == true)
        #expect(pingOnlyHarness.viewModel.libXrayPingProbeResult?.protocolName == "hysteria2")
        #expect(pingOnlyHarness.viewModel.libXrayPingProbeResult?.transportName == "hysteria")
        #expect(pingOnlyHarness.viewModel.libXrayPingProbeResult?.securityName == "tls")
        #expect(pingOnlyHarness.viewModel.libXrayPingProbeResult?.h3ALPNConfigured == true)
        #expect(pingOnlyHarness.viewModel.libXrayPingProbeResult?.nativeErrorPresent == false)
        #expect(pingOnlyHarness.libXrayPingOnlySession.libXrayPingOnlyStartOptions.count == 1)
        let pingRequests = await pingOnlyHarness.libXrayPingMessenger.sentRequests
        #expect(pingRequests.map(\.kind) == [.runLibXrayPingProbe])
    }

    @Test
    @MainActor
    func diagnosticProviderModeFixtureScriptsEverySafeMode() async throws {
        let session = RecordingRuntimeOnlySession(initialStatus: .connected, providerMode: .idle)
        let manager = RecordingDiagnosticTunnelProviderManager(session: session)
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let service = DiagnosticProviderStateService(
            managerStore: store,
            timeout: .milliseconds(50)
        )

        for mode in [
            TunnelDiagnosticProviderMode.idle,
            .runtimeOnly,
            .dataPlane,
            .libXrayPingOnly,
            .lifecycleSmoke,
            .unknown
        ] {
            session.setStatus(.connected, providerMode: mode)
            let state = await service.reconcile()
            #expect(state.providerStatus == .connected)
            #expect(state.mode == mode)
            #expect(state.extensionReachable)
            #expect(state.recoveryRequired == (mode == .unknown))
        }

        session.setStatus(.connected)
        let unreachable = await service.reconcile()
        #expect(unreachable.providerStatus == .connected)
        #expect(unreachable.mode == .unknown)
        #expect(unreachable.extensionReachable == false)
        #expect(unreachable.recoveryRequired)

        session.setStatus(.disconnected)
        let disconnected = await service.reconcile()
        #expect(disconnected.providerStatus == .disconnected)
        #expect(disconnected.mode == .idle)
        #expect(disconnected.extensionReachable == false)
        #expect(disconnected.recoveryRequired == false)
    }

    @Test
    @MainActor
    func diagnosticProviderReconciliationClearsStaleConnectedCacheWhenActualSessionIsDisconnected() async throws {
        let harness = try makeDiagnosticAdmissionHarness(
            profile: makeTCPTLSProfile(),
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless"
        )
        harness.viewModel.providerStatus = .connected
        harness.viewModel.diagnosticProviderMode = .libXrayPingOnly
        harness.viewModel.runtimeOnlyTunnelResult = .runtimeOnlyStarted(
            correlationID: UUID(),
            protocolName: "vless",
            transportName: "tcp",
            securityName: "tls",
            startDurationMs: 1,
            readinessDurationMs: 1,
            totalDurationMs: 2
        )
        harness.runtimeOnlySession.setStatus(.disconnected)

        harness.viewModel.reconcileDiagnosticProviderState()
        await waitForDiagnosticCondition { harness.viewModel.isReconcilingDiagnosticProviderState == false }

        #expect(harness.viewModel.providerStatus == .disconnected)
        #expect(harness.viewModel.diagnosticProviderMode == .idle)
        #expect(harness.viewModel.diagnosticProviderStateIsUnsynchronized == false)
        #expect(harness.viewModel.persistentDiagnosticStartIsEligible)
        #expect(harness.viewModel.runtimeOnlyTunnelResult == nil)
        #expect(harness.viewModel.activeXrayEgressProbeResult == nil)
    }

    @Test
    @MainActor
    func diagnosticProviderReconciliationRestoresRuntimeOnlyOwnershipFromExtension() async throws {
        let harness = try makeDiagnosticAdmissionHarness(
            profile: makeTCPTLSProfile(),
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless"
        )
        harness.runtimeOnlySession.setStatus(.connected, providerMode: .runtimeOnly)
        #expect(harness.viewModel.runtimeOnlyTunnelResult == nil)

        harness.viewModel.reconcileDiagnosticProviderState()
        await waitForDiagnosticCondition { harness.viewModel.runtimeOnlyDiagnosticModeIsRunning }

        #expect(harness.viewModel.providerStatus == .connected)
        #expect(harness.viewModel.diagnosticProviderMode == .runtimeOnly)
        #expect(harness.viewModel.diagnosticProviderStateIsUnsynchronized == false)
        #expect(harness.viewModel.runtimeOnlyDiagnosticModeIsRunning)
        #expect(harness.viewModel.persistentDiagnosticStartIsEligible == false)
        #expect(harness.runtimeOnlySession.providerMessageCount == 1)
    }

    @Test
    @MainActor
    func diagnosticProviderReconciliationRestoresPingOnlyOwnershipFromExtension() async throws {
        let harness = try makeDiagnosticAdmissionHarness(
            profile: makeHysteria2Profile(),
            credential: TestSecrets().password,
            expectedProtocolName: "hysteria2"
        )
        harness.libXrayPingOnlySession.setStatus(.connected, providerMode: .libXrayPingOnly)
        #expect(harness.viewModel.libXrayPingOnlyTunnelResult == nil)

        harness.viewModel.reconcileDiagnosticProviderState()
        await waitForDiagnosticCondition { harness.viewModel.libXrayPingOnlyDiagnosticModeIsRunning }

        #expect(harness.viewModel.providerStatus == .connected)
        #expect(harness.viewModel.diagnosticProviderMode == .libXrayPingOnly)
        #expect(harness.viewModel.diagnosticProviderStateIsUnsynchronized == false)
        #expect(harness.viewModel.libXrayPingOnlyDiagnosticModeIsRunning)
        #expect(harness.viewModel.persistentDiagnosticStartIsEligible == false)
    }

    @Test
    @MainActor
    func diagnosticProviderReconciliationMarksUnknownConnectedStateRecoveryRequired() async throws {
        let harness = try makeDiagnosticAdmissionHarness(
            profile: makeTCPTLSProfile(),
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless"
        )
        harness.runtimeOnlySession.setStatus(.connected)

        harness.viewModel.reconcileDiagnosticProviderState()
        await waitForDiagnosticCondition { harness.viewModel.diagnosticProviderStateIsUnsynchronized }

        #expect(harness.viewModel.providerStatus == .connected)
        #expect(harness.viewModel.diagnosticProviderMode == .unknown)
        #expect(harness.viewModel.diagnosticProviderRecoveryIsAvailable)
        #expect(harness.viewModel.persistentDiagnosticStartIsEligible == false)
    }

    @Test
    @MainActor
    func recoverDiagnosticProviderStopsSessionAndClearsOwnershipWithoutRewritingConfiguration() async throws {
        let harness = try makeDiagnosticAdmissionHarness(
            profile: makeTCPTLSProfile(),
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless"
        )
        harness.runtimeOnlySession.setStatus(.connected)
        harness.viewModel.runtimeOnlyTunnelResult = .runtimeOnlyStarted(
            correlationID: UUID(),
            protocolName: "vless",
            transportName: "tcp",
            securityName: "tls",
            startDurationMs: 1,
            readinessDurationMs: 1,
            totalDurationMs: 2
        )

        harness.viewModel.recoverDiagnosticProvider()
        await waitForDiagnosticCondition { harness.viewModel.isRecoveringDiagnosticProvider == false }

        #expect(harness.runtimeOnlySession.stopCount == 1)
        #expect(harness.viewModel.providerStatus == .disconnected)
        #expect(harness.viewModel.diagnosticProviderMode == .idle)
        #expect(harness.viewModel.diagnosticProviderStateIsUnsynchronized == false)
        #expect(harness.viewModel.runtimeOnlyTunnelResult == nil)
        #expect(harness.diagnosticManager.providerConfiguration == nil)
        #expect(!harness.diagnosticManager.sequence.contains("configureRuntime"))
        #expect(!harness.diagnosticManager.sequence.contains("configureSentinel"))
        #expect(!harness.diagnosticManager.sequence.contains("save"))
    }

    @Test
    @MainActor
    func pingOnlyStartReconcilesDisconnectedSessionBeforeStarting() async throws {
        let profile = makeHysteria2Profile()
        let harness = try makeDiagnosticAdmissionHarness(
            profile: profile,
            credential: TestSecrets().password,
            expectedProtocolName: "hysteria2"
        )
        harness.viewModel.providerStatus = .connected
        harness.viewModel.diagnosticProviderMode = .unknown
        harness.viewModel.diagnosticProviderStateIsUnsynchronized = true
        harness.libXrayPingOnlySession.setStatus(.disconnected)

        harness.viewModel.startLibXrayPingOnlyTunnel(profile: profile)
        await waitForDiagnosticCondition {
            harness.viewModel.libXrayPingOnlyTunnelResult != nil &&
                harness.viewModel.diagnosticProviderMode == .libXrayPingOnly
        }

        #expect(harness.viewModel.libXrayPingOnlyTunnelResult?.success == true)
        #expect(harness.viewModel.providerStatus == .connected)
        #expect(harness.viewModel.diagnosticProviderMode == .libXrayPingOnly)
        #expect(harness.viewModel.diagnosticProviderStateIsUnsynchronized == false)
        #expect(harness.libXrayPingOnlySession.libXrayPingOnlyStartOptions.count == 1)
    }

    @Test
    @MainActor
    func unsupportedProtocolsStillRejectBeforeDebugIPCOrTunnelStart() async throws {
        for unsupported in [VPNProtocol.wireGuard, .tuic, .ikev2] {
            let profile = makeUnsupportedDiagnosticProfile(protocolType: unsupported)
            let harness = try makeDiagnosticAdmissionHarness(
                profile: makeTCPTLSProfile(),
                credential: TestSecrets().vlessUUID,
                expectedProtocolName: "vless"
            )

            harness.viewModel.validateRuntimeConfiguration(profile: profile)
            #expect(harness.viewModel.runtimeValidationResult == nil)
            #expect(harness.viewModel.runtimeValidationDiagnostic?.category == .unsupportedProtocol)
            #expect(harness.viewModel.runtimeValidationDiagnostic?.extensionRequestReached == false)
            #expect(await harness.runtimeMessenger.sentRequests.isEmpty)

            harness.viewModel.validateXrayConfiguration(profile: profile)
            #expect(harness.viewModel.xrayValidationResult == nil)
            #expect(harness.viewModel.xrayValidationDiagnostic?.category == .unsupportedProtocol)
            #expect(harness.viewModel.xrayValidationDiagnostic?.extensionRequestReached == false)
            #expect(await harness.xrayMessenger.sentRequests.isEmpty)

            harness.viewModel.runXrayLifecycleSmokeTest(profile: profile)
            #expect(harness.viewModel.xrayLifecycleSmokeTestResult == nil)
            #expect(harness.viewModel.xrayLifecycleSmokeTestDiagnostic?.category == .unsupportedProfileForRuntimeSmoke)
            #expect(harness.viewModel.xrayLifecycleSmokeTestDiagnostic?.extensionRequestReached == false)
            #expect(await harness.lifecycleMessenger.sentRequests.isEmpty)

            harness.viewModel.runXrayRemoteEgressProbe(profile: profile)
            #expect(harness.viewModel.xrayRemoteEgressProbeResult == nil)
            #expect(harness.viewModel.xrayRemoteEgressProbeDiagnostic?.category == .configurationRejected)
            #expect(harness.viewModel.xrayRemoteEgressProbeDiagnostic?.extensionRequestReached == false)
            #expect(await harness.remoteEgressMessenger.sentRequests.isEmpty)

            harness.viewModel.startRuntimeOnlyTunnel(profile: profile)
            #expect(harness.viewModel.runtimeOnlyTunnelResult == nil)
            #expect(harness.viewModel.runtimeOnlyTunnelDiagnostic?.category == .unsupportedProfileForRuntimeSmoke)
            #expect(harness.viewModel.runtimeOnlyTunnelDiagnostic?.extensionRequestReached == false)
            #expect(harness.runtimeOnlySession.runtimeOnlyStartOptions.isEmpty)

            harness.viewModel.startDataPlaneTunnel(profile: profile)
            #expect(harness.viewModel.dataPlaneTunnelResult == nil)
            #expect(harness.viewModel.dataPlaneTunnelDiagnostic?.category == .unsupportedProfileForRuntimeSmoke)
            #expect(harness.viewModel.dataPlaneTunnelDiagnostic?.extensionRequestReached == false)
            #expect(harness.dataPlaneSession.dataPlaneStartOptions.isEmpty)

            harness.viewModel.startLibXrayPingOnlyTunnel(profile: profile)
            #expect(harness.viewModel.libXrayPingOnlyTunnelResult == nil)
            #expect(harness.viewModel.libXrayPingOnlyTunnelDiagnostic?.category == .unsupportedProfileForRuntimeSmoke)
            #expect(harness.viewModel.libXrayPingOnlyTunnelDiagnostic?.extensionRequestReached == false)
            #expect(harness.libXrayPingOnlySession.libXrayPingOnlyStartOptions.isEmpty)

            harness.viewModel.runLibXrayPingProbe(profile: profile)
            #expect(harness.viewModel.libXrayPingProbeResult == nil)
            #expect(harness.viewModel.libXrayPingProbeDiagnostic?.category == .configurationRejected)
            #expect(harness.viewModel.libXrayPingProbeDiagnostic?.extensionRequestReached == false)
            #expect(await harness.libXrayPingMessenger.sentRequests.isEmpty)
        }
    }

    @Test
    @MainActor
    func newUnsupportedDiagnosticOperationClearsPreviousSuccessFields() async throws {
        let harness = try makeDiagnosticAdmissionHarness(
            profile: makeTCPTLSProfile(),
            credential: TestSecrets().vlessUUID,
            expectedProtocolName: "vless"
        )
        let unsupported = makeUnsupportedDiagnosticProfile(protocolType: .wireGuard)

        harness.viewModel.validateRuntimeConfiguration(profile: makeTCPTLSProfile())
        await waitForDiagnosticCondition { harness.viewModel.runtimeValidationResult?.success == true }
        harness.viewModel.validateRuntimeConfiguration(profile: unsupported)
        #expect(harness.viewModel.runtimeValidationResult == nil)
        #expect(harness.viewModel.runtimeValidationDiagnostic?.category == .unsupportedProtocol)

        harness.viewModel.validateXrayConfiguration(profile: makeTCPTLSProfile())
        await waitForDiagnosticCondition { harness.viewModel.xrayValidationResult?.success == true }
        harness.viewModel.validateXrayConfiguration(profile: unsupported)
        #expect(harness.viewModel.xrayValidationResult == nil)
        #expect(harness.viewModel.xrayValidationDiagnostic?.category == .unsupportedProtocol)

        harness.viewModel.runXrayLifecycleSmokeTest(profile: makeTCPTLSProfile())
        await waitForDiagnosticCondition { harness.viewModel.xrayLifecycleSmokeTestResult?.success == true }
        harness.viewModel.runXrayLifecycleSmokeTest(profile: unsupported)
        #expect(harness.viewModel.xrayLifecycleSmokeTestResult == nil)
        #expect(harness.viewModel.xrayLifecycleSmokeTestDiagnostic?.category == .unsupportedProfileForRuntimeSmoke)

        harness.viewModel.runXrayRemoteEgressProbe(profile: makeTCPTLSProfile())
        await waitForDiagnosticCondition { harness.viewModel.xrayRemoteEgressProbeResult?.success == true }
        harness.viewModel.runXrayRemoteEgressProbe(profile: unsupported)
        #expect(harness.viewModel.xrayRemoteEgressProbeResult == nil)
        #expect(harness.viewModel.xrayRemoteEgressProbeDiagnostic?.category == .configurationRejected)

        harness.viewModel.startRuntimeOnlyTunnel(profile: makeTCPTLSProfile())
        await waitForDiagnosticCondition { harness.viewModel.runtimeOnlyTunnelResult?.success == true }
        harness.viewModel.runUDPControlProbe()
        await waitForDiagnosticCondition { harness.viewModel.udpControlProbeResult?.success == true }
        let runtimeOnlyStartCount = harness.runtimeOnlySession.runtimeOnlyStartOptions.count
        harness.viewModel.startRuntimeOnlyTunnel(profile: unsupported)
        #expect(harness.viewModel.runtimeOnlyTunnelResult == nil)
        #expect(harness.viewModel.runtimeOnlyTunnelDiagnostic?.category == .unsupportedProfileForRuntimeSmoke)
        #expect(harness.viewModel.udpControlProbeResult == nil)
        #expect(harness.runtimeOnlySession.runtimeOnlyStartOptions.count == runtimeOnlyStartCount)

        harness.viewModel.stopRuntimeOnlyTunnel()
        await waitForDiagnosticCondition { harness.viewModel.providerStatus == .disconnected }

        harness.viewModel.startDataPlaneTunnel(profile: makeTCPTLSProfile())
        await waitForDiagnosticCondition { harness.viewModel.dataPlaneTunnelResult?.success == true }
        let dataPlaneStartCount = harness.dataPlaneSession.dataPlaneStartOptions.count
        harness.viewModel.startDataPlaneTunnel(profile: unsupported)
        #expect(harness.viewModel.dataPlaneTunnelResult == nil)
        #expect(harness.viewModel.dataPlaneTunnelDiagnostic?.category == .unsupportedProfileForRuntimeSmoke)
        #expect(harness.dataPlaneSession.dataPlaneStartOptions.count == dataPlaneStartCount)
    }

    @Test
    func hysteria2StructuralDiagnosticsContainOnlySafeBooleans() throws {
        let correlationID = UUID()
        let validationRequest = TunnelMessageRequest(kind: .validateXrayConfiguration)
        let validationResponse = TunnelMessageResponse.success(
            request: validationRequest,
            payload: .xrayConfigurationValidation(.success(
                correlationID: correlationID,
                protocolName: "hysteria2",
                transportName: "hysteria",
                securityName: "tls",
                h3ALPNConfigured: true,
                sniConfigured: true
            ))
        )
        let lifecycleRequest = TunnelMessageRequest(kind: .runXrayLifecycleSmokeTest)
        let lifecycleResponse = TunnelMessageResponse.success(
            request: lifecycleRequest,
            payload: .xrayLifecycleSmokeTest(.runtimeOnlyStarted(
                correlationID: correlationID,
                protocolName: "hysteria2",
                transportName: "hysteria",
                securityName: "tls",
                h3ALPNConfigured: true,
                sniConfigured: true,
                startDurationMs: 1,
                readinessDurationMs: 1,
                totalDurationMs: 2
            ))
        )
        let remoteRequest = TunnelMessageRequest(kind: .runXrayRemoteEgressProbe)
        let remoteResponse = TunnelMessageResponse.success(
            request: remoteRequest,
            payload: .xrayRemoteEgressProbe(.success(
                correlationID: correlationID,
                protocolName: "hysteria2",
                transportName: "hysteria",
                securityName: "tls",
                h3ALPNConfigured: true,
                sniConfigured: true,
                allowInsecureConfigured: true,
                startDurationMs: 1,
                readinessDurationMs: 1,
                remoteConnectDurationMs: 1,
                stopDurationMs: 1,
                totalDurationMs: 4
            ))
        )

        let validationJSON = String(decoding: try encode(validationResponse), as: UTF8.self)
        let lifecycleJSON = String(decoding: try encode(lifecycleResponse), as: UTF8.self)
        let remoteJSON = String(decoding: try encode(remoteResponse), as: UTF8.self)

        #expect(validationJSON.contains(#""h3ALPNConfigured":true"#))
        #expect(validationJSON.contains(#""sniConfigured":true"#))
        #expect(lifecycleJSON.contains(#""h3ALPNConfigured":true"#))
        #expect(lifecycleJSON.contains(#""sniConfigured":true"#))
        #expect(remoteJSON.contains(#""h3ALPNConfigured":true"#))
        #expect(remoteJSON.contains(#""sniConfigured":true"#))
        #expect(remoteJSON.contains(#""allowInsecureConfigured":true"#))
        #expect(!validationJSON.contains("hy2-sni.example.com"))
        #expect(!lifecycleJSON.contains("hy2-sni.example.com"))
        #expect(!remoteJSON.contains("hy2-sni.example.com"))
        assertNoSecretMaterial(in: validationJSON, secrets: TestSecrets())
        assertNoSecretMaterial(in: lifecycleJSON, secrets: TestSecrets())
        assertNoSecretMaterial(in: remoteJSON, secrets: TestSecrets())
    }
}

struct RuntimeConfigurationLocalizationTests {
    @Test
    func runtimeValidationLocalizationKeysExistInEnglishAndRussian() throws {
        let keys = [
            "diagnostics.runtime_validation.run",
            "diagnostics.runtime_validation.passed",
            "diagnostics.runtime_validation.failed",
            "diagnostics.runtime_validation.provider_config",
            "diagnostics.runtime_validation.provider_config_subreason",
            "diagnostics.runtime_validation.provider_config_key_count",
            "diagnostics.runtime_validation.provider_config_keys",
            "diagnostics.runtime_validation.provider_config_types",
            "diagnostics.runtime_validation.app_persisted_matches_intent",
            "diagnostics.runtime_validation.extension_matches_persisted",
            "diagnostics.runtime_validation.extension_matches_request",
            "diagnostics.runtime_validation.stale_k1_observed",
            "diagnostics.runtime_validation.stale_profile_observed",
            "diagnostics.runtime_validation.configuration_propagation_timed_out",
            "diagnostics.runtime_validation.record_found",
            "diagnostics.runtime_validation.profile_match",
            "diagnostics.runtime_validation.revision_match",
            "diagnostics.runtime_validation.schema",
            "diagnostics.runtime_validation.protocol_supported",
            "diagnostics.runtime_validation.credential_reference",
            "diagnostics.runtime_validation.credential_found",
            "diagnostics.runtime_validation.credential_format",
            "diagnostics.runtime_validation.extension_reached",
            "diagnostics.runtime_validation.error.no_profile",
            "diagnostics.runtime_validation.error.unsupported_protocol",
            "diagnostics.runtime_validation.error.shared_container",
            "diagnostics.xray_validation.run",
            "diagnostics.xray_validation.passed",
            "diagnostics.xray_validation.failed",
            "diagnostics.xray_validation.runtime_config",
            "diagnostics.xray_validation.builder",
            "diagnostics.xray_validation.libxray_available",
            "diagnostics.xray_validation.libxray_api",
            "diagnostics.xray_validation.testxray_invoked",
            "diagnostics.xray_validation.testxray_passed",
            "diagnostics.xray_validation.protocol",
            "diagnostics.xray_validation.transport",
            "diagnostics.xray_validation.security",
            "diagnostics.hysteria2.h3_alpn",
            "diagnostics.hysteria2.allow_insecure",
            "diagnostics.hysteria2.sni_configured",
            "diagnostics.xray_validation.duration",
            "diagnostics.xray_validation.stage",
            "diagnostics.xray_validation.category",
            "diagnostics.xray_validation.extension_reached",
            "diagnostics.xray_validation.error.no_profile",
            "diagnostics.xray_validation.error.unsupported_protocol",
            "diagnostics.xray_validation.error.shared_container",
            "diagnostics.xray_lifecycle.run",
            "diagnostics.xray_lifecycle.warning",
            "diagnostics.xray_lifecycle.passed",
            "diagnostics.xray_lifecycle.failed",
            "diagnostics.xray_lifecycle.diagnostics",
            "diagnostics.xray_lifecycle.runtime_config",
            "diagnostics.xray_lifecycle.builder",
            "diagnostics.xray_lifecycle.testxray_passed",
            "diagnostics.xray_lifecycle.runxray_invoked",
            "diagnostics.xray_lifecycle.running_state",
            "diagnostics.xray_lifecycle.socks_ready",
            "diagnostics.xray_lifecycle.socks_greeting",
            "diagnostics.xray_lifecycle.stopxray_invoked",
            "diagnostics.xray_lifecycle.stopped_state",
            "diagnostics.xray_lifecycle.port_closed",
            "diagnostics.xray_lifecycle.rollback",
            "diagnostics.xray_lifecycle.protocol",
            "diagnostics.xray_lifecycle.transport",
            "diagnostics.xray_lifecycle.security",
            "diagnostics.xray_lifecycle.start_duration",
            "diagnostics.xray_lifecycle.readiness_duration",
            "diagnostics.xray_lifecycle.stop_duration",
            "diagnostics.xray_lifecycle.total_duration",
            "diagnostics.xray_lifecycle.stage",
            "diagnostics.xray_lifecycle.category",
            "diagnostics.xray_lifecycle.extension_reached",
            "diagnostics.xray_lifecycle.error.no_profile",
            "diagnostics.xray_lifecycle.error.unsupported_protocol",
            "diagnostics.xray_lifecycle.error.shared_container",
            "diagnostics.xray_remote_egress.run",
            "diagnostics.xray_remote_egress.warning",
            "diagnostics.xray_remote_egress.passed",
            "diagnostics.xray_remote_egress.failed",
            "diagnostics.xray_remote_egress.diagnostics",
            "diagnostics.xray_remote_egress.builder",
            "diagnostics.xray_remote_egress.testxray",
            "diagnostics.xray_remote_egress.xray_running",
            "diagnostics.xray_remote_egress.local_socks",
            "diagnostics.xray_remote_egress.remote_attempted",
            "diagnostics.xray_remote_egress.remote_succeeded",
            "diagnostics.xray_remote_egress.remote_category",
            "diagnostics.xray_remote_egress.remote_duration",
            "diagnostics.xray_remote_egress.cleanup",
            "diagnostics.xray_remote_egress.error.no_profile",
            "diagnostics.xray_remote_egress.error.unsupported_protocol",
            "diagnostics.xray_remote_egress.error.shared_container",
            "diagnostics.runtime_only.warning",
            "diagnostics.runtime_only.start",
            "diagnostics.runtime_only.stop",
            "diagnostics.runtime_only.failed",
            "diagnostics.runtime_only.diagnostics",
            "diagnostics.runtime_only.error.no_profile",
            "diagnostics.runtime_only.error.unsupported_protocol",
            "diagnostics.runtime_only.error.shared_container"
        ]
        let strings = try runtimeConfigurationLocalizableStrings()

        for key in keys {
            let localization = try #require(strings[key] as? [String: Any])
            let localizations = try #require(localization["localizations"] as? [String: Any])
            #expect(localizations["en"] != nil)
            #expect(localizations["ru"] != nil)
        }
    }
}

private let fixedDate: @Sendable () -> Date = {
    Date(timeIntervalSince1970: 1_800_000_000)
}

private struct TestSecrets {
    let vlessUUID = "11111111-2222-4333-8444-555555555555"
    let vlessUUIDCanary = "SECRET-VLESS-UUID-DO-NOT-LEAK"
    let xrayCredentialReference = "keychain://SECRET-XRAY-REFERENCE"
    let realityPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    let password = "SECRET-PASSWORD-DO-NOT-LEAK"
    let token = "SECRET-TOKEN-DO-NOT-LEAK"
    let rawURI = "vless://SECRET-RAW-URI-DO-NOT-LEAK"
    let subscriptionURL = "https://subscription.example.test/SECRET-TOKEN-DO-NOT-LEAK"
    let privateKey = "SECRET-PRIVATE-KEY-DO-NOT-LEAK"
    let arbitraryMetadataSecret = "SECRET-METADATA-DO-NOT-LEAK"
}

private func makeVLESSProfile(
    credentialReference: String? = "keychain://vpn.credentials/account-1",
    metadata: [String: String] = [:]
) -> VPNProfile {
    VPNProfile.draft(
        name: "K2 VLESS",
        protocolType: .vless,
        serverAddress: "Example.COM",
        port: 443,
        credentialReference: credentialReference,
        transportSettings: VPNTransportSettings(
            network: "ws",
            security: "tls",
            path: "/ws",
            host: "cdn.example.com",
            metadata: ["secretOption": TestSecrets().arbitraryMetadataSecret]
        ),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: "sni.example.com",
            allowInsecure: false,
            fingerprint: "chrome"
        ),
        protocolConfiguration: .vless(VLESSProfileConfiguration(flow: "xtls-rprx-vision", encryption: "none")),
        source: .manual,
        metadata: metadata
    )
}

private func makeRealityProfile(
    credentialReference: String? = "keychain://vpn.credentials/account-1",
    publicKey: String? = TestSecrets().realityPublicKey,
    serverName: String? = "site.example.com",
    shortID: String? = "abcd",
    network: String = "tcp",
    path: String? = nil,
    host: String? = nil,
    mode: String? = nil,
    metadata: [String: String] = [:]
) -> VPNProfile {
    var transportMetadata: [String: String] = [:]
    if let mode {
        transportMetadata["mode"] = mode
    }
    return VPNProfile.draft(
        name: "K2 Reality",
        protocolType: .vless,
        serverAddress: "Reality.Example.COM",
        port: 443,
        credentialReference: credentialReference,
        transportSettings: VPNTransportSettings(
            network: network,
            security: "reality",
            path: path,
            host: host,
            metadata: transportMetadata
        ),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: serverName,
            allowInsecure: false,
            fingerprint: "chrome",
            realityPublicKey: publicKey,
            shortID: shortID,
            spiderX: "/"
        ),
        protocolConfiguration: .vless(VLESSProfileConfiguration(flow: "xtls-rprx-vision", encryption: "none")),
        source: .manual,
        metadata: metadata
    )
}

private func makeXHTTPTLSProfile(
    credentialReference: String? = "keychain://vpn.credentials/account-1",
    network: String = "xhttp",
    path: String? = "/xhttp",
    host: String? = "cdn.example.com",
    mode: String? = "auto"
) -> VPNProfile {
    var transportMetadata: [String: String] = [:]
    if let mode {
        transportMetadata["mode"] = mode
    }
    return VPNProfile.draft(
        name: "K2 XHTTP TLS",
        protocolType: .vless,
        serverAddress: "XHTTP.Example.COM",
        port: 443,
        credentialReference: credentialReference,
        transportSettings: VPNTransportSettings(
            network: network,
            security: "tls",
            path: path,
            host: host,
            metadata: transportMetadata
        ),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: "sni.example.com",
            allowInsecure: false,
            fingerprint: "chrome"
        ),
        protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
        source: .manual
    )
}

private func makeTCPTLSProfile(
    credentialReference: String? = "keychain://vpn.credentials/account-1"
) -> VPNProfile {
    VPNProfile.draft(
        name: "K3A TCP TLS",
        protocolType: .vless,
        serverAddress: "TCP.Example.COM",
        port: 443,
        credentialReference: credentialReference,
        transportSettings: VPNTransportSettings(network: "tcp", security: "tls"),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: "sni.example.com",
            allowInsecure: false,
            fingerprint: "chrome"
        ),
        protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
        source: .manual
    )
}

private func makeVMessProfile(
    credentialReference: String? = "keychain://vpn.credentials/vmess-account"
) -> VPNProfile {
    VPNProfile.draft(
        name: "K3B4 VMess",
        protocolType: .vmess,
        serverAddress: "VMess.Example.COM",
        port: 443,
        credentialReference: credentialReference,
        transportSettings: VPNTransportSettings(
            network: "ws",
            security: "tls",
            path: "/vmess",
            host: "cdn.example.com"
        ),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: "vmess-sni.example.com",
            allowInsecure: false,
            fingerprint: "chrome"
        ),
        protocolConfiguration: .vmess(VMessProfileConfiguration(alterID: 0, security: "auto")),
        source: .manual
    )
}

private func makeTrojanProfile(
    credentialReference: String? = "keychain://vpn.credentials/trojan-account"
) -> VPNProfile {
    VPNProfile.draft(
        name: "K3B4 Trojan",
        protocolType: .trojan,
        serverAddress: "Trojan.Example.COM",
        port: 443,
        credentialReference: credentialReference,
        transportSettings: VPNTransportSettings(
            network: "xhttp",
            security: "tls",
            path: "/trojan",
            host: "cdn.example.com",
            metadata: ["mode": "stream-one"]
        ),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: "trojan-sni.example.com",
            allowInsecure: false,
            fingerprint: "chrome"
        ),
        protocolConfiguration: .trojan(TrojanProfileConfiguration(alpn: ["h2", "http/1.1"])),
        source: .manual
    )
}

private func makeShadowsocksProfile(
    credentialReference: String? = "keychain://vpn.credentials/shadowsocks-account",
    outline: Bool = false,
    plugin: String? = nil
) -> VPNProfile {
    var metadata: [String: String] = [:]
    if outline {
        metadata["outline"] = "1"
    }
    if let plugin {
        metadata["plugin"] = plugin
    }
    return VPNProfile.draft(
        name: outline ? "K3B4 Outline" : "K3B4 Shadowsocks",
        protocolType: .shadowsocks,
        serverAddress: "SS.Example.COM",
        port: 8388,
        credentialReference: credentialReference,
        transportSettings: VPNTransportSettings(metadata: metadata),
        tlsSettings: VPNTLSSettings(),
        protocolConfiguration: .shadowsocks(ShadowsocksProfileConfiguration(method: "chacha20-ietf-poly1305", plugin: plugin)),
        source: .manual,
        metadata: metadata
    )
}

private func makeHysteria2Profile(
    credentialReference: String? = "keychain://vpn.credentials/hysteria2-account",
    security: String = "tls",
    obfs: String? = nil,
    bandwidthHint: String? = nil,
    obfsPasswordReference: String? = nil,
    serverName: String? = "hy2-sni.example.com",
    serverAddress: String = "HY2.Example.COM",
    allowInsecure: Bool = false,
    metadata extraMetadata: [String: String] = [:]
) -> VPNProfile {
    var metadata = extraMetadata
    if let obfs {
        metadata["obfs"] = obfs
    }
    if let bandwidthHint {
        metadata["bandwidth"] = bandwidthHint
    }
    return VPNProfile.draft(
        name: "K3B4 Hysteria2",
        protocolType: .hysteria2,
        serverAddress: serverAddress,
        port: 443,
        credentialReference: credentialReference,
        transportSettings: VPNTransportSettings(network: "udp", security: security, metadata: metadata),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: serverName,
            allowInsecure: allowInsecure,
            fingerprint: "chrome"
        ),
        protocolConfiguration: .hysteria2(Hysteria2ProfileConfiguration(
            obfs: obfs,
            bandwidthHint: bandwidthHint,
            obfsPasswordReference: obfsPasswordReference
        )),
        source: .manual,
        metadata: metadata
    )
}

private func resolvedConfiguration(
    from profile: VPNProfile,
    credential: String = TestSecrets().vlessUUID,
    hysteria2ObfsPassword: String? = nil
) throws -> ResolvedVLESSRuntimeConfiguration {
    let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: profile)
    return ResolvedVLESSRuntimeConfiguration(
        profileID: record.profileID,
        recordRevision: record.recordRevision,
        protocolKind: record.protocolKind,
        endpoint: ResolvedRuntimeEndpoint(host: record.endpoint.host, port: record.endpoint.port),
        transport: record.transport,
        security: record.security,
        vless: record.vless,
        vmess: record.vmess,
        trojan: record.trojan,
        shadowsocks: record.shadowsocks,
        hysteria2: record.hysteria2,
        credential: SensitiveRuntimeCredential(credential),
        hysteria2ObfsPassword: hysteria2ObfsPassword.map(SensitiveRuntimeCredential.init)
    )
}

private func xrayConfiguration(
    from profile: VPNProfile,
    credential: String = TestSecrets().vlessUUID,
    hysteria2ObfsPassword: String? = nil,
    options: XrayBuildOptions = XrayBuildOptions()
) throws -> SensitiveXrayConfiguration {
    try XrayConfigurationBuilder().build(
        from: resolvedConfiguration(
            from: profile,
            credential: credential,
            hysteria2ObfsPassword: hysteria2ObfsPassword
        ),
        options: options
    )
}

private func xrayJSONString(
    from profile: VPNProfile,
    credential: String = TestSecrets().vlessUUID,
    hysteria2ObfsPassword: String? = nil,
    options: XrayBuildOptions = XrayBuildOptions()
) throws -> String {
    try xrayConfiguration(
        from: profile,
        credential: credential,
        hysteria2ObfsPassword: hysteria2ObfsPassword,
        options: options
    ).withJSONString { $0 }
}

private func firstXrayOutbound(from json: String) throws -> [String: Any] {
    let object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
    let outbounds = try #require(object["outbounds"] as? [[String: Any]])
    return try #require(outbounds.first)
}

private func firstXrayOutboundTLSSettings(from json: String) throws -> [String: Any] {
    let outbound = try firstXrayOutbound(from: json)
    let streamSettings = try #require(outbound["streamSettings"] as? [String: Any])
    return try #require(streamSettings["tlsSettings"] as? [String: Any])
}

private func temporaryDirectory() -> URL {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("KVNRuntimeConfigurationTests", isDirectory: true)
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
}

private func runtimeProfileCollectionURL(root: URL) -> URL {
    root.appendingPathComponent("runtime-profiles-v1", isDirectory: false).appendingPathExtension("json")
}

private func encodedJSONString<T: Encodable>(_ value: T) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    let data = try encoder.encode(value)
    return String(decoding: data, as: UTF8.self)
}

private func propertyListJSONString(_ value: [String: NSObject]) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    return String(decoding: data, as: UTF8.self)
}

private func dnsResponse(transactionID: UInt16) -> Data {
    Data([
        UInt8((transactionID >> 8) & 0xFF),
        UInt8(transactionID & 0xFF),
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00
    ])
}

private func encode<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    return try encoder.encode(value)
}

private func tunnelMessageDecoder() -> JSONDecoder {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return decoder
}

private let lifecycleForbiddenJSONKeys: Set<String> = ["localPort", "socksPort", "selectedPort", "listenPort", "xrayJson"]

private func assertJSONDoesNotContainForbiddenKeys(
    in data: Data,
    forbiddenKeys: Set<String>,
    sourceLocation: SourceLocation = #_sourceLocation
) throws {
    let paths = try forbiddenJSONKeyPaths(in: data, forbiddenKeys: forbiddenKeys)
    #expect(paths.isEmpty, sourceLocation: sourceLocation)
}

private func forbiddenJSONKeyPaths(in data: Data, forbiddenKeys: Set<String>) throws -> [String] {
    let object = try JSONSerialization.jsonObject(with: data)
    return forbiddenJSONKeyPaths(in: object, forbiddenKeys: forbiddenKeys, path: [])
}

private func forbiddenJSONKeyPaths(in object: Any, forbiddenKeys: Set<String>, path: [String]) -> [String] {
    if let dictionary = object as? [String: Any] {
        return dictionary.flatMap { key, value -> [String] in
            let nextPath = path + [key]
            let currentMatch = forbiddenKeys.contains(key) ? [nextPath.joined(separator: ".")] : []
            return currentMatch + forbiddenJSONKeyPaths(in: value, forbiddenKeys: forbiddenKeys, path: nextPath)
        }
        .sorted()
    }

    if let array = object as? [Any] {
        return array.enumerated().flatMap { index, value in
            forbiddenJSONKeyPaths(in: value, forbiddenKeys: forbiddenKeys, path: path + ["[\(index)]"])
        }
        .sorted()
    }

    return []
}

private func runtimeConfigurationLocalizableStrings() throws -> [String: Any] {
    let testsURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let candidates = [
        testsURL.deletingLastPathComponent().appendingPathComponent("VPN/Resources/Localizable.xcstrings"),
        testsURL.deletingLastPathComponent().appendingPathComponent("Resources/Localizable.xcstrings"),
        testsURL.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("VPN/Resources/Localizable.xcstrings")
    ]
    let catalogURL = try #require(candidates.first { FileManager.default.fileExists(atPath: $0.path) })
    let data = try Data(contentsOf: catalogURL)
    let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    return try #require(object?["strings"] as? [String: Any])
}

private func projectFileContents(_ relativePath: String) throws -> String {
    let testsURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    let environmentRoots = ["SRCROOT", "PROJECT_DIR", "PWD"].compactMap { key -> URL? in
        guard let path = ProcessInfo.processInfo.environment[key], path.isEmpty == false else {
            return nil
        }
        return URL(fileURLWithPath: path)
    }
    let roots = [
        testsURL.deletingLastPathComponent(),
        testsURL.deletingLastPathComponent().deletingLastPathComponent(),
        URL(fileURLWithPath: FileManager.default.currentDirectoryPath),
        URL(fileURLWithPath: FileManager.default.currentDirectoryPath).deletingLastPathComponent()
    ] + environmentRoots
    let candidates = roots.lazy.flatMap { root in
        [
            root.appendingPathComponent(relativePath),
            root.appendingPathComponent("VPN").appendingPathComponent(relativePath)
        ]
    }
    let fileURL = try #require(candidates.first {
        FileManager.default.fileExists(atPath: $0.path)
    })
    return try String(contentsOf: fileURL, encoding: .utf8)
}

private func sourceSlice(
    in text: String,
    from startMarker: String,
    to endMarker: String
) throws -> String {
    let start = try #require(text.range(of: startMarker))
    let tail = text[start.lowerBound...]
    let end = try #require(tail.range(of: endMarker))
    return String(tail[..<end.lowerBound])
}

private enum SourceExtractionError: Error {
    case missingClosingBrace
}

private func sourceFunctionBody(in text: String, from startMarker: String) throws -> String {
    let start = try #require(text.range(of: startMarker))
    let bodyStart = try #require(text[start.lowerBound...].firstIndex(of: "{"))
    var depth = 0
    var index = bodyStart

    while index < text.endIndex {
        let character = text[index]
        if character == "{" {
            depth += 1
        } else if character == "}" {
            depth -= 1
            if depth == 0 {
                let bodyEnd = text.index(after: index)
                return String(text[start.lowerBound..<bodyEnd])
            }
        }
        index = text.index(after: index)
    }

    throw SourceExtractionError.missingClosingBrace
}

private func assertNoSecretMaterial(in text: String, secrets: TestSecrets, sourceLocation: SourceLocation = #_sourceLocation) {
    for secret in [
        secrets.vlessUUID,
        secrets.vlessUUIDCanary,
        secrets.password,
        secrets.token,
        secrets.rawURI,
        secrets.subscriptionURL,
        secrets.privateKey,
        secrets.arbitraryMetadataSecret
    ] {
        #expect(!text.contains(secret), sourceLocation: sourceLocation)
    }
}

private func expectValidationFailure(
    _ operation: @escaping () async throws -> Void,
    sourceLocation: SourceLocation = #_sourceLocation
) async {
    do {
        try await operation()
        Issue.record("Expected TunnelRuntimeConfigurationValidationFailure", sourceLocation: sourceLocation)
    } catch is TunnelRuntimeConfigurationValidationFailure {
        // Expected.
    } catch {
        Issue.record("Unexpected error: \(error)", sourceLocation: sourceLocation)
    }
}

private func expectXrayValidationFailure(
    _ operation: @escaping () async throws -> Void,
    sourceLocation: SourceLocation = #_sourceLocation
) async {
    do {
        try await operation()
        Issue.record("Expected TunnelXrayConfigurationValidationFailure", sourceLocation: sourceLocation)
    } catch is TunnelXrayConfigurationValidationFailure {
        // Expected.
    } catch {
        Issue.record("Unexpected error: \(error)", sourceLocation: sourceLocation)
    }
}

private func expectXrayLifecycleFailure(
    _ operation: @escaping () async throws -> Void,
    sourceLocation: SourceLocation = #_sourceLocation
) async {
    do {
        try await operation()
        Issue.record("Expected TunnelXrayLifecycleSmokeTestFailure", sourceLocation: sourceLocation)
    } catch is TunnelXrayLifecycleSmokeTestFailure {
        // Expected.
    } catch {
        Issue.record("Unexpected error: \(error)", sourceLocation: sourceLocation)
    }
}

private func expectXrayRemoteEgressFailure(
    _ operation: @escaping () async throws -> Void,
    sourceLocation: SourceLocation = #_sourceLocation
) async {
    do {
        try await operation()
        Issue.record("Expected TunnelXrayRemoteEgressProbeFailure", sourceLocation: sourceLocation)
    } catch is TunnelXrayRemoteEgressProbeFailure {
        // Expected.
    } catch {
        Issue.record("Unexpected error: \(error)", sourceLocation: sourceLocation)
    }
}

private actor InMemoryRuntimeProfileStore: SharedRuntimeProfileStoring {
    private var records: [UUID: SharedRuntimeProfileRecord]

    init(records: [UUID: SharedRuntimeProfileRecord] = [:]) {
        self.records = records
    }

    func write(_ record: SharedRuntimeProfileRecord) async throws {
        records[record.profileID] = record
    }

    func read(profileID: UUID) async throws -> SharedRuntimeProfileRecord {
        guard let record = records[profileID] else {
            throw RuntimeConfigurationError.profileRecordNotFound
        }
        return record
    }

    func records() async throws -> [SharedRuntimeProfileRecord] {
        records.values.sorted { lhs, rhs in
            lhs.profileID.uuidString < rhs.profileID.uuidString
        }
    }

    func replaceAll(_ records: [SharedRuntimeProfileRecord]) async throws {
        self.records = Dictionary(uniqueKeysWithValues: records.map { ($0.profileID, $0) })
    }

    func delete(profileID: UUID) async throws {
        records[profileID] = nil
    }
}

private struct StaticRuntimeCredentialResolver: RuntimeCredentialResolving {
    let secrets: [String: String]

    func credential(for reference: String) async throws -> String? {
        secrets[reference]
    }
}

private actor StaticCredentialStore: CredentialStoring {
    private let secrets: [String: String]

    init(secrets: [String: String]) {
        self.secrets = secrets
    }

    func store(_ secret: String, label: String) async throws -> String {
        "keychain://vpn.credentials/new-account"
    }

    func secret(for reference: String) async throws -> String? {
        secrets[reference]
    }

    func delete(reference: String) async throws {}
}

private actor CanonicalInMemoryCredentialStore: CredentialStoring {
    private var secrets: [String: String] = [:]
    private var nextAccount = 0

    func store(_ secret: String, label: String) async throws -> String {
        nextAccount += 1
        let reference = "keychain://vpn.credentials/test-account-\(nextAccount)"
        secrets[reference] = secret
        return reference
    }

    func secret(for reference: String) async throws -> String? {
        secrets[reference]
    }

    func delete(reference: String) async throws {
        secrets[reference] = nil
    }
}

private actor MockValidationLoader: RuntimeConfigurationValidationLoading {
    private let response: TunnelRuntimeConfigurationValidationResponse
    private(set) var callCount = 0

    init(response: TunnelRuntimeConfigurationValidationResponse) {
        self.response = response
    }

    func validateRuntimeConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelRuntimeConfigurationValidationResponse {
        callCount += 1
        return response
    }
}

@MainActor
private final class MockXrayConfigurationValidator: XrayConfigurationValidating {
    private let response: TunnelXrayConfigurationValidationResponse
    private(set) var callCount = 0

    init(response: TunnelXrayConfigurationValidationResponse) {
        self.response = response
    }

    func validateXrayConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayConfigurationValidationResponse {
        callCount += 1
        return response
    }
}

private actor StaticValidationMessenger: TunnelRuntimeConfigurationValidationMessaging {
    private let responseBuilder: @Sendable (TunnelMessageRequest) -> TunnelMessageResponse
    private(set) var sentRequests: [TunnelMessageRequest] = []
    private(set) var sentProviderConfigurations: [RuntimeProviderConfiguration] = []

    init(responseBuilder: @escaping @Sendable (TunnelMessageRequest) -> TunnelMessageResponse) {
        self.responseBuilder = responseBuilder
    }

    func sendRuntimeConfigurationValidation(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelRuntimeConfigurationValidationMessageResult {
        sentRequests.append(request)
        sentProviderConfigurations.append(providerConfiguration)
        return TunnelRuntimeConfigurationValidationMessageResult(
            response: responseBuilder(request),
            diagnostic: TunnelRuntimeConfigurationValidationDiagnostic(
                stage: .responseValidation,
                category: .none,
                extensionRequestReached: true
            )
        )
    }
}

private actor StaticXrayValidationMessenger: TunnelXrayConfigurationValidationMessaging {
    private let responseBuilder: @Sendable (TunnelMessageRequest) -> TunnelMessageResponse
    private(set) var sentRequests: [TunnelMessageRequest] = []
    private(set) var sentProviderConfigurations: [RuntimeProviderConfiguration] = []

    init(responseBuilder: @escaping @Sendable (TunnelMessageRequest) -> TunnelMessageResponse) {
        self.responseBuilder = responseBuilder
    }

    func sendXrayConfigurationValidation(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelXrayConfigurationValidationMessageResult {
        sentRequests.append(request)
        sentProviderConfigurations.append(providerConfiguration)
        return TunnelXrayConfigurationValidationMessageResult(
            response: responseBuilder(request),
            diagnostic: TunnelXrayConfigurationValidationDiagnostic(
                stage: .responseValidation,
                category: .none,
                extensionRequestReached: true
            )
        )
    }
}

private actor StaticXrayLifecycleSmokeTestMessenger: TunnelXrayLifecycleSmokeTestMessaging {
    private let responseBuilder: @Sendable (TunnelMessageRequest) -> TunnelMessageResponse
    private(set) var sentRequests: [TunnelMessageRequest] = []
    private(set) var sentProviderConfigurations: [RuntimeProviderConfiguration] = []

    init(responseBuilder: @escaping @Sendable (TunnelMessageRequest) -> TunnelMessageResponse) {
        self.responseBuilder = responseBuilder
    }

    func sendXrayLifecycleSmokeTest(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelXrayLifecycleSmokeTestMessageResult {
        sentRequests.append(request)
        sentProviderConfigurations.append(providerConfiguration)
        return TunnelXrayLifecycleSmokeTestMessageResult(
            response: responseBuilder(request),
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .responseValidation,
                category: .none,
                extensionRequestReached: true
            )
        )
    }
}

private actor StaticXrayRemoteEgressProbeMessenger: TunnelXrayRemoteEgressProbeMessaging {
    private let responseBuilder: @Sendable (TunnelMessageRequest) -> TunnelMessageResponse
    private(set) var sentRequests: [TunnelMessageRequest] = []
    private(set) var sentProviderConfigurations: [RuntimeProviderConfiguration] = []

    init(responseBuilder: @escaping @Sendable (TunnelMessageRequest) -> TunnelMessageResponse) {
        self.responseBuilder = responseBuilder
    }

    func sendXrayRemoteEgressProbe(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelXrayRemoteEgressProbeMessageResult {
        sentRequests.append(request)
        sentProviderConfigurations.append(providerConfiguration)
        return TunnelXrayRemoteEgressProbeMessageResult(
            response: responseBuilder(request),
            diagnostic: TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .responseValidation,
                category: .none,
                extensionRequestReached: true
            )
        )
    }
}

private actor StaticUDPControlProbeMessenger: TunnelUDPControlProbeMessaging {
    private let responseBuilder: @Sendable (TunnelMessageRequest) -> TunnelMessageResponse
    private(set) var sentRequests: [TunnelMessageRequest] = []

    init(responseBuilder: @escaping @Sendable (TunnelMessageRequest) -> TunnelMessageResponse) {
        self.responseBuilder = responseBuilder
    }

    func sendUDPControlProbe(_ request: TunnelMessageRequest) async throws -> TunnelUDPControlProbeMessageResult {
        sentRequests.append(request)
        return TunnelUDPControlProbeMessageResult(
            response: responseBuilder(request),
            diagnostic: TunnelUDPControlProbeDiagnostic(
                category: .none,
                extensionRequestReached: true
            )
        )
    }
}

private actor StaticLibXrayPingProbeMessenger: TunnelLibXrayPingProbeMessaging {
    private let responseBuilder: @Sendable (TunnelMessageRequest) -> TunnelMessageResponse
    private(set) var sentRequests: [TunnelMessageRequest] = []
    private(set) var sentProviderConfigurations: [RuntimeProviderConfiguration] = []

    init(responseBuilder: @escaping @Sendable (TunnelMessageRequest) -> TunnelMessageResponse) {
        self.responseBuilder = responseBuilder
    }

    func sendLibXrayPingProbe(
        _ request: TunnelMessageRequest,
        providerConfiguration: RuntimeProviderConfiguration
    ) async throws -> TunnelLibXrayPingProbeMessageResult {
        sentRequests.append(request)
        sentProviderConfigurations.append(providerConfiguration)
        return TunnelLibXrayPingProbeMessageResult(
            response: responseBuilder(request),
            diagnostic: TunnelLibXrayPingProbeDiagnostic(
                stage: .responseValidation,
                category: .none,
                extensionRequestReached: true
            )
        )
    }
}

private struct StaticTunnelProviderSessionProvider: TunnelProviderSessionProviding {
    let session: any TunnelProviderSessionConnection

    func currentSession() async throws -> any TunnelProviderSessionConnection {
        session
    }
}

private final class RecordingRuntimeOnlySession: RuntimeOnlyPacketTunnelSessionConnection, DataPlanePacketTunnelSessionConnection, LibXrayPingOnlyPacketTunnelSessionConnection, DiagnosticProviderRecoverySessionConnection, @unchecked Sendable {
    private let lock = NSLock()
    private var currentStatus: TunnelProviderSessionStatus
    private var currentProviderMode: TunnelDiagnosticProviderMode?
    private(set) var startOptions: [[String: NSObject]] = []
    private(set) var runtimeOnlyStartOptions: [[String: NSObject]] = []
    private(set) var dataPlaneStartOptions: [[String: NSObject]] = []
    private(set) var libXrayPingOnlyStartOptions: [[String: NSObject]] = []
    private(set) var stopCount = 0
    private(set) var providerMessageCount = 0

    init(
        initialStatus: TunnelProviderSessionStatus,
        providerMode: TunnelDiagnosticProviderMode? = nil
    ) {
        self.currentStatus = initialStatus
        self.currentProviderMode = providerMode
    }

    func status() async -> TunnelProviderSessionStatus {
        lock.withLock { currentStatus }
    }

    func setStatus(_ status: TunnelProviderSessionStatus, providerMode: TunnelDiagnosticProviderMode? = nil) {
        lock.withLock {
            currentStatus = status
            if status == .disconnected || status == .invalid {
                currentProviderMode = .idle
            } else {
                currentProviderMode = providerMode
            }
        }
    }

    func sendProviderMessage(
        _ data: Data,
        responseHandler: @escaping @Sendable (Result<Data?, any Error>) -> Void
    ) {
        lock.withLock {
            providerMessageCount += 1
        }
        do {
            let request = try tunnelMessageDecoder().decode(TunnelMessageRequest.self, from: data)
            guard request.kind == .getDiagnosticProviderMode else {
                responseHandler(.failure(TunnelMessageErrorCode.unsupportedRequest))
                return
            }
            guard let mode = lock.withLock({ currentProviderMode }) else {
                responseHandler(.failure(TunnelMessageErrorCode.unsupportedRequest))
                return
            }
            let response = TunnelMessageResponse.success(
                request: request,
                payload: .diagnosticProviderMode(TunnelDiagnosticProviderModeResponse(mode: mode))
            )
            responseHandler(.success(try encode(response)))
        } catch {
            responseHandler(.failure(error))
        }
    }

    func startRuntimeOnlyTunnel(options: [String: NSObject]) async throws {
        lock.withLock {
            startOptions.append(options)
            runtimeOnlyStartOptions.append(options)
            currentStatus = .connected
            currentProviderMode = .runtimeOnly
        }
    }

    func stopRuntimeOnlyTunnel() async {
        lock.withLock {
            stopCount += 1
            currentStatus = .disconnected
            currentProviderMode = .idle
        }
    }

    func startDataPlaneTunnel(options: [String: NSObject]) async throws {
        lock.withLock {
            startOptions.append(options)
            dataPlaneStartOptions.append(options)
            currentStatus = .connected
            currentProviderMode = .dataPlane
        }
    }

    func stopDataPlaneTunnel() async {
        lock.withLock {
            stopCount += 1
            currentStatus = .disconnected
            currentProviderMode = .idle
        }
    }

    func startLibXrayPingOnlyTunnel(options: [String: NSObject]) async throws {
        lock.withLock {
            startOptions.append(options)
            libXrayPingOnlyStartOptions.append(options)
            currentStatus = .connected
            currentProviderMode = .libXrayPingOnly
        }
    }

    func stopLibXrayPingOnlyTunnel() async {
        lock.withLock {
            stopCount += 1
            currentStatus = .disconnected
            currentProviderMode = .idle
        }
    }

    func stopDiagnosticProviderTunnel() async {
        lock.withLock {
            stopCount += 1
            currentStatus = .disconnected
            currentProviderMode = .idle
        }
    }
}

private actor RecordingDiagnosticTunnelProviderManagerStore: DiagnosticTunnelProviderManagerStore {
    private var managers: [any DiagnosticTunnelProviderManager]

    init(managers: [any DiagnosticTunnelProviderManager]) {
        self.managers = managers
    }

    func loadAllManagers() async throws -> [any DiagnosticTunnelProviderManager] {
        managers
    }

    func makeManager() async throws -> any DiagnosticTunnelProviderManager {
        let manager = RecordingDiagnosticTunnelProviderManager(session: RecordingRuntimeOnlySession(initialStatus: .disconnected))
        managers.append(manager)
        return manager
    }
}

private final class RecordingDiagnosticTunnelProviderManager: DiagnosticTunnelProviderManager, @unchecked Sendable {
    private let lock = NSLock()
    private let session: any TunnelProviderSessionConnection
    private let bundleID: String
    private(set) var providerConfiguration: [String: Any]?
    private(set) var sequence: [String] = []

    init(
        session: any TunnelProviderSessionConnection,
        bundleID: String = "su.24kvn.kvn-app.PacketTunnelExtension"
    ) {
        self.session = session
        self.bundleID = bundleID
    }

    func providerBundleIdentifier() async -> String? {
        bundleID
    }

    func providerConfigurationPropertyList() async -> [String: Any]? {
        lock.withLock { providerConfiguration }
    }

    func prepareExistingForSentinel(providerBundleIdentifier: String) async {
        lock.withLock {
            sequence.append("prepareSentinel")
        }
    }

    func configureForSentinel(
        providerBundleIdentifier: String,
        configuration: TunnelSentinelProviderConfiguration
    ) async {
        lock.withLock {
            providerConfiguration = configuration.propertyList
            sequence.append("configureSentinel")
        }
    }

    func configureForRuntimeValidation(
        providerBundleIdentifier: String,
        configuration: RuntimeProviderConfiguration
    ) async {
        lock.withLock {
            providerConfiguration = configuration.propertyList
            sequence.append("configureRuntime")
        }
    }

    func saveToPreferences() async throws {
        lock.withLock {
            sequence.append("save")
        }
    }

    func loadFromPreferences() async throws {
        lock.withLock {
            sequence.append("reload")
        }
    }

    func tunnelProviderSession() async throws -> any TunnelProviderSessionConnection {
        lock.withLock {
            sequence.append("session")
        }
        return session
    }
}

private struct StaticTunnelProviderMessenger: TunnelProviderMessaging {
    var providerStatus: TunnelProviderSessionStatus = .connected

    func status() async -> TunnelProviderSessionStatus {
        providerStatus
    }

    func send(_ request: TunnelMessageRequest) async throws -> TunnelMessageResponse {
        throw TunnelMessageErrorCode.unsupportedRequest
    }
}

@MainActor
private struct DiagnosticAdmissionHarness {
    let viewModel: TunnelTelemetryDiagnosticsViewModel
    let runtimeMessenger: StaticValidationMessenger
    let xrayMessenger: StaticXrayValidationMessenger
    let lifecycleMessenger: StaticXrayLifecycleSmokeTestMessenger
    let remoteEgressMessenger: StaticXrayRemoteEgressProbeMessenger
    let udpControlMessenger: StaticUDPControlProbeMessenger
    let libXrayPingMessenger: StaticLibXrayPingProbeMessenger
    let runtimeOnlySession: RecordingRuntimeOnlySession
    let dataPlaneSession: RecordingRuntimeOnlySession
    let libXrayPingOnlySession: RecordingRuntimeOnlySession
    let diagnosticManager: RecordingDiagnosticTunnelProviderManager
    let diagnosticManagerStore: RecordingDiagnosticTunnelProviderManagerStore
}

private struct DiagnosticAdmissionFixture {
    let profile: VPNProfile
    let credential: String
    let expectedProtocolName: String
}

@MainActor
private func makeDiagnosticAdmissionHarness(
    profile: VPNProfile,
    credential: String,
    expectedProtocolName: String,
    activeProbeContext: TunnelXrayRemoteEgressProbeContext? = .dataPlane
) throws -> DiagnosticAdmissionHarness {
    let secrets = [try #require(profile.credentialReference): credential]
    let credentialStore = StaticCredentialStore(secrets: secrets)
    let record = try SharedRuntimeProfileMapper(now: fixedDate).record(from: profile)
    let transportName = record.transport.kind.rawValue
    let securityName = record.security.kind.rawValue

    func publisher() -> SharedRuntimeProfilePublisher {
        SharedRuntimeProfilePublisher(
            mapper: SharedRuntimeProfileMapper(now: fixedDate),
            store: InMemoryRuntimeProfileStore(),
            credentialStore: credentialStore
        )
    }

    let runtimeMessenger = StaticValidationMessenger { request in
        guard case .runtimeConfigurationValidation(let payload)? = request.payload else {
            return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
        }
        return TunnelMessageResponse.success(
            request: request,
            payload: .runtimeConfigurationValidation(.success(
                correlationID: payload.correlationID,
                protocolName: expectedProtocolName,
                transportName: transportName,
                securityName: securityName
            ))
        )
    }
    let xrayMessenger = StaticXrayValidationMessenger { request in
        guard case .xrayConfigurationValidation(let payload)? = request.payload else {
            return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
        }
        return TunnelMessageResponse.success(
            request: request,
            payload: .xrayConfigurationValidation(.success(
                correlationID: payload.correlationID,
                protocolName: expectedProtocolName,
                transportName: transportName,
                securityName: securityName
            ))
        )
    }
    let lifecycleMessenger = StaticXrayLifecycleSmokeTestMessenger { request in
        guard case .xrayLifecycleSmokeTest(let payload)? = request.payload else {
            return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
        }
        return TunnelMessageResponse.success(
            request: request,
            payload: .xrayLifecycleSmokeTest(.success(
                correlationID: payload.correlationID,
                protocolName: expectedProtocolName,
                transportName: transportName,
                securityName: securityName,
                startDurationMs: 1,
                readinessDurationMs: 1,
                stopDurationMs: 1,
                totalDurationMs: 3
            ))
        )
    }
    let remoteEgressMessenger = StaticXrayRemoteEgressProbeMessenger { request in
        guard case .xrayRemoteEgressProbe(let payload)? = request.payload else {
            return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
        }
        return TunnelMessageResponse.success(
            request: request,
            payload: .xrayRemoteEgressProbe(.success(
                correlationID: payload.correlationID,
                protocolName: expectedProtocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: expectedProtocolName == "hysteria2" ? true : nil,
                sniConfigured: expectedProtocolName == "hysteria2" ? true : nil,
                allowInsecureConfigured: expectedProtocolName == "hysteria2" ? false : nil,
                probeContext: request.kind == .probeActiveXrayEgress ? activeProbeContext : nil,
                startDurationMs: 1,
                readinessDurationMs: 1,
                remoteConnectDurationMs: 1,
                stopDurationMs: 1,
                totalDurationMs: 4
            ))
        )
    }
    let udpControlMessenger = StaticUDPControlProbeMessenger { request in
        guard case .udpControlProbe(let payload)? = request.payload else {
            return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
        }
        return TunnelMessageResponse.success(
            request: request,
            payload: .udpControlProbe(.success(
                correlationID: payload.correlationID,
                pathSnapshot: TunnelUDPControlProbePathSnapshot(
                    pathStatus: .satisfied,
                    usesWiFi: true,
                    usesCellular: false,
                    usesWiredEthernet: false,
                    supportsIPv4: true,
                    supportsIPv6: true,
                    supportsDNS: true
                ),
                durationMs: 12
            ))
        )
    }
    let libXrayPingMessenger = StaticLibXrayPingProbeMessenger { request in
        guard case .libXrayPingProbe(let payload)? = request.payload else {
            return TunnelMessageResponse.failure(requestID: request.requestID, code: .malformedRequest)
        }
        return TunnelMessageResponse.success(
            request: request,
            payload: .libXrayPingProbe(.success(
                correlationID: payload.correlationID,
                delayMs: 37,
                protocolName: expectedProtocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: expectedProtocolName == "hysteria2" ? true : nil,
                sniConfigured: expectedProtocolName == "hysteria2" ? true : nil,
                allowInsecureConfigured: expectedProtocolName == "hysteria2" ? false : nil,
                durationMs: 37
            ))
        )
    }

    let persistentSession = RecordingRuntimeOnlySession(initialStatus: .disconnected, providerMode: .idle)
    let persistentManager = RecordingDiagnosticTunnelProviderManager(session: persistentSession)
    let persistentManagerStore = RecordingDiagnosticTunnelProviderManagerStore(managers: [persistentManager])
    let persistentBootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: persistentManagerStore)
    let persistentSessionProvider = StaticTunnelProviderSessionProvider(session: persistentSession)
    let runtimeOnlyService = RuntimeOnlyPacketTunnelService(
        publisher: publisher(),
        bootstrapper: persistentBootstrapper,
        sessionProvider: persistentSessionProvider,
        statusTimeout: .milliseconds(50),
        statusPollInterval: .milliseconds(1)
    )

    let dataPlaneService = DataPlanePacketTunnelService(
        publisher: publisher(),
        bootstrapper: persistentBootstrapper,
        sessionProvider: persistentSessionProvider,
        statusTimeout: .milliseconds(50),
        statusPollInterval: .milliseconds(1)
    )

    let libXrayPingOnlyService = LibXrayPingOnlyPacketTunnelService(
        publisher: publisher(),
        bootstrapper: persistentBootstrapper,
        sessionProvider: persistentSessionProvider,
        statusTimeout: .milliseconds(50),
        statusPollInterval: .milliseconds(1)
    )

    let viewModel = TunnelTelemetryDiagnosticsViewModel(
        messenger: StaticTunnelProviderMessenger(),
        snapshotStore: nil,
        coreUpdater: nil,
        keychainSmokeTester: nil,
        runtimeValidationService: RuntimeConfigurationValidationService(
            publisher: publisher(),
            messenger: runtimeMessenger
        ),
        xrayValidationService: XrayConfigurationValidationService(
            publisher: publisher(),
            messenger: xrayMessenger
        ),
        xrayLifecycleSmokeTestService: XrayLifecycleSmokeTestService(
            publisher: publisher(),
            messenger: lifecycleMessenger
        ),
        xrayRemoteEgressProbeService: XrayRemoteEgressProbeService(
            publisher: publisher(),
            messenger: remoteEgressMessenger
        ),
        udpControlProbeService: UDPControlProbeService(messenger: udpControlMessenger),
        libXrayPingProbeService: LibXrayPingProbeService(
            publisher: publisher(),
            messenger: libXrayPingMessenger
        ),
        runtimeOnlyPacketTunnelService: runtimeOnlyService,
        dataPlanePacketTunnelService: dataPlaneService,
        libXrayPingOnlyPacketTunnelService: libXrayPingOnlyService,
        diagnosticProviderStateService: DiagnosticProviderStateService(
            managerStore: persistentManagerStore,
            timeout: .milliseconds(50)
        ),
        diagnosticProviderRecoveryService: DiagnosticProviderRecoveryService(
            managerStore: persistentManagerStore,
            statusTimeout: .milliseconds(50),
            statusPollInterval: .milliseconds(1)
        )
    )

    return DiagnosticAdmissionHarness(
        viewModel: viewModel,
        runtimeMessenger: runtimeMessenger,
        xrayMessenger: xrayMessenger,
        lifecycleMessenger: lifecycleMessenger,
        remoteEgressMessenger: remoteEgressMessenger,
        udpControlMessenger: udpControlMessenger,
        libXrayPingMessenger: libXrayPingMessenger,
        runtimeOnlySession: persistentSession,
        dataPlaneSession: persistentSession,
        libXrayPingOnlySession: persistentSession,
        diagnosticManager: persistentManager,
        diagnosticManagerStore: persistentManagerStore
    )
}

private func k3b4DiagnosticAdmissionFixtures() -> [DiagnosticAdmissionFixture] {
    [
        DiagnosticAdmissionFixture(profile: makeTCPTLSProfile(), credential: TestSecrets().vlessUUID, expectedProtocolName: "vless"),
        DiagnosticAdmissionFixture(profile: makeVMessProfile(), credential: TestSecrets().vlessUUID, expectedProtocolName: "vmess"),
        DiagnosticAdmissionFixture(profile: makeTrojanProfile(), credential: TestSecrets().password, expectedProtocolName: "trojan"),
        DiagnosticAdmissionFixture(profile: makeShadowsocksProfile(), credential: TestSecrets().password, expectedProtocolName: "shadowsocks"),
        DiagnosticAdmissionFixture(profile: makeHysteria2Profile(), credential: TestSecrets().password, expectedProtocolName: "hysteria2")
    ]
}

private func makeUnsupportedDiagnosticProfile(protocolType: VPNProtocol) -> VPNProfile {
    let protocolConfiguration: VPNProtocolConfiguration
    let username: String?
    switch protocolType {
    case .wireGuard:
        protocolConfiguration = .wireGuard(WireGuardProfileConfiguration(peerPublicKeyReference: nil, presharedKeyReference: nil, allowedIPs: ["0.0.0.0/0"]))
        username = nil
    case .ikev2:
        protocolConfiguration = .ikev2(IKEv2ProfileConfiguration(remoteIdentifier: nil, localIdentifier: nil, authenticationMethod: "password"))
        username = "diagnostic-user"
    case .tuic:
        protocolConfiguration = .tuic(TUICProfileConfiguration(congestionControl: nil, udpRelayMode: nil))
        username = nil
    case .vless, .vmess, .trojan, .shadowsocks, .hysteria2:
        protocolConfiguration = .vless(VLESSProfileConfiguration(flow: nil, encryption: "none"))
        username = nil
    }

    return VPNProfile.draft(
        name: "Unsupported Diagnostic \(protocolType.displayName)",
        protocolType: protocolType,
        serverAddress: "unsupported.example.com",
        port: 443,
        username: username,
        credentialReference: "keychain://vpn.credentials/unsupported",
        transportSettings: VPNTransportSettings(network: "tcp", security: "tls"),
        tlsSettings: VPNTLSSettings(isEnabled: true, serverName: "unsupported.example.com"),
        protocolConfiguration: protocolConfiguration,
        source: .manual
    )
}

@MainActor
private func waitForDiagnosticCondition(_ condition: @MainActor () -> Bool) async {
    for _ in 0..<100 {
        if condition() {
            return
        }
        try? await Task.sleep(for: .milliseconds(5))
    }
}

private final class RecordingLibXrayRawInvoker: LibXrayRawInvoking, @unchecked Sendable {
    let apiVersion: Int64
    private let response: String?
    private let lock = NSLock()
    private var requests: [String] = []
    private var activeInvocations = 0
    private var maximumActiveInvocations = 0

    init(apiVersion: Int64 = LibXrayTestAdapterCore.supportedAPIVersion, response: String?) {
        self.apiVersion = apiVersion
        self.response = response
    }

    var requestCount: Int {
        locked { requests.count }
    }

    var lastRequest: String? {
        locked { requests.last }
    }

    var maximumConcurrentInvocations: Int {
        locked { maximumActiveInvocations }
    }

    func invoke(requestJSON: String) -> String? {
        lock.lock()
        activeInvocations += 1
        maximumActiveInvocations = max(maximumActiveInvocations, activeInvocations)
        requests.append(requestJSON)
        activeInvocations -= 1
        let response = self.response
        lock.unlock()
        return response
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
