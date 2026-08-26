//
//  Stage0RuntimeWireCharacterizationTests.swift
//  VPNTests
//
//  Immutable Stage 0 locks for the runtime v1 wire and revision contracts.
//

import Foundation
import Testing
@testable import VPN

struct Stage0RuntimeWireCharacterizationTests {
    @Test
    func canonicalVersionOneCollectionDecodesAndReencodesByteForByte() throws {
        let fixture = try Stage0TestResources.fixtureData(named: "runtime-profile-collection-v1")
        let collection = try stage0RuntimeDecoder().decode(SharedRuntimeProfileCollection.self, from: fixture)

        #expect(RuntimeConfigurationProtocol.profileSchemaVersion == 1)
        #expect(RuntimeConfigurationProtocol.profileCollectionSchemaVersion == 1)
        #expect(RuntimeConfigurationProtocol.providerConfigurationSchemaVersion == 1)
        #expect(collection.schemaVersion == 1)
        #expect(collection.records.count == 5)
        #expect(collection.records.map(\.profileID.uuidString) == [
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444",
            "55555555-5555-4555-8555-555555555555"
        ])
        #expect(collection.records.map(\.protocolKind) == [
            .vless, .vmess, .trojan, .shadowsocks, .hysteria2
        ])

        let vless = collection.records[0]
        #expect(vless.backendKind == .xray)
        #expect(vless.completeness == .complete)
        #expect(vless.endpoint == SharedRuntimeEndpoint(host: "vless.stage0.example.invalid", port: 443))
        #expect(vless.transport.kind == .xhttp)
        #expect(vless.transport.xhttp?.path == "/stage0-vless")
        #expect(vless.transport.xhttp?.host == "cdn.stage0.example.invalid")
        #expect(vless.transport.xhttp?.mode == .packetUp)
        #expect(vless.security.kind == .reality)
        #expect(vless.security.reality?.serverName == "reality.stage0.example.invalid")
        #expect(vless.security.reality?.publicKey == String(repeating: "A", count: 43))
        #expect(vless.security.reality?.shortID == "a1b2c3d4")
        #expect(vless.security.reality?.spiderX == "/")
        #expect(vless.vless.flow == "xtls-rprx-vision")
        #expect(vless.vless.encryption == "none")

        let vmess = collection.records[1]
        #expect(vmess.transport.kind == .websocket)
        #expect(vmess.transport.path == "/stage0-vmess")
        #expect(vmess.transport.host == "ws.stage0.example.invalid")
        #expect(vmess.security.alpn == ["h2", "http/1.1"])
        #expect(vmess.vmess == SharedRuntimeVMessParameters(alterID: 0, security: "auto"))
        #expect(vmess.trojan == nil)

        let trojan = collection.records[2]
        #expect(trojan.transport.kind == .grpc)
        #expect(trojan.transport.serviceName == "stage0-trojan")
        #expect(trojan.trojan?.alpn == ["h2"])
        #expect(trojan.vmess == nil)

        let outline = collection.records[3]
        #expect(outline.protocolKind == .shadowsocks)
        #expect(outline.security.kind == .none)
        #expect(outline.shadowsocks?.method == "chacha20-ietf-poly1305")
        #expect(outline.shadowsocks?.plugin == nil)
        #expect(outline.shadowsocks?.isOutlineStaticKey == true)

        let hysteria2 = collection.records[4]
        #expect(hysteria2.transport.kind == .hysteria)
        #expect(hysteria2.security.kind == .tls)
        #expect(hysteria2.security.alpn == ["h3"])
        #expect(hysteria2.hysteria2?.obfs == "salamander")
        #expect(hysteria2.hysteria2?.bandwidthHint == nil)
        #expect(hysteria2.hysteria2?.obfsPasswordReference == "keychain://stage0.runtime/hysteria2-obfs")
        #expect(hysteria2.credentialReferences == [
            "keychain://stage0.runtime/hysteria2-primary",
            "keychain://stage0.runtime/hysteria2-obfs"
        ])

        let encoded = try stage0RuntimeEncoder().encode(collection)
        let encodedText = try #require(String(data: encoded, encoding: .utf8))
        try Stage0TestResources.requireGoldenJSON(encodedText, named: "runtime-profile-collection-v1")
    }

    @Test
    func collectionOrderingAndOptionalFieldOmissionStayCanonical() throws {
        let collection = try stage0RuntimeCollection()
        let reversed = SharedRuntimeProfileCollection(records: collection.records.reversed())
        #expect(reversed.records == collection.records)

        let data = try stage0RuntimeEncoder().encode(collection)
        let root = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let records = try #require(root["records"] as? [[String: Any]])

        #expect(records[0]["vmess"] == nil)
        #expect(records[0]["trojan"] == nil)
        #expect(records[0]["shadowsocks"] == nil)
        #expect(records[0]["hysteria2"] == nil)
        #expect((records[0]["transport"] as? [String: Any])?["path"] as? String == "/stage0-vless")
        #expect((records[0]["transport"] as? [String: Any])?["xhttp"] != nil)

        #expect(records[1]["vmess"] != nil)
        #expect(records[1]["trojan"] == nil)
        #expect((records[1]["vless"] as? [String: Any])?.isEmpty == true)
        #expect((records[1]["transport"] as? [String: Any])?["xhttp"] == nil)

        #expect((records[3]["shadowsocks"] as? [String: Any])?["plugin"] == nil)
        #expect((records[4]["hysteria2"] as? [String: Any])?["bandwidthHint"] == nil)
    }

    @Test
    func runtimeFixtureContainsOnlyOpaqueCredentialReferences() throws {
        let text = try Stage0TestResources.fixtureText(named: "runtime-profile-collection-v1")
        let collection = try stage0RuntimeCollection()
        let expectedReferences: Set<String> = [
            "keychain://stage0.runtime/vless-primary",
            "keychain://stage0.runtime/vmess-primary",
            "keychain://stage0.runtime/trojan-primary",
            "keychain://stage0.runtime/outline-primary",
            "keychain://stage0.runtime/hysteria2-primary",
            "keychain://stage0.runtime/hysteria2-obfs"
        ]

        #expect(Set(collection.records.flatMap(\.credentialReferences)) == expectedReferences)
        for reference in expectedReferences {
            #expect(text.contains(reference.replacingOccurrences(of: "/", with: "\\/")))
        }
        for forbiddenSecret in [
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "stage0-trojan-password-DO-NOT-USE",
            "stage0-outline-password-DO-NOT-USE",
            "stage0-hysteria-auth-DO-NOT-USE",
            "stage0-salamander-secret-DO-NOT-USE",
            "STAGE0_RUNTIME_PLAINTEXT_SECRET"
        ] {
            #expect(!text.contains(forbiddenSecret))
        }
    }

    @Test
    func runtimeRawValuesAndSensitiveCodableNamesRemainExact() throws {
        #expect(SharedRuntimeProtocolKind.vless.rawValue == "vless")
        #expect(SharedRuntimeProtocolKind.vmess.rawValue == "vmess")
        #expect(SharedRuntimeProtocolKind.trojan.rawValue == "trojan")
        #expect(SharedRuntimeProtocolKind.shadowsocks.rawValue == "shadowsocks")
        #expect(SharedRuntimeProtocolKind.hysteria2.rawValue == "hysteria2")
        #expect(SharedRuntimeBackendKind.xray.rawValue == "xray")
        #expect(SharedRuntimeTransportKind.websocket.rawValue == "websocket")
        #expect(SharedRuntimeTransportKind.httpUpgrade.rawValue == "httpUpgrade")
        #expect(SharedRuntimeSecurityKind.none.rawValue == "none")
        #expect(SharedRuntimeSecurityKind.tls.rawValue == "tls")
        #expect(SharedRuntimeSecurityKind.reality.rawValue == "reality")
        #expect(SharedRuntimeCompleteness.complete.rawValue == "complete")
        #expect(SharedRuntimeCompleteness.incomplete.rawValue == "incomplete")
        #expect(SharedRuntimeXHTTPMode.packetUp.rawValue == "packet-up")
        #expect(SharedRuntimeXHTTPMode.streamUp.rawValue == "stream-up")
        #expect(SharedRuntimeXHTTPMode.streamOne.rawValue == "stream-one")

        let collection = try stage0RuntimeCollection()
        let data = try stage0RuntimeEncoder().encode(collection)
        let text = try #require(String(data: data, encoding: .utf8))
        #expect(text.contains(#""shortID" : "a1b2c3d4""#))
        #expect(!text.contains(#""shortId""#))
        #expect(text.contains(#""alterID" : 0"#))
        #expect(!text.contains(#""alterId""#))
        #expect(text.contains(#""kind" : "websocket""#))
    }
}

struct Stage0RuntimeRevisionCharacterizationTests {
    @Test
    func committedRecordsKeepExactNormalizedRevisionsAndProviderTokens() throws {
        let collection = try stage0RuntimeCollection()
        let expectedRevisions = [
            "v1-a0191e87b3919948",
            "v1-b8bf2c0e535a4cb6",
            "v1-f6bc9f53fd68e72a",
            "v1-f83bce6ca614c958",
            "v1-d58e63ced98fb916"
        ]
        let expectedTokens: [Int64] = [
            2_668_131_022_336_979_028,
            8_246_559_824_354_483_126,
            4_387_796_889_195_010_630,
            1_739_759_092_434_321_660,
            3_307_916_102_570_965_359
        ]

        #expect(collection.records.map(\.recordRevision) == expectedRevisions)
        #expect(try collection.records.map {
            try stage0ReferenceRecordRevision($0)
        } == expectedRevisions)
        #expect(try collection.records.map {
            try RuntimeProviderConfiguration.revisionToken(for: $0.recordRevision)
        } == expectedTokens)

        for record in collection.records {
            #expect(try stage0ReferenceRecordRevision(record) == record.recordRevision)
            #expect(try stage0ReferenceRecordRevision(record) == stage0ReferenceRecordRevision(record))
        }
    }

    @Test
    func revisionNormalizationExcludesOnlyCurrentIdentityNoise() throws {
        let original = try stage0RuntimeCollection().records[0]

        var identityNoise = original
        identityNoise.recordRevision = "ignored-existing-revision"
        identityNoise.updatedAt = Date(timeIntervalSince1970: 4_102_444_800)
        #expect(try stage0ReferenceRecordRevision(identityNoise) == original.recordRevision)

        var endpointChanged = original
        endpointChanged.endpoint.port = 8443
        #expect(try stage0ReferenceRecordRevision(endpointChanged) != original.recordRevision)

        var credentialReferenceChanged = original
        credentialReferenceChanged.credentialReference += "-changed"
        #expect(try stage0ReferenceRecordRevision(credentialReferenceChanged) != original.recordRevision)

        var transportChanged = original
        transportChanged.transport.xhttp?.mode = .streamUp
        #expect(try stage0ReferenceRecordRevision(transportChanged) != original.recordRevision)
    }

    @Test
    func productionMapperProducesLockedRevisionsForVLESSOutlineAndHysteria2() throws {
        let collection = try stage0RuntimeCollection()
        let mapperCases: [(VPNProfile, Date, String)] = [
            (
                stage0VLESSProfile(matching: collection.records[0]),
                collection.records[0].updatedAt,
                "v1-a0191e87b3919948"
            ),
            (
                stage0OutlineProfile(matching: collection.records[3]),
                collection.records[3].updatedAt,
                "v1-f83bce6ca614c958"
            ),
            (
                stage0Hysteria2Profile(matching: collection.records[4]),
                collection.records[4].updatedAt,
                "v1-d58e63ced98fb916"
            )
        ]

        for (profile, now, expectedRevision) in mapperCases {
            let first = try SharedRuntimeProfileMapper(now: { now }).record(from: profile)
            let second = try SharedRuntimeProfileMapper(now: { now }).record(from: profile)
            #expect(first.recordRevision == expectedRevision)
            #expect(second.recordRevision == expectedRevision)
        }

        var cosmeticChange = mapperCases[0].0
        cosmeticChange.name = "A cosmetic name ignored by the runtime record"
        cosmeticChange.localNotes = "Also not part of the runtime record"
        #expect(
            try SharedRuntimeProfileMapper(now: { mapperCases[0].1 }).record(from: cosmeticChange).recordRevision
                == mapperCases[0].2
        )
    }
}

struct Stage0ProviderConfigurationCharacterizationTests {
    @Test
    func propertyListUsesExactVersionKeysValuesAndFoundationBridgeTypes() throws {
        let profileID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
        let provider = try RuntimeProviderConfiguration(
            profileID: profileID,
            sharedRecordRevision: "v1-a0191e87b3919948"
        )
        let propertyList = provider.propertyList

        #expect(provider.schemaVersion == 1)
        #expect(provider.profileID == profileID)
        #expect(provider.recordRevision == 2_668_131_022_336_979_028)
        #expect(Set(propertyList.keys) == ["schemaVersion", "profileID", "recordRevision"])
        #expect(propertyList["schemaVersion"] is NSNumber)
        #expect(propertyList["profileID"] is NSString)
        #expect(propertyList["recordRevision"] is NSNumber)
        #expect(propertyList.values.allSatisfy { PropertyListSerialization.propertyList($0, isValidFor: .binary) })

        let parsed = try RuntimeProviderConfiguration.parse(propertyList)
        #expect(parsed == provider)
    }

    @Test
    func parserRejectsMissingMalformedBooleanFractionalNonpositiveAndOverflowValues() throws {
        let profileID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
        let valid: [String: Any] = try RuntimeProviderConfiguration(
            profileID: profileID,
            sharedRecordRevision: "v1-a0191e87b3919948"
        ).propertyList

        #expect(throws: RuntimeConfigurationError.missingProviderConfiguration) {
            _ = try RuntimeProviderConfiguration.parse(nil)
        }

        for (key, expectedError) in [
            ("schemaVersion", RuntimeConfigurationError.providerConfigurationMissingSchemaVersion),
            ("profileID", RuntimeConfigurationError.providerConfigurationMissingProfileID),
            ("recordRevision", RuntimeConfigurationError.providerConfigurationMissingRecordRevision)
        ] {
            var value = valid
            value.removeValue(forKey: key)
            #expect(throws: expectedError) {
                _ = try RuntimeProviderConfiguration.parse(value)
            }
        }

        var unknown = valid
        unknown["future"] = NSNumber(value: 1)
        #expect(throws: RuntimeConfigurationError.providerConfigurationUnknownKey) {
            _ = try RuntimeProviderConfiguration.parse(unknown)
        }

        var malformedID = valid
        malformedID["profileID"] = "not-a-uuid" as NSString
        #expect(throws: RuntimeConfigurationError.providerConfigurationMalformedProfileID) {
            _ = try RuntimeProviderConfiguration.parse(malformedID)
        }

        var wrongProfileType = valid
        wrongProfileType["profileID"] = NSNumber(value: 1)
        #expect(throws: RuntimeConfigurationError.providerConfigurationWrongProfileIDType) {
            _ = try RuntimeProviderConfiguration.parse(wrongProfileType)
        }

        for badSchema in [NSNumber(value: true), NSNumber(value: 1.5), "1" as NSString] {
            var value = valid
            value["schemaVersion"] = badSchema
            #expect(throws: RuntimeConfigurationError.providerConfigurationWrongSchemaVersionType) {
                _ = try RuntimeProviderConfiguration.parse(value)
            }
        }

        for badSchema in [NSNumber(value: -1), NSNumber(value: 0), NSNumber(value: UInt64.max)] {
            var value = valid
            value["schemaVersion"] = badSchema
            #expect(throws: RuntimeConfigurationError.providerConfigurationUnsupportedSchemaVersion) {
                _ = try RuntimeProviderConfiguration.parse(value)
            }
        }

        for badRevision in [NSNumber(value: true), NSNumber(value: 1.5), "1" as NSString] {
            var value = valid
            value["recordRevision"] = badRevision
            #expect(throws: RuntimeConfigurationError.providerConfigurationWrongRecordRevisionType) {
                _ = try RuntimeProviderConfiguration.parse(value)
            }
        }

        for badRevision in [
            NSNumber(value: -1),
            NSNumber(value: 0),
            NSDecimalNumber(string: "9223372036854775808")
        ] {
            var value = valid
            value["recordRevision"] = badRevision
            #expect(throws: RuntimeConfigurationError.providerConfigurationInvalidRecordRevision) {
                _ = try RuntimeProviderConfiguration.parse(value)
            }
        }
    }

    @Test
    func providerRevisionTokenAlgorithmKeepsKnownCrossProcessFixture() throws {
        let expected: Int64 = 6_875_115_447_722_027_723
        #expect(try RuntimeProviderConfiguration.revisionToken(for: "rev-stable-cross-process") == expected)
        #expect(try RuntimeProviderConfiguration.revisionToken(for: "  rev-stable-cross-process\n") == expected)
        #expect(try RuntimeProviderConfiguration.revisionToken(for: "rev-stable-cross-process") == expected)
        #expect(try RuntimeProviderConfiguration.revisionToken(for: "rev-stable-cross-process-2") != expected)
        #expect(throws: RuntimeConfigurationError.providerConfigurationInvalidRecordRevision) {
            _ = try RuntimeProviderConfiguration.revisionToken(for: " \n ")
        }
    }
}

func stage0RuntimeCollection() throws -> SharedRuntimeProfileCollection {
    try stage0RuntimeDecoder().decode(
        SharedRuntimeProfileCollection.self,
        from: Stage0TestResources.fixtureData(named: "runtime-profile-collection-v1")
    )
}

private func stage0RuntimeEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    return encoder
}

private func stage0RuntimeDecoder() -> JSONDecoder {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return decoder
}

private func stage0ReferenceRecordRevision(_ record: SharedRuntimeProfileRecord) throws -> String {
    var normalized = record
    normalized.recordRevision = ""
    normalized.updatedAt = Date(timeIntervalSince1970: 0)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    let data = try encoder.encode(normalized)

    var hash: UInt64 = 0xcbf29ce484222325
    for byte in data {
        hash ^= UInt64(byte)
        hash &*= 0x100000001b3
    }
    return "v1-" + String(hash, radix: 16)
}

func stage0VLESSProfile(matching record: SharedRuntimeProfileRecord) -> VPNProfile {
    var profile = VPNProfile.draft(
        name: "Stage 0 VLESS",
        protocolType: .vless,
        serverAddress: record.endpoint.host,
        port: record.endpoint.port,
        credentialReference: record.credentialReference,
        transportSettings: VPNTransportSettings(
            network: "xhttp",
            security: "reality",
            path: record.transport.xhttp?.path,
            host: record.transport.xhttp?.host,
            metadata: ["mode": record.transport.xhttp?.mode?.rawValue ?? "auto"]
        ),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: record.security.reality?.serverName,
            allowInsecure: record.security.allowInsecure,
            fingerprint: record.security.reality?.fingerprint,
            realityPublicKey: record.security.reality?.publicKey,
            shortID: record.security.reality?.shortID,
            spiderX: record.security.reality?.spiderX
        ),
        protocolConfiguration: .vless(VLESSProfileConfiguration(
            flow: record.vless.flow,
            encryption: record.vless.encryption
        )),
        source: .manual,
        now: record.updatedAt
    )
    profile.id = record.profileID
    return profile
}

func stage0OutlineProfile(matching record: SharedRuntimeProfileRecord) -> VPNProfile {
    var profile = VPNProfile.draft(
        name: "Stage 0 Outline",
        protocolType: .shadowsocks,
        serverAddress: record.endpoint.host,
        port: record.endpoint.port,
        credentialReference: record.credentialReference,
        transportSettings: VPNTransportSettings(metadata: ["outline": "1"]),
        tlsSettings: VPNTLSSettings(),
        protocolConfiguration: .shadowsocks(ShadowsocksProfileConfiguration(
            method: record.shadowsocks?.method,
            plugin: record.shadowsocks?.plugin
        )),
        source: .manual,
        metadata: ["outline": "1"],
        now: record.updatedAt
    )
    profile.id = record.profileID
    return profile
}

func stage0Hysteria2Profile(matching record: SharedRuntimeProfileRecord) -> VPNProfile {
    var profile = VPNProfile.draft(
        name: "Stage 0 Hysteria2",
        protocolType: .hysteria2,
        serverAddress: record.endpoint.host,
        port: record.endpoint.port,
        credentialReference: record.credentialReference,
        transportSettings: VPNTransportSettings(
            network: "udp",
            security: "tls",
            metadata: [
                "alpn": "h3",
                "obfs": record.hysteria2?.obfs ?? ""
            ]
        ),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: record.security.serverName,
            allowInsecure: record.security.allowInsecure,
            fingerprint: record.security.fingerprint,
            alpn: ["h3"]
        ),
        protocolConfiguration: .hysteria2(Hysteria2ProfileConfiguration(
            obfs: record.hysteria2?.obfs,
            bandwidthHint: record.hysteria2?.bandwidthHint,
            obfsPasswordReference: record.hysteria2?.obfsPasswordReference
        )),
        source: .manual,
        metadata: [
            "alpn": "h3",
            "obfs": record.hysteria2?.obfs ?? ""
        ],
        now: record.updatedAt
    )
    profile.id = record.profileID
    return profile
}
