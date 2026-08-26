//
//  Stage0ValidationConcurrencyCharacterizationTests.swift
//  VPNTests
//
//  Stage 0 locks for rejection, redaction, and actor-isolation behavior.
//

import Foundation
import Testing
@testable import VPN

struct Stage0RuntimeRejectionCharacterizationTests {
    @Test
    func capabilityAdmissionKeepsUnsupportedIncompleteAndHysteria2Categories() throws {
        let records = try stage0RuntimeCollection().records

        let unsupported = stage0UnsupportedTUICProfile()
        #expect(unsupported.isComplete)
        #expect(
            VPNRuntimeCapabilityEvaluator().evaluate(unsupported)
                == .unsupported(.unsupportedProtocol(.tuic))
        )

        var incomplete = stage0VLESSProfile(matching: records[0])
        incomplete.serverAddress = ""
        #expect(
            VPNRuntimeCapabilityEvaluator().evaluate(incomplete)
                == .incomplete(["server address"])
        )

        var unsupportedShadowsocksMethod = stage0OutlineProfile(matching: records[3])
        unsupportedShadowsocksMethod.protocolConfiguration = .shadowsocks(
            ShadowsocksProfileConfiguration(method: "stage0-unsupported-method", plugin: nil)
        )
        #expect(
            VPNRuntimeCapabilityEvaluator().evaluate(unsupportedShadowsocksMethod)
                == .unsupported(.unsupportedFeature(
                    protocolType: .shadowsocks,
                    feature: .shadowsocksMethod
                ))
        )

        var unsupportedShadowsocksPlugin = stage0OutlineProfile(matching: records[3])
        unsupportedShadowsocksPlugin.protocolConfiguration = .shadowsocks(
            ShadowsocksProfileConfiguration(
                method: "chacha20-ietf-poly1305",
                plugin: "v2ray-plugin"
            )
        )
        #expect(
            VPNRuntimeCapabilityEvaluator().evaluate(unsupportedShadowsocksPlugin)
                == .unsupported(.unsupportedFeature(
                    protocolType: .shadowsocks,
                    feature: .shadowsocksPlugin,
                    detail: "v2ray-plugin"
                ))
        )

        var hysteria2Bandwidth = stage0Hysteria2Profile(matching: records[4])
        hysteria2Bandwidth.protocolConfiguration = .hysteria2(
            Hysteria2ProfileConfiguration(
                obfs: "salamander",
                bandwidthHint: "100 mbps",
                obfsPasswordReference: records[4].hysteria2?.obfsPasswordReference
            )
        )
        #expect(
            VPNRuntimeCapabilityEvaluator().evaluate(hysteria2Bandwidth)
                == .unsupported(.unsupportedFeature(
                    protocolType: .hysteria2,
                    feature: .hysteria2Bandwidth
                ))
        )

        var hysteria2CertificatePinning = stage0Hysteria2Profile(matching: records[4])
        hysteria2CertificatePinning.metadata["pinSHA256"] = "stage0-pin"
        #expect(
            VPNRuntimeCapabilityEvaluator().evaluate(hysteria2CertificatePinning)
                == .unsupported(.unsupportedFeature(
                    protocolType: .hysteria2,
                    feature: .hysteria2CertificatePinning
                ))
        )

        var hysteria2ECH = stage0Hysteria2Profile(matching: records[4])
        hysteria2ECH.metadata["echConfig"] = "stage0-ech"
        #expect(
            VPNRuntimeCapabilityEvaluator().evaluate(hysteria2ECH)
                == .unsupported(.unsupportedFeature(
                    protocolType: .hysteria2,
                    feature: .hysteria2ECH
                ))
        )

        var hysteria2PortHopping = stage0Hysteria2Profile(matching: records[4])
        hysteria2PortHopping.metadata["mport"] = "5000-6000"
        #expect(
            VPNRuntimeCapabilityEvaluator().evaluate(hysteria2PortHopping)
                == .unsupported(.unsupportedFeature(
                    protocolType: .hysteria2,
                    feature: .hysteria2PortHopping
                ))
        )

        var hysteria2Obfuscation = stage0Hysteria2Profile(matching: records[4])
        hysteria2Obfuscation.protocolConfiguration = .hysteria2(
            Hysteria2ProfileConfiguration(
                obfs: "future-obfs",
                bandwidthHint: nil,
                obfsPasswordReference: records[4].hysteria2?.obfsPasswordReference
            )
        )
        #expect(
            VPNRuntimeCapabilityEvaluator().evaluate(hysteria2Obfuscation)
                == .unsupported(.unsupportedFeature(
                    protocolType: .hysteria2,
                    feature: .hysteria2Obfuscation
                ))
        )

        var invalidHysteria2ALPN = stage0Hysteria2Profile(matching: records[4])
        invalidHysteria2ALPN.metadata["alpn"] = "h2"
        invalidHysteria2ALPN.transportSettings.metadata["alpn"] = "h2"
        invalidHysteria2ALPN.tlsSettings.alpn = ["h2"]
        #expect(invalidHysteria2ALPN.isComplete)
        #expect(
            VPNRuntimeCapabilityEvaluator().evaluate(invalidHysteria2ALPN)
                == .unsupported(.unsupportedFeature(
                    protocolType: .hysteria2,
                    feature: .runtimeConfiguration
                ))
        )
    }

    @Test
    func builderKeepsProtocolTransportSecurityAndALPNRejections() {
        let builder = XrayConfigurationBuilder()

        let missingShadowsocksParameters = stage0ResolvedConfiguration(
            id: "60000000-0000-4000-8000-000000000001",
            kind: .shadowsocks,
            host: "shadowsocks.stage0.example.invalid",
            port: 8388,
            transport: stage0Transport(.tcp),
            security: .init(kind: .none),
            credential: "stage0-rejection-password-DO-NOT-USE",
            shadowsocks: nil
        )
        #expect(throws: XrayConfigurationBuilderError.unsupportedProtocol) {
            _ = try builder.build(from: missingShadowsocksParameters)
        }

        let unsupportedTransport = stage0ResolvedConfiguration(
            id: "60000000-0000-4000-8000-000000000002",
            kind: .vless,
            host: "vless.stage0.example.invalid",
            port: 443,
            transport: stage0Transport(.hysteria),
            security: stage0TLS("vless.stage0.example.invalid"),
            credential: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            vless: .init(flow: nil, encryption: "none")
        )
        #expect(throws: XrayConfigurationBuilderError.unsupportedTransport) {
            _ = try builder.build(from: unsupportedTransport)
        }

        let unsupportedSecurity = stage0ResolvedConfiguration(
            id: "60000000-0000-4000-8000-000000000003",
            kind: .vless,
            host: "vless.stage0.example.invalid",
            port: 443,
            transport: stage0Transport(.tcp),
            security: .init(kind: .none),
            credential: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            vless: .init(flow: nil, encryption: "none")
        )
        #expect(throws: XrayConfigurationBuilderError.unsupportedSecurity) {
            _ = try builder.build(from: unsupportedSecurity)
        }

        let invalidALPN = stage0ResolvedConfiguration(
            id: "60000000-0000-4000-8000-000000000004",
            kind: .vmess,
            host: "vmess.stage0.example.invalid",
            port: 443,
            transport: stage0Transport(.tcp),
            security: stage0TLS("vmess.stage0.example.invalid", alpn: ["h 2"]),
            credential: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            vmess: .init(alterID: 0, security: "auto")
        )
        #expect(throws: XrayConfigurationBuilderError.invalidTLSConfiguration) {
            _ = try builder.build(from: invalidALPN)
        }
    }

    @Test
    func realityValidationKeepsLayerSpecificErrorCategories() {
        let malformedCases = [
            SharedRuntimeRealityPublicParameters(
                serverName: "reality.stage0.example.invalid",
                publicKey: "bad-key",
                shortID: "abcd1234",
                fingerprint: "chrome",
                spiderX: nil
            ),
            SharedRuntimeRealityPublicParameters(
                serverName: "reality.stage0.example.invalid",
                publicKey: String(repeating: "A", count: 43),
                shortID: "xyz",
                fingerprint: "chrome",
                spiderX: nil
            )
        ]

        for (index, reality) in malformedCases.enumerated() {
            #expect(throws: RuntimeConfigurationError.invalidSecurityConfiguration) {
                try RealityPublicParametersValidator.validate(reality)
            }

            let configuration = stage0ResolvedConfiguration(
                id: "60000000-0000-4000-8000-00000000001\(index)",
                kind: .vless,
                host: "reality.stage0.example.invalid",
                port: 443,
                transport: stage0Transport(.tcp),
                security: SharedRuntimeSecurity(
                    kind: .reality,
                    serverName: reality.serverName,
                    allowInsecure: false,
                    fingerprint: reality.fingerprint,
                    alpn: nil,
                    shortID: reality.shortID,
                    reality: reality
                ),
                credential: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                vless: .init(flow: nil, encryption: "none")
            )
            #expect(throws: XrayConfigurationBuilderError.invalidRealityConfiguration) {
                _ = try XrayConfigurationBuilder().build(from: configuration)
            }
        }
    }

    @Test
    func xhttpValidationKeepsMissingModePathAndHostCategories() {
        let valid = SharedRuntimeXHTTPParameters(
            path: "/stage0",
            host: "cdn.stage0.example.invalid",
            mode: .packetUp
        )
        let cases: [(SharedRuntimeTransport, XrayConfigurationBuilderError)] = [
            (
                SharedRuntimeTransport(
                    kind: .xhttp,
                    path: nil,
                    host: nil,
                    serviceName: nil,
                    mode: nil,
                    xhttp: nil
                ),
                .invalidXHTTPConfiguration
            ),
            (
                SharedRuntimeTransport(
                    kind: .xhttp,
                    path: nil,
                    host: nil,
                    serviceName: nil,
                    mode: "future-mode",
                    xhttp: valid
                ),
                .invalidXHTTPMode
            ),
            (
                SharedRuntimeTransport(
                    kind: .xhttp,
                    path: "not/rooted",
                    host: nil,
                    serviceName: nil,
                    mode: nil,
                    xhttp: valid
                ),
                .invalidXHTTPPath
            ),
            (
                SharedRuntimeTransport(
                    kind: .xhttp,
                    path: nil,
                    host: "bad host",
                    serviceName: nil,
                    mode: nil,
                    xhttp: valid
                ),
                .invalidXHTTPHost
            )
        ]

        for (index, item) in cases.enumerated() {
            let configuration = stage0ResolvedConfiguration(
                id: "60000000-0000-4000-8000-00000000002\(index)",
                kind: .vless,
                host: "xhttp.stage0.example.invalid",
                port: 443,
                transport: item.0,
                security: stage0TLS("xhttp.stage0.example.invalid"),
                credential: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                vless: .init(flow: nil, encryption: "none")
            )
            #expect(throws: item.1) {
                _ = try XrayConfigurationBuilder().build(from: configuration)
            }
        }
    }

    @Test
    func shadowsocksAndHysteria2AdvancedFeaturesKeepCurrentBuilderCategories() {
        let builder = XrayConfigurationBuilder()
        let shadowsocksCases = [
            SharedRuntimeShadowsocksParameters(
                method: "unsupported-stage0-method",
                plugin: nil,
                isOutlineStaticKey: false
            ),
            SharedRuntimeShadowsocksParameters(
                method: "chacha20-ietf-poly1305",
                plugin: "v2ray-plugin",
                isOutlineStaticKey: false
            )
        ]
        for (index, parameters) in shadowsocksCases.enumerated() {
            let configuration = stage0ResolvedConfiguration(
                id: "60000000-0000-4000-8000-00000000003\(index)",
                kind: .shadowsocks,
                host: "shadowsocks.stage0.example.invalid",
                port: 8388,
                transport: stage0Transport(.tcp),
                security: .init(kind: .none),
                credential: "stage0-rejection-password-DO-NOT-USE",
                shadowsocks: parameters
            )
            #expect(throws: XrayConfigurationBuilderError.unsupportedProtocol) {
                _ = try builder.build(from: configuration)
            }
        }

        let hysteria2Cases = [
            SharedRuntimeHysteria2Parameters(
                obfs: nil,
                bandwidthHint: "100 mbps",
                obfsPasswordReference: nil
            ),
            SharedRuntimeHysteria2Parameters(
                obfs: "future-obfs",
                bandwidthHint: nil,
                obfsPasswordReference: "keychain://stage0.runtime/obfs"
            )
        ]
        for (index, parameters) in hysteria2Cases.enumerated() {
            let configuration = stage0ResolvedConfiguration(
                id: "60000000-0000-4000-8000-00000000004\(index)",
                kind: .hysteria2,
                host: "hy2.stage0.example.invalid",
                port: 443,
                transport: stage0Transport(.hysteria),
                security: stage0TLS("hy2.stage0.example.invalid", alpn: ["h3"]),
                credential: "stage0-hysteria-password-DO-NOT-USE",
                hysteria2: parameters,
                obfsPassword: parameters.obfs == nil ? nil : "stage0-obfs-password-DO-NOT-USE"
            )
            #expect(throws: XrayConfigurationBuilderError.unsupportedProtocol) {
                _ = try builder.build(from: configuration)
            }
        }
    }

    @Test
    func loaderKeepsRecordProviderAndCredentialErrorCategories() async throws {
        let records = try stage0RuntimeCollection().records
        let base = records[0]
        let baseProvider = try RuntimeProviderConfiguration(
            profileID: base.profileID,
            sharedRecordRevision: base.recordRevision
        ).propertyList
        let validPrimary = [base.credentialReference: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]

        var disabled = base
        disabled.enabled = false
        await stage0ExpectLoadError(.profileDisabled, record: disabled, provider: baseProvider, secrets: validPrimary)

        var incomplete = base
        incomplete.completeness = .incomplete
        await stage0ExpectLoadError(.profileIncomplete, record: incomplete, provider: baseProvider, secrets: validPrimary)

        var schemaMismatch = base
        schemaMismatch.schemaVersion = 2
        await stage0ExpectLoadError(.profileSchemaMismatch, record: schemaMismatch, provider: baseProvider, secrets: validPrimary)

        var malformedReference = base
        malformedReference.credentialReference = "not-a-credential-reference"
        await stage0ExpectLoadError(
            .malformedCredentialReference,
            record: malformedReference,
            provider: baseProvider,
            secrets: [malformedReference.credentialReference: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
        )

        await stage0ExpectLoadError(.credentialUnavailable, record: base, provider: baseProvider, secrets: [:])

        let mismatchedProfileID = UUID(uuidString: "66666666-6666-4666-8666-666666666666")!
        let profileMismatchProvider = RuntimeProviderConfiguration(
            profileID: mismatchedProfileID,
            recordRevision: try RuntimeProviderConfiguration.revisionToken(for: base.recordRevision)
        ).propertyList
        await stage0ExpectLoadError(
            .profileIdentityMismatch,
            record: base,
            storageKey: mismatchedProfileID,
            provider: profileMismatchProvider,
            secrets: validPrimary
        )

        let revisionMismatchProvider = RuntimeProviderConfiguration(
            profileID: base.profileID,
            recordRevision: 1
        ).propertyList
        await stage0ExpectLoadError(
            .profileRevisionMismatch,
            record: base,
            provider: revisionMismatchProvider,
            secrets: validPrimary
        )

        let hysteria2 = records[4]
        let hysteria2Provider = try RuntimeProviderConfiguration(
            profileID: hysteria2.profileID,
            sharedRecordRevision: hysteria2.recordRevision
        ).propertyList
        await stage0ExpectLoadError(
            .credentialUnavailable,
            record: hysteria2,
            provider: hysteria2Provider,
            secrets: [hysteria2.credentialReference: "stage0-hysteria-password-DO-NOT-USE"]
        )
    }
}

struct Stage0SecretRedactionCharacterizationTests {
    @Test
    func sensitiveDescriptionsErrorsDiagnosticsTelemetryAndWireRemainSecretFree() throws {
        let secret = "STAGE0_REDACTION_CANARY_9E6F92B7_DO_NOT_USE"
        let credential = SensitiveRuntimeCredential(secret)
        let resolved = stage0ResolvedConfiguration(
            id: "70000000-0000-4000-8000-000000000001",
            kind: .trojan,
            host: "redaction.stage0.example.invalid",
            port: 443,
            transport: stage0Transport(.tcp),
            security: stage0TLS("redaction.stage0.example.invalid"),
            credential: secret,
            trojan: .init(alpn: ["h2"])
        )
        let sensitiveXray = try XrayConfigurationBuilder().build(from: resolved)
        let sensitiveJSON = try sensitiveXray.withJSONString { $0 }

        #expect(credential.description == "<redacted>")
        #expect(credential.debugDescription == "<redacted>")
        #expect(!resolved.description.contains(secret))
        #expect(!resolved.debugDescription.contains(secret))
        #expect(sensitiveXray.description == "<redacted>")
        #expect(sensitiveXray.debugDescription == "<redacted>")
        let finalConfigurationContainsCredential = sensitiveJSON.contains(secret)
        #expect(finalConfigurationContainsCredential)

        let capability = VPNRuntimeCapability.unsupported(.unsupportedFeature(
            protocolType: .hysteria2,
            feature: .runtimeConfiguration
        ))
        let runtimeError = RuntimeConfigurationError.credentialMalformed
        let builderError = XrayConfigurationBuilderError.invalidCredential
        let provider = try RuntimeProviderConfiguration(
            profileID: resolved.profileID,
            sharedRecordRevision: "stage0-redaction-revision"
        )
        let validation = TunnelRuntimeConfigurationValidationResponse.failure(
            correlationID: UUID(uuidString: "70000000-0000-4000-8000-000000000002")!,
            stage: .credential,
            category: .credentialMalformed,
            providerConfigurationValid: true
        )
        let telemetry = TunnelStoredTelemetrySnapshot(
            schemaVersion: TunnelMessageProtocol.schemaVersion,
            generatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            runtime: .notRunning(generatedAt: Date(timeIntervalSince1970: 1_700_000_000)),
            events: [
                TunnelEventSnapshot(
                    generatedAt: Date(timeIntervalSince1970: 1_700_000_000),
                    category: "credentialUnavailable",
                    runtimeState: .failed,
                    failureCategory: .credentialUnavailable
                )
            ]
        )
        let runtimeFixture = try Stage0TestResources.fixtureText(named: "runtime-profile-collection-v1")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601

        let secretFreeRepresentations = [
            String(describing: runtimeError),
            String(reflecting: runtimeError),
            runtimeError.localizedDescription,
            String(describing: builderError),
            String(reflecting: builderError),
            builderError.localizedDescription,
            capability.statusText,
            String(describing: provider.propertyList),
            String(data: try encoder.encode(validation), encoding: .utf8) ?? "",
            String(data: try encoder.encode(telemetry), encoding: .utf8) ?? "",
            runtimeFixture
        ]
        let leakedSecret = secretFreeRepresentations.contains { $0.contains(secret) }
        #expect(!leakedSecret)

        #expect(Set(provider.propertyList.keys) == ["schemaVersion", "profileID", "recordRevision"])
        #expect(!runtimeFixture.contains("password"))
        #expect(!runtimeFixture.contains("auth"))
    }
}

struct Stage0ConcurrencyCharacterizationTests {
    @Test
    func immutableBuilderConformerRunsOffMainActor() async throws {
        let builder: any XrayConfigurationBuilding = Stage0ImmutableXrayBuilder()
        let configuration = stage0ResolvedConfiguration(
            id: "80000000-0000-4000-8000-000000000001",
            kind: .vless,
            host: "concurrency.stage0.example.invalid",
            port: 443,
            transport: stage0Transport(.tcp),
            security: stage0TLS("concurrency.stage0.example.invalid"),
            credential: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            vless: .init(flow: nil, encryption: "none")
        )

        let protocolName = try await Task.detached {
            let sensitive = try builder.build(from: configuration, options: XrayBuildOptions())
            return try sensitive.withJSONString { json in
                let root = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
                let outbounds = root?["outbounds"] as? [[String: Any]]
                return outbounds?.first?["protocol"] as? String
            }
        }.value
        #expect(protocolName == "vless")
    }

    @Test
    func actorConformersProtectMutableStoreResolverAndValidationState() async throws {
        let record = try stage0RuntimeCollection().records[0]
        let store: any SharedRuntimeProfileStoring = Stage0RuntimeProfileStore()
        try await store.write(record)
        #expect(try await store.read(profileID: record.profileID) == record)
        #expect(try await store.records() == [record])

        let resolver = Stage0CountingCredentialResolver(values: [record.credentialReference: "stage0-value"])
        async let first = resolver.credential(for: record.credentialReference)
        async let second = resolver.credential(for: record.credentialReference)
        #expect(try await [first, second] == ["stage0-value", "stage0-value"])
        #expect(await resolver.callCount == 2)

        let validationLoader = Stage0CountingValidationLoader()
        let response = await validationLoader.validateRuntimeConfiguration(
            correlationID: UUID(uuidString: "80000000-0000-4000-8000-000000000002")!,
            expectedProfileID: record.profileID,
            expectedRevisionToken: nil,
            requestGeneration: 7
        )
        #expect(response.success)
        #expect(await validationLoader.callCount == 1)
    }

    @Test
    func appXrayValidatorRemainsMainActorBound() async {
        let validator = await MainActor.run { Stage0MainActorXrayValidator() }
        let response = await validator.validateXrayConfiguration(
            correlationID: UUID(uuidString: "80000000-0000-4000-8000-000000000003")!,
            expectedProfileID: nil,
            expectedRevisionToken: nil,
            requestGeneration: nil
        )
        #expect(response.success)
        #expect(await MainActor.run { validator.callCount } == 1)
    }
}

private struct Stage0ImmutableXrayBuilder: XrayConfigurationBuilding {
    nonisolated func build(
        from configuration: ResolvedVLESSRuntimeConfiguration,
        options: XrayBuildOptions
    ) throws -> SensitiveXrayConfiguration {
        try XrayConfigurationBuilder().build(from: configuration, options: options)
    }
}

private actor Stage0RuntimeProfileStore: SharedRuntimeProfileStoring {
    private var storage: [UUID: SharedRuntimeProfileRecord]

    init(storage: [UUID: SharedRuntimeProfileRecord] = [:]) {
        self.storage = storage
    }

    func write(_ record: SharedRuntimeProfileRecord) {
        storage[record.profileID] = record
    }

    func read(profileID: UUID) throws -> SharedRuntimeProfileRecord {
        guard let record = storage[profileID] else {
            throw RuntimeConfigurationError.profileRecordNotFound
        }
        return record
    }

    func records() -> [SharedRuntimeProfileRecord] {
        storage.values.sorted { $0.profileID.uuidString < $1.profileID.uuidString }
    }

    func replaceAll(_ records: [SharedRuntimeProfileRecord]) {
        storage = Dictionary(uniqueKeysWithValues: records.map { ($0.profileID, $0) })
    }

    func delete(profileID: UUID) {
        storage.removeValue(forKey: profileID)
    }
}

private actor Stage0CountingCredentialResolver: RuntimeCredentialResolving {
    private let values: [String: String]
    private(set) var callCount = 0

    init(values: [String: String]) {
        self.values = values
    }

    func credential(for reference: String) -> String? {
        callCount += 1
        return values[reference]
    }
}

private actor Stage0CountingValidationLoader: RuntimeConfigurationValidationLoading {
    private(set) var callCount = 0

    func validateRuntimeConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) -> TunnelRuntimeConfigurationValidationResponse {
        callCount += 1
        return .success(
            correlationID: correlationID,
            protocolName: "vless",
            transportName: "tcp",
            securityName: "tls"
        )
    }
}

@MainActor
private final class Stage0MainActorXrayValidator: XrayConfigurationValidating {
    private(set) var callCount = 0

    func validateXrayConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) -> TunnelXrayConfigurationValidationResponse {
        callCount += 1
        return .success(
            correlationID: correlationID,
            protocolName: "vless",
            transportName: "tcp",
            securityName: "tls"
        )
    }
}

private func stage0ExpectLoadError(
    _ expected: RuntimeConfigurationError,
    record: SharedRuntimeProfileRecord,
    storageKey: UUID? = nil,
    provider: [String: Any],
    secrets: [String: String]
) async {
    let store = Stage0RuntimeProfileStore(storage: [storageKey ?? record.profileID: record])
    let resolver = Stage0CountingCredentialResolver(values: secrets)
    let loader = RuntimeConfigurationLoader(store: store, credentialResolver: resolver)
    await #expect(throws: expected) {
        _ = try await loader.load(providerConfiguration: provider)
    }
}

private func stage0UnsupportedTUICProfile() -> VPNProfile {
    VPNProfile.draft(
        name: "Stage 0 unsupported TUIC",
        protocolType: .tuic,
        serverAddress: "tuic.stage0.example.invalid",
        port: 443,
        credentialReference: "keychain://stage0.runtime/tuic-primary",
        transportSettings: VPNTransportSettings(network: "udp", security: "tls"),
        tlsSettings: VPNTLSSettings(
            isEnabled: true,
            serverName: "tuic.stage0.example.invalid",
            allowInsecure: false,
            fingerprint: "chrome",
            alpn: ["h3"]
        ),
        protocolConfiguration: .tuic(TUICProfileConfiguration(
            congestionControl: nil,
            udpRelayMode: nil
        )),
        source: .manual
    )
}
