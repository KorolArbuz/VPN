//
//  NativeWireGuardRuntimeTests.swift
//  VPNTests
//
//  Focused coverage for the real WireGuard/AmneziaWG dependency seam.
//

import Foundation
import NetworkExtension
import Testing
@testable import VPN

@Suite(.serialized)
struct NativeWireGuardRuntimeTests {
    @Test
    func wireGuardImportCreatesTypedMultiPeerSecretFreeProfile() async throws {
        let credentialStore = NativeTestCredentialStore()
        let result = try await VPNLinkParser(credentialStore: credentialStore).parse(wireGuardConfiguration())
        let profile = try nativeProfile(from: result)

        #expect(profile.protocolType == .wireGuard)
        #expect(profile.runtimeCapability.isReady)
        #expect(profile.serverAddress == "wg.example.invalid")
        #expect(profile.port == 51_820)
        guard case .wireGuard(let configuration) = profile.protocolConfiguration else {
            Issue.record("Expected typed WireGuard configuration")
            return
        }
        #expect(configuration.interfaceAddresses == ["10.8.0.2/32", "fd00::2/128"])
        #expect(configuration.dnsServers == ["1.1.1.1"])
        #expect(configuration.dnsSearchDomains == ["corp.example.invalid"])
        #expect(configuration.peers.count == 2)
        #expect(configuration.peers[0].allowedIPs == ["0.0.0.0/0", "::/0"])
        #expect(configuration.peers[0].excludedIPs == ["192.0.2.0/24"])
        #expect(configuration.peers[1].endpoint == nil)
        #expect(profile.credentialReferences.count == 3)
        #expect(profile.credentialReferences.allSatisfy(CredentialReferenceValidator.isValid))

        let encodedProfile = String(decoding: try JSONEncoder().encode(profile), as: UTF8.self)
        for secret in [nativeKey(1), nativeKey(4), nativeKey(5)] {
            #expect(encodedProfile.contains(secret) == false)
            #expect(result.sanitizedSummary.values.contains { $0.contains(secret) } == false)
        }
        #expect(await credentialStore.activeSecretCount() == 3)
    }

    @Test
    func amneziaWGImportPreservesProtectionParametersAndSecureHeaderKey() async throws {
        let credentialStore = NativeTestCredentialStore()
        let result = try await VPNLinkParser(credentialStore: credentialStore).parse(amneziaWGConfiguration())
        let profile = try nativeProfile(from: result)

        #expect(profile.protocolType == .amneziaWG)
        #expect(profile.runtimeCapability.isReady)
        guard case .amneziaWG(let configuration) = profile.protocolConfiguration else {
            Issue.record("Expected typed AmneziaWG configuration")
            return
        }
        #expect(configuration.amnezia?.junkPacketCount == 4)
        #expect(configuration.amnezia?.junkPacketMinSize == 40)
        #expect(configuration.amnezia?.junkPacketMaxSize == 80)
        #expect(configuration.amnezia?.initPacketJunkSize == 11)
        #expect(configuration.amnezia?.responsePacketJunkSize == 22)
        #expect(configuration.amnezia?.cookieReplyPacketJunkSize == 33)
        #expect(configuration.amnezia?.transportPacketJunkSize == 44)
        #expect(configuration.amnezia?.initPacketMagicHeader == "123456789")
        #expect(configuration.amnezia?.responsePacketMagicHeader == "987654321")
        #expect(configuration.amnezia?.underloadPacketMagicHeader == "192837465")
        #expect(configuration.amnezia?.transportPacketMagicHeader == "564738291")
        #expect(configuration.interfaceAddresses == ["10.9.0.2/32"])
        #expect(configuration.dnsServers == ["9.9.9.9"])
        #expect(configuration.mtu == 1_280)
        #expect(configuration.peers.first?.allowedIPs == ["0.0.0.0/0"])
        #expect(configuration.peers.first?.persistentKeepAlive == "15-30")
        #expect(configuration.peers.first?.presharedKeyReference != nil)
        #expect(configuration.headerProtectionKeyReference != nil)
        #expect(profile.credentialReferences.count == 3)

        let runtimeRecord = try NativeWireGuardProfileMapper().record(from: profile)
        #expect(runtimeRecord.amnezia?.junkPacketCount == 4)
        #expect(runtimeRecord.amnezia?.junkPacketMinSize == 40)
        #expect(runtimeRecord.amnezia?.junkPacketMaxSize == 80)
        #expect(runtimeRecord.amnezia?.initPacketJunkSize == 11)
        #expect(runtimeRecord.amnezia?.responsePacketJunkSize == 22)
        #expect(runtimeRecord.amnezia?.cookieReplyPacketJunkSize == 33)
        #expect(runtimeRecord.amnezia?.transportPacketJunkSize == 44)
        #expect(runtimeRecord.amnezia?.initPacketMagicHeader == "123456789")
        #expect(runtimeRecord.amnezia?.responsePacketMagicHeader == "987654321")
        #expect(runtimeRecord.amnezia?.underloadPacketMagicHeader == "192837465")
        #expect(runtimeRecord.amnezia?.transportPacketMagicHeader == "564738291")
        #expect(runtimeRecord.mtu == 1_280)
        #expect(runtimeRecord.dnsServers == ["9.9.9.9"])
        #expect(runtimeRecord.peers.first?.allowedIPs == ["0.0.0.0/0"])
        #expect(runtimeRecord.peers.first?.persistentKeepAlive == "15-30")
        #expect(runtimeRecord.privateKeyReference == profile.credentialReference)
        #expect(runtimeRecord.peers.first?.presharedKeyReference == configuration.peers.first?.presharedKeyReference)

        let encodedProfile = String(decoding: try JSONEncoder().encode(profile), as: UTF8.self)
        #expect(encodedProfile.contains(nativeKey(7)) == false)
        #expect(result.sanitizedSummary["headerProtectionKey"] == "Stored securely")
    }

    @Test
    func pasteFileAndQRCodeRoutesAllRecognizeNativeConfiguration() async throws {
        for routeKind in NativeImportRouteKind.allCases {
            let credentialStore = NativeTestCredentialStore()
            let importer = VPNLinkParser(credentialStore: credentialStore)
            let router = ImportPayloadRouter(
                importer: importer,
                subscriptionParser: SubscriptionContentParser(linkParser: importer)
            )
            let route: ImportPayloadRoute
            switch routeKind {
            case .paste:
                route = try await router.route(text: wireGuardConfiguration(), title: "Pasted WireGuard")
            case .file:
                route = try await router.route(data: Data(wireGuardConfiguration().utf8), title: "tunnel.conf")
            case .qrCode:
                route = try await QRCodeImageImportProcessor(
                    detector: NativeStaticQRCodeDetector(payload: wireGuardConfiguration()),
                    router: router
                ).process(data: Data([0x01]), title: "WireGuard QR")
            }

            guard case .single(let result) = route else {
                Issue.record("Expected one native profile for \(routeKind)")
                continue
            }
            #expect(try nativeProfile(from: result).protocolType == .wireGuard)
        }
    }

    @Test
    func parserRollsBackEverySecretWhenLaterCredentialStorageFails() async {
        let credentialStore = NativeTestCredentialStore(failOnStoreCall: 3)

        await #expect(throws: (any Error).self) {
            _ = try await NativeWireGuardConfigParser(credentialStore: credentialStore)
                .parse(wireGuardConfiguration())
        }
        #expect(await credentialStore.activeSecretCount() == 0)
        #expect(await credentialStore.deletedReferenceCount() == 2)
    }

    @Test
    func protocolModeMismatchAndCrossModeOptionsFailClosed() throws {
        let plainConfiguration = nativeProfileConfiguration(mode: .wireGuard)
        var mismatch = nativeProfile(mode: .wireGuard, configuration: plainConfiguration)
        mismatch.protocolType = .amneziaWG

        #expect(throws: NativeWireGuardRuntimeError.protocolConfigurationMismatch) {
            _ = try NativeWireGuardProfileValidator.validatedConfiguration(for: mismatch)
        }

        var protectedConfiguration = plainConfiguration
        protectedConfiguration.amnezia = AmneziaWGProfileParameters(junkPacketCount: 4)
        let plainWithAmneziaOptions = nativeProfile(mode: .wireGuard, configuration: protectedConfiguration)
        #expect(throws: NativeWireGuardRuntimeError.amneziaParametersForbidden) {
            _ = try NativeWireGuardProfileValidator.validatedConfiguration(for: plainWithAmneziaOptions)
        }

        let unprotectedAmnezia = nativeProfile(mode: .amneziaWG, configuration: plainConfiguration)
        #expect(throws: NativeWireGuardRuntimeError.amneziaParametersRequired) {
            _ = try NativeWireGuardProfileValidator.validatedConfiguration(for: unprotectedAmnezia)
        }
    }

    @Test
    func wireGuardRejectsAmneziaKeepaliveRange() throws {
        var configuration = nativeProfileConfiguration(mode: .wireGuard)
        configuration.peers[0].persistentKeepAlive = "15-30"
        let profile = nativeProfile(mode: .wireGuard, configuration: configuration)

        #expect(throws: NativeWireGuardRuntimeError.invalidPersistentKeepAlive) {
            _ = try NativeWireGuardProfileValidator.validatedConfiguration(for: profile)
        }
    }

    @Test
    func deterministicRevisionCanonicalizesOrderingWhitespaceAndTimestamps() throws {
        let profileID = UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!
        var firstConfiguration = nativeProfileConfiguration(mode: .wireGuard)
        firstConfiguration.interfaceAddresses = ["fd00::2/128", "10.8.0.2/32"]
        firstConfiguration.dnsServers = ["9.9.9.9", "1.1.1.1"]
        firstConfiguration.peers[0].allowedIPs = ["::/0", "0.0.0.0/0"]
        firstConfiguration.peers[0].excludedIPs = ["198.51.100.0/24", "192.0.2.0/24"]

        var secondConfiguration = firstConfiguration
        secondConfiguration.interfaceAddresses.reverse()
        secondConfiguration.dnsServers.reverse()
        secondConfiguration.peers.reverse()
        secondConfiguration.peers[1].allowedIPs.reverse()
        secondConfiguration.peers[1].excludedIPs.reverse()
        secondConfiguration.peers[1].publicKey = "  \(secondConfiguration.peers[1].publicKey)  "

        var first = nativeProfile(mode: .wireGuard, configuration: firstConfiguration, id: profileID)
        var second = nativeProfile(mode: .wireGuard, configuration: secondConfiguration, id: profileID)
        first.updatedAt = Date(timeIntervalSince1970: 100)
        second.updatedAt = Date(timeIntervalSince1970: 10_000)

        let mapper = NativeWireGuardProfileMapper(now: { Date(timeIntervalSince1970: 1_000) })
        let firstRecord = try mapper.record(from: first)
        let secondRecord = try mapper.record(from: second)

        #expect(firstRecord.recordRevision == secondRecord.recordRevision)
        #expect(firstRecord.peers.map(\.publicKey) == secondRecord.peers.map(\.publicKey))
        #expect(firstRecord.peers[0].allowedIPs == firstRecord.peers[0].allowedIPs.sorted())
        #expect(firstRecord.peers[0].excludedIPs == firstRecord.peers[0].excludedIPs.sorted())
    }

    @Test
    func fileStoreRejectsTamperedRevision() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("native-wg-tests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = FileNativeWireGuardProfileStore(fileURL: directory.appendingPathComponent("profiles.json"))
        let record = try NativeWireGuardProfileMapper(now: { Date(timeIntervalSince1970: 1_000) }).record(
            from: nativeProfile(mode: .wireGuard, configuration: nativeProfileConfiguration(mode: .wireGuard))
        )

        try await store.write(record)
        #expect(try await store.read(profileID: record.profileID) == record)

        var tampered = record
        tampered.recordRevision = "v1-tampered"
        await #expect(throws: NativeWireGuardRuntimeError.revisionMismatch) {
            try await store.write(tampered)
        }
    }

    @Test
    func publisherValidatesEveryCredentialBeforeWritingSecretFreeRecord() async throws {
        let credentialStore = NativeTestCredentialStore()
        let recordStore = NativeTestRecordStore()
        let profile = nativeProfile(mode: .wireGuard, configuration: nativeProfileConfiguration(mode: .wireGuard))
        try await credentialStore.insert(nativeKey(1), for: profile.credentialReference!)
        let publisher = NativeWireGuardProfilePublisher(store: recordStore, credentialStore: credentialStore)

        await #expect(throws: NativeWireGuardRuntimeError.credentialUnavailable) {
            _ = try await publisher.publish(profile)
        }
        #expect(await recordStore.allRecords().isEmpty)

        for reference in profile.credentialReferences {
            try await credentialStore.insert(nativeKey(4), for: reference)
        }
        let record = try await publisher.publish(profile)
        let encodedRecord = String(decoding: try JSONEncoder().encode(record), as: UTF8.self)
        #expect(encodedRecord.contains(nativeKey(1)) == false)
        #expect(encodedRecord.contains(nativeKey(4)) == false)
        #expect(record.credentialReferences == profile.credentialReferences)
    }

    @Test
    func nativeRuntimeDiagnosticChecksActualPublishedAWGRecordAndCredentialReferences() async throws {
        let credentialStore = NativeTestCredentialStore()
        let parsed = try await VPNLinkParser(credentialStore: credentialStore)
            .parse(amneziaWGConfiguration())
        let profile = try nativeProfile(from: parsed)
        let record = try NativeWireGuardProfileMapper().record(from: profile)
        let profileStore = NativeTestRecordStore()
        try await profileStore.write(record)
        let service = NativeTunnelRuntimeDiagnosticService(
            store: profileStore,
            credentialStore: credentialStore
        )

        let result = await service.inspect(profileID: profile.id)

        #expect(result.runtimeProfileExists)
        #expect(result.profileIDMatches)
        #expect(result.protocolName == NativeWireGuardMode.amneziaWG.rawValue)
        #expect(result.recordRevision == record.recordRevision)
        #expect(result.credentialReferencesValid)
        #expect(result.credentialsAvailable)
        #expect(result.awgFieldCompleteness)
        #expect(result.missingFields.isEmpty)
        #expect(result.interfaceAddressCount == 1)
        #expect(result.dnsServerCount == 1)
        #expect(result.mtu == 1_280)
        #expect(result.peerCount == 1)
        #expect(result.allowedIPCount == 1)
        #expect(result.endpointPresent)
        #expect(result.privateKeyPresent)
        #expect(result.presharedKeyPresent)
    }

    @Test
    func compositeSynchronizerRoutesNativeAndXrayProfilesExclusively() async throws {
        let xray = NativeRecordingSynchronizer(references: ["keychain://vpn.credentials/xray"])
        let native = NativeRecordingSynchronizer(references: ["keychain://vpn.credentials/native"])
        let composite = CompositeRuntimeProfileSynchronizer(xray: xray, native: native)
        let nativeProfile = nativeProfile(mode: .wireGuard, configuration: nativeProfileConfiguration(mode: .wireGuard))
        let xrayProfile = VPNProfile.draft(
            name: "VLESS",
            protocolType: .vless,
            serverAddress: "vless.example.invalid",
            port: 443,
            credentialReference: "keychain://vpn.credentials/vless",
            protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
            source: .manual
        )

        _ = try await composite.profileSaved(nativeProfile)
        _ = try await composite.profileSaved(xrayProfile)

        #expect(await xray.savedIDs() == [xrayProfile.id])
        #expect(await native.savedIDs() == [nativeProfile.id])
        #expect(await xray.deletedIDs().contains(nativeProfile.id))
        #expect(await native.deletedIDs().contains(xrayProfile.id))
        #expect(try await composite.credentialReferences() == [
            "keychain://vpn.credentials/xray",
            "keychain://vpn.credentials/native"
        ])
    }

    @Test
    func nativeConnectionServicePublishesStartsAndStops() async throws {
        let profile = nativeProfile(mode: .amneziaWG, configuration: nativeProfileConfiguration(mode: .amneziaWG))
        let credentialStore = NativeTestCredentialStore()
        try await seedCredentials(for: profile, in: credentialStore)
        let recordStore = NativeTestRecordStore()
        let publisher = NativeWireGuardProfilePublisher(store: recordStore, credentialStore: credentialStore)
        let systemManager = NativeTestSystemManager()
        let service = NativeWireGuardVPNConnectionService(publisher: publisher, systemManager: systemManager)
        let attemptID = UUID()

        try await service.connect(using: profile, attemptID: attemptID)
        #expect(await systemManager.startedRecords().map(\.profileID) == [profile.id])
        #expect(await systemManager.observedAttemptIDs() == [attemptID])
        #expect(await recordStore.allRecords().count == 1)
        await service.disconnect()
        #expect(await systemManager.stopCount() == 1)
    }

    @Test
    func runtimePublicationPrecedesStartAndProviderConfigurationMatchesRevision() async throws {
        let profile = nativeProfile(
            mode: .amneziaWG,
            configuration: nativeProfileConfiguration(mode: .amneziaWG)
        )
        let credentialStore = NativeTestCredentialStore()
        try await seedCredentials(for: profile, in: credentialStore)
        let recordStore = NativeTestRecordStore()
        let systemManager = NativeTestSystemManager(recordStore: recordStore)
        let service = NativeWireGuardVPNConnectionService(
            publisher: NativeWireGuardProfilePublisher(
                store: recordStore,
                credentialStore: credentialStore
            ),
            systemManager: systemManager
        )
        let attemptID = UUID()

        _ = try await service.connect(using: profile, attemptID: attemptID)

        let publishedRecord = try await recordStore.read(profileID: profile.id)
        #expect(await systemManager.publishedRecordObservedAtStart() == publishedRecord)
        let launchContract = try #require(await systemManager.observedLaunchContract())
        #expect(launchContract.mode == .amneziaWG)
        let expectedProviderConfiguration = try RuntimeProviderConfiguration(
            profileID: publishedRecord.profileID,
            sharedRecordRevision: publishedRecord.recordRevision
        )
        #expect(launchContract.providerConfiguration == expectedProviderConfiguration)
        #expect(Set(launchContract.providerConfiguration.propertyList.keys) == RuntimeProviderConfiguration.allowedKeys)
        #expect(await systemManager.observedAttemptIDs() == [attemptID])
    }

    @Test
    func failedNativeStartRestoresPreviousRuntimeRecordAndStopsPartialSession() async throws {
        let profileID = UUID()
        var previous = nativeProfile(
            mode: .wireGuard,
            configuration: nativeProfileConfiguration(mode: .wireGuard),
            id: profileID
        )
        previous.name = "Previous"
        var replacement = previous
        replacement.name = "Replacement"
        replacement.updatedAt = Date(timeIntervalSince1970: 5_000)
        if case .wireGuard(var configuration) = replacement.protocolConfiguration {
            configuration.mtu = 1_280
            replacement.protocolConfiguration = .wireGuard(configuration)
        }

        let credentialStore = NativeTestCredentialStore()
        try await seedCredentials(for: replacement, in: credentialStore)
        let recordStore = NativeTestRecordStore()
        let publisher = NativeWireGuardProfilePublisher(store: recordStore, credentialStore: credentialStore)
        let previousRecord = try await publisher.publish(previous)
        let systemManager = NativeTestSystemManager(shouldFail: true)
        let service = NativeWireGuardVPNConnectionService(publisher: publisher, systemManager: systemManager)
        let attemptID = UUID()

        await #expect(throws: NativeTestFailure.startFailed) {
            _ = try await service.connect(using: replacement, attemptID: attemptID)
        }

        #expect(try await recordStore.read(profileID: profileID) == previousRecord)
        #expect(await systemManager.stopCount() == 1)
    }

    @Test
    func productionManagerSwitchesFromNativeToFallbackWithoutOverlappingBackends() async throws {
        let nativeProfile = nativeProfile(mode: .wireGuard, configuration: nativeProfileConfiguration(mode: .wireGuard))
        let credentialStore = NativeTestCredentialStore()
        try await seedCredentials(for: nativeProfile, in: credentialStore)
        let recordStore = NativeTestRecordStore()
        let systemManager = NativeTestSystemManager()
        let service = NativeWireGuardVPNConnectionService(
            publisher: NativeWireGuardProfilePublisher(store: recordStore, credentialStore: credentialStore),
            systemManager: systemManager
        )
        let fallback = NativeTestFallbackConnectionManager()
        let manager = ProductionVPNConnectionManager(nativeService: service, fallback: fallback)

        _ = try await manager.connect(using: nativeProfile)
        _ = try await manager.connect(using: fallbackProfile())

        #expect(await systemManager.stopCount() == 1)
        #expect(await fallback.connectCount() == 1)
        #expect(await manager.currentState() == .connected)
        await manager.disconnect()
        #expect(await fallback.disconnectCount() == 1)
        #expect(await manager.currentState() == .disconnected)
    }

    @Test
    func providerDisconnectErrorIsNotCollapsedIntoGenericNativeFailure() async {
        let descriptor = NativeTunnelDisconnectErrorDescriptor(
            domain: NativeTunnelDisconnectErrorMapper.providerErrorDomain,
            code: NativeTunnelProviderFailure.credentialUnavailable.rawValue
        )
        let fetcher = NativeDisconnectDescriptorFetcher(descriptor: descriptor)
        let resolver = NativeTunnelDisconnectFailureResolver {
            await fetcher.fetch()
        }

        let mapped = await resolver.connectionError(fallback: .connectionFailed)

        #expect(mapped == .providerFailure(.credentialUnavailable))
        #expect(mapped.errorDescription == "Secure WireGuard credential is unavailable.")
        #expect(await fetcher.fetchCount() == 1)
    }

    @Test
    func localSDKDecodesConnectionErrorCodeTwelveAsPluginFailed() throws {
        let decoded = try #require(NEVPNConnectionError(rawValue: 12))
        let descriptor = NativeTunnelDisconnectErrorDescriptor(
            domain: NEVPNConnectionErrorDomain,
            code: 12,
            diagnosticError: TunnelDiagnosticError(
                error: NSError(
                    domain: NEVPNConnectionErrorDomain,
                    code: 12,
                    userInfo: [NSLocalizedDescriptionKey: "The VPN plugin died unexpectedly."]
                )
            )
        )

        #expect(decoded == .pluginFailed)
        #expect(descriptor.neConnectionErrorCase == "pluginFailed")
        #expect(NativeTunnelNEVPNConnectionErrorDecoder.terminationEvidence(
            domain: descriptor.domain,
            code: descriptor.code
        ) == "NEVPNConnectionError.pluginFailed")
        #expect(NativeTunnelDisconnectErrorMapper.connectionError(
            for: descriptor,
            fallback: .connectionFailed
        ) == .connectionFailed)
    }

    @Test
    func everySanitizedProviderFailureCodeSurvivesDisconnectMapping() {
        for failure in NativeTunnelProviderFailure.allCases {
            let descriptor = NativeTunnelDisconnectErrorDescriptor(
                domain: NativeTunnelDisconnectErrorMapper.providerErrorDomain,
                code: failure.rawValue
            )

            #expect(NativeTunnelDisconnectErrorMapper.connectionError(
                for: descriptor,
                fallback: .connectionFailed
            ) == .providerFailure(failure))
        }

        #expect(NativeTunnelDisconnectErrorMapper.connectionError(
            for: NativeTunnelDisconnectErrorDescriptor(domain: "unknown", code: 1),
            fallback: .connectionFailed
        ) == .connectionFailed)
    }

    @Test
    func persistedProviderFailureRecoversTypedReasonWhenSystemDisconnectErrorIsMissing() {
        #expect(
            NativeTunnelPersistedFailureMapper.connectionError(for: .sharedCredentialUnavailable)
                == .providerFailure(.credentialUnavailable)
        )
        #expect(
            NativeTunnelPersistedFailureMapper.connectionError(for: .networkSettingsRejected)
                == .providerFailure(.networkSettingsRejected)
        )
        #expect(
            NativeTunnelPersistedFailureMapper.connectionError(for: .nativeBackendStartupFailed)
                == .providerFailure(.backendStartFailed)
        )
        #expect(
            NativeTunnelPersistedFailureMapper.connectionError(for: .adapterStartTimeout)
                == .providerFailure(.adapterStartTimeout)
        )
        #expect(NativeTunnelPersistedFailureMapper.connectionError(for: .unknown) == nil)
    }

    @Test
    func productionApplicationCompositionSelectsNativeRouterForWireGuardProtocols() {
        let manager = ProductionVPNConnectionComposition.makeConnectionManager()
        let wireGuard = nativeProfile(
            mode: .wireGuard,
            configuration: nativeProfileConfiguration(mode: .wireGuard)
        )
        let amneziaWG = nativeProfile(
            mode: .amneziaWG,
            configuration: nativeProfileConfiguration(mode: .amneziaWG)
        )

        #expect(manager.routesTrafficThroughProductionCore(using: wireGuard))
        #expect(manager.routesTrafficThroughProductionCore(using: amneziaWG))
        #expect(manager.routesTrafficThroughProductionCore(using: fallbackProfile()) == false)
    }

    @Test
    @MainActor
    func productionCompositionNormalMainButtonStartsSelectedWireGuardProfile() async throws {
        let harness = try await connectedDashboard(mode: .wireGuard)

        #expect(harness.viewModel.selectedProfile?.id == harness.profile.id)
        #expect(harness.viewModel.activeProfileID == harness.profile.id)
        #expect(harness.viewModel.effectiveProtocol == .wireGuard)
        #expect(harness.viewModel.connectionState == .connected)
        #expect(await harness.manager.currentState() == .connected)
        #expect(await harness.systemManager.startedRecords().map(\.profileID) == [harness.profile.id])
        #expect(await harness.fallback.connectCount() == 0)
    }

    @Test
    @MainActor
    func productionCompositionNormalMainButtonStartsSelectedAmneziaWGProfile() async throws {
        let harness = try await connectedDashboard(mode: .amneziaWG)

        #expect(harness.viewModel.selectedProfile?.id == harness.profile.id)
        #expect(harness.viewModel.activeProfileID == harness.profile.id)
        #expect(harness.viewModel.effectiveProtocol == .amneziaWG)
        #expect(harness.viewModel.connectionState == .connected)
        #expect(await harness.manager.currentState() == .connected)
        #expect(await harness.systemManager.startedRecords().map(\.profileID) == [harness.profile.id])
        #expect(await harness.fallback.connectCount() == 0)
    }

    @Test
    @MainActor
    func productionNativeSelectionDoesNotAdvertiseDemoMode() async throws {
        let harness = try await connectedDashboard(mode: .amneziaWG)

        #expect(harness.viewModel.showsDemoModeNotice == false)
    }

    @Test
    @MainActor
    func mockManagerSelectionContinuesToAdvertiseDemoMode() async throws {
        let profile = nativeProfile(
            mode: .amneziaWG,
            configuration: nativeProfileConfiguration(mode: .amneziaWG)
        )
        let repository = InMemoryVPNProfileRepository()
        try await repository.save(profile)
        let activeProfileStore = NativeTestActiveProfileStore()
        await activeProfileStore.saveActiveProfileID(profile.id)
        let viewModel = VPNDashboardViewModel(
            connectionManager: MockVPNConnectionManager(),
            profileRepository: repository,
            credentialStore: NativeTestCredentialStore(),
            activeProfileStore: activeProfileStore
        )

        await viewModel.loadInitialData()

        #expect(viewModel.showsDemoModeNotice)
    }

    @Test
    @MainActor
    func nativeSessionStatusPropagatesThroughProductionManagerToDashboard() async throws {
        let harness = try await connectedDashboard(mode: .wireGuard)
        #expect(harness.viewModel.connectionState == .connected)

        await harness.systemManager.emitBufferedStateWithoutChangingAuthoritativeState(.connecting)
        for _ in 0..<50 {
            await Task.yield()
        }

        #expect(await harness.manager.currentState() == .connected)
        #expect(harness.viewModel.connectionState == .connected)

        await harness.systemManager.emit(.disconnected)
        await waitForDashboardState(.disconnected, viewModel: harness.viewModel)

        #expect(await harness.manager.currentState() == .disconnected)
        #expect(harness.viewModel.connectionState == .disconnected)
    }

    @Test
    @MainActor
    func dashboardNormalConnectDoesNotSynthesizeConnectedState() async throws {
        let profile = nativeProfile(
            mode: .wireGuard,
            configuration: nativeProfileConfiguration(mode: .wireGuard)
        )
        let repository = InMemoryVPNProfileRepository()
        try await repository.save(profile)
        let activeProfileStore = NativeTestActiveProfileStore()
        await activeProfileStore.saveActiveProfileID(profile.id)
        let connectionManager = NativeNeverConnectedConnectionManager()
        let viewModel = VPNDashboardViewModel(
            connectionManager: connectionManager,
            profileRepository: repository,
            credentialStore: NativeTestCredentialStore(),
            activeProfileStore: activeProfileStore
        )

        await viewModel.loadInitialData()
        await viewModel.toggleConnection()

        #expect(await connectionManager.connectedProfileIDs() == [profile.id])
        #expect(viewModel.connectionState == .failed)
        #expect(viewModel.connectionState != .connected)
    }

    @Test
    @MainActor
    func dashboardSaveRollsBackDurableProfileWhenRuntimePublicationFails() async throws {
        let repository = InMemoryVPNProfileRepository()
        let synchronizer = NativeSelectiveFailingSynchronizer(failSave: true)
        let viewModel = VPNDashboardViewModel(
            profileRepository: repository,
            credentialStore: NativeTestCredentialStore(),
            activeProfileStore: NativeTestActiveProfileStore(),
            runtimeProfileSynchronizer: synchronizer
        )
        let profile = nativeProfile(mode: .wireGuard, configuration: nativeProfileConfiguration(mode: .wireGuard))

        #expect(await viewModel.saveProfileDraft(profile) == false)
        #expect(try await repository.profiles().isEmpty)
        #expect(viewModel.profileSaveMessage?.isEmpty == false)
    }

    @Test
    @MainActor
    func dashboardEnableAndRenameRestorePreviousProfileWhenRuntimePublicationFails() async throws {
        let repository = InMemoryVPNProfileRepository()
        var original = nativeProfile(mode: .wireGuard, configuration: nativeProfileConfiguration(mode: .wireGuard))
        original.isEnabled = false
        try await repository.save(original)
        let synchronizer = NativeSelectiveFailingSynchronizer(failSave: true)
        let viewModel = VPNDashboardViewModel(
            profileRepository: repository,
            credentialStore: NativeTestCredentialStore(),
            activeProfileStore: NativeTestActiveProfileStore(),
            runtimeProfileSynchronizer: synchronizer
        )

        await viewModel.setProfileEnabled(original, isEnabled: true)
        #expect(try #require(await repository.profiles().first).isEnabled == false)

        var enabledProfile = original
        enabledProfile.isEnabled = true
        try await repository.save(enabledProfile)
        await viewModel.renameProfile(enabledProfile, to: "Must roll back")
        #expect(try #require(await repository.profiles().first).name == enabledProfile.name)
    }

    @Test
    @MainActor
    func dashboardDeleteRestoresProfileWhenRuntimeDeletionFails() async throws {
        let repository = InMemoryVPNProfileRepository()
        let profile = nativeProfile(mode: .wireGuard, configuration: nativeProfileConfiguration(mode: .wireGuard))
        try await repository.save(profile)
        let synchronizer = NativeSelectiveFailingSynchronizer(failDelete: true)
        let viewModel = VPNDashboardViewModel(
            profileRepository: repository,
            credentialStore: NativeTestCredentialStore(),
            activeProfileStore: NativeTestActiveProfileStore(),
            runtimeProfileSynchronizer: synchronizer
        )

        await viewModel.deleteProfile(profile)

        let restored = try #require(await repository.profiles().first)
        #expect(restored.id == profile.id)
        #expect(restored.name == profile.name)
        #expect(restored.protocolConfiguration == profile.protocolConfiguration)
        #expect(restored.credentialReferences == profile.credentialReferences)
        #expect(viewModel.errorMessage?.isEmpty == false)
    }

    @MainActor
    private func connectedDashboard(mode: NativeWireGuardMode) async throws -> NativeDashboardHarness {
        let profile = nativeProfile(mode: mode, configuration: nativeProfileConfiguration(mode: mode))
        let credentialStore = NativeTestCredentialStore()
        try await seedCredentials(for: profile, in: credentialStore)
        let recordStore = NativeTestRecordStore()
        let systemManager = NativeTestSystemManager(recordStore: recordStore)
        let service = NativeWireGuardVPNConnectionService(
            publisher: NativeWireGuardProfilePublisher(
                store: recordStore,
                credentialStore: credentialStore
            ),
            systemManager: systemManager
        )
        let fallback = NativeTestFallbackConnectionManager()
        let manager = ProductionVPNConnectionComposition.makeConnectionManager(
            nativeService: service,
            fallback: fallback
        )
        let repository = InMemoryVPNProfileRepository()
        try await repository.save(profile)
        let activeProfileStore = NativeTestActiveProfileStore()
        await activeProfileStore.saveActiveProfileID(profile.id)
        let viewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: repository,
            credentialStore: credentialStore,
            activeProfileStore: activeProfileStore
        )

        await viewModel.loadInitialData()
        await viewModel.toggleConnection()

        return NativeDashboardHarness(
            profile: profile,
            viewModel: viewModel,
            manager: manager,
            systemManager: systemManager,
            fallback: fallback
        )
    }

    @MainActor
    private func waitForDashboardState(
        _ expectedState: VPNConnectionState,
        viewModel: VPNDashboardViewModel
    ) async {
        for _ in 0..<200 {
            if viewModel.connectionState == expectedState {
                return
            }
            await Task.yield()
        }
    }
}

private struct NativeDashboardHarness {
    let profile: VPNProfile
    let viewModel: VPNDashboardViewModel
    let manager: ProductionVPNConnectionManager
    let systemManager: NativeTestSystemManager
    let fallback: NativeTestFallbackConnectionManager
}

private enum NativeImportRouteKind: CaseIterable, CustomStringConvertible {
    case paste
    case file
    case qrCode

    var description: String {
        switch self {
        case .paste: "paste"
        case .file: "file"
        case .qrCode: "QR code"
        }
    }
}

private enum NativeTestFailure: Error, Equatable {
    case credentialStoreFailed
    case startFailed
}

private actor NativeDisconnectDescriptorFetcher {
    private let descriptor: NativeTunnelDisconnectErrorDescriptor?
    private var count = 0

    init(descriptor: NativeTunnelDisconnectErrorDescriptor?) {
        self.descriptor = descriptor
    }

    func fetch() -> NativeTunnelDisconnectErrorDescriptor? {
        count += 1
        return descriptor
    }

    func fetchCount() -> Int {
        count
    }
}

private actor NativeTestCredentialStore: CredentialStoring {
    private var secrets: [String: String] = [:]
    private var storeCallCount = 0
    private var deleteCount = 0
    private let failOnStoreCall: Int?

    init(failOnStoreCall: Int? = nil) {
        self.failOnStoreCall = failOnStoreCall
    }

    func store(_ secret: String, label: String) async throws -> String {
        storeCallCount += 1
        if storeCallCount == failOnStoreCall {
            throw NativeTestFailure.credentialStoreFailed
        }
        let reference = "keychain://vpn.credentials/native-test-\(storeCallCount)"
        secrets[reference] = secret
        return reference
    }

    func secret(for reference: String) async throws -> String? {
        secrets[reference]
    }

    func delete(reference: String) async throws {
        if secrets.removeValue(forKey: reference) != nil {
            deleteCount += 1
        }
    }

    func insert(_ secret: String, for reference: String) async throws {
        secrets[reference] = secret
    }

    func activeSecretCount() -> Int {
        secrets.count
    }

    func deletedReferenceCount() -> Int {
        deleteCount
    }
}

private actor NativeTestRecordStore: NativeWireGuardProfileStoring {
    private var recordsByID: [UUID: NativeWireGuardProfileRecord] = [:]

    func write(_ record: NativeWireGuardProfileRecord) async throws {
        recordsByID[record.profileID] = record
    }

    func read(profileID: UUID) async throws -> NativeWireGuardProfileRecord {
        guard let record = recordsByID[profileID] else {
            throw NativeWireGuardRuntimeError.recordNotFound
        }
        return record
    }

    func records() async throws -> [NativeWireGuardProfileRecord] {
        Array(recordsByID.values)
    }

    func delete(profileID: UUID) async throws {
        recordsByID[profileID] = nil
    }

    func allRecords() -> [NativeWireGuardProfileRecord] {
        Array(recordsByID.values)
    }
}

private actor NativeTestActiveProfileStore: ActiveProfileStoring {
    private var profileID: UUID?

    func activeProfileID() async -> UUID? {
        profileID
    }

    func saveActiveProfileID(_ id: UUID?) async {
        profileID = id
    }
}

private actor NativeRecordingSynchronizer: RuntimeProfileSynchronizing {
    private var saved: [UUID] = []
    private var deleted: [UUID] = []
    private let references: Set<String>

    init(references: Set<String>) {
        self.references = references
    }

    func profileSaved(_ profile: VPNProfile) async throws -> RuntimeProfileSynchronizationSummary {
        saved.append(profile.id)
        return RuntimeProfileSynchronizationSummary(publishedProfileIDs: [profile.id], omissions: [])
    }

    func profileDeleted(id: UUID) async throws {
        deleted.append(id)
    }

    func credentialReferences() async throws -> Set<String> {
        references
    }

    func savedIDs() -> [UUID] {
        saved
    }

    func deletedIDs() -> [UUID] {
        deleted
    }
}

private actor NativeSelectiveFailingSynchronizer: RuntimeProfileSynchronizing {
    private let failSave: Bool
    private let failDelete: Bool

    init(failSave: Bool = false, failDelete: Bool = false) {
        self.failSave = failSave
        self.failDelete = failDelete
    }

    func profileSaved(_ profile: VPNProfile) async throws -> RuntimeProfileSynchronizationSummary {
        if failSave {
            throw NativeTestFailure.startFailed
        }
        return RuntimeProfileSynchronizationSummary(publishedProfileIDs: [profile.id], omissions: [])
    }

    func profileDeleted(id: UUID) async throws {
        if failDelete {
            throw NativeTestFailure.startFailed
        }
    }

    func credentialReferences() async throws -> Set<String> {
        []
    }
}

private actor NativeTestSystemManager: NativeTunnelSystemManaging {
    private var records: [NativeWireGuardProfileRecord] = []
    private var stops = 0
    private let shouldFail: Bool
    private let recordStore: NativeTestRecordStore?
    private var state: VPNConnectionState = .disconnected
    private var continuations: [UUID: AsyncStream<VPNConnectionState>.Continuation] = [:]
    private var recordVisibleAtStart: NativeWireGuardProfileRecord?
    private var launchContract: NativeTunnelLaunchContract?
    private var attemptIDs: [UUID] = []

    init(shouldFail: Bool = false, recordStore: NativeTestRecordStore? = nil) {
        self.shouldFail = shouldFail
        self.recordStore = recordStore
    }

    func currentState() async -> VPNConnectionState {
        state
    }

    func stateUpdates() async -> AsyncStream<VPNConnectionState> {
        let id = UUID()
        return AsyncStream { continuation in
            continuations[id] = continuation
            continuation.onTermination = { _ in
                Task { await self.removeContinuation(id: id) }
            }
        }
    }

    func configureAndStart(
        record: NativeWireGuardProfileRecord,
        displayName: String,
        attemptID: UUID
    ) async throws {
        attemptIDs.append(attemptID)
        publish(.connecting)
        records.append(record)
        launchContract = try NativeTunnelLaunchContract(record: record)
        if let recordStore {
            recordVisibleAtStart = try await recordStore.read(profileID: record.profileID)
        }
        if shouldFail {
            publish(.failed)
            throw NativeTestFailure.startFailed
        }
        publish(.connected)
    }

    func stop() async {
        stops += 1
        publish(.disconnecting)
        publish(.disconnected)
    }

    func startedRecords() -> [NativeWireGuardProfileRecord] {
        records
    }

    func stopCount() -> Int {
        stops
    }

    func publishedRecordObservedAtStart() -> NativeWireGuardProfileRecord? {
        recordVisibleAtStart
    }

    func observedLaunchContract() -> NativeTunnelLaunchContract? {
        launchContract
    }

    func observedAttemptIDs() -> [UUID] {
        attemptIDs
    }

    func emit(_ newState: VPNConnectionState) {
        publish(newState)
    }

    func emitBufferedStateWithoutChangingAuthoritativeState(_ bufferedState: VPNConnectionState) {
        continuations.values.forEach { $0.yield(bufferedState) }
    }

    private func publish(_ newState: VPNConnectionState) {
        state = newState
        continuations.values.forEach { $0.yield(newState) }
    }

    private func removeContinuation(id: UUID) {
        continuations[id] = nil
    }
}

private actor NativeTestFallbackConnectionManager: VPNConnectionManaging {
    private var state: VPNConnectionState = .disconnected
    private var connects = 0
    private var disconnects = 0

    func currentState() async -> VPNConnectionState {
        state
    }

    nonisolated func stateUpdates() -> AsyncStream<VPNConnectionState> {
        AsyncStream { continuation in
            continuation.finish()
        }
    }

    func connect(using profile: VPNProfile) async throws {
        connects += 1
        state = .connected
    }

    func disconnect() async {
        disconnects += 1
        state = .disconnected
    }

    func connectCount() -> Int {
        connects
    }

    func disconnectCount() -> Int {
        disconnects
    }
}

private actor NativeNeverConnectedConnectionManager: VPNConnectionManaging {
    private var connectedIDs: [UUID] = []

    func currentState() async -> VPNConnectionState {
        connectedIDs.isEmpty ? .disconnected : .connecting
    }

    nonisolated func stateUpdates() -> AsyncStream<VPNConnectionState> {
        AsyncStream { continuation in
            continuation.finish()
        }
    }

    func connect(using profile: VPNProfile) async throws {
        connectedIDs.append(profile.id)
    }

    func disconnect() async {}

    func connectedProfileIDs() -> [UUID] {
        connectedIDs
    }
}

private struct NativeStaticQRCodeDetector: QRCodeImageDetecting {
    let payload: String

    func detectPayloads(in data: Data) async throws -> [String] {
        [payload]
    }
}

private func nativeProfile(from result: VPNImportResult) throws -> VPNProfile {
    guard case .profile(let profile) = result.kind else {
        throw VPNImportError.invalidPayload("Expected a profile import result.")
    }
    return profile
}

private func nativeKey(_ byte: UInt8) -> String {
    Data(repeating: byte, count: 32).base64EncodedString()
}

private func wireGuardConfiguration() -> String {
    """
    [Interface]
    PrivateKey = \(nativeKey(1))
    Address = 10.8.0.2/32, fd00::2/128
    DNS = 1.1.1.1, corp.example.invalid
    ListenPort = 51820
    MTU = 1380

    [Peer]
    PublicKey = \(nativeKey(2))
    PresharedKey = \(nativeKey(4))
    AllowedIPs = 0.0.0.0/0, ::/0
    ExcludedIPs = 192.0.2.0/24
    Endpoint = wg.example.invalid:51820
    PersistentKeepalive = 25

    [Peer]
    PublicKey = \(nativeKey(3))
    PresharedKey = \(nativeKey(5))
    AllowedIPs = 10.20.0.0/16
    """
}

private func amneziaWGConfiguration() -> String {
    """
    [Interface]
    PrivateKey = \(nativeKey(6))
    Address = 10.9.0.2/32
    DNS = 9.9.9.9
    MTU = 1280
    Jc = 4
    Jmin = 40
    Jmax = 80
    S1 = 11
    S2 = 22
    S3 = 33
    S4 = 44
    H1 = 123456789
    H2 = 987654321
    H3 = 192837465
    H4 = 564738291
    HeaderProtectionKey = \(nativeKey(7))

    [Peer]
    PublicKey = \(nativeKey(8))
    PresharedKey = \(nativeKey(9))
    AllowedIPs = 0.0.0.0/0
    Endpoint = awg.example.invalid:443
    PersistentKeepalive = 15-30
    """
}

private func nativeProfileConfiguration(mode: NativeWireGuardMode) -> WireGuardProfileConfiguration {
    WireGuardProfileConfiguration(
        interfaceAddresses: ["10.8.0.2/32", "fd00::2/128"],
        dnsServers: ["1.1.1.1"],
        dnsSearchDomains: ["corp.example.invalid"],
        listenPort: 51_820,
        mtu: 1_380,
        peers: [
            WireGuardPeerProfileConfiguration(
                publicKey: nativeKey(2),
                presharedKeyReference: "keychain://vpn.credentials/native-psk-1",
                allowedIPs: ["0.0.0.0/0", "::/0"],
                excludedIPs: ["192.0.2.0/24"],
                endpoint: WireGuardEndpointProfileConfiguration(host: "wg.example.invalid", port: 51_820),
                persistentKeepAlive: mode == .amneziaWG ? "15-30" : "25"
            ),
            WireGuardPeerProfileConfiguration(
                publicKey: nativeKey(3),
                presharedKeyReference: "keychain://vpn.credentials/native-psk-2",
                allowedIPs: ["10.20.0.0/16"]
            )
        ],
        headerProtectionKeyReference: mode == .amneziaWG
            ? "keychain://vpn.credentials/native-header-key"
            : nil,
        amnezia: mode == .amneziaWG
            ? AmneziaWGProfileParameters(junkPacketCount: 4, junkPacketMinSize: 40, junkPacketMaxSize: 80)
            : nil
    )
}

private func nativeProfile(
    mode: NativeWireGuardMode,
    configuration: WireGuardProfileConfiguration,
    id: UUID = UUID()
) -> VPNProfile {
    let protocolType: VPNProtocol = mode == .wireGuard ? .wireGuard : .amneziaWG
    let protocolConfiguration: VPNProtocolConfiguration = mode == .wireGuard
        ? .wireGuard(configuration)
        : .amneziaWG(configuration)
    var profile = VPNProfile.draft(
        name: protocolType.displayName,
        protocolType: protocolType,
        serverAddress: "wg.example.invalid",
        port: 51_820,
        credentialReference: "keychain://vpn.credentials/native-private-key",
        transportSettings: VPNTransportSettings(network: "native"),
        protocolConfiguration: protocolConfiguration,
        source: .manual
    )
    profile.id = id
    return profile
}

private func seedCredentials(
    for profile: VPNProfile,
    in credentialStore: NativeTestCredentialStore
) async throws {
    for (index, reference) in profile.credentialReferences.sorted().enumerated() {
        try await credentialStore.insert(nativeKey(UInt8(index + 20)), for: reference)
    }
}

private func fallbackProfile() -> VPNProfile {
    VPNProfile.draft(
        name: "Fallback",
        protocolType: .ikev2,
        serverAddress: "ikev2.example.invalid",
        port: 500,
        credentialReference: "keychain://vpn.credentials/fallback",
        protocolConfiguration: .ikev2(
            IKEv2ProfileConfiguration(
                remoteIdentifier: nil,
                localIdentifier: nil,
                authenticationMethod: nil
            )
        ),
        source: .manual
    )
}
