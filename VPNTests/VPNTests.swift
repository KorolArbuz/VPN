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
    @MainActor
    func subscriptionPreviewAndSaveCreatesProfiles() async {
        let viewModel = VPNDashboardViewModel(
            profileRepository: InMemoryVPNProfileRepository(),
            subscriptionRepository: InMemorySubscriptionRepository(),
            subscriptionUpdater: URLSessionSubscriptionUpdater(client: StubSubscriptionClient(result: .success(Data("trojan://sample-password@sub.example.invalid:443#Sub".utf8)))),
            credentialStore: InMemoryCredentialStore(),
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
        let viewModel = VPNDashboardViewModel(
            profileRepository: repository,
            subscriptionRepository: subscriptionRepository,
            subscriptionUpdater: URLSessionSubscriptionUpdater(client: StubSubscriptionClient(result: .success(Data("vless://sample-user-id@dup.example.invalid:443#Dup".utf8)))),
            credentialStore: InMemoryCredentialStore(),
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
        let detector = DelayedQRCodeDetector()
        let coordinator = QRImageImportCoordinator(processor: QRCodeImageImportProcessor(
            detector: detector,
            router: ImportPayloadRouter(
                importer: VPNLinkParser(credentialStore: InMemoryCredentialStore()),
                subscriptionParser: SubscriptionContentParser(linkParser: VPNLinkParser(credentialStore: InMemoryCredentialStore()))
            )
        ))

        async let first: ImportPayloadRoute? = coordinator.start(data: Data("first".utf8), title: "First")
        async let second: ImportPayloadRoute? = coordinator.start(data: Data("second".utf8), title: "Second")
        let results = await (first, second)

        #expect(results.0 == nil || results.1 != nil)
        #expect(await detector.callCount >= 1)
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
        let viewModel = VPNDashboardViewModel(connectionManager: manager)

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
        let activeStore = InMemoryActiveProfileStore()
        let firstViewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: repository,
            activeProfileStore: activeStore
        )

        await firstViewModel.loadInitialData()
        await firstViewModel.connect()

        let recreatedViewModel = VPNDashboardViewModel(
            connectionManager: manager,
            profileRepository: repository,
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
        let viewModel = VPNDashboardViewModel(connectionManager: manager)

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
        let viewModel = VPNDashboardViewModel(connectionManager: manager)

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
        let keys = ["app.name", "settings.language", "home.status.connected", "profiles.add", "qr.camera_permission_required"]

        for key in keys {
            let localization = try #require(strings[key] as? [String: Any])
            let localizations = try #require(localization["localizations"] as? [String: Any])
            #expect(localizations["en"] != nil)
        }
    }

    @Test
    func keyRussianLocalizationsExist() throws {
        let strings = try localizableStrings()
        let keys = ["app.name", "settings.language", "home.status.connected", "profiles.add", "qr.camera_permission_required"]

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
        #expect(configuration.credentialReference == "test-reference")
    }

    @Test
    func vlessRealityRequiresFields() {
        var profile = makeCompleteProfile(name: "Reality")
        profile.transportSettings.security = "reality"
        profile.tlsSettings = VPNTLSSettings(isEnabled: true, serverName: "site.example.invalid", publicKeyReference: "public-key-ref", shortID: nil)

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
        try? await Task.sleep(for: .milliseconds(10))

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
        try? await Task.sleep(for: .milliseconds(10))
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

        try? await Task.sleep(for: .milliseconds(20))
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
        let stream = await coordinator.events
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
            credentialReference: "test-reference",
            protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
            source: .subscription
        )
        return merger.makeSubscriptionProfile(profile, subscriptionID: subscriptionID, now: Date())
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

private actor DelayedQRCodeDetector: QRCodeImageDetecting {
    private(set) var callCount = 0

    func detectPayloads(in data: Data) async throws -> [String] {
        callCount += 1
        try await Task.sleep(for: .milliseconds(data == Data("first".utf8) ? 100 : 10))
        return ["vless://sample-user-id@delayed.example.invalid:443#Delayed"]
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

    func store(_ secret: String, label: String) async throws -> String {
        storeCount += 1
        let reference = "recording://credential/\(storeCount)"
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

private actor RecordingConnectionManager: VPNConnectionManaging {
    private var state: VPNConnectionState = .disconnected
    private var continuations: [UUID: AsyncStream<VPNConnectionState>.Continuation] = [:]
    private(set) var connectCount = 0
    private(set) var disconnectCount = 0

    func currentState() async -> VPNConnectionState {
        state
    }

    func stateUpdates() -> AsyncStream<VPNConnectionState> {
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
