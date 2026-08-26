//
//  SharedKeychainTests.swift
//  VPNTests
//
//  Phase F2B-K1: shared Keychain boundary and DEBUG sentinel IPC tests.
//

import Foundation
import Security
import Testing
@testable import VPN

struct SharedKeychainAccessGroupTests {
    private let accessGroup = "TEAMID.su.24kvn.app.shared"
    private let service = "test.credentials"
    private let account = "account-1"

    @Test
    func accessGroupValidatorRejectsSourceMacroAndAcceptsResolvedGroup() throws {
        #expect(try SharedKeychainAccessGroupValidator.validate(accessGroup) == accessGroup)
        #expect(try SharedKeychainAccessGroupValidator.validate(" \(accessGroup)\n") == accessGroup)
        do {
            _ = try SharedKeychainAccessGroupValidator.validate("$(AppIdentifierPrefix)su.24kvn.app.shared")
            Issue.record("Expected invalid access group")
        } catch CredentialStoreError.invalidAccessGroup {
            // Expected.
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test
    func validCompiledInfoPlistGroupResolves() throws {
        let provider = InfoPlistSharedKeychainAccessGroupProvider {
            accessGroup
        }

        #expect(try provider.sharedKeychainAccessGroup() == accessGroup)
    }

    @Test
    func missingInfoPlistKeyIsRejected() throws {
        let provider = InfoPlistSharedKeychainAccessGroupProvider {
            nil
        }

        #expect(throws: CredentialStoreError.accessGroupUnavailable) {
            _ = try provider.sharedKeychainAccessGroup()
        }
    }

    @Test
    func nonStringInfoPlistValueIsRejected() throws {
        let provider = InfoPlistSharedKeychainAccessGroupProvider {
            42
        }

        #expect(throws: CredentialStoreError.invalidAccessGroup) {
            _ = try provider.sharedKeychainAccessGroup()
        }
    }

    @Test(arguments: [
        "",
        "   ",
        "$(AppIdentifierPrefix)su.24kvn.app.shared",
        "TEAMID.example.shared",
        "su.24kvn.app.shared"
    ])
    func invalidInfoPlistValuesAreRejected(value: String) throws {
        let provider = InfoPlistSharedKeychainAccessGroupProvider {
            value
        }

        #expect(throws: CredentialStoreError.invalidAccessGroup) {
            _ = try provider.sharedKeychainAccessGroup()
        }
    }

    @Test
    func appAndExtensionFixtureResolveIdenticalExpandedGroup() throws {
        let appProvider = InfoPlistSharedKeychainAccessGroupProvider {
            accessGroup
        }
        let extensionResolved = try SharedKeychainAccessGroupValidator.validate(accessGroup)

        #expect(try appProvider.sharedKeychainAccessGroup() == extensionResolved)
    }

    @Test
    func hostedAppAndEmbeddedExtensionResolveIdenticalCompiledAccessGroup() throws {
        let appGroup = try #require(
            Bundle.main.object(forInfoDictionaryKey: SharedKeychainAccessGroupValidator.infoPlistKey) as? String
        )
        let plugInsURL = try #require(Bundle.main.builtInPlugInsURL)
        let extensionURL = plugInsURL.appendingPathComponent("PacketTunnelExtension.appex", isDirectory: true)
        let extensionBundle = try #require(Bundle(url: extensionURL))
        let extensionGroup = try #require(
            extensionBundle.object(forInfoDictionaryKey: SharedKeychainAccessGroupValidator.infoPlistKey) as? String
        )

        #expect(try SharedKeychainAccessGroupValidator.validate(appGroup) == appGroup)
        #expect(try SharedKeychainAccessGroupValidator.validate(extensionGroup) == extensionGroup)
        #expect(appGroup == extensionGroup)
    }

    @Test
    func explicitAccessGroupIsPresentOnAddReadUpdateDeleteQueries() {
        let builder = KeychainCredentialQueryBuilder()
        let descriptor = KeychainItemDescriptor(service: service, account: account, accessGroup: accessGroup)
        let payload = KeychainItemPayload(data: Data("secret".utf8), label: "label")

        let add = builder.addQuery(descriptor: descriptor, payload: payload)
        let copy = builder.copyQuery(descriptor: descriptor)
        let update = builder.updateQuery(descriptor: descriptor)
        let delete = builder.deleteQuery(descriptor: descriptor)

        #expect(add[kSecAttrAccessGroup as String] as? String == accessGroup)
        #expect(copy[kSecAttrAccessGroup as String] as? String == accessGroup)
        #expect(update[kSecAttrAccessGroup as String] as? String == accessGroup)
        #expect(delete[kSecAttrAccessGroup as String] as? String == accessGroup)
    }

    @Test
    func accessibilityAndSynchronizableAreHardened() {
        let builder = KeychainCredentialQueryBuilder()
        let descriptor = KeychainItemDescriptor(service: service, account: account, accessGroup: accessGroup)
        let payload = KeychainItemPayload(data: Data("secret".utf8), label: "label")

        let add = builder.addQuery(descriptor: descriptor, payload: payload)
        let copy = builder.copyQuery(descriptor: descriptor)
        let update = builder.updateQuery(descriptor: descriptor)
        let delete = builder.deleteQuery(descriptor: descriptor)

        #expect((add[kSecAttrAccessible as String] as? String) == (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String))
        #expect(isFalse(add[kSecAttrSynchronizable as String]))
        #expect(isFalse(copy[kSecAttrSynchronizable as String]))
        #expect(isFalse(update[kSecAttrSynchronizable as String]))
        #expect(isFalse(delete[kSecAttrSynchronizable as String]))
    }

    @Test
    func canonicalGroupReadUsesSharedAccessGroup() async throws {
        let client = RecordingGenericPasswordKeychainClient()
        let store = KeychainCredentialStore(
            service: service,
            accessGroupProvider: StaticSharedKeychainAccessGroupProvider(accessGroup: accessGroup),
            client: client,
            allowsLegacyMigration: false
        )
        let reference = "keychain://\(service)/\(account)"
        client.seed(
            descriptor: KeychainItemDescriptor(service: service, account: account, accessGroup: accessGroup),
            data: Data("shared-secret".utf8)
        )

        let value = try await store.secret(for: reference)

        #expect(value == "shared-secret")
        #expect(client.copyDescriptors == [KeychainItemDescriptor(service: service, account: account, accessGroup: accessGroup)])
    }

    @Test
    func appMigratesLegacyItemIntoCanonicalGroupAndPreservesReference() async throws {
        let client = RecordingGenericPasswordKeychainClient()
        let store = KeychainCredentialStore(
            service: service,
            accessGroupProvider: StaticSharedKeychainAccessGroupProvider(accessGroup: accessGroup),
            client: client,
            allowsLegacyMigration: true
        )
        let reference = "keychain://\(service)/\(account)"
        let legacyDescriptor = KeychainItemDescriptor(service: service, account: account, accessGroup: nil)
        let canonicalDescriptor = KeychainItemDescriptor(service: service, account: account, accessGroup: accessGroup)
        client.seed(descriptor: legacyDescriptor, data: Data("legacy-secret".utf8))

        let value = try await store.secret(for: reference)

        #expect(value == "legacy-secret")
        #expect(client.data(for: canonicalDescriptor) == Data("legacy-secret".utf8))
        #expect(client.data(for: legacyDescriptor) == nil)
        #expect(reference == "keychain://\(service)/\(account)")
        #expect(client.operationLog == [
            "copy:\(canonicalDescriptor)",
            "copy:\(legacyDescriptor)",
            "add:\(canonicalDescriptor)",
            "copy:\(canonicalDescriptor)",
            "delete:\(legacyDescriptor)"
        ])
    }

    @Test
    func migrationIsIdempotentAfterCanonicalCopyExists() async throws {
        let client = RecordingGenericPasswordKeychainClient()
        let store = KeychainCredentialStore(
            service: service,
            accessGroupProvider: StaticSharedKeychainAccessGroupProvider(accessGroup: accessGroup),
            client: client,
            allowsLegacyMigration: true
        )
        let reference = "keychain://\(service)/\(account)"
        let legacyDescriptor = KeychainItemDescriptor(service: service, account: account, accessGroup: nil)
        let canonicalDescriptor = KeychainItemDescriptor(service: service, account: account, accessGroup: accessGroup)
        client.seed(descriptor: legacyDescriptor, data: Data("legacy-secret".utf8))

        _ = try await store.secret(for: reference)
        client.resetRecords()
        let second = try await store.secret(for: reference)

        #expect(second == "legacy-secret")
        #expect(client.copyDescriptors == [canonicalDescriptor])
        #expect(client.data(for: legacyDescriptor) == nil)
    }

    @Test
    func extensionCanonicalOnlyStoreDoesNotSearchLegacyGroup() async throws {
        let client = RecordingGenericPasswordKeychainClient()
        let store = KeychainCredentialStore(
            service: service,
            accessGroupProvider: StaticSharedKeychainAccessGroupProvider(accessGroup: accessGroup),
            client: client,
            allowsLegacyMigration: false
        )
        let reference = "keychain://\(service)/\(account)"
        client.seed(
            descriptor: KeychainItemDescriptor(service: service, account: account, accessGroup: nil),
            data: Data("legacy-secret".utf8)
        )

        let value = try await store.secret(for: reference)

        #expect(value == nil)
        #expect(client.copyDescriptors == [KeychainItemDescriptor(service: service, account: account, accessGroup: accessGroup)])
    }

    @Test
    func updateAndDeleteUseCanonicalAccessGroup() async throws {
        let client = RecordingGenericPasswordKeychainClient()
        let store = KeychainCredentialStore(
            service: service,
            accessGroupProvider: StaticSharedKeychainAccessGroupProvider(accessGroup: accessGroup),
            client: client,
            allowsLegacyMigration: false
        )
        let reference = "keychain://\(service)/\(account)"

        try await store.update("new-secret", reference: reference)
        try await store.delete(reference: reference)

        #expect(client.updateDescriptors.contains(KeychainItemDescriptor(service: service, account: account, accessGroup: accessGroup)))
        #expect(client.deleteDescriptors.contains(KeychainItemDescriptor(service: service, account: account, accessGroup: accessGroup)))
    }
}

struct KeychainSentinelSmokeTests {
    @Test
    func accessGroupResolutionFailureMapsToDiagnosticStage() async {
        let store = InMemoryTunnelKeychainSentinelStore(accessGroupError: CredentialStoreError.invalidAccessGroup)
        let tester = TunnelKeychainSentinelSmokeTester(store: store, messenger: SentinelSmokeMessenger(found: true))

        await expectSentinelDiagnosticFailure(stage: .accessGroupResolution, category: .invalidAccessGroup) {
            _ = try await tester.runOnce()
        }
    }

    @Test
    func appKeychainWriteFailureMapsToDiagnosticStage() async {
        let store = InMemoryTunnelKeychainSentinelStore(storeError: CredentialStoreError.keychainFailed(-34018))
        let tester = TunnelKeychainSentinelSmokeTester(store: store, messenger: SentinelSmokeMessenger(found: true))

        await expectSentinelDiagnosticFailure(stage: .appKeychainWrite, category: .keychainStatus, osStatus: -34018) {
            _ = try await tester.runOnce()
        }
    }

    @Test
    func appVerificationFailureMapsToDiagnosticStage() async {
        let store = InMemoryTunnelKeychainSentinelStore(verifyResultOverride: false)
        let tester = TunnelKeychainSentinelSmokeTester(store: store, messenger: SentinelSmokeMessenger(found: true))

        await expectSentinelDiagnosticFailure(stage: .appKeychainVerify, category: .sentinelMissing, cleanupSucceeded: true) {
            _ = try await tester.runOnce()
        }
    }

    @Test
    func sentinelResponseNeverContainsSecret() async throws {
        let correlationID = UUID()
        let sentinel = "sentinel-secret-that-must-not-cross-ipc"
        let store = InMemoryTunnelKeychainSentinelStore()
        try await store.storeSentinel(correlationID: correlationID, sentinel: sentinel)
        let handler = TunnelAppMessageHandler(keychainSentinelStore: store)
        let request = TunnelMessageRequest(
            kind: .verifyKeychainSentinel,
            payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: correlationID))
        )

        let responseData = await handler.handle(try tunnelMessageEncoder().encode(request))
        let response = try tunnelMessageDecoder().decode(TunnelMessageResponse.self, from: responseData)
        let responseJSON = String(data: responseData, encoding: .utf8) ?? ""
        let responseObject = try #require(JSONSerialization.jsonObject(with: responseData) as? [String: Any])
        let generatedAt = try #require(responseObject["generatedAt"] as? String)
        let payloadObject = try #require(responseObject["payload"] as? [String: Any])
        let payloadData = try #require(payloadObject["data"] as? [String: Any])

        guard case .keychainSentinel(let payload)? = response.payload else {
            Issue.record("Expected sentinel response")
            return
        }
        #expect(generatedAt.isEmpty == false)
        #expect(payload.found)
        #expect(payload.correlationID == correlationID)
        #expect(Set(payloadData.keys).isSubset(of: ["found", "correlationID", "diagnostic"]))
        #expect(responseJSON.contains("sentinelLength") == false)
        #expect(responseJSON.contains("\"length\"") == false)
        #expect(responseJSON.contains(sentinel) == false)
        #expect(responseJSON.contains(Data(sentinel.utf8).base64EncodedString()) == false)
    }

    @Test
    func sentinelResponseUsesCanonicalGeneratedAtEncoding() async throws {
        let correlationID = UUID()
        let store = InMemoryTunnelKeychainSentinelStore()
        try await store.storeSentinel(correlationID: correlationID, sentinel: "secret")
        let handler = TunnelAppMessageHandler(keychainSentinelStore: store)
        let request = TunnelMessageRequest(
            kind: .verifyKeychainSentinel,
            payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: correlationID))
        )

        let responseData = await handler.handle(try tunnelMessageEncoder().encode(request))
        let response = try tunnelMessageDecoder().decode(TunnelMessageResponse.self, from: responseData)
        let object = try #require(JSONSerialization.jsonObject(with: responseData) as? [String: Any])

        #expect(object["generatedAt"] as? String != nil)
        guard case .keychainSentinel(let payload)? = response.payload else {
            Issue.record("Expected sentinel response")
            return
        }
        #expect(payload.found)
        #expect(payload.correlationID == correlationID)
    }

    @Test
    func sentinelRequestContainsCorrelationOnly() throws {
        let sentinel = "sentinel-secret-that-must-not-cross-ipc"
        let request = TunnelMessageRequest(
            kind: .verifyKeychainSentinel,
            payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: UUID()))
        )

        let json = String(data: try tunnelMessageEncoder().encode(request), encoding: .utf8) ?? ""

        #expect(json.contains(sentinel) == false)
        #expect(json.contains("verifyKeychainSentinel"))
    }

    @Test
    func smokeTesterCleansUpAfterSuccess() async throws {
        let store = InMemoryTunnelKeychainSentinelStore()
        let messenger = SentinelSmokeMessenger(found: true)
        let tester = TunnelKeychainSentinelSmokeTester(store: store, messenger: messenger)

        let result = try await tester.runOnce()

        #expect(result.found)
        #expect(result.deleted)
        #expect(await store.isEmpty())
    }

    @Test
    func smokeTesterCleansUpAfterFailure() async {
        let store = InMemoryTunnelKeychainSentinelStore()
        let tester = TunnelKeychainSentinelSmokeTester(
            store: store,
            messenger: ThrowingTunnelProviderMessenger(error: TunnelMessageErrorCode.providerUnavailable)
        )

        await expectSentinelDiagnosticFailure(
            stage: .providerMessageSend,
            category: .providerUnavailable,
            cleanupSucceeded: true
        ) {
            _ = try await tester.runOnce()
        }
        #expect(await store.isEmpty())
    }

    @Test
    func smokeTesterCleansUpAfterTimeout() async {
        let store = InMemoryTunnelKeychainSentinelStore()
        let tester = TunnelKeychainSentinelSmokeTester(
            store: store,
            messenger: ThrowingTunnelProviderMessenger(error: TunnelMessageErrorCode.timeout)
        )

        await expectSentinelDiagnosticFailure(
            stage: .providerTimeout,
            category: .providerTimeout,
            cleanupSucceeded: true
        ) {
            _ = try await tester.runOnce()
        }
        #expect(await store.isEmpty())
    }

    @Test
    func correlationMismatchMapsToResponseValidationDiagnostic() async {
        let store = InMemoryTunnelKeychainSentinelStore()
        let tester = TunnelKeychainSentinelSmokeTester(
            store: store,
            messenger: WrongCorrelationSentinelMessenger()
        )

        await expectSentinelDiagnosticFailure(
            stage: .responseValidation,
            category: .correlationMismatch,
            cleanupSucceeded: true
        ) {
            _ = try await tester.runOnce()
        }
        #expect(await store.isEmpty())
    }

    @Test
    func extensionSentinelMissingPreservesExtensionDiagnostic() async {
        let store = InMemoryTunnelKeychainSentinelStore()
        let tester = TunnelKeychainSentinelSmokeTester(
            store: store,
            messenger: SentinelSmokeMessenger(found: false)
        )

        await expectSentinelDiagnosticFailure(
            stage: .extensionSentinelMissing,
            category: .sentinelMissing,
            cleanupSucceeded: true
        ) {
            _ = try await tester.runOnce()
        }
        #expect(await store.isEmpty())
    }

    @Test
    func cleanupVerificationFailureIsSurfaced() async {
        let store = InMemoryTunnelKeychainSentinelStore(reportsPresentAfterDelete: true)
        let tester = TunnelKeychainSentinelSmokeTester(store: store, messenger: SentinelSmokeMessenger(found: true))

        await expectSentinelDiagnosticFailure(
            stage: .cleanupVerification,
            category: .cleanupVerificationFailed,
            cleanupSucceeded: false
        ) {
            _ = try await tester.runOnce()
        }
    }

    @Test
    func appTargetHandlerMapsExtensionAccessGroupFailure() async throws {
        let store = InMemoryTunnelKeychainSentinelStore(verifyError: CredentialStoreError.invalidAccessGroup)
        let handler = TunnelAppMessageHandler(keychainSentinelStore: store)
        let request = TunnelMessageRequest(
            kind: .verifyKeychainSentinel,
            payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: UUID()))
        )

        let response = try tunnelMessageDecoder().decode(TunnelMessageResponse.self, from: await handler.handle(try tunnelMessageEncoder().encode(request)))
        guard case .keychainSentinel(let payload)? = response.payload else {
            Issue.record("Expected sentinel response")
            return
        }

        #expect(payload.found == false)
        #expect(payload.diagnostic?.stage == .extensionKeychainRead)
        #expect(payload.diagnostic?.category == .invalidAccessGroup)
    }

    @Test
    func appTargetHandlerMapsExtensionKeychainStatusFailure() async throws {
        let store = InMemoryTunnelKeychainSentinelStore(verifyError: CredentialStoreError.keychainFailed(-25300))
        let handler = TunnelAppMessageHandler(keychainSentinelStore: store)
        let request = TunnelMessageRequest(
            kind: .verifyKeychainSentinel,
            payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: UUID()))
        )

        let response = try tunnelMessageDecoder().decode(TunnelMessageResponse.self, from: await handler.handle(try tunnelMessageEncoder().encode(request)))
        guard case .keychainSentinel(let payload)? = response.payload else {
            Issue.record("Expected sentinel response")
            return
        }

        #expect(payload.found == false)
        #expect(payload.diagnostic?.stage == .extensionKeychainRead)
        #expect(payload.diagnostic?.category == .keychainStatus)
        #expect(payload.diagnostic?.osStatus == -25300)
    }

    @Test
    func diagnosticSerializationContainsNoSecret() throws {
        let sentinel = "sentinel-secret-that-must-not-cross-ipc"
        let diagnostic = TunnelKeychainSentinelDiagnostic(
            stage: .providerTimeout,
            status: .failed,
            category: .providerTimeout,
            vpnStatus: "disconnected",
            correlationIDPrefix: "ABCDEF12",
            cleanupSucceeded: true
        )

        let json = String(data: try tunnelMessageEncoder().encode(diagnostic), encoding: .utf8) ?? ""

        #expect(json.contains(sentinel) == false)
        #expect(json.contains(Data(sentinel.utf8).base64EncodedString()) == false)
        #expect(json.contains("sentinelLength") == false)
        #expect(json.contains("\"length\"") == false)
    }

    @Test
    func repeatedSmokeRunUsesFreshSentinelsAndCleansUp() async throws {
        let store = InMemoryTunnelKeychainSentinelStore()
        let messenger = SentinelSmokeMessenger(found: true)
        let tester = TunnelKeychainSentinelSmokeTester(store: store, messenger: messenger)

        let results = try await tester.runTwice()

        #expect(results.count == 2)
        #expect(results[0].correlationID != results[1].correlationID)
        #expect(await messenger.sendCount == 2)
        #expect(await store.isEmpty())
    }
}

private final class RecordingGenericPasswordKeychainClient: GenericPasswordKeychainClient, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [KeychainItemDescriptor: Data] = [:]
    private(set) var addDescriptors: [KeychainItemDescriptor] = []
    private(set) var copyDescriptors: [KeychainItemDescriptor] = []
    private(set) var updateDescriptors: [KeychainItemDescriptor] = []
    private(set) var deleteDescriptors: [KeychainItemDescriptor] = []
    private(set) var operationLog: [String] = []

    func seed(descriptor: KeychainItemDescriptor, data: Data) {
        lock.withLock {
            storage[descriptor] = data
        }
    }

    func data(for descriptor: KeychainItemDescriptor) -> Data? {
        lock.withLock {
            storage[descriptor]
        }
    }

    func resetRecords() {
        lock.withLock {
            addDescriptors = []
            copyDescriptors = []
            updateDescriptors = []
            deleteDescriptors = []
            operationLog = []
        }
    }

    func add(_ descriptor: KeychainItemDescriptor, payload: KeychainItemPayload) -> OSStatus {
        lock.withLock {
            operationLog.append("add:\(descriptor)")
            addDescriptors.append(descriptor)
            if storage[descriptor] != nil {
                return errSecDuplicateItem
            }
            storage[descriptor] = payload.data
            return errSecSuccess
        }
    }

    func copyData(_ descriptor: KeychainItemDescriptor) -> KeychainLookupResult {
        lock.withLock {
            operationLog.append("copy:\(descriptor)")
            copyDescriptors.append(descriptor)
            guard let data = storage[descriptor] else {
                return KeychainLookupResult(status: errSecItemNotFound, data: nil)
            }
            return KeychainLookupResult(status: errSecSuccess, data: data)
        }
    }

    func update(_ descriptor: KeychainItemDescriptor, payload: KeychainItemPayload) -> OSStatus {
        lock.withLock {
            operationLog.append("update:\(descriptor)")
            updateDescriptors.append(descriptor)
            guard storage[descriptor] != nil else {
                return errSecItemNotFound
            }
            storage[descriptor] = payload.data
            return errSecSuccess
        }
    }

    func delete(_ descriptor: KeychainItemDescriptor) -> OSStatus {
        lock.withLock {
            operationLog.append("delete:\(descriptor)")
            deleteDescriptors.append(descriptor)
            storage[descriptor] = nil
            return errSecSuccess
        }
    }
}

private actor InMemoryTunnelKeychainSentinelStore: TunnelKeychainSentinelStoring {
    private var sentinels: [UUID: String] = [:]
    private let accessGroupError: (any Error)?
    private let storeError: (any Error)?
    private let verifyError: (any Error)?
    private let verifyResultOverride: Bool?
    private let reportsPresentAfterDelete: Bool

    init(
        accessGroupError: (any Error)? = nil,
        storeError: (any Error)? = nil,
        verifyError: (any Error)? = nil,
        verifyResultOverride: Bool? = nil,
        reportsPresentAfterDelete: Bool = false
    ) {
        self.accessGroupError = accessGroupError
        self.storeError = storeError
        self.verifyError = verifyError
        self.verifyResultOverride = verifyResultOverride
        self.reportsPresentAfterDelete = reportsPresentAfterDelete
    }

    func verifyAccessGroupResolution() async throws {
        if let accessGroupError {
            throw accessGroupError
        }
    }

    func storeSentinel(correlationID: UUID, sentinel: String) async throws {
        if let storeError {
            throw storeError
        }
        sentinels[correlationID] = sentinel
    }

    func verifySentinel(correlationID: UUID) async throws -> Bool {
        if let verifyError {
            throw verifyError
        }
        if let verifyResultOverride {
            return verifyResultOverride
        }
        if reportsPresentAfterDelete, sentinels[correlationID] == nil {
            return true
        }
        return sentinels[correlationID]?.isEmpty == false
    }

    func containsValidSentinel(correlationID: UUID) async -> Bool {
        (try? await verifySentinel(correlationID: correlationID)) ?? false
    }

    func deleteSentinel(correlationID: UUID) async throws {
        sentinels[correlationID] = nil
    }

    func isEmpty() -> Bool {
        sentinels.isEmpty
    }
}

private actor SentinelSmokeMessenger: TunnelKeychainSentinelMessaging {
    private let found: Bool
    private(set) var sendCount = 0

    init(found: Bool) {
        self.found = found
    }

    func sendKeychainSentinel(_ request: TunnelMessageRequest) async throws -> TunnelKeychainSentinelMessageResult {
        sendCount += 1
        guard case .keychainSentinel(let payload)? = request.payload else {
            throw TunnelMessageErrorCode.invalidResponse
        }
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .keychainSentinel(
                TunnelKeychainSentinelResponse(
                    found: found,
                    correlationID: payload.correlationID,
                    diagnostic: TunnelKeychainSentinelDiagnostic(
                        stage: found ? .extensionKeychainRead : .extensionSentinelMissing,
                        status: found ? .succeeded : .failed,
                        category: found ? .none : .sentinelMissing,
                        extensionRequestReached: true,
                        correlationIDPrefix: String(payload.correlationID.uuidString.prefix(8))
                    )
                )
            )
        )
        let diagnostic = TunnelKeychainSentinelDiagnostic(
            stage: .providerMessageSend,
            status: .succeeded,
            extensionRequestReached: true,
            correlationIDPrefix: String(payload.correlationID.uuidString.prefix(8))
        )
        return TunnelKeychainSentinelMessageResult(response: response, diagnostic: diagnostic)
    }
}

private actor WrongCorrelationSentinelMessenger: TunnelKeychainSentinelMessaging {
    func sendKeychainSentinel(_ request: TunnelMessageRequest) async throws -> TunnelKeychainSentinelMessageResult {
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .keychainSentinel(TunnelKeychainSentinelResponse(found: true, correlationID: UUID()))
        )
        return TunnelKeychainSentinelMessageResult(
            response: response,
            diagnostic: TunnelKeychainSentinelDiagnostic(stage: .providerMessageSend, status: .succeeded)
        )
    }
}

private nonisolated func tunnelMessageEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    return encoder
}

private nonisolated func tunnelMessageDecoder() -> JSONDecoder {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return decoder
}

private struct ThrowingTunnelProviderMessenger: TunnelKeychainSentinelMessaging {
    let error: TunnelMessageErrorCode

    func sendKeychainSentinel(_ request: TunnelMessageRequest) async throws -> TunnelKeychainSentinelMessageResult {
        throw error
    }
}

private func expectSentinelDiagnosticFailure(
    stage: TunnelKeychainSentinelDiagnosticStage,
    category: TunnelKeychainSentinelDiagnosticCategory,
    osStatus: OSStatus? = nil,
    cleanupSucceeded: Bool? = nil,
    operation: () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("expected sentinel diagnostic failure")
    } catch let failure as TunnelKeychainSentinelDiagnosticFailure {
        #expect(failure.diagnostic.stage == stage)
        #expect(failure.diagnostic.category == category)
        if let osStatus {
            #expect(failure.diagnostic.osStatus == osStatus)
        }
        if let cleanupSucceeded {
            #expect(failure.diagnostic.cleanupSucceeded == cleanupSucceeded)
        }
    } catch {
        Issue.record("expected sentinel diagnostic failure, got \(error)")
    }
}

private nonisolated func isFalse(_ value: Any?) -> Bool {
    if let bool = value as? Bool {
        return bool == false
    }
    return (value as? NSNumber)?.boolValue == false
}
