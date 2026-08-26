//
//  TunnelKeychainSentinelSmokeTest.swift
//  VPN
//
//  DEBUG-only app-side smoke test for the shared Keychain boundary. The
//  sentinel value is a one-time secret that never leaves Keychain through IPC.
//

import Foundation
import Security

nonisolated protocol TunnelKeychainSentinelStoring: Sendable {
    func verifyAccessGroupResolution() async throws
    func storeSentinel(correlationID: UUID, sentinel: String) async throws
    func verifySentinel(correlationID: UUID) async throws -> Bool
    func containsValidSentinel(correlationID: UUID) async -> Bool
    func deleteSentinel(correlationID: UUID) async throws
}

nonisolated struct TunnelKeychainSentinelVerification: Equatable, Sendable {
    var correlationID: UUID
    var found: Bool
    var deleted: Bool
    var diagnostic: TunnelKeychainSentinelDiagnostic
}

nonisolated struct TunnelKeychainSentinelMessageResult: Sendable {
    var response: TunnelMessageResponse
    var diagnostic: TunnelKeychainSentinelDiagnostic
}

nonisolated struct TunnelKeychainSentinelDiagnosticFailure: Error, Equatable, Sendable {
    var diagnostic: TunnelKeychainSentinelDiagnostic

    func withCleanupSucceeded(_ cleanupSucceeded: Bool?) -> TunnelKeychainSentinelDiagnosticFailure {
        var copy = self
        copy.diagnostic.cleanupSucceeded = cleanupSucceeded
        return copy
    }
}

nonisolated enum TunnelKeychainSentinelError: LocalizedError, Sendable {
    case randomGenerationFailed
    case missingResponse
    case notFound
    case cleanupFailed

    var errorDescription: String? {
        switch self {
        case .randomGenerationFailed:
            "Unable to create a keychain sentinel."
        case .missingResponse:
            "The tunnel extension did not return a sentinel response."
        case .notFound:
            "The tunnel extension could not read the shared keychain sentinel."
        case .cleanupFailed:
            "The shared keychain sentinel could not be removed."
        }
    }
}

actor KeychainTunnelKeychainSentinelStore: TunnelKeychainSentinelStoring {
    private let service = "su.24kvn.kvn-app.keychain-sentinel"
    private let accessGroupProvider: any SharedKeychainAccessGroupProviding
    private let client: any GenericPasswordKeychainClient

    init(
        accessGroupProvider: any SharedKeychainAccessGroupProviding = InfoPlistSharedKeychainAccessGroupProvider(),
        client: any GenericPasswordKeychainClient = SystemGenericPasswordKeychainClient()
    ) {
        self.accessGroupProvider = accessGroupProvider
        self.client = client
    }

    func verifyAccessGroupResolution() async throws {
        _ = try accessGroupProvider.sharedKeychainAccessGroup()
    }

    func storeSentinel(correlationID: UUID, sentinel: String) async throws {
        let record = TunnelKeychainSentinelSecret(correlationID: correlationID, nonce: sentinel)
        let data = try JSONEncoder().encode(record)
        let descriptor = try descriptor(correlationID: correlationID)
        let payload = KeychainItemPayload(data: data, label: "KVN shared keychain sentinel")

        let status = client.add(descriptor, payload: payload)
        if status == errSecDuplicateItem {
            let updateStatus = client.update(descriptor, payload: payload)
            guard updateStatus == errSecSuccess else {
                throw CredentialStoreError.keychainFailed(updateStatus)
            }
            return
        }
        guard status == errSecSuccess else {
            throw CredentialStoreError.keychainFailed(status)
        }
    }

    func verifySentinel(correlationID: UUID) async throws -> Bool {
        let lookup = client.copyData(try descriptor(correlationID: correlationID))
        if lookup.status == errSecItemNotFound {
            return false
        }
        guard lookup.status == errSecSuccess,
              let data = lookup.data else {
            throw CredentialStoreError.keychainFailed(lookup.status)
        }
        guard let record = try? JSONDecoder().decode(TunnelKeychainSentinelSecret.self, from: data) else {
            throw CredentialStoreError.encodingFailed
        }
        return record.correlationID == correlationID && record.nonce.isEmpty == false
    }

    func containsValidSentinel(correlationID: UUID) async -> Bool {
        do {
            return try await verifySentinel(correlationID: correlationID)
        } catch {
            return false
        }
    }

    func deleteSentinel(correlationID: UUID) async throws {
        let status = client.delete(try descriptor(correlationID: correlationID))
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CredentialStoreError.keychainFailed(status)
        }
    }

    private func descriptor(correlationID: UUID) throws -> KeychainItemDescriptor {
        KeychainItemDescriptor(
            service: service,
            account: Self.account(correlationID: correlationID),
            accessGroup: try accessGroupProvider.sharedKeychainAccessGroup()
        )
    }

    static func account(correlationID: UUID) -> String {
        "sentinel-\(correlationID.uuidString)"
    }
}

nonisolated struct TunnelKeychainSentinelSecret: Codable, Equatable, Sendable {
    var schemaVersion = TunnelMessageProtocol.schemaVersion
    var correlationID: UUID
    var nonce: String
}

nonisolated struct TunnelKeychainSentinelSmokeTester: Sendable {
    private let store: any TunnelKeychainSentinelStoring
    private let messenger: any TunnelKeychainSentinelMessaging

    init(
        store: any TunnelKeychainSentinelStoring = KeychainTunnelKeychainSentinelStore(),
        messenger: any TunnelKeychainSentinelMessaging = TunnelKeychainSentinelSmokeTester.defaultMessenger()
    ) {
        self.store = store
        self.messenger = messenger
    }

    func runTwice() async throws -> [TunnelKeychainSentinelVerification] {
        [
            try await runOnce(),
            try await runOnce()
        ]
    }

    func runOnce() async throws -> TunnelKeychainSentinelVerification {
        let correlationID = UUID()
        let sentinel = try Self.randomSentinel()
        var sentinelCreated = false

        do {
            do {
                try await store.verifyAccessGroupResolution()
            } catch {
                throw Self.failure(stage: .accessGroupResolution, error: error, correlationID: correlationID)
            }

            do {
                try await store.storeSentinel(correlationID: correlationID, sentinel: sentinel)
                sentinelCreated = true
            } catch {
                throw Self.failure(stage: .appKeychainWrite, error: error, correlationID: correlationID)
            }

            do {
                let appCanRead = try await store.verifySentinel(correlationID: correlationID)
                guard appCanRead else {
                    throw Self.failure(
                        stage: .appKeychainVerify,
                        category: .sentinelMissing,
                        correlationID: correlationID
                    )
                }
            } catch let failure as TunnelKeychainSentinelDiagnosticFailure {
                throw failure
            } catch {
                throw Self.failure(stage: .appKeychainVerify, error: error, correlationID: correlationID)
            }

            let request = TunnelMessageRequest(
                kind: .verifyKeychainSentinel,
                payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: correlationID))
            )

            let messageResult: TunnelKeychainSentinelMessageResult
            do {
                messageResult = try await messenger.sendKeychainSentinel(request)
            } catch let failure as TunnelKeychainSentinelDiagnosticFailure {
                throw failure
            } catch {
                let stage: TunnelKeychainSentinelDiagnosticStage = (error as? TunnelMessageErrorCode) == .timeout
                    ? .providerTimeout
                    : .providerMessageSend
                throw Self.failure(stage: stage, error: error, correlationID: correlationID)
            }

            guard case .keychainSentinel(let payload)? = messageResult.response.payload else {
                throw Self.failure(
                    stage: .responseValidation,
                    category: .invalidResponse,
                    correlationID: correlationID
                )
            }
            guard payload.correlationID == correlationID else {
                throw Self.failure(
                    stage: .responseValidation,
                    category: .correlationMismatch,
                    correlationID: correlationID,
                    base: messageResult.diagnostic
                )
            }
            guard payload.found else {
                let extensionDiagnostic = payload.diagnostic ?? TunnelKeychainSentinelDiagnostic(
                    stage: .extensionSentinelMissing,
                    status: .failed,
                    category: .sentinelMissing,
                    extensionRequestReached: true,
                    correlationIDPrefix: Self.safeCorrelationPrefix(correlationID)
                )
                throw TunnelKeychainSentinelDiagnosticFailure(diagnostic: extensionDiagnostic)
            }

            do {
                try await store.deleteSentinel(correlationID: correlationID)
            } catch {
                throw Self.failure(stage: .cleanup, error: error, correlationID: correlationID)
            }
            do {
                let stillPresent = try await store.verifySentinel(correlationID: correlationID)
                guard stillPresent == false else {
                    throw Self.failure(
                        stage: .cleanupVerification,
                        category: .cleanupVerificationFailed,
                        correlationID: correlationID,
                        cleanupSucceeded: false
                    )
                }
            } catch let failure as TunnelKeychainSentinelDiagnosticFailure {
                throw failure
            } catch {
                throw Self.failure(stage: .cleanupVerification, error: error, correlationID: correlationID, cleanupSucceeded: false)
            }

            var diagnostic = messageResult.diagnostic
            diagnostic.cleanupSucceeded = true
            return TunnelKeychainSentinelVerification(
                correlationID: correlationID,
                found: true,
                deleted: true,
                diagnostic: diagnostic
            )
        } catch {
            let cleanupSucceeded: Bool?
            if sentinelCreated {
                cleanupSucceeded = await Self.cleanup(correlationID: correlationID, store: store)
            } else {
                cleanupSucceeded = nil
            }
            if let failure = error as? TunnelKeychainSentinelDiagnosticFailure {
                throw failure.withCleanupSucceeded(cleanupSucceeded)
            }
            throw error
        }
    }

    private static func cleanup(
        correlationID: UUID,
        store: any TunnelKeychainSentinelStoring
    ) async -> Bool {
        do {
            try await store.deleteSentinel(correlationID: correlationID)
            return try await store.verifySentinel(correlationID: correlationID) == false
        } catch {
            return false
        }
    }

    private static func randomSentinel() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw TunnelKeychainSentinelError.randomGenerationFailed
        }
        return Data(bytes).base64EncodedString()
    }

    private static func failure(
        stage: TunnelKeychainSentinelDiagnosticStage,
        category: TunnelKeychainSentinelDiagnosticCategory? = nil,
        error: (any Error)? = nil,
        correlationID: UUID,
        base: TunnelKeychainSentinelDiagnostic? = nil,
        cleanupSucceeded: Bool? = nil
    ) -> TunnelKeychainSentinelDiagnosticFailure {
        var diagnostic = base ?? TunnelKeychainSentinelDiagnostic(
            stage: stage,
            status: .failed,
            category: category ?? categoryFor(error),
            correlationIDPrefix: safeCorrelationPrefix(correlationID)
        )
        diagnostic.stage = stage
        diagnostic.status = .failed
        diagnostic.category = category ?? categoryFor(error)
        diagnostic.correlationIDPrefix = safeCorrelationPrefix(correlationID)
        diagnostic.cleanupSucceeded = cleanupSucceeded

        if let credentialError = error as? CredentialStoreError,
           case .keychainFailed(let status) = credentialError {
            diagnostic.osStatus = status
        } else if let nsError = error as NSError? {
            diagnostic.errorDomain = nsError.domain
            diagnostic.errorCode = nsError.code
        }

        return TunnelKeychainSentinelDiagnosticFailure(diagnostic: diagnostic)
    }

    private static func categoryFor(_ error: (any Error)?) -> TunnelKeychainSentinelDiagnosticCategory {
        guard let error else {
            return .unknown
        }

        if let credentialError = error as? CredentialStoreError {
            switch credentialError {
            case .accessGroupUnavailable:
                return .accessGroupUnavailable
            case .invalidAccessGroup:
                return .invalidAccessGroup
            case .keychainFailed:
                return .keychainStatus
            case .encodingFailed, .migrationVerificationFailed:
                return .unknown
            }
        }

        if let messageError = error as? TunnelMessageErrorCode {
            switch messageError {
            case .providerUnavailable:
                return .providerUnavailable
            case .providerResponseMissing:
                return .providerResponseMissing
            case .timeout:
                return .providerTimeout
            case .schemaMismatch:
                return .schemaMismatch
            case .requestIDMismatch:
                return .requestIDMismatch
            case .invalidResponse:
                return .invalidResponse
            case .malformedRequest:
                return .malformedRequest
            case .keychainUnavailable:
                return .keychainUnavailable
            case .unsupportedRequest,
                 .providerStatusNotConnected,
                 .payloadTooLarge,
                 .unknown:
                return .unknown
            }
        }

        return .unknown
    }

    static func safeCorrelationPrefix(_ correlationID: UUID) -> String {
        String(correlationID.uuidString.prefix(8))
    }

    private static func defaultMessenger() -> any TunnelKeychainSentinelMessaging {
        NetworkExtensionKeychainSentinelMessenger()
    }
}

private nonisolated struct UnavailableTunnelKeychainSentinelMessenger: TunnelKeychainSentinelMessaging {
    func sendKeychainSentinel(_ request: TunnelMessageRequest) async throws -> TunnelKeychainSentinelMessageResult {
        throw TunnelMessageErrorCode.unsupportedRequest
    }
}
