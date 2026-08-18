//
//  TunnelKeychainSentinelStore.swift
//  PacketTunnelExtension
//
//  Extension-side canonical shared Keychain sentinel reader. It never returns
//  the sentinel value to the app.
//

import Foundation
import Security

protocol TunnelKeychainSentinelReading: Sendable {
    func lookupSentinel(correlationID: UUID) async -> TunnelKeychainSentinelLookup
}

nonisolated enum TunnelSharedKeychainAccessGroup {
    static let infoPlistKey = "KVNSharedKeychainAccessGroup"
    static let canonicalSuffix = "su.24kvn.app.shared"
    static let requiredExpandedSuffix = ".\(canonicalSuffix)"

    static func resolvedAccessGroup(bundle: Bundle = .main) throws -> String {
        try validate(bundle.object(forInfoDictionaryKey: infoPlistKey))
    }

    static func validate(_ value: Any?) throws -> String {
        guard let value else {
            throw TunnelSharedKeychainError.accessGroupUnavailable
        }
        guard let accessGroup = value as? String else {
            throw TunnelSharedKeychainError.invalidAccessGroup
        }
        let trimmed = accessGroup.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false,
              trimmed.contains("$(") == false,
              trimmed.contains(")") == false,
              trimmed.hasSuffix(requiredExpandedSuffix),
              trimmed.dropLast(requiredExpandedSuffix.count).isEmpty == false else {
            throw TunnelSharedKeychainError.invalidAccessGroup
        }
        return trimmed
    }
}

nonisolated enum TunnelSharedKeychainError: Error, Sendable {
    case accessGroupUnavailable
    case invalidAccessGroup
}

nonisolated struct TunnelKeychainSentinelLookup: Equatable, Sendable {
    var found: Bool
    var diagnostic: TunnelKeychainSentinelDiagnostic
}

actor KeychainTunnelKeychainSentinelReader: TunnelKeychainSentinelReading {
    private let service = "su.24kvn.kvn-app.keychain-sentinel"
    private let accessGroupResolver: @Sendable () throws -> String

    init(accessGroupResolver: @escaping @Sendable () throws -> String = { try TunnelSharedKeychainAccessGroup.resolvedAccessGroup() }) {
        self.accessGroupResolver = accessGroupResolver
    }

    func lookupSentinel(correlationID: UUID) async -> TunnelKeychainSentinelLookup {
        do {
            let descriptor = try descriptor(correlationID: correlationID)
            var result: CFTypeRef?
            let status = SecItemCopyMatching(copyQuery(descriptor: descriptor) as CFDictionary, &result)
            if status == errSecItemNotFound {
                return Self.lookup(
                    found: false,
                    stage: .extensionSentinelMissing,
                    category: .sentinelMissing,
                    correlationID: correlationID
                )
            }
            guard status == errSecSuccess else {
                return Self.lookup(
                    found: false,
                    stage: .extensionKeychainRead,
                    category: .keychainStatus,
                    osStatus: status,
                    correlationID: correlationID
                )
            }

            guard let data = result as? Data, data.isEmpty == false else {
                return Self.lookup(
                    found: false,
                    stage: .extensionSentinelMissing,
                    category: .sentinelMissing,
                    correlationID: correlationID
                )
            }

            return Self.lookup(
                found: true,
                stage: .extensionKeychainRead,
                status: .succeeded,
                correlationID: correlationID
            )
        } catch {
            return Self.lookup(
                found: false,
                stage: .extensionKeychainRead,
                category: Self.category(for: error),
                correlationID: correlationID
            )
        }
    }

    private func descriptor(correlationID: UUID) throws -> TunnelKeychainSentinelDescriptor {
        TunnelKeychainSentinelDescriptor(
            service: service,
            account: "sentinel-\(correlationID.uuidString)",
            accessGroup: try accessGroupResolver()
        )
    }

    private func copyQuery(descriptor: TunnelKeychainSentinelDescriptor) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: descriptor.service,
            kSecAttrAccount as String: descriptor.account,
            kSecAttrAccessGroup as String: descriptor.accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecUseDataProtectionKeychain as String: true
        ]
    }

    private static func lookup(
        found: Bool,
        stage: TunnelKeychainSentinelDiagnosticStage,
        status: TunnelKeychainSentinelDiagnosticStatus = .failed,
        category: TunnelKeychainSentinelDiagnosticCategory = .none,
        osStatus: OSStatus? = nil,
        correlationID: UUID
    ) -> TunnelKeychainSentinelLookup {
        TunnelKeychainSentinelLookup(
            found: found,
            diagnostic: TunnelKeychainSentinelDiagnostic(
                stage: stage,
                status: status,
                category: category,
                extensionRequestReached: true,
                osStatus: osStatus,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    private static func category(for error: any Error) -> TunnelKeychainSentinelDiagnosticCategory {
        switch error {
        case TunnelSharedKeychainError.accessGroupUnavailable:
            .accessGroupUnavailable
        case TunnelSharedKeychainError.invalidAccessGroup:
            .invalidAccessGroup
        default:
            .unknown
        }
    }
}

private nonisolated struct TunnelKeychainSentinelDescriptor: Sendable {
    var service: String
    var account: String
    var accessGroup: String
}
