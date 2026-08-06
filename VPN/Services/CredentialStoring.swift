//
//  CredentialStoring.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation
import Security

nonisolated protocol CredentialStoring: Sendable {
    func store(_ secret: String, label: String) async throws -> String
    func delete(reference: String) async throws
}

actor InMemoryCredentialStore: CredentialStoring {
    private var secrets: [String: String] = [:]

    func store(_ secret: String, label: String) async throws -> String {
        let reference = "memory://credential/\(UUID().uuidString)"
        secrets[reference] = secret
        return reference
    }

    func secret(for reference: String) -> String? {
        secrets[reference]
    }

    func delete(reference: String) async throws {
        secrets[reference] = nil
    }
}

nonisolated enum CredentialStoreError: LocalizedError, Sendable {
    case encodingFailed
    case keychainFailed(OSStatus)

    var errorDescription: String? {
        switch self {
        case .encodingFailed:
            "Unable to encode credential."
        case .keychainFailed(let status):
            "Keychain operation failed with status \(status)."
        }
    }
}

actor KeychainCredentialStore: CredentialStoring {
    private let service: String

    init(service: String = "denischizhov.VPN.credentials") {
        self.service = service
    }

    func store(_ secret: String, label: String) async throws -> String {
        guard let data = secret.data(using: .utf8) else {
            throw CredentialStoreError.encodingFailed
        }

        let account = UUID().uuidString
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrLabel as String: label,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CredentialStoreError.keychainFailed(status)
        }

        return "keychain://\(service)/\(account)"
    }

    func delete(reference: String) async throws {
        guard let account = account(from: reference) else {
            return
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CredentialStoreError.keychainFailed(status)
        }
    }

    private func account(from reference: String) -> String? {
        let prefix = "keychain://\(service)/"
        guard reference.hasPrefix(prefix) else {
            return nil
        }

        return String(reference.dropFirst(prefix.count))
    }
}
