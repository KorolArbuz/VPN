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
    func secret(for reference: String) async throws -> String?
    func delete(reference: String) async throws
}

actor InMemoryCredentialStore: CredentialStoring {
    private var secrets: [String: String] = [:]

    func store(_ secret: String, label: String) async throws -> String {
        let reference = "memory://credential/\(UUID().uuidString)"
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

nonisolated enum CredentialStoreError: LocalizedError, Equatable, Sendable {
    case encodingFailed
    case accessGroupUnavailable
    case invalidAccessGroup
    case migrationVerificationFailed
    case keychainFailed(OSStatus)

    var errorDescription: String? {
        switch self {
        case .encodingFailed:
            "Unable to encode credential."
        case .accessGroupUnavailable:
            "Shared keychain access group is unavailable."
        case .invalidAccessGroup:
            "Shared keychain access group is invalid."
        case .migrationVerificationFailed:
            "Credential migration could not be verified."
        case .keychainFailed(let status):
            "Keychain operation failed with status \(status)."
        }
    }
}

nonisolated protocol SharedKeychainAccessGroupProviding: Sendable {
    func sharedKeychainAccessGroup() throws -> String
}

nonisolated struct StaticSharedKeychainAccessGroupProvider: SharedKeychainAccessGroupProviding {
    let accessGroup: String

    func sharedKeychainAccessGroup() throws -> String {
        try SharedKeychainAccessGroupValidator.validate(accessGroup)
    }
}

nonisolated struct InfoPlistSharedKeychainAccessGroupProvider: SharedKeychainAccessGroupProviding {
    private let valueReader: @Sendable () -> Any?

    init(
        bundle: Bundle = .main
    ) {
        self.valueReader = {
            bundle.object(forInfoDictionaryKey: SharedKeychainAccessGroupValidator.infoPlistKey)
        }
    }

    init(valueReader: @escaping @Sendable () -> Any?) {
        self.valueReader = valueReader
    }

    func sharedKeychainAccessGroup() throws -> String {
        guard let value = valueReader() else {
            throw CredentialStoreError.accessGroupUnavailable
        }
        guard let accessGroup = value as? String else {
            throw CredentialStoreError.invalidAccessGroup
        }
        return try SharedKeychainAccessGroupValidator.validate(accessGroup)
    }
}

#if DEBUG
nonisolated struct ProvisioningProfileSharedKeychainAccessGroupDiagnostics {
    static func keychainAccessGroups(bundle: Bundle = .main) -> [String] {
        guard let url = bundle.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url),
              let plistData = EmbeddedProvisioningProfileParser.plistData(from: data),
              let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any],
              let entitlements = plist["Entitlements"] as? [String: Any],
              let groups = entitlements["keychain-access-groups"] as? [String] else {
            return []
        }
        return groups
    }
}

nonisolated enum EmbeddedProvisioningProfileParser {
    static func plistData(from data: Data) -> Data? {
        guard let startRange = data.range(of: Data("<?xml".utf8)),
              let endRange = data.range(of: Data("</plist>".utf8), options: [], in: startRange.lowerBound..<data.endIndex) else {
            return nil
        }

        return data[startRange.lowerBound..<endRange.upperBound]
    }
}
#endif

nonisolated enum SharedKeychainAccessGroupValidator {
    static let infoPlistKey = "KVNSharedKeychainAccessGroup"
    static let canonicalSuffix = "su.24kvn.app.shared"
    static let requiredExpandedSuffix = ".\(canonicalSuffix)"

    static func hasCanonicalSuffix(_ value: String) -> Bool {
        value.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix(requiredExpandedSuffix)
    }

    static func validate(_ value: String) throws -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false,
              trimmed.contains("$(") == false,
              trimmed.contains(")") == false,
              hasCanonicalSuffix(trimmed) else {
            throw CredentialStoreError.invalidAccessGroup
        }
        let prefix = trimmed.dropLast(requiredExpandedSuffix.count)
        guard prefix.isEmpty == false else {
            throw CredentialStoreError.invalidAccessGroup
        }
        return trimmed
    }
}

nonisolated struct KeychainItemDescriptor: Hashable, Sendable {
    var service: String
    var account: String
    var accessGroup: String?
}

nonisolated struct KeychainItemPayload: Sendable {
    var data: Data
    var label: String?
}

nonisolated struct KeychainLookupResult: Sendable {
    var status: OSStatus
    var data: Data?
}

nonisolated protocol GenericPasswordKeychainClient: Sendable {
    func add(_ descriptor: KeychainItemDescriptor, payload: KeychainItemPayload) -> OSStatus
    func copyData(_ descriptor: KeychainItemDescriptor) -> KeychainLookupResult
    func update(_ descriptor: KeychainItemDescriptor, payload: KeychainItemPayload) -> OSStatus
    func delete(_ descriptor: KeychainItemDescriptor) -> OSStatus
}

nonisolated struct SystemGenericPasswordKeychainClient: GenericPasswordKeychainClient {
    private let builder = KeychainCredentialQueryBuilder()

    func add(_ descriptor: KeychainItemDescriptor, payload: KeychainItemPayload) -> OSStatus {
        SecItemAdd(builder.addQuery(descriptor: descriptor, payload: payload) as CFDictionary, nil)
    }

    func copyData(_ descriptor: KeychainItemDescriptor) -> KeychainLookupResult {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(builder.copyQuery(descriptor: descriptor) as CFDictionary, &result)
        return KeychainLookupResult(status: status, data: result as? Data)
    }

    func update(_ descriptor: KeychainItemDescriptor, payload: KeychainItemPayload) -> OSStatus {
        SecItemUpdate(
            builder.updateQuery(descriptor: descriptor) as CFDictionary,
            builder.updateAttributes(payload: payload) as CFDictionary
        )
    }

    func delete(_ descriptor: KeychainItemDescriptor) -> OSStatus {
        SecItemDelete(builder.deleteQuery(descriptor: descriptor) as CFDictionary)
    }
}

nonisolated struct KeychainCredentialQueryBuilder {
    func addQuery(descriptor: KeychainItemDescriptor, payload: KeychainItemPayload) -> [String: Any] {
        var query = baseQuery(descriptor: descriptor)
        query[kSecAttrLabel as String] = payload.label
        query[kSecValueData as String] = payload.data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return query
    }

    func copyQuery(descriptor: KeychainItemDescriptor) -> [String: Any] {
        var query = baseQuery(descriptor: descriptor)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseDataProtectionKeychain as String] = true
        return query
    }

    func updateQuery(descriptor: KeychainItemDescriptor) -> [String: Any] {
        var query = baseQuery(descriptor: descriptor)
        query[kSecUseDataProtectionKeychain as String] = true
        return query
    }

    func updateAttributes(payload: KeychainItemPayload) -> [String: Any] {
        var attributes: [String: Any] = [
            kSecValueData as String: payload.data
        ]
        if let label = payload.label {
            attributes[kSecAttrLabel as String] = label
        }
        return attributes
    }

    func deleteQuery(descriptor: KeychainItemDescriptor) -> [String: Any] {
        var query = baseQuery(descriptor: descriptor)
        query[kSecUseDataProtectionKeychain as String] = true
        return query
    }

    private func baseQuery(descriptor: KeychainItemDescriptor) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: descriptor.service,
            kSecAttrAccount as String: descriptor.account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecUseDataProtectionKeychain as String: true
        ]
        if let accessGroup = descriptor.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}

actor KeychainCredentialStore: CredentialStoring {
    private let service: String
    private let accessGroupProvider: any SharedKeychainAccessGroupProviding
    private let client: any GenericPasswordKeychainClient
    private let allowsLegacyMigration: Bool

    init(
        service: String = "denischizhov.VPN.credentials",
        accessGroupProvider: any SharedKeychainAccessGroupProviding = InfoPlistSharedKeychainAccessGroupProvider(),
        client: any GenericPasswordKeychainClient = SystemGenericPasswordKeychainClient(),
        allowsLegacyMigration: Bool = true
    ) {
        self.service = service
        self.accessGroupProvider = accessGroupProvider
        self.client = client
        self.allowsLegacyMigration = allowsLegacyMigration
    }

    static func extensionCanonicalOnly(
        service: String = "denischizhov.VPN.credentials",
        accessGroupProvider: any SharedKeychainAccessGroupProviding = InfoPlistSharedKeychainAccessGroupProvider()
    ) -> KeychainCredentialStore {
        KeychainCredentialStore(
            service: service,
            accessGroupProvider: accessGroupProvider,
            allowsLegacyMigration: false
        )
    }

    func store(_ secret: String, label: String) async throws -> String {
        guard let data = secret.data(using: .utf8) else {
            throw CredentialStoreError.encodingFailed
        }

        let account = UUID().uuidString
        try writeCanonical(data, account: account, label: label)

        return "keychain://\(service)/\(account)"
    }

    func delete(reference: String) async throws {
        guard let account = account(from: reference) else {
            return
        }

        let status = client.delete(try canonicalDescriptor(account: account))
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CredentialStoreError.keychainFailed(status)
        }

        if allowsLegacyMigration {
            _ = client.delete(legacyDescriptor(account: account))
        }
    }

    func update(_ secret: String, reference: String, label: String? = nil) async throws {
        guard let account = account(from: reference),
              let data = secret.data(using: .utf8) else {
            throw CredentialStoreError.encodingFailed
        }

        let descriptor = try canonicalDescriptor(account: account)
        let status = client.update(descriptor, payload: KeychainItemPayload(data: data, label: label))
        if status == errSecItemNotFound {
            try writeCanonical(data, account: account, label: label)
            return
        }
        guard status == errSecSuccess else {
            throw CredentialStoreError.keychainFailed(status)
        }
    }

    func secret(for reference: String) async throws -> String? {
        guard let account = account(from: reference) else {
            return nil
        }

        let canonical = client.copyData(try canonicalDescriptor(account: account))
        if canonical.status == errSecSuccess {
            return try string(from: canonical.data)
        }
        guard canonical.status == errSecItemNotFound else {
            throw CredentialStoreError.keychainFailed(canonical.status)
        }
        guard allowsLegacyMigration else {
            return nil
        }

        let legacy = client.copyData(legacyDescriptor(account: account))
        if legacy.status == errSecItemNotFound {
            return nil
        }
        guard legacy.status == errSecSuccess else {
            throw CredentialStoreError.keychainFailed(legacy.status)
        }
        guard let legacyData = legacy.data else {
            throw CredentialStoreError.encodingFailed
        }

        try writeCanonical(legacyData, account: account, label: nil)
        let verified = client.copyData(try canonicalDescriptor(account: account))
        guard verified.status == errSecSuccess, verified.data == legacyData else {
            throw CredentialStoreError.migrationVerificationFailed
        }

        _ = client.delete(legacyDescriptor(account: account))
        return try string(from: legacyData)
    }

    private func writeCanonical(_ data: Data, account: String, label: String?) throws {
        let descriptor = try canonicalDescriptor(account: account)
        let payload = KeychainItemPayload(data: data, label: label)
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

    private func canonicalDescriptor(account: String) throws -> KeychainItemDescriptor {
        KeychainItemDescriptor(
            service: service,
            account: account,
            accessGroup: try accessGroupProvider.sharedKeychainAccessGroup()
        )
    }

    private func legacyDescriptor(account: String) -> KeychainItemDescriptor {
        KeychainItemDescriptor(service: service, account: account, accessGroup: nil)
    }

    private func string(from data: Data?) throws -> String? {
        guard let data else {
            throw CredentialStoreError.encodingFailed
        }

        guard let value = String(data: data, encoding: .utf8) else {
            throw CredentialStoreError.encodingFailed
        }
        return value
    }

    private func account(from reference: String) -> String? {
        let prefix = "keychain://\(service)/"
        guard reference.hasPrefix(prefix) else {
            return nil
        }

        return String(reference.dropFirst(prefix.count))
    }
}
