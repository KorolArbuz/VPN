//
//  RuntimeProviderInfrastructure.swift
//  Packet tunnel providers
//
//  Shared non-runtime-specific provider configuration and Keychain access.
//

import Foundation
import Security

nonisolated enum RuntimeConfigurationProtocol {
    static let profileSchemaVersion: UInt32 = 1
    static let profileCollectionSchemaVersion: UInt32 = 1
    static let providerConfigurationSchemaVersion: UInt32 = 1
    static let maximumRecordBytes = 64 * 1_024
    static let maximumCollectionBytes = 512 * 1_024
    static let maximumProfileRecordCount = 256
}

nonisolated enum RuntimeConfigurationError: String, Error, Codable, Equatable, Sendable {
    case missingProviderConfiguration
    case malformedProviderConfiguration
    case providerConfigurationUnknownKey
    case providerConfigurationMissingSchemaVersion
    case providerConfigurationWrongSchemaVersionType
    case providerConfigurationUnsupportedSchemaVersion
    case providerConfigurationMissingProfileID
    case providerConfigurationWrongProfileIDType
    case providerConfigurationMalformedProfileID
    case providerConfigurationMissingRecordRevision
    case providerConfigurationWrongRecordRevisionType
    case providerConfigurationInvalidRecordRevision
    case providerConfigurationPersistedMismatch
    case providerConfigurationContractMismatch
    case providerConfigurationStaleSession
    case unsupportedProviderSchema
    case missingProfileID
    case invalidProfileID
    case missingRevision
    case invalidRevision
    case profileRecordNotFound
    case profileRecordTooLarge
    case profileRecordMalformed
    case profileRecordCountExceeded
    case profileSchemaMismatch
    case profileIdentityMismatch
    case profileRevisionMismatch
    case profileDisabled
    case profileIncomplete
    case unsupportedProtocol
    case invalidEndpoint
    case unsupportedTransport
    case invalidTransportConfiguration
    case invalidXHTTPConfiguration
    case invalidXHTTPMode
    case invalidXHTTPPath
    case invalidXHTTPHost
    case invalidSecurityConfiguration
    case missingCredentialReference
    case malformedCredentialReference
    case credentialUnavailable
    case credentialMalformed
    case sharedContainerUnavailable
    case sharedKeychainConfigurationInvalid
    case writeFailed
    case deleteFailed
}

nonisolated struct RuntimeProviderConfiguration: Equatable, Sendable {
    static let allowedKeys: Set<String> = ["schemaVersion", "profileID", "recordRevision"]

    var schemaVersion: UInt32
    var profileID: UUID
    var recordRevision: Int64

    init(
        schemaVersion: UInt32 = RuntimeConfigurationProtocol.providerConfigurationSchemaVersion,
        profileID: UUID,
        recordRevision: Int64
    ) {
        self.schemaVersion = schemaVersion
        self.profileID = profileID
        self.recordRevision = recordRevision
    }

    func matches(expectedProfileID: UUID?, expectedRevisionToken: Int64?) -> Bool {
        if let expectedProfileID, profileID != expectedProfileID {
            return false
        }
        if let expectedRevisionToken, recordRevision != expectedRevisionToken {
            return false
        }
        return true
    }

    static func parse(_ propertyList: [String: Any]?) throws -> RuntimeProviderConfiguration {
        guard let propertyList else {
            throw RuntimeConfigurationError.missingProviderConfiguration
        }
        let keys = Set(propertyList.keys)
        guard keys.subtracting(allowedKeys).isEmpty else {
            throw RuntimeConfigurationError.providerConfigurationUnknownKey
        }
        guard allowedKeys.subtracting(keys).isEmpty else {
            if propertyList["schemaVersion"] == nil {
                throw RuntimeConfigurationError.providerConfigurationMissingSchemaVersion
            }
            if propertyList["profileID"] == nil {
                throw RuntimeConfigurationError.providerConfigurationMissingProfileID
            }
            throw RuntimeConfigurationError.providerConfigurationMissingRecordRevision
        }
        let schemaVersionValue = try integerValue(
            propertyList["schemaVersion"],
            wrongTypeError: .providerConfigurationWrongSchemaVersionType,
            invalidValueError: .providerConfigurationUnsupportedSchemaVersion
        )
        guard schemaVersionValue <= Int64(UInt32.max) else {
            throw RuntimeConfigurationError.providerConfigurationUnsupportedSchemaVersion
        }
        let schemaVersion = UInt32(schemaVersionValue)
        guard schemaVersion == RuntimeConfigurationProtocol.providerConfigurationSchemaVersion else {
            throw RuntimeConfigurationError.providerConfigurationUnsupportedSchemaVersion
        }
        guard let profileIDText = propertyList["profileID"] as? String else {
            throw RuntimeConfigurationError.providerConfigurationWrongProfileIDType
        }
        let trimmedProfileID = profileIDText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmedProfileID.isEmpty == false else {
            throw RuntimeConfigurationError.providerConfigurationMissingProfileID
        }
        guard let profileID = UUID(uuidString: trimmedProfileID) else {
            throw RuntimeConfigurationError.providerConfigurationMalformedProfileID
        }
        let recordRevision = try positiveIntegerValue(
            propertyList["recordRevision"],
            wrongTypeError: .providerConfigurationWrongRecordRevisionType,
            invalidValueError: .providerConfigurationInvalidRecordRevision
        )
        return RuntimeProviderConfiguration(schemaVersion: schemaVersion, profileID: profileID, recordRevision: recordRevision)
    }

    static func revisionToken(for sharedRecordRevision: String) throws -> Int64 {
        let trimmed = sharedRecordRevision.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false else {
            throw RuntimeConfigurationError.providerConfigurationInvalidRecordRevision
        }
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in trimmed.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001b3
        }
        let token = Int64(hash & 0x7fff_ffff_ffff_ffff)
        return token == 0 ? 1 : token
    }

    static func isRecognizedSentinelBootstrap(_ propertyList: [String: Any]?) -> Bool {
        guard let propertyList else {
            return false
        }
        guard Set(propertyList.keys) == ["schemaVersion", "diagnosticPurpose"] else {
            return false
        }
        guard let purpose = propertyList["diagnosticPurpose"] as? String,
              purpose == "sharedKeychainSentinel" else {
            return false
        }
        guard let schema = try? integerValue(
            propertyList["schemaVersion"],
            wrongTypeError: .providerConfigurationWrongSchemaVersionType,
            invalidValueError: .providerConfigurationUnsupportedSchemaVersion
        ) else {
            return false
        }
        return schema == Int64(TunnelMessageProtocol.schemaVersion)
    }

    static func diagnostic(
        for propertyList: [String: Any]?,
        category: TunnelRuntimeConfigurationValidationCategory
    ) -> TunnelProviderConfigurationDiagnostic {
        guard let propertyList else {
            return TunnelProviderConfigurationDiagnostic(
                keyCount: nil,
                keyNames: nil,
                valueTypesByKey: nil,
                parseSubreason: category
            )
        }

        let keyNames = propertyList.keys.sorted()
        let valueTypes = Dictionary(uniqueKeysWithValues: keyNames.map { key in
            (key, safeFoundationTypeName(for: propertyList[key]))
        })
        return TunnelProviderConfigurationDiagnostic(
            keyCount: propertyList.count,
            keyNames: keyNames,
            valueTypesByKey: valueTypes,
            parseSubreason: category
        )
    }

    private static func positiveIntegerValue(
        _ value: Any?,
        wrongTypeError: RuntimeConfigurationError,
        invalidValueError: RuntimeConfigurationError
    ) throws -> Int64 {
        let integer = try integerValue(value, wrongTypeError: wrongTypeError, invalidValueError: invalidValueError)
        guard integer > 0 else {
            throw invalidValueError
        }
        return integer
    }

    private static func integerValue(
        _ value: Any?,
        wrongTypeError: RuntimeConfigurationError,
        invalidValueError: RuntimeConfigurationError
    ) throws -> Int64 {
        guard let value else {
            throw wrongTypeError
        }
        guard let number = value as? NSNumber, isBooleanNumber(number) == false else {
            throw wrongTypeError
        }
        let decimal = number.decimalValue
        guard decimal.exponent >= 0 else {
            throw wrongTypeError
        }
        let int64 = number.int64Value
        guard int64 >= 0, NSDecimalNumber(value: int64).decimalValue == decimal else {
            throw invalidValueError
        }
        return int64
    }

    private static func isBooleanNumber(_ number: NSNumber) -> Bool {
        CFGetTypeID(number) == CFBooleanGetTypeID()
    }

    private static func safeFoundationTypeName(for value: Any?) -> String {
        guard let value else {
            return "missing"
        }
        if let number = value as? NSNumber, isBooleanNumber(number) {
            return "Bool"
        }
        switch value {
        case is NSString, is String:
            return "String"
        case is NSNumber:
            return "Number"
        case is NSArray, is [Any]:
            return "Array"
        case is NSDictionary, is [String: Any]:
            return "Dictionary"
        case is NSNull:
            return "Null"
        default:
            return String(describing: type(of: value))
        }
    }
}

nonisolated enum CredentialReferenceValidator {
    static func account(from reference: String) throws -> (service: String, account: String) {
        let trimmed = reference.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false else {
            throw RuntimeConfigurationError.missingCredentialReference
        }
        guard let components = URLComponents(string: trimmed),
              components.scheme == "keychain",
              let service = components.host,
              service.isEmpty == false,
              components.path.split(separator: "/").count == 1,
              let account = components.path.split(separator: "/").first,
              account.isEmpty == false else {
            throw RuntimeConfigurationError.malformedCredentialReference
        }
        return (service, String(account))
    }

    static func isValid(_ reference: String) -> Bool {
        (try? account(from: reference)) != nil
    }
}

protocol RuntimeCredentialResolving: Sendable {
    func credential(for reference: String) async throws -> String?
}

actor KeychainRuntimeCredentialResolver: RuntimeCredentialResolving {
    private let accessGroupResolver: @Sendable () throws -> String

    init(accessGroupResolver: @escaping @Sendable () throws -> String = { try TunnelSharedKeychainAccessGroup.resolvedAccessGroup() }) {
        self.accessGroupResolver = accessGroupResolver
    }

    func credential(for reference: String) async throws -> String? {
        let parsed = try CredentialReferenceValidator.account(from: reference)
        let accessGroup: String
        do {
            accessGroup = try accessGroupResolver()
        } catch {
            throw RuntimeConfigurationError.sharedKeychainConfigurationInvalid
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(copyQuery(service: parsed.service, account: parsed.account, accessGroup: accessGroup) as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw RuntimeConfigurationError.credentialUnavailable
        }
        guard let data = result as? Data else {
            throw RuntimeConfigurationError.credentialMalformed
        }
        return String(data: data, encoding: .utf8)
    }

    private func copyQuery(service: String, account: String, accessGroup: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecUseDataProtectionKeychain as String: true
        ]
    }
}
