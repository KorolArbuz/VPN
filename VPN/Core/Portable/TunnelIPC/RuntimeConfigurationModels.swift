//
//  RuntimeConfigurationModels.swift
//  VPN
//
//  Secret-free shared runtime profile records and K2 validation helpers.
//  This layer prepares configuration identity only; it never starts a tunnel.
//

import Foundation

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

nonisolated enum SharedRuntimeProtocolKind: String, Codable, Equatable, Sendable {
    case vless
    case vmess
    case trojan
    case shadowsocks
    case hysteria2
}

nonisolated enum SharedRuntimeBackendKind: String, Codable, Equatable, Sendable {
    case xray
}

nonisolated enum SharedRuntimeTransportKind: String, Codable, Equatable, Sendable {
    case tcp
    case websocket
    case grpc
    case httpUpgrade
    case xhttp
    case hysteria
}

nonisolated enum SharedRuntimeSecurityKind: String, Codable, Equatable, Sendable {
    case none
    case tls
    case reality
}

nonisolated enum SharedRuntimeCompleteness: String, Codable, Equatable, Sendable {
    case complete
    case incomplete
}

nonisolated struct SharedRuntimeEndpoint: Codable, Equatable, Sendable {
    var host: String
    var port: Int
}

nonisolated struct SharedRuntimeTransport: Codable, Equatable, Sendable {
    var kind: SharedRuntimeTransportKind
    var path: String?
    var host: String?
    var serviceName: String?
    var mode: String?
    var xhttp: SharedRuntimeXHTTPParameters?

    enum CodingKeys: String, CodingKey {
        case kind
        case path
        case host
        case serviceName
        case mode
        case xhttp
    }
}

nonisolated enum SharedRuntimeXHTTPMode: String, Codable, Equatable, Sendable {
    case auto
    case packetUp = "packet-up"
    case streamUp = "stream-up"
    case streamOne = "stream-one"
}

nonisolated struct SharedRuntimeXHTTPParameters: Codable, Equatable, Sendable, CustomDebugStringConvertible {
    var path: String?
    var host: String?
    var mode: SharedRuntimeXHTTPMode?

    enum CodingKeys: String, CodingKey {
        case path
        case host
        case mode
    }

    var debugDescription: String {
        "SharedRuntimeXHTTPParameters(path: <redacted>, host: <redacted>, mode: \(mode?.rawValue ?? "<none>"))"
    }
}

nonisolated struct SharedRuntimeRealityPublicParameters: Codable, Equatable, Sendable, CustomDebugStringConvertible {
    var serverName: String
    var publicKey: String
    var shortID: String
    var fingerprint: String?
    var spiderX: String?

    var debugDescription: String {
        "SharedRuntimeRealityPublicParameters(serverName: <redacted>, publicKey: <redacted>, shortID: <redacted>, fingerprint: \(fingerprint ?? "<none>"), spiderX: <redacted>)"
    }
}

nonisolated struct SharedRuntimeSecurity: Codable, Equatable, Sendable {
    var kind: SharedRuntimeSecurityKind
    var serverName: String?
    var allowInsecure: Bool
    var fingerprint: String?
    var alpn: [String]?
    var shortID: String?
    var reality: SharedRuntimeRealityPublicParameters?

    init(
        kind: SharedRuntimeSecurityKind,
        serverName: String? = nil,
        allowInsecure: Bool = false,
        fingerprint: String? = nil,
        alpn: [String]? = nil,
        shortID: String? = nil,
        reality: SharedRuntimeRealityPublicParameters? = nil
    ) {
        self.kind = kind
        self.serverName = serverName
        self.allowInsecure = allowInsecure
        self.fingerprint = fingerprint
        self.alpn = alpn
        self.shortID = shortID
        self.reality = reality
    }
}

nonisolated struct SharedRuntimeVLESSParameters: Codable, Equatable, Sendable {
    var flow: String?
    var encryption: String?
}

nonisolated struct SharedRuntimeVMessParameters: Codable, Equatable, Sendable {
    var alterID: Int?
    var security: String?
}

nonisolated struct SharedRuntimeTrojanParameters: Codable, Equatable, Sendable {
    var alpn: [String]
}

nonisolated struct SharedRuntimeShadowsocksParameters: Codable, Equatable, Sendable {
    var method: String?
    var plugin: String?
    var isOutlineStaticKey: Bool
}

nonisolated struct SharedRuntimeHysteria2Parameters: Codable, Equatable, Sendable {
    var obfs: String?
    var bandwidthHint: String?
    var obfsPasswordReference: String?
}

nonisolated struct SharedRuntimeProfileRecord: Codable, Equatable, Sendable, CustomDebugStringConvertible {
    var schemaVersion: UInt32
    var profileID: UUID
    var recordRevision: String
    var updatedAt: Date
    var enabled: Bool
    var completeness: SharedRuntimeCompleteness
    var credentialReference: String
    var protocolKind: SharedRuntimeProtocolKind
    var backendKind: SharedRuntimeBackendKind
    var endpoint: SharedRuntimeEndpoint
    var transport: SharedRuntimeTransport
    var security: SharedRuntimeSecurity
    var vless: SharedRuntimeVLESSParameters
    var vmess: SharedRuntimeVMessParameters?
    var trojan: SharedRuntimeTrojanParameters?
    var shadowsocks: SharedRuntimeShadowsocksParameters?
    var hysteria2: SharedRuntimeHysteria2Parameters?

    enum CodingKeys: String, CodingKey {
        case schemaVersion
        case profileID
        case recordRevision
        case updatedAt
        case enabled
        case completeness
        case credentialReference
        case protocolKind
        case backendKind
        case endpoint
        case transport
        case security
        case vless
        case vmess
        case trojan
        case shadowsocks
        case hysteria2
    }

    var debugDescription: String {
        "SharedRuntimeProfileRecord(profileID: \(profileID.uuidString), recordRevision: \(recordRevision), protocol: \(protocolKind.rawValue), endpoint: <redacted>, credentialReference: <redacted>)"
    }

    var credentialReferences: Set<String> {
        var references: Set<String> = [credentialReference]
        if let obfsPasswordReference = hysteria2?.obfsPasswordReference {
            references.insert(obfsPasswordReference)
        }
        return references
    }
}

nonisolated struct SharedRuntimeProfileCollection: Codable, Equatable, Sendable, CustomDebugStringConvertible {
    var schemaVersion: UInt32
    var records: [SharedRuntimeProfileRecord]

    enum CodingKeys: String, CodingKey {
        case schemaVersion
        case records
    }

    init(
        schemaVersion: UInt32 = RuntimeConfigurationProtocol.profileCollectionSchemaVersion,
        records: [SharedRuntimeProfileRecord]
    ) {
        self.schemaVersion = schemaVersion
        self.records = records.sorted { lhs, rhs in
            lhs.profileID.uuidString < rhs.profileID.uuidString
        }
    }

    var debugDescription: String {
        "SharedRuntimeProfileCollection(schemaVersion: \(schemaVersion), records: \(records.count), payload: <redacted>)"
    }
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

    init(
        schemaVersion: UInt32 = RuntimeConfigurationProtocol.providerConfigurationSchemaVersion,
        profileID: UUID,
        sharedRecordRevision: String
    ) throws {
        self.init(
            schemaVersion: schemaVersion,
            profileID: profileID,
            recordRevision: try Self.revisionToken(for: sharedRecordRevision)
        )
    }

    var propertyList: [String: NSObject] {
        [
            "schemaVersion": NSNumber(value: schemaVersion),
            "profileID": profileID.uuidString as NSString,
            "recordRevision": NSNumber(value: recordRevision)
        ]
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
        return RuntimeProviderConfiguration(
            schemaVersion: schemaVersion,
            profileID: profileID,
            recordRevision: recordRevision
        )
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

nonisolated protocol SharedRuntimeProfileStoring: Sendable {
    func write(_ record: SharedRuntimeProfileRecord) async throws
    func read(profileID: UUID) async throws -> SharedRuntimeProfileRecord
    func records() async throws -> [SharedRuntimeProfileRecord]
    func replaceAll(_ records: [SharedRuntimeProfileRecord]) async throws
    func delete(profileID: UUID) async throws
}

actor FileSharedRuntimeProfileStore: SharedRuntimeProfileStoring {
    private let rootDirectory: URL
    private let fileManager: FileManager
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let maximumRecordBytes: Int
    private let maximumCollectionBytes: Int
    private let maximumRecordCount: Int

    init(
        rootDirectory: URL,
        fileManager: FileManager = .default,
        maximumRecordBytes: Int = RuntimeConfigurationProtocol.maximumRecordBytes,
        maximumCollectionBytes: Int = RuntimeConfigurationProtocol.maximumCollectionBytes,
        maximumRecordCount: Int = RuntimeConfigurationProtocol.maximumProfileRecordCount
    ) {
        self.rootDirectory = rootDirectory
        self.fileManager = fileManager
        self.maximumRecordBytes = maximumRecordBytes
        self.maximumCollectionBytes = maximumCollectionBytes
        self.maximumRecordCount = maximumRecordCount
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    static func appGroupStore(fileManager: FileManager = .default) -> FileSharedRuntimeProfileStore? {
        guard let containerURL = fileManager.containerURL(forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier) else {
            return nil
        }
        return FileSharedRuntimeProfileStore(
            rootDirectory: containerURL
                .appendingPathComponent("RuntimeProfiles", isDirectory: true),
            fileManager: fileManager
        )
    }

    func write(_ record: SharedRuntimeProfileRecord) async throws {
        var records = try loadCollection().records
        records.removeAll { $0.profileID == record.profileID }
        records.append(record)
        try writeCollection(SharedRuntimeProfileCollection(records: records))
    }

    func read(profileID: UUID) async throws -> SharedRuntimeProfileRecord {
        let collection = try loadCollection()
        guard let record = collection.records.first(where: { $0.profileID == profileID }) else {
            throw RuntimeConfigurationError.profileRecordNotFound
        }
        return record
    }

    func records() async throws -> [SharedRuntimeProfileRecord] {
        try loadCollection().records
    }

    func replaceAll(_ records: [SharedRuntimeProfileRecord]) async throws {
        try writeCollection(SharedRuntimeProfileCollection(records: records))
    }

    func delete(profileID: UUID) async throws {
        var records = try loadCollection().records
        records.removeAll { $0.profileID == profileID }
        try writeCollection(SharedRuntimeProfileCollection(records: records))
    }

    private var collectionFileURL: URL {
        rootDirectory.appendingPathComponent("runtime-profiles-v1", isDirectory: false).appendingPathExtension("json")
    }

    private func loadCollection() throws -> SharedRuntimeProfileCollection {
        let fileURL = collectionFileURL
        guard fileManager.fileExists(atPath: fileURL.path) else {
            return SharedRuntimeProfileCollection(records: [])
        }
        do {
            let values = try fileURL.resourceValues(forKeys: [.fileSizeKey])
            if let size = values.fileSize, size > maximumCollectionBytes {
                throw RuntimeConfigurationError.profileRecordTooLarge
            }
            let data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
            guard data.count <= maximumCollectionBytes else {
                throw RuntimeConfigurationError.profileRecordTooLarge
            }
            let collection = try decoder.decode(SharedRuntimeProfileCollection.self, from: data)
            try validate(collection)
            return collection
        } catch let error as RuntimeConfigurationError {
            throw error
        } catch {
            throw RuntimeConfigurationError.profileRecordMalformed
        }
    }

    private func writeCollection(_ collection: SharedRuntimeProfileCollection) throws {
        try validate(collection)
        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        try setFileProtectionIfPossible(rootDirectory)
        var directoryValues = URLResourceValues()
        directoryValues.isExcludedFromBackup = true
        var mutableDirectoryURL = rootDirectory
        try? mutableDirectoryURL.setResourceValues(directoryValues)

        let data = try encoder.encode(collection)
        guard data.count <= maximumCollectionBytes else {
            throw RuntimeConfigurationError.profileRecordTooLarge
        }
        do {
            try data.write(to: collectionFileURL, options: [.atomic])
            try setFileProtectionIfPossible(collectionFileURL)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var mutableFileURL = collectionFileURL
            try? mutableFileURL.setResourceValues(values)
        } catch {
            throw RuntimeConfigurationError.writeFailed
        }
    }

    private func validate(_ collection: SharedRuntimeProfileCollection) throws {
        guard collection.schemaVersion == RuntimeConfigurationProtocol.profileCollectionSchemaVersion else {
            throw RuntimeConfigurationError.profileSchemaMismatch
        }
        guard collection.records.count <= maximumRecordCount else {
            throw RuntimeConfigurationError.profileRecordCountExceeded
        }
        let ids = collection.records.map(\.profileID)
        guard Set(ids).count == ids.count else {
            throw RuntimeConfigurationError.profileRecordMalformed
        }
        for record in collection.records {
            guard record.schemaVersion == RuntimeConfigurationProtocol.profileSchemaVersion else {
                throw RuntimeConfigurationError.profileSchemaMismatch
            }
            let data = try encoder.encode(record)
            guard data.count <= maximumRecordBytes else {
                throw RuntimeConfigurationError.profileRecordTooLarge
            }
        }
    }

    private func setFileProtectionIfPossible(_ url: URL) throws {
        #if os(iOS)
        try? fileManager.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: url.path
        )
        #endif
    }
}

nonisolated enum CredentialReferenceValidator {
    static func account(from reference: String) throws -> String {
        let trimmed = reference.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false else {
            throw RuntimeConfigurationError.missingCredentialReference
        }
        guard let components = URLComponents(string: trimmed),
              components.scheme == "keychain",
              let host = components.host,
              host.isEmpty == false,
              components.path.split(separator: "/").count == 1,
              let account = components.path.split(separator: "/").first,
              account.isEmpty == false else {
            throw RuntimeConfigurationError.malformedCredentialReference
        }
        return String(account)
    }

    static func isValid(_ reference: String) -> Bool {
        (try? account(from: reference)) != nil
    }
}

nonisolated struct SharedRuntimeProfileMapper {
    private let compiler: ProfileConfigurationCompiling
    private let now: @Sendable () -> Date

    init(
        compiler: ProfileConfigurationCompiling = CompositeProfileConfigurationCompiler(),
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.compiler = compiler
        self.now = now
    }

    func record(from profile: VPNProfile) throws -> SharedRuntimeProfileRecord {
        guard profile.isEnabled else {
            throw RuntimeConfigurationError.profileDisabled
        }
        guard profile.isComplete else {
            throw RuntimeConfigurationError.profileIncomplete
        }
        guard let protocolKind = SharedRuntimeProtocolKind(profile.protocolType) else {
            throw RuntimeConfigurationError.unsupportedProtocol
        }

        let coreConfiguration: CoreConfiguration
        do {
            coreConfiguration = try compiler.compile(profile: profile)
        } catch CoreError.missingCredential {
            throw RuntimeConfigurationError.missingCredentialReference
        } catch CoreError.unsupportedProtocol {
            throw RuntimeConfigurationError.unsupportedProtocol
        } catch CoreError.invalidConfiguration(let message) {
            let lowercased = message.lowercased()
            if lowercased.contains("reality") || lowercased.contains("public key") || lowercased.contains("short id") || lowercased.contains("fingerprint") {
                throw RuntimeConfigurationError.invalidSecurityConfiguration
            }
            if lowercased.contains("xhttp mode") {
                throw RuntimeConfigurationError.invalidXHTTPMode
            }
            if lowercased.contains("xhttp") {
                throw RuntimeConfigurationError.invalidXHTTPConfiguration
            }
            if lowercased.contains("transport") {
                throw RuntimeConfigurationError.unsupportedTransport
            }
            if lowercased.contains("unsupported") || lowercased.contains("not supported") {
                throw RuntimeConfigurationError.unsupportedProtocol
            }
            throw RuntimeConfigurationError.invalidEndpoint
        } catch {
            throw RuntimeConfigurationError.invalidEndpoint
        }

        guard coreConfiguration.endpoint.host.isEmpty == false,
              coreConfiguration.endpoint.host.contains(" ") == false,
              (1...65_535).contains(coreConfiguration.endpoint.port) else {
            throw RuntimeConfigurationError.invalidEndpoint
        }
        guard CredentialReferenceValidator.isValid(coreConfiguration.credentialReference) else {
            throw RuntimeConfigurationError.malformedCredentialReference
        }

        let protocolParameters = try SharedRuntimeProtocolParameters(profile: profile)

        let recordWithoutRevision = SharedRuntimeProfileRecord(
            schemaVersion: RuntimeConfigurationProtocol.profileSchemaVersion,
            profileID: coreConfiguration.profileID,
            recordRevision: "",
            updatedAt: now(),
            enabled: profile.isEnabled,
            completeness: profile.isComplete ? .complete : .incomplete,
            credentialReference: coreConfiguration.credentialReference,
            protocolKind: protocolKind,
            backendKind: .xray,
            endpoint: coreConfiguration.endpoint.sharedRuntimeEndpoint,
            transport: try SharedRuntimeTransport(coreConfiguration.transport, protocolKind: protocolKind),
            security: try SharedRuntimeSecurity(coreConfiguration.security),
            vless: protocolParameters.vless ?? SharedRuntimeVLESSParameters(flow: nil, encryption: nil),
            vmess: protocolParameters.vmess,
            trojan: protocolParameters.trojan,
            shadowsocks: protocolParameters.shadowsocks,
            hysteria2: protocolParameters.hysteria2
        )

        var record = recordWithoutRevision
        record.recordRevision = try RuntimeProfileRevisionCalculator.revision(for: recordWithoutRevision)
        return record
    }
}

nonisolated enum VPNRuntimeUnsupportedFeature: String, Equatable, Sendable {
    case shadowsocksPlugin
    case shadowsocksMethod
    case hysteria2Bandwidth
    case hysteria2CertificatePinning
    case hysteria2ECH
    case hysteria2PortHopping
    case hysteria2Obfuscation
    case tcpHeader
    case packetEncoding
    case mux
    case realityALPN
    case vlessEncryption
    case vlessFlow
    case vmessCipher
    case runtimeConfiguration
    case nativeProtocolMode
}

nonisolated enum VPNRuntimeCapabilityIssue: Equatable, Sendable {
    case unsupportedProtocol(VPNProtocol)
    case unsupportedTransport(protocolType: VPNProtocol, transport: String)
    case unsupportedSecurity(protocolType: VPNProtocol, security: String)
    case unsupportedFeature(
        protocolType: VPNProtocol,
        feature: VPNRuntimeUnsupportedFeature,
        detail: String? = nil
    )
    case invalidConfiguration(protocolType: VPNProtocol, component: String)

    var message: String {
        switch self {
        case .unsupportedProtocol(let protocolType):
            if protocolType == .tuic {
                return "TUIC runtime is not available in this build."
            }
            return "\(protocolType.displayName) runtime is not available in this build."
        case .unsupportedTransport(let protocolType, let transport):
            return "\(protocolType.displayName) transport \"\(transport)\" is not supported by this build."
        case .unsupportedSecurity(let protocolType, let security):
            return "\(protocolType.displayName) security mode \"\(security)\" is not supported by this build."
        case .unsupportedFeature(let protocolType, let feature, let detail):
            switch feature {
            case .shadowsocksPlugin:
                if let detail {
                    return "Shadowsocks plugin \"\(detail)\" is not supported by this build."
                }
                return "Shadowsocks plugins are not supported by this build."
            case .shadowsocksMethod:
                return "The imported Shadowsocks encryption method is not supported by this build."
            case .hysteria2Bandwidth:
                return "Hysteria2 bandwidth hints are not supported by this build."
            case .hysteria2CertificatePinning:
                return "Hysteria2 certificate pinning is not supported by this build."
            case .hysteria2ECH:
                return "Hysteria2 ECH is not supported by this build."
            case .hysteria2PortHopping:
                return "Hysteria2 port hopping is not supported by this build."
            case .hysteria2Obfuscation:
                return "The requested Hysteria2 obfuscation is not supported by this build."
            case .tcpHeader:
                return "The requested \(protocolType.displayName) TCP header mode is not supported by this build."
            case .packetEncoding:
                return "The requested \(protocolType.displayName) packet encoding is not supported by this build."
            case .mux:
                return "The requested \(protocolType.displayName) mux setting is not supported by this build."
            case .realityALPN:
                return "Custom ALPN values with \(protocolType.displayName) REALITY are not supported by this build."
            case .vlessEncryption:
                return "The requested VLESS encryption mode is not supported by this build."
            case .vlessFlow:
                return "The requested VLESS flow is not supported for this configuration."
            case .vmessCipher:
                return "The requested VMess cipher is not supported by this build."
            case .runtimeConfiguration:
                return "This \(protocolType.displayName) configuration is not supported by the current runtime."
            case .nativeProtocolMode:
                return "This \(protocolType.displayName) native protocol configuration is not supported."
            }
        case .invalidConfiguration(let protocolType, let component):
            return "The \(protocolType.displayName) \(component) configuration is invalid."
        }
    }
}

nonisolated enum VPNRuntimeCapability: Equatable, Sendable {
    case ready
    case incomplete([String])
    case unsupported(VPNRuntimeCapabilityIssue)
    case invalid(VPNRuntimeCapabilityIssue)

    var isReady: Bool {
        self == .ready
    }

    var statusText: String {
        switch self {
        case .ready:
            return "Ready"
        case .incomplete(let fields):
            return "Incomplete: \(fields.joined(separator: ", "))"
        case .unsupported(let issue):
            return "Unsupported: \(issue.message)"
        case .invalid(let issue):
            return "Invalid: \(issue.message)"
        }
    }

    var issue: VPNRuntimeCapabilityIssue? {
        switch self {
        case .ready, .incomplete:
            return nil
        case .unsupported(let issue), .invalid(let issue):
            return issue
        }
    }
}

nonisolated struct VPNRuntimeCapabilityEvaluator {
    private let mapper: SharedRuntimeProfileMapper
    private let builder: XrayConfigurationBuilder

    init(
        mapper: SharedRuntimeProfileMapper = SharedRuntimeProfileMapper(),
        builder: XrayConfigurationBuilder = XrayConfigurationBuilder()
    ) {
        self.mapper = mapper
        self.builder = builder
    }

    func evaluate(_ profile: VPNProfile) -> VPNRuntimeCapability {
        if profile.protocolType == .wireGuard || profile.protocolType == .amneziaWG {
            var enabledProfile = profile
            enabledProfile.isEnabled = true
            return NativeWireGuardProfileValidator.capability(for: enabledProfile)
        }
        guard profile.isComplete else {
            return .incomplete(profile.missingRequiredFields)
        }
        if let capability = explicitCapabilityFailure(in: profile) {
            return capability
        }

        var enabledProfile = profile
        enabledProfile.isEnabled = true

        do {
            let record = try mapper.record(from: enabledProfile)
            let resolved = resolvedConfiguration(forCapabilityCheck: record)
            _ = try builder.build(from: resolved, options: XrayBuildOptions())
            return .ready
        } catch let error as RuntimeConfigurationError {
            return capability(for: error, profile: profile)
        } catch let error as XrayConfigurationBuilderError {
            return capability(for: error, profile: profile)
        } catch {
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "runtime"))
        }
    }

    private func explicitCapabilityFailure(in profile: VPNProfile) -> VPNRuntimeCapability? {
        switch profile.protocolType {
        case .wireGuard, .amneziaWG, .ikev2, .tuic:
            return .unsupported(.unsupportedProtocol(profile.protocolType))
        case .vless, .vmess, .trojan, .shadowsocks, .hysteria2:
            break
        }

        if let headerType = metadataValue(in: profile, keys: ["headerType", "header-type"]),
           ["", "none"].contains(headerType.lowercased()) == false {
            return .unsupported(.unsupportedFeature(
                protocolType: profile.protocolType,
                feature: .tcpHeader
            ))
        }
        if let packetEncoding = metadataValue(in: profile, keys: ["packetEncoding", "packet-encoding"]),
           ["", "none"].contains(packetEncoding.lowercased()) == false {
            return .unsupported(.unsupportedFeature(
                protocolType: profile.protocolType,
                feature: .packetEncoding
            ))
        }
        if let mux = metadataValue(in: profile, keys: ["mux"]),
           ["", "0", "false", "none", "off"].contains(mux.lowercased()) == false {
            return .unsupported(.unsupportedFeature(protocolType: profile.protocolType, feature: .mux))
        }
        if normalizedSecurity(profile) == "reality", hasCustomRealityALPN(in: profile) {
            return .unsupported(.unsupportedFeature(protocolType: profile.protocolType, feature: .realityALPN))
        }
        let requestedSecurity = normalizedSecurity(profile)
        let supportedSecurities: Set<String>?
        switch profile.protocolType {
        case .vless:
            supportedSecurities = ["tls", "reality"]
        case .vmess:
            supportedSecurities = ["none", "tls", "reality"]
        case .trojan:
            supportedSecurities = ["tls", "reality"]
        case .wireGuard, .amneziaWG, .ikev2, .shadowsocks, .hysteria2, .tuic:
            supportedSecurities = nil
        }
        if let supportedSecurities, supportedSecurities.contains(requestedSecurity) == false {
            return .unsupported(.unsupportedSecurity(
                protocolType: profile.protocolType,
                security: sanitizedLabel(requestedSecurity)
            ))
        }

        switch profile.protocolConfiguration {
        case .vless(let configuration):
            let encryption = normalized(configuration.encryption)?.lowercased()
            if let encryption, encryption != "none" {
                return .unsupported(.unsupportedFeature(protocolType: .vless, feature: .vlessEncryption))
            }
            if let flow = normalized(configuration.flow)?.lowercased() {
                guard flow == "xtls-rprx-vision" else {
                    return .unsupported(.unsupportedFeature(protocolType: .vless, feature: .vlessFlow))
                }
                let network = normalizedNetwork(profile)
                guard ["tcp", "xhttp", "splithttp"].contains(network) else {
                    return .unsupported(.unsupportedFeature(protocolType: .vless, feature: .vlessFlow))
                }
            }
        case .vmess(let configuration):
            if let alterID = configuration.alterID, alterID < 0 {
                return .invalid(.invalidConfiguration(protocolType: .vmess, component: "alter ID"))
            }
            if let cipher = normalized(configuration.security)?.lowercased(),
               ["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"].contains(cipher) == false {
                return .unsupported(.unsupportedFeature(protocolType: .vmess, feature: .vmessCipher))
            }
        case .trojan:
            break
        case .shadowsocks(let configuration):
            let plugin = normalized(configuration.plugin)
                ?? metadataValue(in: profile, keys: ["plugin"])
            if let plugin {
                return .unsupported(.unsupportedFeature(
                    protocolType: .shadowsocks,
                    feature: .shadowsocksPlugin,
                    detail: sanitizedPluginName(plugin)
                ))
            }
        case .hysteria2(let configuration):
            if normalized(configuration.bandwidthHint) != nil {
                return .unsupported(.unsupportedFeature(protocolType: .hysteria2, feature: .hysteria2Bandwidth))
            }
            if metadataValue(in: profile, keys: ["pinSHA256", "pin-sha256"]) != nil {
                return .unsupported(.unsupportedFeature(protocolType: .hysteria2, feature: .hysteria2CertificatePinning))
            }
            if profile.metadata.merging(profile.transportSettings.metadata, uniquingKeysWith: { current, _ in current }).contains(where: { key, value in
                guard normalized(value) != nil else { return false }
                let normalizedKey = key
                    .replacingOccurrences(of: "-", with: "")
                    .replacingOccurrences(of: "_", with: "")
                    .lowercased()
                return ["ech", "echconfig", "echconfiglist"].contains(normalizedKey)
            }) {
                return .unsupported(.unsupportedFeature(protocolType: .hysteria2, feature: .hysteria2ECH))
            }
            if metadataValue(in: profile, keys: ["mport"]) != nil {
                return .unsupported(.unsupportedFeature(protocolType: .hysteria2, feature: .hysteria2PortHopping))
            }
            if let alpn = metadataValue(in: profile, keys: ["alpn"]) {
                let values = alpn.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                if values.isEmpty == false, values != ["h3"] {
                    return .unsupported(.unsupportedFeature(protocolType: .hysteria2, feature: .runtimeConfiguration))
                }
            }
            if let obfs = normalized(configuration.obfs)?.lowercased() {
                guard obfs == "salamander" else {
                    return .unsupported(.unsupportedFeature(protocolType: .hysteria2, feature: .hysteria2Obfuscation))
                }
                guard normalized(configuration.obfsPasswordReference) != nil else {
                    return .invalid(.invalidConfiguration(protocolType: .hysteria2, component: "obfuscation password"))
                }
            }
        case .wireGuard, .amneziaWG, .ikev2, .tuic:
            break
        }

        return nil
    }

    private func hasCustomRealityALPN(in profile: VPNProfile) -> Bool {
        let tlsALPN = profile.tlsSettings.alpn ?? []
        let protocolALPN: [String]
        if case .trojan(let configuration) = profile.protocolConfiguration {
            protocolALPN = configuration.alpn
        } else {
            protocolALPN = []
        }
        return (tlsALPN + protocolALPN).contains { normalized($0) != nil }
    }

    private func resolvedConfiguration(forCapabilityCheck record: SharedRuntimeProfileRecord) -> ResolvedVLESSRuntimeConfiguration {
        let primaryCredential: String
        switch record.protocolKind {
        case .vless, .vmess:
            primaryCredential = "00000000-0000-4000-8000-000000000001"
        case .trojan, .shadowsocks, .hysteria2:
            primaryCredential = "runtime-capability-check"
        }
        let obfsPassword = record.hysteria2?.obfsPasswordReference == nil
            ? nil
            : SensitiveRuntimeCredential("runtime-capability-check")

        return ResolvedVLESSRuntimeConfiguration(
            profileID: record.profileID,
            recordRevision: record.recordRevision,
            protocolKind: record.protocolKind,
            endpoint: ResolvedRuntimeEndpoint(host: record.endpoint.host, port: record.endpoint.port),
            transport: record.transport,
            security: record.security,
            vless: record.vless,
            vmess: record.vmess,
            trojan: record.trojan,
            shadowsocks: record.shadowsocks,
            hysteria2: record.hysteria2,
            credential: SensitiveRuntimeCredential(primaryCredential),
            hysteria2ObfsPassword: obfsPassword
        )
    }

    private func capability(for error: RuntimeConfigurationError, profile: VPNProfile) -> VPNRuntimeCapability {
        switch error {
        case .profileIncomplete:
            return .incomplete(profile.missingRequiredFields)
        case .unsupportedProtocol:
            return unsupportedRuntimeConfiguration(for: profile)
        case .unsupportedTransport:
            return .unsupported(.unsupportedTransport(
                protocolType: profile.protocolType,
                transport: sanitizedLabel(normalizedNetwork(profile))
            ))
        case .invalidSecurityConfiguration:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "security"))
        case .invalidXHTTPConfiguration, .invalidXHTTPMode, .invalidXHTTPPath, .invalidXHTTPHost:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "XHTTP"))
        case .invalidEndpoint:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "endpoint"))
        case .missingCredentialReference, .malformedCredentialReference, .credentialUnavailable, .credentialMalformed:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "credential"))
        default:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "runtime"))
        }
    }

    private func capability(for error: XrayConfigurationBuilderError, profile: VPNProfile) -> VPNRuntimeCapability {
        switch error {
        case .unsupportedProtocol:
            return unsupportedRuntimeConfiguration(for: profile)
        case .unsupportedTransport:
            return .unsupported(.unsupportedTransport(
                protocolType: profile.protocolType,
                transport: sanitizedLabel(normalizedNetwork(profile))
            ))
        case .unsupportedSecurity:
            return .unsupported(.unsupportedSecurity(
                protocolType: profile.protocolType,
                security: sanitizedLabel(normalizedSecurity(profile))
            ))
        case .invalidTLSConfiguration:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "TLS"))
        case .invalidRealityConfiguration:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "REALITY"))
        case .invalidXHTTPConfiguration, .invalidXHTTPMode, .invalidXHTTPPath, .invalidXHTTPHost:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "XHTTP"))
        case .invalidEndpoint:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "endpoint"))
        case .invalidCredential:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "credential"))
        case .encodingFailed:
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "runtime encoding"))
        }
    }

    private func unsupportedRuntimeConfiguration(for profile: VPNProfile) -> VPNRuntimeCapability {
        switch profile.protocolConfiguration {
        case .shadowsocks(let configuration):
            if normalized(configuration.plugin) != nil || metadataValue(in: profile, keys: ["plugin"]) != nil {
                return .unsupported(.unsupportedFeature(protocolType: .shadowsocks, feature: .shadowsocksPlugin))
            }
            return .unsupported(.unsupportedFeature(protocolType: .shadowsocks, feature: .shadowsocksMethod))
        case .hysteria2(let configuration):
            if normalized(configuration.bandwidthHint) != nil {
                return .unsupported(.unsupportedFeature(protocolType: .hysteria2, feature: .hysteria2Bandwidth))
            }
            return .unsupported(.unsupportedFeature(protocolType: .hysteria2, feature: .hysteria2Obfuscation))
        case .wireGuard, .amneziaWG, .ikev2, .tuic:
            return .unsupported(.unsupportedProtocol(profile.protocolType))
        case .vless, .vmess, .trojan:
            return .unsupported(.unsupportedFeature(protocolType: profile.protocolType, feature: .runtimeConfiguration))
        }
    }

    private func metadataValue(in profile: VPNProfile, keys: Set<String>) -> String? {
        let normalizedKeys = Set(keys.map { $0.lowercased() })
        for metadata in [profile.transportSettings.metadata, profile.metadata] {
            for (key, value) in metadata where normalizedKeys.contains(key.lowercased()) {
                if let value = normalized(value) {
                    return value
                }
            }
        }
        return nil
    }

    private func normalizedNetwork(_ profile: VPNProfile) -> String {
        normalized(profile.transportSettings.network)?.lowercased() ?? (profile.protocolType == .hysteria2 ? "udp" : "tcp")
    }

    private func normalizedSecurity(_ profile: VPNProfile) -> String {
        if let security = normalized(profile.transportSettings.security ?? profile.metadata["security"])?.lowercased() {
            return security
        }
        return profile.tlsSettings.isEnabled ? "tls" : "none"
    }

    private func normalized(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }

    private func sanitizedPluginName(_ value: String) -> String? {
        let name = value.split(separator: ";", maxSplits: 1).first.map(String.init) ?? value
        let sanitized = name.unicodeScalars.filter { scalar in
            CharacterSet.alphanumerics.contains(scalar) || ".-_".unicodeScalars.contains(scalar)
        }
        let label = String(String.UnicodeScalarView(sanitized)).prefix(64)
        return label.isEmpty ? nil : String(label)
    }

    private func sanitizedLabel(_ value: String) -> String {
        let sanitized = value.unicodeScalars.filter { scalar in
            CharacterSet.alphanumerics.contains(scalar) || ".-_".unicodeScalars.contains(scalar)
        }
        let label = String(String.UnicodeScalarView(sanitized)).prefix(32)
        return label.isEmpty ? "requested" : String(label)
    }
}

nonisolated extension VPNProfile {
    var runtimeCapability: VPNRuntimeCapability {
        VPNRuntimeCapabilityEvaluator().evaluate(self)
    }

    var isRuntimeReady: Bool {
        runtimeCapability.isReady
    }
}

private extension SharedRuntimeEndpoint {
    nonisolated init(_ endpoint: CoreEndpoint) {
        self.init(host: endpoint.host, port: endpoint.port)
    }
}

private extension CoreEndpoint {
    nonisolated var sharedRuntimeEndpoint: SharedRuntimeEndpoint {
        SharedRuntimeEndpoint(self)
    }
}

private nonisolated struct SharedRuntimeProtocolParameters {
    var vless: SharedRuntimeVLESSParameters?
    var vmess: SharedRuntimeVMessParameters?
    var trojan: SharedRuntimeTrojanParameters?
    var shadowsocks: SharedRuntimeShadowsocksParameters?
    var hysteria2: SharedRuntimeHysteria2Parameters?

    init(profile: VPNProfile) throws {
        switch profile.protocolConfiguration {
        case .vless(let configuration):
            self.vless = SharedRuntimeVLESSParameters(flow: configuration.flow, encryption: configuration.encryption)
        case .vmess(let configuration):
            self.vmess = SharedRuntimeVMessParameters(alterID: configuration.alterID, security: configuration.security)
        case .trojan(let configuration):
            self.trojan = SharedRuntimeTrojanParameters(alpn: configuration.alpn)
        case .shadowsocks(let configuration):
            let source = profile.metadata["outline"] == "1" || profile.transportSettings.metadata["outline"] == "1"
            self.shadowsocks = SharedRuntimeShadowsocksParameters(
                method: configuration.method,
                plugin: configuration.plugin,
                isOutlineStaticKey: source
            )
        case .hysteria2(let configuration):
            self.hysteria2 = SharedRuntimeHysteria2Parameters(
                obfs: configuration.obfs,
                bandwidthHint: configuration.bandwidthHint,
                obfsPasswordReference: configuration.obfsPasswordReference
            )
        case .wireGuard, .amneziaWG, .ikev2, .tuic:
            throw RuntimeConfigurationError.unsupportedProtocol
        }
    }
}

private extension SharedRuntimeProtocolKind {
    nonisolated init?(_ protocolType: VPNProtocol) {
        switch protocolType {
        case .vless:
            self = .vless
        case .vmess:
            self = .vmess
        case .trojan:
            self = .trojan
        case .shadowsocks:
            self = .shadowsocks
        case .hysteria2:
            self = .hysteria2
        case .wireGuard, .amneziaWG, .ikev2, .tuic:
            return nil
        }
    }
}

private extension SharedRuntimeTransport {
    nonisolated init(_ transport: CoreTransportConfiguration, protocolKind: SharedRuntimeProtocolKind) throws {
        switch transport {
        case .tcp:
            self.init(kind: .tcp, path: nil, host: nil, serviceName: nil, mode: nil, xhttp: nil)
        case .websocket(let path, let host, _):
            self.init(kind: .websocket, path: path, host: host, serviceName: nil, mode: nil, xhttp: nil)
        case .grpc(let serviceName, _):
            self.init(kind: .grpc, path: nil, host: nil, serviceName: serviceName, mode: nil, xhttp: nil)
        case .httpUpgrade(let path, let host, _):
            self.init(kind: .httpUpgrade, path: path, host: host, serviceName: nil, mode: nil, xhttp: nil)
        case .xhttp(let path, let host, let mode, _):
            let xhttp = try SharedRuntimeXHTTPParameters.normalized(path: path, host: host, mode: mode)
            self.init(kind: .xhttp, path: xhttp.path, host: xhttp.host, serviceName: nil, mode: xhttp.mode?.rawValue, xhttp: xhttp)
        case .udp where protocolKind == .hysteria2:
            self.init(kind: .hysteria, path: nil, host: nil, serviceName: nil, mode: nil, xhttp: nil)
        case .udp, .quic:
            throw RuntimeConfigurationError.unsupportedTransport
        }
    }
}

nonisolated enum XHTTPParametersValidator {
    static func validate(_ parameters: SharedRuntimeXHTTPParameters) throws {
        if let path = parameters.path {
            try validatePath(path)
        }
        if let host = parameters.host {
            try validateHost(host)
        }
        if let mode = parameters.mode {
            guard SharedRuntimeXHTTPMode(rawValue: mode.rawValue) != nil else {
                throw RuntimeConfigurationError.invalidXHTTPMode
            }
        }
    }

    static func validate(transport: SharedRuntimeTransport) throws {
        guard transport.kind == .xhttp else {
            return
        }
        guard let parameters = transport.xhttp else {
            throw RuntimeConfigurationError.invalidXHTTPConfiguration
        }
        try validate(parameters)
        if let legacyMode = normalizedOptional(transport.mode),
           SharedRuntimeXHTTPMode(rawValue: legacyMode) == nil {
            throw RuntimeConfigurationError.invalidXHTTPMode
        }
        if let legacyPath = normalizedOptional(transport.path) {
            try validatePath(legacyPath)
        }
        if let legacyHost = normalizedOptional(transport.host) {
            try validateHost(legacyHost)
        }
    }

    private static func validatePath(_ value: String) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false,
              trimmed.hasPrefix("/"),
              trimmed.contains("\n") == false,
              trimmed.contains("\r") == false,
              trimmed.utf8.count <= 512 else {
            throw RuntimeConfigurationError.invalidXHTTPPath
        }
    }

    private static func validateHost(_ value: String) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false,
              trimmed.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              trimmed.rangeOfCharacter(from: CharacterSet.controlCharacters) == nil,
              trimmed.utf8.count <= 255 else {
            throw RuntimeConfigurationError.invalidXHTTPHost
        }
    }

    private nonisolated static func normalizedOptional(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }
}

private extension SharedRuntimeXHTTPParameters {
    nonisolated static func normalized(path: String?, host: String?, mode: String?) throws -> SharedRuntimeXHTTPParameters {
        let normalizedPath = normalizedOptional(path)
        let normalizedHost = normalizedOptional(host)
        let normalizedMode = normalizedOptional(mode)
        let typedMode: SharedRuntimeXHTTPMode?
        if let normalizedMode {
            guard let parsed = SharedRuntimeXHTTPMode(rawValue: normalizedMode) else {
                throw RuntimeConfigurationError.invalidXHTTPMode
            }
            typedMode = parsed
        } else {
            typedMode = nil
        }
        let parameters = SharedRuntimeXHTTPParameters(path: normalizedPath, host: normalizedHost, mode: typedMode)
        try XHTTPParametersValidator.validate(parameters)
        return parameters
    }

    private nonisolated static func normalizedOptional(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }
}

private extension SharedRuntimeSecurity {
    nonisolated init(_ security: CoreSecurityConfiguration) throws {
        switch security {
        case .none:
            self.init(kind: .none, serverName: nil, allowInsecure: false, fingerprint: nil, shortID: nil)
        case .tls(let tls):
            self.init(
                kind: .tls,
                serverName: tls.serverName,
                allowInsecure: tls.allowInsecure,
                fingerprint: tls.fingerprint,
                alpn: tls.alpn,
                shortID: nil
            )
        case .reality(let reality):
            let publicParameters = SharedRuntimeRealityPublicParameters(
                serverName: reality.serverName,
                publicKey: reality.publicKey,
                shortID: reality.shortID,
                fingerprint: reality.fingerprint,
                spiderX: reality.spiderX
            )
            try RealityPublicParametersValidator.validate(publicParameters)
            self.init(
                kind: .reality,
                serverName: nil,
                allowInsecure: false,
                fingerprint: nil,
                shortID: nil,
                reality: publicParameters
            )
        }
    }
}

nonisolated enum RealityPublicParametersValidator {
    private static let supportedFingerprints: Set<String> = [
        "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"
    ]

    static func validate(_ parameters: SharedRuntimeRealityPublicParameters) throws {
        let serverName = parameters.serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard serverName.isEmpty == false, serverName.contains(" ") == false else {
            throw RuntimeConfigurationError.invalidSecurityConfiguration
        }
        guard isValidRealityPublicKey(parameters.publicKey) else {
            throw RuntimeConfigurationError.invalidSecurityConfiguration
        }
        guard isValidRealityShortID(parameters.shortID) else {
            throw RuntimeConfigurationError.invalidSecurityConfiguration
        }
        if let fingerprint = parameters.fingerprint?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
           fingerprint.isEmpty == false,
           supportedFingerprints.contains(fingerprint) == false {
            throw RuntimeConfigurationError.invalidSecurityConfiguration
        }
        if let spiderX = parameters.spiderX {
            guard spiderX.contains("\n") == false, spiderX.contains("\r") == false, spiderX.utf8.count <= 512 else {
                throw RuntimeConfigurationError.invalidSecurityConfiguration
            }
        }
    }

    static func isValidRealityPublicKey(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count == 43 else {
            return false
        }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        return trimmed.unicodeScalars.allSatisfy { scalar in
            allowed.contains(scalar)
        }
    }

    static func isValidRealityShortID(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (2...16).contains(trimmed.count), trimmed.count.isMultiple(of: 2) else {
            return false
        }
        let allowed = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
        return trimmed.unicodeScalars.allSatisfy { scalar in
            allowed.contains(scalar)
        }
    }
}

private nonisolated enum RuntimeProfileRevisionCalculator {
    static func revision(for record: SharedRuntimeProfileRecord) throws -> String {
        var input = record
        input.recordRevision = ""
        input.updatedAt = Date(timeIntervalSince1970: 0)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(input)
        return "v1-\(fnv1a64Hex(data))"
    }

    private static func fnv1a64Hex(_ data: Data) -> String {
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in data {
            hash ^= UInt64(byte)
            hash &*= 0x100000001b3
        }
        return String(hash, radix: 16)
    }
}

nonisolated enum RealityPublicKeyMigration {
    static func profileByResolvingLegacyReferenceIfNeeded(
        in profile: VPNProfile,
        credentialStore: any CredentialStoring
    ) async throws -> VPNProfile {
        let security = profile.transportSettings.security?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            ?? profile.metadata["security"]?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let hasDirectPublicKey = profile.tlsSettings.realityPublicKey?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
        let hasLegacyReference = profile.tlsSettings.publicKeyReference?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
        guard hasDirectPublicKey == false,
              hasLegacyReference,
              security == "reality" || profile.tlsSettings.publicKeyReference != nil else {
            return profile
        }
        guard let reference = profile.tlsSettings.publicKeyReference,
              let publicKey = try await credentialStore.secret(for: reference),
              publicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false else {
            throw RuntimeConfigurationError.invalidSecurityConfiguration
        }

        var migrated = profile
        migrated.tlsSettings.realityPublicKey = publicKey.trimmingCharacters(in: .whitespacesAndNewlines)
        return migrated
    }
}

actor SharedRuntimeProfilePublisher {
    private let mapper: SharedRuntimeProfileMapper
    private let store: any SharedRuntimeProfileStoring
    private let credentialStore: any CredentialStoring

    init(
        mapper: SharedRuntimeProfileMapper = SharedRuntimeProfileMapper(),
        store: any SharedRuntimeProfileStoring,
        credentialStore: any CredentialStoring = KeychainCredentialStore()
    ) {
        self.mapper = mapper
        self.store = store
        self.credentialStore = credentialStore
    }

    static func appGroupPublisher(credentialStore: any CredentialStoring = KeychainCredentialStore()) -> SharedRuntimeProfilePublisher? {
        guard let store = FileSharedRuntimeProfileStore.appGroupStore() else {
            return nil
        }
        return SharedRuntimeProfilePublisher(store: store, credentialStore: credentialStore)
    }

    func publish(_ profile: VPNProfile) async throws -> SharedRuntimeProfileRecord {
        let record = try await preparedRecord(from: profile)
        try await store.write(record)
        return record
    }

    func preparedRecord(from profile: VPNProfile) async throws -> SharedRuntimeProfileRecord {
        let preparedProfile = try await RealityPublicKeyMigration.profileByResolvingLegacyReferenceIfNeeded(
            in: profile,
            credentialStore: credentialStore
        )
        let record = try mapper.record(from: preparedProfile)
        guard CredentialReferenceValidator.isValid(record.credentialReference) else {
            throw RuntimeConfigurationError.malformedCredentialReference
        }
        guard let credential = try await credentialStore.secret(for: record.credentialReference), credential.isEmpty == false else {
            throw RuntimeConfigurationError.credentialUnavailable
        }
        return record
    }

    func delete(profileID: UUID) async throws {
        try await store.delete(profileID: profileID)
    }
}

nonisolated struct RuntimeProfileSynchronizationOmission: Equatable, Sendable {
    var profileID: UUID
    var reason: RuntimeConfigurationError
}

nonisolated struct RuntimeProfileSynchronizationSummary: Equatable, Sendable {
    var publishedProfileIDs: [UUID]
    var omissions: [RuntimeProfileSynchronizationOmission]
}

nonisolated protocol RuntimeProfileSynchronizing: Sendable {
    func profileSaved(_ profile: VPNProfile) async throws -> RuntimeProfileSynchronizationSummary
    func profileDeleted(id: UUID) async throws
    func credentialReferences() async throws -> Set<String>
}

nonisolated struct UnavailableRuntimeProfileSynchronizer: RuntimeProfileSynchronizing {
    func profileSaved(_ profile: VPNProfile) async throws -> RuntimeProfileSynchronizationSummary {
        throw RuntimeConfigurationError.sharedContainerUnavailable
    }

    func profileDeleted(id: UUID) async throws {
        throw RuntimeConfigurationError.sharedContainerUnavailable
    }

    func credentialReferences() async throws -> Set<String> {
        throw RuntimeConfigurationError.sharedContainerUnavailable
    }
}

actor RuntimeProfileSynchronizer: RuntimeProfileSynchronizing {
    private let profileRepository: any VPNProfileRepository
    private let mapper: SharedRuntimeProfileMapper
    private let store: any SharedRuntimeProfileStoring
    private let credentialStore: any CredentialStoring

    init(
        profileRepository: any VPNProfileRepository,
        mapper: SharedRuntimeProfileMapper = SharedRuntimeProfileMapper(),
        store: any SharedRuntimeProfileStoring,
        credentialStore: any CredentialStoring = KeychainCredentialStore()
    ) {
        self.profileRepository = profileRepository
        self.mapper = mapper
        self.store = store
        self.credentialStore = credentialStore
    }

    static func appGroupSynchronizer(
        profileRepository: any VPNProfileRepository,
        credentialStore: any CredentialStoring = KeychainCredentialStore()
    ) -> RuntimeProfileSynchronizer? {
        guard let store = FileSharedRuntimeProfileStore.appGroupStore() else {
            return nil
        }
        return RuntimeProfileSynchronizer(
            profileRepository: profileRepository,
            store: store,
            credentialStore: credentialStore
        )
    }

    func synchronizeExistingProfiles() async throws -> RuntimeProfileSynchronizationSummary {
        let profiles = try await profileRepository.profiles()
        var records: [SharedRuntimeProfileRecord] = []
        var omissions: [RuntimeProfileSynchronizationOmission] = []

        for profile in profiles.sorted(by: { $0.id.uuidString < $1.id.uuidString }) {
            do {
                records.append(try await preparedRecord(from: profile))
            } catch let error as RuntimeConfigurationError {
                omissions.append(RuntimeProfileSynchronizationOmission(profileID: profile.id, reason: error))
            } catch {
                omissions.append(RuntimeProfileSynchronizationOmission(profileID: profile.id, reason: .profileRecordMalformed))
            }
        }

        try await store.replaceAll(records)
        return RuntimeProfileSynchronizationSummary(
            publishedProfileIDs: records.map(\.profileID),
            omissions: omissions
        )
    }

    @discardableResult
    func profileSaved(_ profile: VPNProfile) async throws -> RuntimeProfileSynchronizationSummary {
        do {
            let record = try await preparedRecord(from: profile)
            try await store.write(record)
            return RuntimeProfileSynchronizationSummary(publishedProfileIDs: [record.profileID], omissions: [])
        } catch let error as RuntimeConfigurationError {
            try await store.delete(profileID: profile.id)
            return RuntimeProfileSynchronizationSummary(
                publishedProfileIDs: [],
                omissions: [RuntimeProfileSynchronizationOmission(profileID: profile.id, reason: error)]
            )
        }
    }

    func profileDeleted(id: UUID) async throws {
        try await store.delete(profileID: id)
    }

    func credentialReferences() async throws -> Set<String> {
        let records = try await store.records()
        return records.reduce(into: Set<String>()) { references, record in
            references.formUnion(record.credentialReferences)
        }
    }

    private func preparedRecord(from profile: VPNProfile) async throws -> SharedRuntimeProfileRecord {
        let preparedProfile = try await RealityPublicKeyMigration.profileByResolvingLegacyReferenceIfNeeded(
            in: profile,
            credentialStore: credentialStore
        )
        let record = try mapper.record(from: preparedProfile)
        guard CredentialReferenceValidator.isValid(record.credentialReference) else {
            throw RuntimeConfigurationError.malformedCredentialReference
        }
        guard let credential = try await credentialStore.secret(for: record.credentialReference), credential.isEmpty == false else {
            throw RuntimeConfigurationError.credentialUnavailable
        }
        return record
    }
}

actor RuntimeConfigurationValidationService {
    private let publisher: SharedRuntimeProfilePublisher
    private let messenger: any TunnelRuntimeConfigurationValidationMessaging
    private var nextRequestGeneration: UInt64 = 0

    init(
        publisher: SharedRuntimeProfilePublisher,
        messenger: any TunnelRuntimeConfigurationValidationMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) {
        self.publisher = publisher
        self.messenger = messenger
    }

    static func appGroupService(
        credentialStore: any CredentialStoring = KeychainCredentialStore(),
        messenger: any TunnelRuntimeConfigurationValidationMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) -> RuntimeConfigurationValidationService? {
        guard let publisher = SharedRuntimeProfilePublisher.appGroupPublisher(credentialStore: credentialStore) else {
            return nil
        }
        return RuntimeConfigurationValidationService(publisher: publisher, messenger: messenger)
    }

    func validate(profile: VPNProfile) async throws -> TunnelRuntimeConfigurationValidationResponse {
        try Task.checkCancellation()
        let record = try await publisher.publish(profile)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: record.profileID,
            sharedRecordRevision: record.recordRevision
        )
        nextRequestGeneration &+= 1
        let requestGeneration = nextRequestGeneration
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .validateRuntimeConfiguration,
            payload: .runtimeConfigurationValidation(
                TunnelRuntimeConfigurationValidationRequest(
                    correlationID: correlationID,
                    expectedProfileID: record.profileID,
                    expectedRevisionToken: providerConfiguration.recordRevision,
                    requestGeneration: requestGeneration
                )
            )
        )
        try Task.checkCancellation()
        let message = try await messenger.sendRuntimeConfigurationValidation(
            request,
            providerConfiguration: providerConfiguration
        )
        try Task.checkCancellation()
        guard case .runtimeConfigurationValidation(var validation)? = message.response.payload else {
            throw TunnelRuntimeConfigurationValidationFailure(
                diagnostic: TunnelRuntimeConfigurationValidationDiagnostic(
                    stage: .responseValidation,
                    category: .invalidResponse,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        if validation.providerConfigurationValid == false,
           validation.diagnostic?.stage == .providerConfiguration,
           validation.diagnostic?.category != .providerConfigurationStaleSession {
            validation.diagnostic = TunnelRuntimeConfigurationValidationDiagnostic(
                stage: .providerConfiguration,
                category: .providerConfigurationContractMismatch,
                extensionRequestReached: message.diagnostic.extensionRequestReached,
                correlationIDPrefix: validation.diagnostic?.correlationIDPrefix,
                providerConfiguration: validation.diagnostic?.providerConfiguration
            )
        }
        guard validation.correlationID == correlationID else {
            throw TunnelRuntimeConfigurationValidationFailure(
                diagnostic: TunnelRuntimeConfigurationValidationDiagnostic(
                    stage: .responseValidation,
                    category: .correlationMismatch,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        return validation
    }
}

actor XrayConfigurationValidationService {
    private let publisher: SharedRuntimeProfilePublisher
    private let messenger: any TunnelXrayConfigurationValidationMessaging
    private var nextRequestGeneration: UInt64 = 0

    init(
        publisher: SharedRuntimeProfilePublisher,
        messenger: any TunnelXrayConfigurationValidationMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) {
        self.publisher = publisher
        self.messenger = messenger
    }

    static func appGroupService(
        credentialStore: any CredentialStoring = KeychainCredentialStore(),
        messenger: any TunnelXrayConfigurationValidationMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) -> XrayConfigurationValidationService? {
        guard let publisher = SharedRuntimeProfilePublisher.appGroupPublisher(credentialStore: credentialStore) else {
            return nil
        }
        return XrayConfigurationValidationService(publisher: publisher, messenger: messenger)
    }

    func validate(profile: VPNProfile) async throws -> TunnelXrayConfigurationValidationResponse {
        try Task.checkCancellation()
        let record = try await publisher.publish(profile)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: record.profileID,
            sharedRecordRevision: record.recordRevision
        )
        nextRequestGeneration &+= 1
        let requestGeneration = nextRequestGeneration
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .validateXrayConfiguration,
            payload: .xrayConfigurationValidation(
                TunnelXrayConfigurationValidationRequest(
                    correlationID: correlationID,
                    expectedProfileID: record.profileID,
                    expectedRevisionToken: providerConfiguration.recordRevision,
                    requestGeneration: requestGeneration
                )
            )
        )

        try Task.checkCancellation()
        let message = try await messenger.sendXrayConfigurationValidation(
            request,
            providerConfiguration: providerConfiguration
        )
        try Task.checkCancellation()
        guard case .xrayConfigurationValidation(let validation)? = message.response.payload else {
            throw TunnelXrayConfigurationValidationFailure(
                diagnostic: TunnelXrayConfigurationValidationDiagnostic(
                    stage: .responseValidation,
                    category: .invalidResponse,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        guard validation.correlationID == correlationID else {
            throw TunnelXrayConfigurationValidationFailure(
                diagnostic: TunnelXrayConfigurationValidationDiagnostic(
                    stage: .responseValidation,
                    category: .correlationMismatch,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        return validation
    }
}

actor XrayLifecycleSmokeTestService {
    private let publisher: SharedRuntimeProfilePublisher
    private let messenger: any TunnelXrayLifecycleSmokeTestMessaging
    private var nextRequestGeneration: UInt64 = 0

    init(
        publisher: SharedRuntimeProfilePublisher,
        messenger: any TunnelXrayLifecycleSmokeTestMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) {
        self.publisher = publisher
        self.messenger = messenger
    }

    static func appGroupService(
        credentialStore: any CredentialStoring = KeychainCredentialStore(),
        messenger: any TunnelXrayLifecycleSmokeTestMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) -> XrayLifecycleSmokeTestService? {
        guard let publisher = SharedRuntimeProfilePublisher.appGroupPublisher(credentialStore: credentialStore) else {
            return nil
        }
        return XrayLifecycleSmokeTestService(publisher: publisher, messenger: messenger)
    }

    func run(profile: VPNProfile) async throws -> TunnelXrayLifecycleSmokeTestResponse {
        try Task.checkCancellation()
        let record = try await publisher.publish(profile)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: record.profileID,
            sharedRecordRevision: record.recordRevision
        )
        nextRequestGeneration &+= 1
        let requestGeneration = nextRequestGeneration
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .runXrayLifecycleSmokeTest,
            payload: .xrayLifecycleSmokeTest(
                TunnelXrayLifecycleSmokeTestRequest(
                    correlationID: correlationID,
                    expectedProfileID: record.profileID,
                    expectedRevisionToken: providerConfiguration.recordRevision,
                    requestGeneration: requestGeneration
                )
            )
        )

        try Task.checkCancellation()
        let message = try await messenger.sendXrayLifecycleSmokeTest(
            request,
            providerConfiguration: providerConfiguration
        )
        try Task.checkCancellation()
        guard case .xrayLifecycleSmokeTest(let smokeTest)? = message.response.payload else {
            throw TunnelXrayLifecycleSmokeTestFailure(
                diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                    stage: .responseValidation,
                    category: .invalidResponse,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        guard smokeTest.correlationID == correlationID else {
            throw TunnelXrayLifecycleSmokeTestFailure(
                diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                    stage: .responseValidation,
                    category: .correlationMismatch,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        return smokeTest
    }
}

actor XrayRemoteEgressProbeService {
    private let publisher: SharedRuntimeProfilePublisher
    private let messenger: any TunnelXrayRemoteEgressProbeMessaging
    private var nextRequestGeneration: UInt64 = 0

    init(
        publisher: SharedRuntimeProfilePublisher,
        messenger: any TunnelXrayRemoteEgressProbeMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) {
        self.publisher = publisher
        self.messenger = messenger
    }

    static func appGroupService(
        credentialStore: any CredentialStoring = KeychainCredentialStore(),
        messenger: any TunnelXrayRemoteEgressProbeMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) -> XrayRemoteEgressProbeService? {
        guard let publisher = SharedRuntimeProfilePublisher.appGroupPublisher(credentialStore: credentialStore) else {
            return nil
        }
        return XrayRemoteEgressProbeService(publisher: publisher, messenger: messenger)
    }

    func run(profile: VPNProfile) async throws -> TunnelXrayRemoteEgressProbeResponse {
        try await send(profile: profile, kind: .runXrayRemoteEgressProbe)
    }

    func probeActiveXrayEgress(profile: VPNProfile) async throws -> TunnelXrayRemoteEgressProbeResponse {
        try await send(profile: profile, kind: .probeActiveXrayEgress)
    }

    func probeActiveDataPlane(profile: VPNProfile) async throws -> TunnelXrayRemoteEgressProbeResponse {
        try await probeActiveXrayEgress(profile: profile)
    }

    private func send(
        profile: VPNProfile,
        kind: TunnelMessageKind
    ) async throws -> TunnelXrayRemoteEgressProbeResponse {
        try Task.checkCancellation()
        let record = try await publisher.publish(profile)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: record.profileID,
            sharedRecordRevision: record.recordRevision
        )
        nextRequestGeneration &+= 1
        let requestGeneration = nextRequestGeneration
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: kind,
            payload: .xrayRemoteEgressProbe(
                TunnelXrayRemoteEgressProbeRequest(
                    correlationID: correlationID,
                    expectedProfileID: record.profileID,
                    expectedRevisionToken: providerConfiguration.recordRevision,
                    requestGeneration: requestGeneration
                )
            )
        )

        try Task.checkCancellation()
        let message = try await messenger.sendXrayRemoteEgressProbe(
            request,
            providerConfiguration: providerConfiguration
        )
        try Task.checkCancellation()
        guard case .xrayRemoteEgressProbe(let probe)? = message.response.payload else {
            throw TunnelXrayRemoteEgressProbeFailure(
                diagnostic: TunnelXrayRemoteEgressProbeDiagnostic(
                    stage: .responseValidation,
                    category: .invalidResponse,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        guard probe.correlationID == correlationID else {
            throw TunnelXrayRemoteEgressProbeFailure(
                diagnostic: TunnelXrayRemoteEgressProbeDiagnostic(
                    stage: .responseValidation,
                    category: .correlationMismatch,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        return probe
    }
}

actor UDPControlProbeService {
    private let messenger: any TunnelUDPControlProbeMessaging
    private var nextRequestGeneration: UInt64 = 0

    init(messenger: any TunnelUDPControlProbeMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()) {
        self.messenger = messenger
    }

    static func appGroupService(
        messenger: any TunnelUDPControlProbeMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) -> UDPControlProbeService? {
        UDPControlProbeService(messenger: messenger)
    }

    func run() async throws -> TunnelUDPControlProbeResponse {
        try Task.checkCancellation()
        nextRequestGeneration &+= 1
        let requestGeneration = nextRequestGeneration
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .runUDPControlProbe,
            payload: .udpControlProbe(
                TunnelUDPControlProbeRequest(
                    correlationID: correlationID,
                    requestGeneration: requestGeneration
                )
            )
        )

        try Task.checkCancellation()
        let message = try await messenger.sendUDPControlProbe(request)
        try Task.checkCancellation()
        guard case .udpControlProbe(let probe)? = message.response.payload else {
            throw TunnelUDPControlProbeFailure(
                diagnostic: TunnelUDPControlProbeDiagnostic(
                    category: .invalidResponse,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        guard probe.correlationID == correlationID else {
            throw TunnelUDPControlProbeFailure(
                diagnostic: TunnelUDPControlProbeDiagnostic(
                    category: .correlationMismatch,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        return probe
    }
}

actor LibXrayPingProbeService {
    private let publisher: SharedRuntimeProfilePublisher
    private let messenger: any TunnelLibXrayPingProbeMessaging
    private var nextRequestGeneration: UInt64 = 0

    init(
        publisher: SharedRuntimeProfilePublisher,
        messenger: any TunnelLibXrayPingProbeMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) {
        self.publisher = publisher
        self.messenger = messenger
    }

    static func appGroupService(
        credentialStore: any CredentialStoring = KeychainCredentialStore(),
        messenger: any TunnelLibXrayPingProbeMessaging = NetworkExtensionRuntimeConfigurationValidationMessenger()
    ) -> LibXrayPingProbeService? {
        guard let publisher = SharedRuntimeProfilePublisher.appGroupPublisher(credentialStore: credentialStore) else {
            return nil
        }
        return LibXrayPingProbeService(publisher: publisher, messenger: messenger)
    }

    func run(profile: VPNProfile) async throws -> TunnelLibXrayPingProbeResponse {
        try Task.checkCancellation()
        let record = try await publisher.publish(profile)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: record.profileID,
            sharedRecordRevision: record.recordRevision
        )
        nextRequestGeneration &+= 1
        let requestGeneration = nextRequestGeneration
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .runLibXrayPingProbe,
            payload: .libXrayPingProbe(
                TunnelLibXrayPingProbeRequest(
                    correlationID: correlationID,
                    expectedProfileID: record.profileID,
                    expectedRevisionToken: providerConfiguration.recordRevision,
                    requestGeneration: requestGeneration
                )
            )
        )

        try Task.checkCancellation()
        let message = try await messenger.sendLibXrayPingProbe(
            request,
            providerConfiguration: providerConfiguration
        )
        try Task.checkCancellation()
        guard case .libXrayPingProbe(let probe)? = message.response.payload else {
            throw TunnelLibXrayPingProbeFailure(
                diagnostic: TunnelLibXrayPingProbeDiagnostic(
                    stage: .responseValidation,
                    category: .invalidResponse,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        guard probe.correlationID == correlationID else {
            throw TunnelLibXrayPingProbeFailure(
                diagnostic: TunnelLibXrayPingProbeDiagnostic(
                    stage: .responseValidation,
                    category: .correlationMismatch,
                    extensionRequestReached: message.diagnostic.extensionRequestReached
                )
            )
        }
        return probe
    }
}

#if DEBUG
actor RuntimeOnlyPacketTunnelService {
    private let publisher: SharedRuntimeProfilePublisher
    private let bootstrapper: DiagnosticTunnelProviderSessionBootstrapper
    private let sessionProvider: any TunnelProviderSessionProviding
    private let statusTimeout: Duration
    private let statusPollInterval: Duration

    init(
        publisher: SharedRuntimeProfilePublisher,
        bootstrapper: DiagnosticTunnelProviderSessionBootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        ),
        sessionProvider: any TunnelProviderSessionProviding = NetworkExtensionTunnelSessionProvider(
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        ),
        statusTimeout: Duration = .seconds(6),
        statusPollInterval: Duration = .milliseconds(100)
    ) {
        self.publisher = publisher
        self.bootstrapper = bootstrapper
        self.sessionProvider = sessionProvider
        self.statusTimeout = statusTimeout
        self.statusPollInterval = statusPollInterval
    }

    static func appGroupService(
        credentialStore: any CredentialStoring = KeychainCredentialStore()
    ) -> RuntimeOnlyPacketTunnelService? {
        guard let publisher = SharedRuntimeProfilePublisher.appGroupPublisher(credentialStore: credentialStore) else {
            return nil
        }
        return RuntimeOnlyPacketTunnelService(publisher: publisher)
    }

    func start(profile: VPNProfile) async throws -> TunnelXrayLifecycleSmokeTestResponse {
        try Task.checkCancellation()
        let record = try await publisher.publish(profile)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: record.profileID,
            sharedRecordRevision: record.recordRevision
        )
        let bootstrap = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: providerConfiguration)
        guard let session = bootstrap.session as? any RuntimeOnlyPacketTunnelSessionConnection else {
            throw failure(stage: .preStartState, category: .providerUnavailable)
        }
        let status = await session.status()
        guard status == .disconnected else {
            throw failure(stage: .preStartState, category: .runtimeAlreadyRunning)
        }

        let correlationID = UUID()
        try Task.checkCancellation()
        try await session.startRuntimeOnlyTunnel(options: RuntimeOnlyPacketTunnelStartOptions.propertyList)
        guard await waitForStatus([.connected, .reasserting], through: session) else {
            throw failure(correlationID: correlationID, stage: .runningState, category: .providerTimeout)
        }
        return .runtimeOnlyStarted(
            correlationID: correlationID,
            protocolName: record.protocolKind.rawValue,
            transportName: record.transport.kind.rawValue,
            securityName: record.security.kind.rawValue,
            startDurationMs: nil,
            readinessDurationMs: nil,
            totalDurationMs: nil
        )
    }

    func stop() async throws -> TunnelXrayLifecycleSmokeTestResponse {
        try Task.checkCancellation()
        let session = try await sessionProvider.currentSession()
        guard let runtimeSession = session as? any RuntimeOnlyPacketTunnelSessionConnection else {
            throw failure(stage: .stopXray, category: .providerUnavailable)
        }
        let correlationID = UUID()
        await runtimeSession.stopRuntimeOnlyTunnel()
        guard await waitForStatus([.disconnected, .invalid], through: runtimeSession) else {
            throw failure(correlationID: correlationID, stage: .stoppedState, category: .providerTimeout)
        }
        return .success(
            correlationID: correlationID,
            protocolName: nil,
            transportName: nil,
            securityName: nil,
            startDurationMs: nil,
            readinessDurationMs: nil,
            stopDurationMs: nil,
            totalDurationMs: nil
        )
    }

    private func waitForStatus(
        _ expectedStatuses: [TunnelProviderSessionStatus],
        through session: any TunnelProviderSessionConnection
    ) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: statusTimeout)
        while ContinuousClock.now < deadline {
            if expectedStatuses.contains(await session.status()) {
                return true
            }
            try? await Task.sleep(for: statusPollInterval)
        }
        return expectedStatuses.contains(await session.status())
    }

    private func failure(
        correlationID: UUID = UUID(),
        stage: TunnelXrayLifecycleSmokeTestStage,
        category: TunnelXrayLifecycleSmokeTestCategory
    ) -> TunnelXrayLifecycleSmokeTestFailure {
        TunnelXrayLifecycleSmokeTestFailure(
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: stage,
                category: category,
                extensionRequestReached: false,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }
}

actor LibXrayPingOnlyPacketTunnelService {
    private let publisher: SharedRuntimeProfilePublisher
    private let bootstrapper: DiagnosticTunnelProviderSessionBootstrapper
    private let sessionProvider: any TunnelProviderSessionProviding
    private let statusTimeout: Duration
    private let statusPollInterval: Duration

    init(
        publisher: SharedRuntimeProfilePublisher,
        bootstrapper: DiagnosticTunnelProviderSessionBootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        ),
        sessionProvider: any TunnelProviderSessionProviding = NetworkExtensionTunnelSessionProvider(
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        ),
        statusTimeout: Duration = .seconds(6),
        statusPollInterval: Duration = .milliseconds(100)
    ) {
        self.publisher = publisher
        self.bootstrapper = bootstrapper
        self.sessionProvider = sessionProvider
        self.statusTimeout = statusTimeout
        self.statusPollInterval = statusPollInterval
    }

    static func appGroupService(
        credentialStore: any CredentialStoring = KeychainCredentialStore()
    ) -> LibXrayPingOnlyPacketTunnelService? {
        guard let publisher = SharedRuntimeProfilePublisher.appGroupPublisher(credentialStore: credentialStore) else {
            return nil
        }
        return LibXrayPingOnlyPacketTunnelService(publisher: publisher)
    }

    func start(profile: VPNProfile) async throws -> TunnelXrayLifecycleSmokeTestResponse {
        try Task.checkCancellation()
        let record = try await publisher.publish(profile)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: record.profileID,
            sharedRecordRevision: record.recordRevision
        )
        let bootstrap = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: providerConfiguration)
        guard let session = bootstrap.session as? any LibXrayPingOnlyPacketTunnelSessionConnection else {
            throw failure(stage: .preStartState, category: .providerUnavailable)
        }
        let status = await session.status()
        guard status == .disconnected else {
            throw failure(stage: .preStartState, category: .runtimeAlreadyRunning)
        }

        let correlationID = UUID()
        try Task.checkCancellation()
        try await session.startLibXrayPingOnlyTunnel(options: LibXrayPingOnlyPacketTunnelStartOptions.propertyList)
        guard await waitForStatus([.connected, .reasserting], through: session) else {
            throw failure(correlationID: correlationID, stage: .runningState, category: .providerTimeout)
        }
        return TunnelXrayLifecycleSmokeTestResponse(
            correlationID: correlationID,
            success: true,
            runtimeConfigurationLoaded: false,
            xrayConfigurationBuilt: false,
            testXrayPassed: false,
            runXrayInvoked: false,
            runningStateObserved: false,
            socksListenerReady: false,
            socksGreetingAccepted: false,
            stopXrayInvoked: false,
            stoppedStateObserved: false,
            localPortClosed: false,
            rollbackAttempted: false,
            rollbackSucceeded: true,
            protocolName: "libXrayPingOnly",
            transportName: "none",
            securityName: "none",
            h3ALPNConfigured: nil,
            sniConfigured: nil,
            failureStage: nil,
            failureCategory: nil,
            startDurationMs: nil,
            readinessDurationMs: nil,
            stopDurationMs: nil,
            totalDurationMs: nil,
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .preStartState,
                category: .none,
                extensionRequestReached: true,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    func stop() async throws -> TunnelXrayLifecycleSmokeTestResponse {
        try Task.checkCancellation()
        let session = try await sessionProvider.currentSession()
        guard let pingOnlySession = session as? any LibXrayPingOnlyPacketTunnelSessionConnection else {
            throw failure(stage: .stoppedState, category: .providerUnavailable)
        }
        let correlationID = UUID()
        await pingOnlySession.stopLibXrayPingOnlyTunnel()
        guard await waitForStatus([.disconnected, .invalid], through: pingOnlySession) else {
            throw failure(correlationID: correlationID, stage: .stoppedState, category: .providerTimeout)
        }
        return TunnelXrayLifecycleSmokeTestResponse(
            correlationID: correlationID,
            success: true,
            runtimeConfigurationLoaded: false,
            xrayConfigurationBuilt: false,
            testXrayPassed: false,
            runXrayInvoked: false,
            runningStateObserved: false,
            socksListenerReady: false,
            socksGreetingAccepted: false,
            stopXrayInvoked: false,
            stoppedStateObserved: false,
            localPortClosed: false,
            rollbackAttempted: false,
            rollbackSucceeded: true,
            protocolName: "libXrayPingOnly",
            transportName: "none",
            securityName: "none",
            h3ALPNConfigured: nil,
            sniConfigured: nil,
            failureStage: nil,
            failureCategory: nil,
            startDurationMs: nil,
            readinessDurationMs: nil,
            stopDurationMs: nil,
            totalDurationMs: nil,
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .stoppedState,
                category: .none,
                extensionRequestReached: true,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    private func waitForStatus(
        _ expectedStatuses: [TunnelProviderSessionStatus],
        through session: any TunnelProviderSessionConnection
    ) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: statusTimeout)
        while ContinuousClock.now < deadline {
            if expectedStatuses.contains(await session.status()) {
                return true
            }
            try? await Task.sleep(for: statusPollInterval)
        }
        return expectedStatuses.contains(await session.status())
    }

    private func failure(
        correlationID: UUID = UUID(),
        stage: TunnelXrayLifecycleSmokeTestStage,
        category: TunnelXrayLifecycleSmokeTestCategory
    ) -> TunnelXrayLifecycleSmokeTestFailure {
        TunnelXrayLifecycleSmokeTestFailure(
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: stage,
                category: category,
                extensionRequestReached: false,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }
}
#endif

actor DataPlanePacketTunnelService {
    private let publisher: SharedRuntimeProfilePublisher
    private let bootstrapper: DiagnosticTunnelProviderSessionBootstrapper
    private let sessionProvider: any TunnelProviderSessionProviding
    private let statusTimeout: Duration
    private let statusPollInterval: Duration

    init(
        publisher: SharedRuntimeProfilePublisher,
        bootstrapper: DiagnosticTunnelProviderSessionBootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        ),
        sessionProvider: any TunnelProviderSessionProviding = NetworkExtensionTunnelSessionProvider(
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        ),
        statusTimeout: Duration = .seconds(8),
        statusPollInterval: Duration = .milliseconds(100)
    ) {
        self.publisher = publisher
        self.bootstrapper = bootstrapper
        self.sessionProvider = sessionProvider
        self.statusTimeout = statusTimeout
        self.statusPollInterval = statusPollInterval
    }

    static func appGroupService(
        credentialStore: any CredentialStoring = KeychainCredentialStore()
    ) -> DataPlanePacketTunnelService? {
        guard let publisher = SharedRuntimeProfilePublisher.appGroupPublisher(credentialStore: credentialStore) else {
            return nil
        }
        return DataPlanePacketTunnelService(publisher: publisher)
    }

    func start(profile: VPNProfile) async throws -> TunnelXrayLifecycleSmokeTestResponse {
        try Task.checkCancellation()
        let record = try await publisher.publish(profile)
        let providerConfiguration = try RuntimeProviderConfiguration(
            profileID: record.profileID,
            sharedRecordRevision: record.recordRevision
        )
        let bootstrap = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: providerConfiguration)
        guard let session = bootstrap.session as? any DataPlanePacketTunnelSessionConnection else {
            throw failure(stage: .dataPlane, category: .providerUnavailable)
        }
        let status = await session.status()
        guard status == .disconnected else {
            throw failure(stage: .preStartState, category: .runtimeAlreadyRunning)
        }

        let correlationID = UUID()
        try Task.checkCancellation()
        try await session.startDataPlaneTunnel(options: DataPlanePacketTunnelStartOptions.propertyList)
        guard await waitForStatus([.connected, .reasserting], through: session) else {
            throw failure(correlationID: correlationID, stage: .dataPlane, category: .providerTimeout)
        }
        return .runtimeOnlyStarted(
            correlationID: correlationID,
            protocolName: record.protocolKind.rawValue,
            transportName: record.transport.kind.rawValue,
            securityName: record.security.kind.rawValue,
            startDurationMs: nil,
            readinessDurationMs: nil,
            totalDurationMs: nil
        )
    }

    func stop() async throws -> TunnelXrayLifecycleSmokeTestResponse {
        try Task.checkCancellation()
        let session = try await sessionProvider.currentSession()
        guard let dataPlaneSession = session as? any DataPlanePacketTunnelSessionConnection else {
            throw failure(stage: .tun2SocksStop, category: .providerUnavailable)
        }
        let correlationID = UUID()
        await dataPlaneSession.stopDataPlaneTunnel()
        guard await waitForStatus([.disconnected, .invalid], through: dataPlaneSession) else {
            throw failure(correlationID: correlationID, stage: .stoppedState, category: .providerTimeout)
        }
        return .success(
            correlationID: correlationID,
            protocolName: nil,
            transportName: nil,
            securityName: nil,
            startDurationMs: nil,
            readinessDurationMs: nil,
            stopDurationMs: nil,
            totalDurationMs: nil
        )
    }

    private func waitForStatus(
        _ expectedStatuses: [TunnelProviderSessionStatus],
        through session: any TunnelProviderSessionConnection
    ) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: statusTimeout)
        while ContinuousClock.now < deadline {
            if expectedStatuses.contains(await session.status()) {
                return true
            }
            try? await Task.sleep(for: statusPollInterval)
        }
        return expectedStatuses.contains(await session.status())
    }

    private func failure(
        correlationID: UUID = UUID(),
        stage: TunnelXrayLifecycleSmokeTestStage,
        category: TunnelXrayLifecycleSmokeTestCategory
    ) -> TunnelXrayLifecycleSmokeTestFailure {
        TunnelXrayLifecycleSmokeTestFailure(
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: stage,
                category: category,
                extensionRequestReached: false,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }
}

#if DEBUG
nonisolated struct DiagnosticProviderStateSnapshot: Equatable, Sendable {
    var providerStatus: TunnelProviderSessionStatus
    var mode: TunnelDiagnosticProviderMode
    var extensionReachable: Bool
    var recoveryRequired: Bool

    static let disconnectedIdle = DiagnosticProviderStateSnapshot(
        providerStatus: .disconnected,
        mode: .idle,
        extensionReachable: false,
        recoveryRequired: false
    )
}

nonisolated enum DiagnosticProviderRecoveryError: Error, Equatable, Sendable {
    case providerUnavailable
    case timeout
}

actor DiagnosticProviderStateService {
    private let managerStore: any DiagnosticTunnelProviderManagerStore
    private let providerBundleIdentifier: String
    private let timeout: Duration
    private let maximumResponseBytes: Int

    init(
        managerStore: any DiagnosticTunnelProviderManagerStore = NetworkExtensionDiagnosticTunnelProviderManagerStore(),
        providerBundleIdentifier: String = PacketTunnelProviderRouting.xrayBundleIdentifier,
        timeout: Duration = .seconds(3),
        maximumResponseBytes: Int = TunnelMessageProtocol.maximumResponseBytes
    ) {
        self.managerStore = managerStore
        self.providerBundleIdentifier = providerBundleIdentifier
        self.timeout = timeout
        self.maximumResponseBytes = maximumResponseBytes
    }

    func reconcile() async -> DiagnosticProviderStateSnapshot {
        let managers: [any DiagnosticTunnelProviderManager]
        do {
            managers = try await managerStore.loadAllManagers()
        } catch {
            return DiagnosticProviderStateSnapshot(
                providerStatus: .unknown,
                mode: .unknown,
                extensionReachable: false,
                recoveryRequired: false
            )
        }

        guard let manager = await existingManager(in: managers) else {
            return .disconnectedIdle
        }

        let session: any TunnelProviderSessionConnection
        do {
            session = try await manager.tunnelProviderSession()
        } catch {
            return DiagnosticProviderStateSnapshot(
                providerStatus: .unknown,
                mode: .unknown,
                extensionReachable: false,
                recoveryRequired: false
            )
        }

        let status = await session.status()
        switch status {
        case .disconnected, .invalid:
            return DiagnosticProviderStateSnapshot(
                providerStatus: status,
                mode: .idle,
                extensionReachable: false,
                recoveryRequired: false
            )
        case .connected, .reasserting:
            let mode = await queryDiagnosticMode(through: session)
            return DiagnosticProviderStateSnapshot(
                providerStatus: status,
                mode: mode.mode,
                extensionReachable: mode.extensionReachable,
                recoveryRequired: mode.extensionReachable == false || mode.mode == .unknown
            )
        case .connecting:
            return DiagnosticProviderStateSnapshot(
                providerStatus: status,
                mode: .unknown,
                extensionReachable: false,
                recoveryRequired: true
            )
        case .disconnecting:
            return DiagnosticProviderStateSnapshot(
                providerStatus: status,
                mode: .unknown,
                extensionReachable: false,
                recoveryRequired: false
            )
        case .unknown:
            return DiagnosticProviderStateSnapshot(
                providerStatus: status,
                mode: .unknown,
                extensionReachable: false,
                recoveryRequired: false
            )
        }
    }

    private func queryDiagnosticMode(
        through session: any TunnelProviderSessionConnection
    ) async -> (mode: TunnelDiagnosticProviderMode, extensionReachable: Bool) {
        let messenger = NetworkExtensionTunnelMessenger(
            sessionProvider: DiagnosticProviderSingleSessionProvider(session: session),
            timeout: timeout,
            maximumResponseBytes: maximumResponseBytes
        )
        do {
            let response = try await messenger.send(TunnelMessageRequest(kind: .getDiagnosticProviderMode))
            guard case .diagnosticProviderMode(let payload)? = response.payload else {
                return (.unknown, true)
            }
            return (payload.mode, true)
        } catch {
            return (.unknown, false)
        }
    }

    private func existingManager(in managers: [any DiagnosticTunnelProviderManager]) async -> (any DiagnosticTunnelProviderManager)? {
        for manager in managers {
            if await manager.providerBundleIdentifier() == providerBundleIdentifier {
                return manager
            }
        }
        return nil
    }
}

actor DiagnosticProviderRecoveryService {
    private let managerStore: any DiagnosticTunnelProviderManagerStore
    private let providerBundleIdentifier: String
    private let statusTimeout: Duration
    private let statusPollInterval: Duration

    init(
        managerStore: any DiagnosticTunnelProviderManagerStore = NetworkExtensionDiagnosticTunnelProviderManagerStore(),
        providerBundleIdentifier: String = PacketTunnelProviderRouting.xrayBundleIdentifier,
        statusTimeout: Duration = .seconds(6),
        statusPollInterval: Duration = .milliseconds(100)
    ) {
        self.managerStore = managerStore
        self.providerBundleIdentifier = providerBundleIdentifier
        self.statusTimeout = statusTimeout
        self.statusPollInterval = statusPollInterval
    }

    func recover() async throws {
        let managers = try await managerStore.loadAllManagers()
        guard let manager = await existingManager(in: managers) else {
            return
        }
        let session = try await manager.tunnelProviderSession()
        let status = await session.status()
        guard status != .disconnected && status != .invalid else {
            try? await manager.loadFromPreferences()
            return
        }
        guard let recoverySession = session as? any DiagnosticProviderRecoverySessionConnection else {
            throw DiagnosticProviderRecoveryError.providerUnavailable
        }
        await recoverySession.stopDiagnosticProviderTunnel()
        guard await waitForDisconnected(through: recoverySession) else {
            throw DiagnosticProviderRecoveryError.timeout
        }
        try? await manager.loadFromPreferences()
    }

    private func waitForDisconnected(through session: any TunnelProviderSessionConnection) async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: statusTimeout)
        while ContinuousClock.now < deadline {
            let status = await session.status()
            if status == .disconnected || status == .invalid {
                return true
            }
            try? await Task.sleep(for: statusPollInterval)
        }
        let status = await session.status()
        return status == .disconnected || status == .invalid
    }

    private func existingManager(in managers: [any DiagnosticTunnelProviderManager]) async -> (any DiagnosticTunnelProviderManager)? {
        for manager in managers {
            if await manager.providerBundleIdentifier() == providerBundleIdentifier {
                return manager
            }
        }
        return nil
    }
}

private nonisolated struct DiagnosticProviderSingleSessionProvider: TunnelProviderSessionProviding {
    let session: any TunnelProviderSessionConnection

    func currentSession() async throws -> any TunnelProviderSessionConnection {
        session
    }
}
#endif

nonisolated struct SensitiveRuntimeCredential: CustomStringConvertible, CustomDebugStringConvertible, Sendable {
    private let value: String

    init(_ value: String) {
        self.value = value
    }

    var description: String { "<redacted>" }
    var debugDescription: String { "<redacted>" }

    var isValidVLESSUserID: Bool {
        UUID(uuidString: value) != nil
    }

    var isValidUUID: Bool {
        UUID(uuidString: value) != nil
    }

    var isNonEmptySecret: Bool {
        value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
    }

    func withString<R>(_ body: (String) throws -> R) rethrows -> R {
        try body(value)
    }
}

nonisolated struct ResolvedRuntimeEndpoint: Equatable, Sendable {
    var host: String
    var port: Int
}

nonisolated struct ResolvedVLESSRuntimeConfiguration: CustomStringConvertible, CustomDebugStringConvertible, Sendable {
    var profileID: UUID
    var recordRevision: String
    var protocolKind: SharedRuntimeProtocolKind
    var endpoint: ResolvedRuntimeEndpoint
    var transport: SharedRuntimeTransport
    var security: SharedRuntimeSecurity
    var vless: SharedRuntimeVLESSParameters
    var vmess: SharedRuntimeVMessParameters?
    var trojan: SharedRuntimeTrojanParameters?
    var shadowsocks: SharedRuntimeShadowsocksParameters?
    var hysteria2: SharedRuntimeHysteria2Parameters?
    var credential: SensitiveRuntimeCredential
    var hysteria2ObfsPassword: SensitiveRuntimeCredential?

    var description: String {
        "ResolvedProxyRuntimeConfiguration(profileID: \(profileID.uuidString), recordRevision: \(recordRevision), protocol: \(protocolKind.rawValue), endpoint: <redacted>, credential: <redacted>)"
    }

    var debugDescription: String { description }
}

nonisolated enum XrayConfigurationBuilderError: String, Error, Equatable, Sendable {
    case unsupportedProtocol
    case unsupportedTransport
    case unsupportedSecurity
    case invalidEndpoint
    case invalidCredential
    case invalidTLSConfiguration
    case invalidRealityConfiguration
    case invalidXHTTPConfiguration
    case invalidXHTTPMode
    case invalidXHTTPPath
    case invalidXHTTPHost
    case encodingFailed
}

nonisolated struct XrayBuildOptions: Equatable, Sendable {
    var localSocksListenAddress: String
    var localSocksPort: Int
    var localSocksUDPEnabled: Bool

    init(
        localSocksListenAddress: String = "127.0.0.1",
        localSocksPort: Int = 10_808,
        localSocksUDPEnabled: Bool = false
    ) {
        self.localSocksListenAddress = localSocksListenAddress
        self.localSocksPort = localSocksPort
        self.localSocksUDPEnabled = localSocksUDPEnabled
    }
}

nonisolated struct Tun2SocksRuntimeConfiguration: CustomStringConvertible, CustomDebugStringConvertible, Sendable {
    private let content: String

    init(content: String) {
        self.content = content
    }

    var description: String { "<redacted tun2socks configuration>" }
    var debugDescription: String { description }

    func withString<R>(_ body: (String) throws -> R) rethrows -> R {
        try body(content)
    }
}

nonisolated enum Tun2SocksConfigurationBuilderError: String, Error, Equatable, Sendable {
    case invalidLoopbackSocksEndpoint
    case invalidMTU
}

nonisolated struct Tun2SocksConfigurationBuilder: Sendable {
    var mtu: Int
    var taskStackSize: Int
    var tcpBufferSize: Int
    var maximumSessionCount: Int

    init(
        mtu: Int = 9_000,
        taskStackSize: Int = 24_576,
        tcpBufferSize: Int = 4_096,
        maximumSessionCount: Int = 768
    ) {
        self.mtu = mtu
        self.taskStackSize = taskStackSize
        self.tcpBufferSize = tcpBufferSize
        self.maximumSessionCount = maximumSessionCount
    }

    func build(localSocksHost: String, localSocksPort: Int, udpEnabled: Bool = false) throws -> Tun2SocksRuntimeConfiguration {
        guard localSocksHost == "127.0.0.1", (1...65_535).contains(localSocksPort) else {
            throw Tun2SocksConfigurationBuilderError.invalidLoopbackSocksEndpoint
        }
        guard (1_280...16_000).contains(mtu) else {
            throw Tun2SocksConfigurationBuilderError.invalidMTU
        }

        var lines = [
            "tunnel:",
            "  mtu: \(mtu)",
            "",
            "socks5:",
            "  port: \(localSocksPort)",
            "  address: \(localSocksHost)"
        ]
        if udpEnabled {
            lines.append("  udp: 'udp'")
        }
        lines.append(contentsOf: [
            "",
            "misc:",
            "  task-stack-size: \(taskStackSize)",
            "  tcp-buffer-size: \(tcpBufferSize)",
            "  max-session-count: \(maximumSessionCount)",
            "  connect-timeout: 5000",
            "  read-write-timeout: 60000",
            "  log-file: stderr",
            "  log-level: error",
            "  limit-nofile: 65535"
        ])
        return Tun2SocksRuntimeConfiguration(content: lines.joined(separator: "\n") + "\n")
    }
}

nonisolated enum XraySOCKS5RemoteConnect {
    static let targetHost = "1.1.1.1"
    static let targetPort = 80
    static let requestBytes = Data([0x05, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x50])

    static func parseReply(_ data: Data) -> TunnelXrayRemoteEgressProbeCategory {
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else {
            return .timeout
        }
        guard bytes[0] == 0x05 else {
            return .unknown
        }
        guard let expectedLength = expectedReplyLength(bytes), bytes.count >= expectedLength else {
            return .timeout
        }
        switch bytes[1] {
        case 0x00:
            return .success
        default:
            return .socksConnectRejected
        }
    }

    static func expectedReplyLength(_ bytes: [UInt8]) -> Int? {
        guard bytes.count >= 4 else {
            return nil
        }
        switch bytes[3] {
        case 0x01:
            return 10
        case 0x03:
            guard bytes.count >= 5 else {
                return nil
            }
            return 5 + Int(bytes[4]) + 2
        case 0x04:
            return 22
        default:
            return nil
        }
    }
}

nonisolated struct XrayRemoteEgressProbeResult: Equatable, Sendable {
    var success: Bool
    var category: TunnelXrayRemoteEgressProbeCategory
    var socksConnectRequested: Bool
    var socksConnectAccepted: Bool
    var payloadWriteSucceeded: Bool
    var remoteFirstByteReceived: Bool
    var remoteResponseValidated: Bool

    init(
        success: Bool,
        category: TunnelXrayRemoteEgressProbeCategory,
        socksConnectRequested: Bool = false,
        socksConnectAccepted: Bool = false,
        payloadWriteSucceeded: Bool = false,
        remoteFirstByteReceived: Bool = false,
        remoteResponseValidated: Bool = false
    ) {
        self.success = success
        self.category = category
        self.socksConnectRequested = socksConnectRequested
        self.socksConnectAccepted = socksConnectAccepted
        self.payloadWriteSucceeded = payloadWriteSucceeded
        self.remoteFirstByteReceived = remoteFirstByteReceived
        self.remoteResponseValidated = remoteResponseValidated
    }
}

nonisolated enum XrayRemoteEgressHTTPProbe {
    static let maximumResponseBytes = 16 * 1_024
    static let requestBytes = Data("GET / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n".utf8)

    static func evaluate(
        socksConnectRequested: Bool,
        socksConnectCategory: TunnelXrayRemoteEgressProbeCategory,
        payloadWriteSucceeded: Bool,
        responseData: Data?,
        responseReadFailed: Bool = false
    ) -> XrayRemoteEgressProbeResult {
        guard socksConnectRequested else {
            return XrayRemoteEgressProbeResult(success: false, category: .socksConnectRejected)
        }
        guard socksConnectCategory == .success else {
            return XrayRemoteEgressProbeResult(
                success: false,
                category: socksConnectCategory,
                socksConnectRequested: true
            )
        }
        guard payloadWriteSucceeded else {
            return XrayRemoteEgressProbeResult(
                success: false,
                category: .payloadWriteFailed,
                socksConnectRequested: true,
                socksConnectAccepted: true
            )
        }
        guard let responseData else {
            return XrayRemoteEgressProbeResult(
                success: false,
                category: responseReadFailed ? .remoteReadFailed : .remoteFirstByteTimeout,
                socksConnectRequested: true,
                socksConnectAccepted: true,
                payloadWriteSucceeded: true
            )
        }
        guard responseData.isEmpty == false else {
            return XrayRemoteEgressProbeResult(
                success: false,
                category: .remoteFirstByteTimeout,
                socksConnectRequested: true,
                socksConnectAccepted: true,
                payloadWriteSucceeded: true
            )
        }
        guard isValidHTTPResponsePrefix(responseData) else {
            return XrayRemoteEgressProbeResult(
                success: false,
                category: .remoteResponseInvalid,
                socksConnectRequested: true,
                socksConnectAccepted: true,
                payloadWriteSucceeded: true,
                remoteFirstByteReceived: true
            )
        }
        return XrayRemoteEgressProbeResult(
            success: true,
            category: .success,
            socksConnectRequested: true,
            socksConnectAccepted: true,
            payloadWriteSucceeded: true,
            remoteFirstByteReceived: true,
            remoteResponseValidated: true
        )
    }

    static func isValidHTTPResponsePrefix(_ data: Data) -> Bool {
        let prefix = [UInt8](data.prefix(5))
        return prefix == [0x48, 0x54, 0x54, 0x50, 0x2F]
    }
}

nonisolated struct UDPControlProbeResult: Equatable, Sendable {
    var success: Bool
    var category: TunnelUDPControlProbeCategory
    var udpConnectionReady: Bool
    var udpWriteSucceeded: Bool
    var udpResponseReceived: Bool
    var udpResponseValidated: Bool

    init(
        success: Bool,
        category: TunnelUDPControlProbeCategory,
        udpConnectionReady: Bool = false,
        udpWriteSucceeded: Bool = false,
        udpResponseReceived: Bool = false,
        udpResponseValidated: Bool = false
    ) {
        self.success = success
        self.category = category
        self.udpConnectionReady = udpConnectionReady
        self.udpWriteSucceeded = udpWriteSucceeded
        self.udpResponseReceived = udpResponseReceived
        self.udpResponseValidated = udpResponseValidated
    }
}

nonisolated enum UDPControlDNSProbe {
    static let transactionID: UInt16 = 0x4B4E
    static let targetHost = "1.1.1.1"
    static let targetPort = 53
    static let maximumResponseBytes = 512
    static let requestBytes = requestBytes(transactionID: transactionID)

    static func requestBytes(transactionID: UInt16) -> Data {
        var bytes: [UInt8] = [
            UInt8((transactionID >> 8) & 0xFF),
            UInt8(transactionID & 0xFF),
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00
        ]
        for label in ["one", "one", "one", "one"] {
            let labelBytes = [UInt8](label.utf8)
            bytes.append(UInt8(labelBytes.count))
            bytes.append(contentsOf: labelBytes)
        }
        bytes.append(0x00)
        bytes.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        return Data(bytes)
    }

    static func evaluate(
        connectionReady: Bool,
        writeSucceeded: Bool,
        responseData: Data?,
        responseReadFailed: Bool = false,
        pathUnsatisfied: Bool = false,
        cancelled: Bool = false,
        transactionID: UInt16 = transactionID
    ) -> UDPControlProbeResult {
        if cancelled {
            return UDPControlProbeResult(success: false, category: .cancelled)
        }
        if pathUnsatisfied {
            return UDPControlProbeResult(success: false, category: .pathUnsatisfied)
        }
        guard connectionReady else {
            return UDPControlProbeResult(success: false, category: .connectionFailed)
        }
        guard writeSucceeded else {
            return UDPControlProbeResult(
                success: false,
                category: .writeFailed,
                udpConnectionReady: true
            )
        }
        guard let responseData else {
            return UDPControlProbeResult(
                success: false,
                category: responseReadFailed ? .readFailed : .readTimeout,
                udpConnectionReady: true,
                udpWriteSucceeded: true
            )
        }
        guard responseData.isEmpty == false else {
            return UDPControlProbeResult(
                success: false,
                category: .readTimeout,
                udpConnectionReady: true,
                udpWriteSucceeded: true
            )
        }
        guard responseMatches(responseData, transactionID: transactionID) else {
            return UDPControlProbeResult(
                success: false,
                category: .invalidResponse,
                udpConnectionReady: true,
                udpWriteSucceeded: true,
                udpResponseReceived: true
            )
        }
        return UDPControlProbeResult(
            success: true,
            category: .success,
            udpConnectionReady: true,
            udpWriteSucceeded: true,
            udpResponseReceived: true,
            udpResponseValidated: true
        )
    }

    static func responseMatches(_ data: Data, transactionID: UInt16) -> Bool {
        let bytes = [UInt8](data.prefix(12))
        guard bytes.count >= 12 else {
            return false
        }
        let responseTransactionID = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
        guard responseTransactionID == transactionID else {
            return false
        }
        let flags = (UInt16(bytes[2]) << 8) | UInt16(bytes[3])
        return (flags & 0x8000) != 0
    }
}

nonisolated struct PacketTunnelNetworkSettingsPlan: Equatable, Sendable {
    var tunnelRemoteAddress: String
    var ipv4Address: String
    var ipv4SubnetMask: String
    var mtu: Int
    var dnsServers: [String]
    var dnsMatchDomains: [String]
    var ipv6Policy: String
    var udpPolicy: String

    static let k3b3aIPv4FullTunnel = PacketTunnelNetworkSettingsPlan(
        tunnelRemoteAddress: "127.0.0.1",
        ipv4Address: "10.24.0.2",
        ipv4SubnetMask: "255.255.255.0",
        mtu: 9_000,
        dnsServers: ["1.1.1.1", "8.8.8.8"],
        dnsMatchDomains: [""],
        ipv6Policy: "ipv4OnlyNoIPv6Settings",
        udpPolicy: "enabledForDataPlaneDNSForwarding"
    )
}

nonisolated struct SensitiveXrayConfiguration: CustomStringConvertible, CustomDebugStringConvertible, Sendable {
    private static let maximumBytes = 512 * 1_024
    private let jsonData: Data

    init(jsonData: Data) throws {
        guard jsonData.isEmpty == false, jsonData.count <= Self.maximumBytes else {
            throw XrayConfigurationBuilderError.encodingFailed
        }
        self.jsonData = jsonData
    }

    var description: String { "<redacted>" }
    var debugDescription: String { "<redacted>" }

    func withJSONString<R>(_ body: (String) throws -> R) throws -> R {
        guard let json = String(data: jsonData, encoding: .utf8) else {
            throw XrayConfigurationBuilderError.encodingFailed
        }
        return try body(json)
    }
}

nonisolated protocol XrayConfigurationBuilding: Sendable {
    nonisolated func build(
        from configuration: ResolvedVLESSRuntimeConfiguration,
        options: XrayBuildOptions
    ) throws -> SensitiveXrayConfiguration
}

nonisolated struct XrayConfigurationBuilder: XrayConfigurationBuilding {
    private static let supportedFingerprints: Set<String> = [
        "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn"
    ]

    nonisolated func build(
        from configuration: ResolvedVLESSRuntimeConfiguration,
        options: XrayBuildOptions = XrayBuildOptions()
    ) throws -> SensitiveXrayConfiguration {
        try validateEndpoint(configuration.endpoint)
        try validateInboundOptions(options)
        try validateProtocolMatrix(configuration)

        let credential = try configuration.credential.withString { value -> String in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.isEmpty == false else {
                throw XrayConfigurationBuilderError.invalidCredential
            }
            return trimmed
        }

        let transport = try streamTransport(for: configuration.transport)
        var security = try streamSecurity(for: configuration.security, protocolKind: configuration.protocolKind)
        if configuration.protocolKind == .trojan,
           security.security == "tls",
           let alpn = try normalizedALPN(configuration.trojan?.alpn) {
            security.tlsSettings?.alpn = alpn
        }
        let outbound = try outboundConfiguration(
            for: configuration,
            credential: credential,
            transport: transport,
            security: security
        )
        let document = XrayJSONDocument(
            log: XrayLogConfiguration(access: "none", error: "none", loglevel: "none"),
            inbounds: [
                XrayInboundConfiguration(
                    listen: options.localSocksListenAddress,
                    port: options.localSocksPort,
                    protocolName: "socks",
                    settings: XraySocksInboundSettings(auth: "noauth", udp: options.localSocksUDPEnabled)
                )
            ],
            outbounds: [outbound]
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        do {
            return try SensitiveXrayConfiguration(jsonData: encoder.encode(document))
        } catch {
            throw XrayConfigurationBuilderError.encodingFailed
        }
    }

    private func validateEndpoint(_ endpoint: ResolvedRuntimeEndpoint) throws {
        let host = endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard host.isEmpty == false,
              host.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              host.rangeOfCharacter(from: .controlCharacters) == nil,
              (1...65_535).contains(endpoint.port) else {
            throw XrayConfigurationBuilderError.invalidEndpoint
        }
    }

    private func validateInboundOptions(_ options: XrayBuildOptions) throws {
        guard options.localSocksListenAddress == "127.0.0.1",
              (1...65_535).contains(options.localSocksPort) else {
            throw XrayConfigurationBuilderError.invalidEndpoint
        }
    }

    private func normalizedALPN(_ values: [String]?) throws -> [String]? {
        guard let values else { return nil }
        let normalized = values.compactMap { value -> String? in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        guard normalized.allSatisfy({ value in
            value.utf8.count <= 255
                && value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
                && value.rangeOfCharacter(from: .controlCharacters) == nil
        }) else {
            throw XrayConfigurationBuilderError.invalidTLSConfiguration
        }
        return normalized.isEmpty ? nil : normalized
    }

    private func validateProtocolMatrix(_ configuration: ResolvedVLESSRuntimeConfiguration) throws {
        switch configuration.protocolKind {
        case .vless:
            guard [.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(configuration.transport.kind) else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard [.tls, .reality].contains(configuration.security.kind) else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            let encryption = normalizedOptional(configuration.vless.encryption)?.lowercased()
            guard encryption == nil || encryption == "none" else {
                throw XrayConfigurationBuilderError.unsupportedProtocol
            }
            if let flow = normalizedOptional(configuration.vless.flow)?.lowercased() {
                guard flow == "xtls-rprx-vision",
                      [.tcp, .xhttp].contains(configuration.transport.kind) else {
                    throw XrayConfigurationBuilderError.unsupportedProtocol
                }
            }
        case .vmess:
            guard [.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(configuration.transport.kind) else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard [.none, .tls, .reality].contains(configuration.security.kind) else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            if let vmess = configuration.vmess {
                guard vmess.alterID.map({ $0 >= 0 }) ?? true else {
                    throw XrayConfigurationBuilderError.unsupportedProtocol
                }
                let cipher = normalizedOptional(vmess.security)?.lowercased()
                if let cipher, ["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"].contains(cipher) == false {
                    throw XrayConfigurationBuilderError.unsupportedProtocol
                }
            }
        case .trojan:
            guard [.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(configuration.transport.kind) else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard [.tls, .reality].contains(configuration.security.kind) else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
        case .shadowsocks:
            guard configuration.transport.kind == .tcp else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard configuration.security.kind == .none else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
        case .hysteria2:
            guard configuration.transport.kind == .hysteria else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard configuration.security.kind == .tls else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
        }
    }

    private func vlessUserParameters(_ parameters: SharedRuntimeVLESSParameters, credential: String) throws -> XrayVLESSUser {
        guard UUID(uuidString: credential) != nil else {
            throw XrayConfigurationBuilderError.invalidCredential
        }
        let encryption = normalizedOptional(parameters.encryption) ?? "none"
        guard encryption.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else {
            throw XrayConfigurationBuilderError.invalidCredential
        }
        let flow = normalizedOptional(parameters.flow)
        return XrayVLESSUser(id: credential, encryption: encryption, flow: flow)
    }

    private func outboundConfiguration(
        for configuration: ResolvedVLESSRuntimeConfiguration,
        credential: String,
        transport: XrayTransportMapping,
        security: XraySecurityMapping
    ) throws -> XrayOutboundConfiguration {
        let endpointHost = configuration.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines)
        let streamSettings = XrayStreamSettings(
            method: transport.method,
            network: transport.network,
            security: security.security,
            tlsSettings: security.tlsSettings,
            realitySettings: security.realitySettings,
            wsSettings: transport.wsSettings,
            grpcSettings: transport.grpcSettings,
            httpUpgradeSettings: transport.httpUpgradeSettings,
            xhttpSettings: transport.xhttpSettings,
            hysteriaSettings: transport.hysteriaSettings,
            finalmask: nil
        )

        switch configuration.protocolKind {
        case .vless:
            let vless = try vlessUserParameters(configuration.vless, credential: credential)
            return XrayOutboundConfiguration(
                protocolName: "vless",
                tag: "proxy",
                settings: .vless(XrayVLESSOutboundSettings(
                    vnext: [
                        XrayVLESSServer(
                            address: endpointHost,
                            port: configuration.endpoint.port,
                            users: [vless]
                        )
                    ]
                )),
                streamSettings: streamSettings
            )
        case .vmess:
            guard UUID(uuidString: credential) != nil else {
                throw XrayConfigurationBuilderError.invalidCredential
            }
            let vmess = configuration.vmess ?? SharedRuntimeVMessParameters(alterID: nil, security: nil)
            let user = XrayVMessUser(
                id: credential,
                alterId: max(0, vmess.alterID ?? 0),
                security: normalizedOptional(vmess.security) ?? "auto"
            )
            return XrayOutboundConfiguration(
                protocolName: "vmess",
                tag: "proxy",
                settings: .vmess(XrayVMessOutboundSettings(
                    vnext: [
                        XrayVMessServer(
                            address: endpointHost,
                            port: configuration.endpoint.port,
                            users: [user]
                        )
                    ]
                )),
                streamSettings: streamSettings
            )
        case .trojan:
            guard security.security != "none" else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            return XrayOutboundConfiguration(
                protocolName: "trojan",
                tag: "proxy",
                settings: .trojan(XrayTrojanOutboundSettings(
                    servers: [
                        XrayTrojanServer(
                            address: endpointHost,
                            port: configuration.endpoint.port,
                            password: credential
                        )
                    ]
                )),
                streamSettings: streamSettings
            )
        case .shadowsocks:
            guard configuration.security.kind == .none else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            guard configuration.transport.kind == .tcp else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            let shadowsocksMethod = try shadowsocksMethod(configuration.shadowsocks)
            return XrayOutboundConfiguration(
                protocolName: "shadowsocks",
                tag: "proxy",
                settings: .shadowsocks(XrayShadowsocksOutboundSettings(
                    servers: [
                        XrayShadowsocksServer(
                            address: endpointHost,
                            port: configuration.endpoint.port,
                            method: shadowsocksMethod,
                            password: credential
                        )
                    ]
                )),
                streamSettings: streamSettings
            )
        case .hysteria2:
            guard configuration.transport.kind == .hysteria else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard configuration.security.kind == .tls else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            let tlsSettings = try Hysteria2XrayTLSPolicy.tlsSettings(
                from: security.tlsSettings,
                endpointHost: endpointHost
            )
            let finalmask = try hysteria2FinalMaskSettings(for: configuration)
            let hysteriaStreamSettings = XrayStreamSettings(
                method: transport.method,
                network: transport.network,
                security: security.security,
                tlsSettings: tlsSettings,
                realitySettings: security.realitySettings,
                wsSettings: nil,
                grpcSettings: nil,
                httpUpgradeSettings: nil,
                xhttpSettings: nil,
                hysteriaSettings: XrayHysteriaStreamSettings(version: 2, auth: credential),
                finalmask: finalmask
            )
            return XrayOutboundConfiguration(
                protocolName: "hysteria",
                tag: "proxy",
                settings: .hysteria(XrayHysteriaOutboundSettings(
                    version: 2,
                    address: endpointHost,
                    port: configuration.endpoint.port
                )),
                streamSettings: hysteriaStreamSettings
            )
        }
    }

    private func shadowsocksMethod(_ parameters: SharedRuntimeShadowsocksParameters?) throws -> String {
        guard let method = normalizedOptional(parameters?.method)?.lowercased(),
              isSupportedShadowsocksMethod(method),
              normalizedOptional(parameters?.plugin) == nil else {
            throw XrayConfigurationBuilderError.unsupportedProtocol
        }
        return method
    }

    private func hysteria2FinalMaskSettings(for configuration: ResolvedVLESSRuntimeConfiguration) throws -> XrayFinalMaskSettings? {
        let parameters = configuration.hysteria2
        guard normalizedOptional(parameters?.bandwidthHint) == nil else {
            throw XrayConfigurationBuilderError.unsupportedProtocol
        }
        let obfs = normalizedOptional(parameters?.obfs)?.lowercased()
        guard let obfs else {
            return nil
        }
        guard obfs == "salamander", let obfsPassword = configuration.hysteria2ObfsPassword else {
            throw XrayConfigurationBuilderError.unsupportedProtocol
        }
        let password = try obfsPassword.withString { value -> String in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.isEmpty == false else {
                throw XrayConfigurationBuilderError.invalidCredential
            }
            return trimmed
        }
        return XrayFinalMaskSettings(
            udp: [
                XrayFinalMaskLayer(
                    type: "salamander",
                    settings: XrayFinalMaskSalamanderSettings(password: password)
                )
            ]
        )
    }

    private func streamTransport(for transport: SharedRuntimeTransport) throws -> XrayTransportMapping {
        switch transport.kind {
        case .tcp:
            return XrayTransportMapping(network: "tcp")
        case .websocket:
            return XrayTransportMapping(
                network: "ws",
                wsSettings: XrayWebSocketSettings(
                    path: normalizedOptional(transport.path),
                    headers: XrayHeaderSettings(host: normalizedOptional(transport.host))
                )
            )
        case .grpc:
            return XrayTransportMapping(
                network: "grpc",
                grpcSettings: XrayGRPCSettings(serviceName: normalizedOptional(transport.serviceName))
            )
        case .httpUpgrade:
            return XrayTransportMapping(
                network: "httpupgrade",
                httpUpgradeSettings: XrayHTTPUpgradeSettings(
                    path: normalizedOptional(transport.path),
                    host: normalizedOptional(transport.host)
                )
            )
        case .xhttp:
            guard let xhttp = transport.xhttp else {
                throw XrayConfigurationBuilderError.invalidXHTTPConfiguration
            }
            do {
                try XHTTPParametersValidator.validate(transport: transport)
            } catch RuntimeConfigurationError.invalidXHTTPMode {
                throw XrayConfigurationBuilderError.invalidXHTTPMode
            } catch RuntimeConfigurationError.invalidXHTTPPath {
                throw XrayConfigurationBuilderError.invalidXHTTPPath
            } catch RuntimeConfigurationError.invalidXHTTPHost {
                throw XrayConfigurationBuilderError.invalidXHTTPHost
            } catch {
                throw XrayConfigurationBuilderError.invalidXHTTPConfiguration
            }
            return XrayTransportMapping(
                network: "xhttp",
                xhttpSettings: XrayXHTTPSettings(
                    host: normalizedOptional(xhttp.host),
                    path: normalizedOptional(xhttp.path),
                    mode: xhttp.mode?.rawValue
                )
            )
        case .hysteria:
            return XrayTransportMapping(
                network: "hysteria",
                method: "hysteria"
            )
        }
    }

    private func streamSecurity(
        for security: SharedRuntimeSecurity,
        protocolKind: SharedRuntimeProtocolKind
    ) throws -> XraySecurityMapping {
        switch security.kind {
        case .none:
            guard protocolKind == .shadowsocks || protocolKind == .vmess else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            return XraySecurityMapping(security: "none", tlsSettings: nil, realitySettings: nil)
        case .tls:
            let serverName = normalizedOptional(security.serverName)
            guard serverName != nil || protocolKind == .hysteria2 else {
                throw XrayConfigurationBuilderError.invalidTLSConfiguration
            }
            let fingerprint = normalizedOptional(security.fingerprint)?.lowercased()
            guard isSupportedFingerprint(fingerprint) else {
                throw XrayConfigurationBuilderError.invalidTLSConfiguration
            }
            guard security.allowInsecure == false || protocolKind != .vless else {
                throw XrayConfigurationBuilderError.invalidTLSConfiguration
            }
            return XraySecurityMapping(
                security: "tls",
                tlsSettings: XrayTLSSettings(
                    serverName: serverName,
                    allowInsecure: security.allowInsecure,
                    fingerprint: fingerprint,
                    alpn: try normalizedALPN(security.alpn)
                ),
                realitySettings: nil
            )
        case .reality:
            guard let reality = security.reality else {
                throw XrayConfigurationBuilderError.invalidRealityConfiguration
            }
            do {
                try RealityPublicParametersValidator.validate(reality)
            } catch {
                throw XrayConfigurationBuilderError.invalidRealityConfiguration
            }
            return XraySecurityMapping(
                security: "reality",
                tlsSettings: nil,
                realitySettings: XrayRealitySettings(
                    serverName: reality.serverName.trimmingCharacters(in: .whitespacesAndNewlines),
                    fingerprint: normalizedOptional(reality.fingerprint)?.lowercased(),
                    publicKey: reality.publicKey.trimmingCharacters(in: .whitespacesAndNewlines),
                    shortId: reality.shortID.trimmingCharacters(in: .whitespacesAndNewlines),
                    spiderX: normalizedOptional(reality.spiderX)
                )
            )
        }
    }

    private func isSupportedFingerprint(_ value: String?) -> Bool {
        guard let value else {
            return true
        }
        return Self.supportedFingerprints.contains(value)
    }

    private func isSupportedShadowsocksMethod(_ value: String) -> Bool {
        [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "chacha20-ietf-poly1305",
            "xchacha20-poly1305",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305"
        ].contains(value)
    }

    private func normalizedOptional(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }
}

private nonisolated struct XrayTransportMapping {
    var network: String
    var method: String?
    var wsSettings: XrayWebSocketSettings?
    var grpcSettings: XrayGRPCSettings?
    var httpUpgradeSettings: XrayHTTPUpgradeSettings?
    var xhttpSettings: XrayXHTTPSettings?
    var hysteriaSettings: XrayHysteriaStreamSettings?
}

private nonisolated struct XraySecurityMapping {
    var security: String
    var tlsSettings: XrayTLSSettings?
    var realitySettings: XrayRealitySettings?
}

private nonisolated enum Hysteria2XrayTLSPolicy {
    static let requiredALPN = ["h3"]

    static func tlsSettings(
        from tlsSettings: XrayTLSSettings?,
        endpointHost: String
    ) throws -> XrayTLSSettings {
        guard let tlsSettings else {
            throw XrayConfigurationBuilderError.invalidTLSConfiguration
        }
        let serverName = try effectiveServerName(
            explicitServerName: tlsSettings.serverName,
            endpointHost: endpointHost
        )
        return XrayTLSSettings(
            serverName: serverName,
            allowInsecure: tlsSettings.allowInsecure,
            fingerprint: tlsSettings.fingerprint,
            alpn: requiredALPN
        )
    }

    static func h3ALPNConfigured(for configuration: ResolvedVLESSRuntimeConfiguration) -> Bool? {
        configuration.protocolKind == .hysteria2 ? true : nil
    }

    static func sniConfigured(for configuration: ResolvedVLESSRuntimeConfiguration) -> Bool? {
        guard configuration.protocolKind == .hysteria2 else {
            return nil
        }
        return (try? effectiveServerName(
            explicitServerName: configuration.security.serverName,
            endpointHost: configuration.endpoint.host
        )) != nil
    }

    static func allowInsecureConfigured(for configuration: ResolvedVLESSRuntimeConfiguration) -> Bool? {
        configuration.protocolKind == .hysteria2 ? configuration.security.allowInsecure : nil
    }

    private static func effectiveServerName(
        explicitServerName: String?,
        endpointHost: String
    ) throws -> String? {
        if let explicit = normalizedOptional(explicitServerName) {
            try validateServerName(explicit)
            return explicit
        }

        let host = endpointHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isHostnameCandidate(host) else {
            return nil
        }
        try validateServerName(host)
        return host
    }

    private static func validateServerName(_ serverName: String) throws {
        guard serverName.isEmpty == false,
              serverName.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              serverName.rangeOfCharacter(from: .controlCharacters) == nil,
              serverName.contains("/") == false,
              serverName.contains(":") == false else {
            throw XrayConfigurationBuilderError.invalidTLSConfiguration
        }
    }

    private static func isHostnameCandidate(_ host: String) -> Bool {
        guard host.isEmpty == false,
              host.hasPrefix("[") == false,
              host.hasSuffix("]") == false,
              host.contains(":") == false,
              isIPv4AddressLiteral(host) == false else {
            return false
        }
        return true
    }

    private static func isIPv4AddressLiteral(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else {
            return false
        }
        return parts.allSatisfy { part in
            guard part.isEmpty == false,
                  part.unicodeScalars.allSatisfy({ CharacterSet.decimalDigits.contains($0) }),
                  let value = Int(part),
                  (0...255).contains(value) else {
                return false
            }
            return true
        }
    }

    private static func normalizedOptional(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }
}

private nonisolated struct XrayJSONDocument: Encodable {
    var log: XrayLogConfiguration
    var inbounds: [XrayInboundConfiguration]
    var outbounds: [XrayOutboundConfiguration]
}

private nonisolated struct XrayLogConfiguration: Encodable {
    var access: String
    var error: String
    var loglevel: String
}

private nonisolated struct XrayInboundConfiguration: Encodable {
    var listen: String
    var port: Int
    var protocolName: String
    var settings: XraySocksInboundSettings

    enum CodingKeys: String, CodingKey {
        case listen, port, settings
        case protocolName = "protocol"
    }
}

private nonisolated struct XraySocksInboundSettings: Encodable {
    var auth: String
    var udp: Bool
}

private nonisolated struct XrayOutboundConfiguration: Encodable {
    var protocolName: String
    var tag: String
    var settings: XrayOutboundSettings
    var streamSettings: XrayStreamSettings

    enum CodingKeys: String, CodingKey {
        case tag, settings, streamSettings
        case protocolName = "protocol"
    }
}

private nonisolated enum XrayOutboundSettings: Encodable {
    case vless(XrayVLESSOutboundSettings)
    case vmess(XrayVMessOutboundSettings)
    case trojan(XrayTrojanOutboundSettings)
    case shadowsocks(XrayShadowsocksOutboundSettings)
    case hysteria(XrayHysteriaOutboundSettings)

    func encode(to encoder: Encoder) throws {
        switch self {
        case .vless(let settings):
            try settings.encode(to: encoder)
        case .vmess(let settings):
            try settings.encode(to: encoder)
        case .trojan(let settings):
            try settings.encode(to: encoder)
        case .shadowsocks(let settings):
            try settings.encode(to: encoder)
        case .hysteria(let settings):
            try settings.encode(to: encoder)
        }
    }
}

private nonisolated struct XrayVLESSOutboundSettings: Encodable {
    var vnext: [XrayVLESSServer]
}

private nonisolated struct XrayVLESSServer: Encodable {
    var address: String
    var port: Int
    var users: [XrayVLESSUser]
}

private nonisolated struct XrayVLESSUser: Encodable {
    var id: String
    var encryption: String
    var flow: String?
}

private nonisolated struct XrayVMessOutboundSettings: Encodable {
    var vnext: [XrayVMessServer]
}

private nonisolated struct XrayVMessServer: Encodable {
    var address: String
    var port: Int
    var users: [XrayVMessUser]
}

private nonisolated struct XrayVMessUser: Encodable {
    var id: String
    var alterId: Int
    var security: String
}

private nonisolated struct XrayTrojanOutboundSettings: Encodable {
    var servers: [XrayTrojanServer]
}

private nonisolated struct XrayTrojanServer: Encodable {
    var address: String
    var port: Int
    var password: String
}

private nonisolated struct XrayShadowsocksOutboundSettings: Encodable {
    var servers: [XrayShadowsocksServer]
}

private nonisolated struct XrayShadowsocksServer: Encodable {
    var address: String
    var port: Int
    var method: String
    var password: String
}

private nonisolated struct XrayHysteriaOutboundSettings: Encodable {
    var version: Int
    var address: String
    var port: Int
}

private nonisolated struct XrayStreamSettings: Encodable {
    var method: String?
    var network: String
    var security: String
    var tlsSettings: XrayTLSSettings?
    var realitySettings: XrayRealitySettings?
    var wsSettings: XrayWebSocketSettings?
    var grpcSettings: XrayGRPCSettings?
    var httpUpgradeSettings: XrayHTTPUpgradeSettings?
    var xhttpSettings: XrayXHTTPSettings?
    var hysteriaSettings: XrayHysteriaStreamSettings?
    var finalmask: XrayFinalMaskSettings?
}

private nonisolated struct XrayTLSSettings: Encodable {
    var serverName: String?
    var allowInsecure: Bool
    var fingerprint: String?
    var alpn: [String]?
}

private nonisolated struct XrayRealitySettings: Encodable {
    var serverName: String
    var fingerprint: String?
    var publicKey: String
    var shortId: String
    var spiderX: String?
}

private nonisolated struct XrayXHTTPSettings: Encodable {
    var host: String?
    var path: String?
    var mode: String?
}

private nonisolated struct XrayWebSocketSettings: Encodable {
    var path: String?
    var headers: XrayHeaderSettings?
}

private nonisolated struct XrayHeaderSettings: Encodable {
    var host: String?

    enum CodingKeys: String, CodingKey {
        case host = "Host"
    }
}

private nonisolated struct XrayGRPCSettings: Encodable {
    var serviceName: String?
}

private nonisolated struct XrayHTTPUpgradeSettings: Encodable {
    var path: String?
    var host: String?
}

private nonisolated struct XrayHysteriaStreamSettings: Encodable {
    var version: Int
    var auth: String
}

private nonisolated struct XrayFinalMaskSettings: Encodable {
    var udp: [XrayFinalMaskLayer]
}

private nonisolated struct XrayFinalMaskLayer: Encodable {
    var type: String
    var settings: XrayFinalMaskSalamanderSettings
}

private nonisolated struct XrayFinalMaskSalamanderSettings: Encodable {
    var password: String
}

nonisolated struct LibXrayTestInvocationResult: Equatable, Sendable {
    var success: Bool
    var apiVersionSupported: Bool
    var invoked: Bool
    var category: TunnelXrayConfigurationValidationCategory
}

nonisolated protocol LibXrayTestInvoking: Sendable {
    func test(_ configuration: SensitiveXrayConfiguration) async -> LibXrayTestInvocationResult
}

nonisolated protocol LibXrayRawInvoking: Sendable {
    var apiVersion: Int64 { get }
    func invoke(requestJSON: String) -> String?
}

nonisolated final class LibXrayTestAdapterCore: LibXrayTestInvoking, @unchecked Sendable {
    static let supportedAPIVersion: Int64 = 2

    private let invoker: any LibXrayRawInvoking
    private let queue = DispatchQueue(label: "su.24kvn.k3a.libxray-test")

    init(invoker: any LibXrayRawInvoking) {
        self.invoker = invoker
    }

    func test(_ configuration: SensitiveXrayConfiguration) async -> LibXrayTestInvocationResult {
        await withCheckedContinuation { continuation in
            queue.async { [invoker] in
                continuation.resume(returning: Self.performTest(configuration, invoker: invoker))
            }
        }
    }

    private static func performTest(
        _ configuration: SensitiveXrayConfiguration,
        invoker: any LibXrayRawInvoking
    ) -> LibXrayTestInvocationResult {
        guard invoker.apiVersion == Self.supportedAPIVersion else {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: false,
                invoked: false,
                category: .unsupportedLibXrayAPIVersion
            )
        }

        let requestString: String
        do {
            requestString = try configuration.withJSONString { xrayJSON in
                let envelope = LibXrayInvokeEnvelope(
                    apiVersion: Self.supportedAPIVersion,
                    method: "testXray",
                    payload: LibXrayTestPayload(xrayJson: xrayJSON)
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys]
                let requestData = try encoder.encode(envelope)
                return String(decoding: requestData, as: UTF8.self)
            }
        } catch {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: true,
                invoked: false,
                category: .requestEncodingFailed
            )
        }

        guard let responseString = invoker.invoke(requestJSON: requestString) else {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: true,
                invoked: true,
                category: .invocationFailed
            )
        }
        guard responseString.isEmpty == false else {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: true,
                invoked: true,
                category: .emptyResponse
            )
        }
        guard let responseData = responseString.data(using: .utf8) else {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: true,
                invoked: true,
                category: .malformedResponse
            )
        }

        do {
            let decoder = JSONDecoder()
            let response = try decoder.decode(LibXrayInvokeResponse.self, from: responseData)
            guard response.success else {
                return LibXrayTestInvocationResult(
                    success: false,
                    apiVersionSupported: true,
                    invoked: true,
                    category: .configurationRejected
                )
            }
            return LibXrayTestInvocationResult(
                success: true,
                apiVersionSupported: true,
                invoked: true,
                category: .none
            )
        } catch {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: true,
                invoked: true,
                category: .malformedResponse
            )
        }
    }
}

private nonisolated struct LibXrayInvokeEnvelope: Encodable {
    var apiVersion: Int64
    var method: String
    var payload: LibXrayTestPayload
}

private nonisolated struct LibXrayTestPayload: Encodable {
    var xrayJson: String
}

private nonisolated struct LibXrayInvokeResponse: Decodable {
    var success: Bool
}

nonisolated protocol RuntimeCredentialResolving: Sendable {
    func credential(for reference: String) async throws -> String?
}

struct CredentialStoreRuntimeCredentialResolver: RuntimeCredentialResolving {
    let credentialStore: any CredentialStoring

    func credential(for reference: String) async throws -> String? {
        try await credentialStore.secret(for: reference)
    }
}

actor RuntimeConfigurationLoader {
    private let store: any SharedRuntimeProfileStoring
    private let credentialResolver: any RuntimeCredentialResolving

    init(store: any SharedRuntimeProfileStoring, credentialResolver: any RuntimeCredentialResolving) {
        self.store = store
        self.credentialResolver = credentialResolver
    }

    func load(providerConfiguration propertyList: [String: Any]?) async throws -> ResolvedVLESSRuntimeConfiguration {
        let providerConfiguration = try RuntimeProviderConfiguration.parse(propertyList)
        let record = try await store.read(profileID: providerConfiguration.profileID)
        try validate(record: record, providerConfiguration: providerConfiguration)

        guard CredentialReferenceValidator.isValid(record.credentialReference) else {
            throw RuntimeConfigurationError.malformedCredentialReference
        }
        guard let credential = try await credentialResolver.credential(for: record.credentialReference) else {
            throw RuntimeConfigurationError.credentialUnavailable
        }
        guard credential.isEmpty == false else {
            throw RuntimeConfigurationError.credentialMalformed
        }
        let sensitiveCredential = SensitiveRuntimeCredential(credential)
        try validateCredential(sensitiveCredential, for: record.protocolKind)
        let sensitiveObfsPassword = try await resolveHysteria2ObfsPasswordIfNeeded(from: record)

        return ResolvedVLESSRuntimeConfiguration(
            profileID: record.profileID,
            recordRevision: record.recordRevision,
            protocolKind: record.protocolKind,
            endpoint: ResolvedRuntimeEndpoint(host: record.endpoint.host, port: record.endpoint.port),
            transport: record.transport,
            security: record.security,
            vless: record.vless,
            vmess: record.vmess,
            trojan: record.trojan,
            shadowsocks: record.shadowsocks,
            hysteria2: record.hysteria2,
            credential: sensitiveCredential,
            hysteria2ObfsPassword: sensitiveObfsPassword
        )
    }

    func validateRuntimeConfiguration(
        providerConfiguration propertyList: [String: Any]?,
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64? = nil
    ) async -> TunnelRuntimeConfigurationValidationResponse {
        let providerConfiguration: RuntimeProviderConfiguration
        do {
            providerConfiguration = try RuntimeProviderConfiguration.parse(propertyList)
        } catch {
            let category = Self.category(for: error)
            return .failure(
                correlationID: correlationID,
                stage: .providerConfiguration,
                category: category,
                providerConfigurationDiagnostic: RuntimeProviderConfiguration.diagnostic(for: propertyList, category: category)
            )
        }

        if let expectedProfileID, expectedProfileID != providerConfiguration.profileID {
            return .failure(
                correlationID: correlationID,
                stage: .providerConfiguration,
                category: .profileIdentityMismatch,
                providerConfigurationValid: true
            )
        }
        if let expectedRevisionToken, expectedRevisionToken != providerConfiguration.recordRevision {
            return .failure(
                correlationID: correlationID,
                stage: .providerConfiguration,
                category: .profileRevisionMismatch,
                providerConfigurationValid: true
            )
        }

        do {
            let resolved = try await load(providerConfiguration: propertyList)
            return TunnelRuntimeConfigurationValidationResponse.success(
                correlationID: correlationID,
                protocolName: resolved.protocolKind.rawValue,
                transportName: resolved.transport.kind.rawValue,
                securityName: resolved.security.kind.rawValue
            )
        } catch {
            return .failure(
                correlationID: correlationID,
                stage: Self.stage(for: error),
                category: Self.category(for: error),
                providerConfigurationValid: true
            )
        }
    }

    private func validate(record: SharedRuntimeProfileRecord, providerConfiguration: RuntimeProviderConfiguration) throws {
        guard record.schemaVersion == RuntimeConfigurationProtocol.profileSchemaVersion else {
            throw RuntimeConfigurationError.profileSchemaMismatch
        }
        guard record.profileID == providerConfiguration.profileID else {
            throw RuntimeConfigurationError.profileIdentityMismatch
        }
        let recordRevisionToken = try RuntimeProviderConfiguration.revisionToken(for: record.recordRevision)
        guard recordRevisionToken == providerConfiguration.recordRevision else {
            throw RuntimeConfigurationError.profileRevisionMismatch
        }
        guard record.enabled else {
            throw RuntimeConfigurationError.profileDisabled
        }
        guard record.completeness == .complete else {
            throw RuntimeConfigurationError.profileIncomplete
        }
        guard [.vless, .vmess, .trojan, .shadowsocks, .hysteria2].contains(record.protocolKind) else {
            throw RuntimeConfigurationError.unsupportedProtocol
        }
        try validateProtocolPayload(record)
        guard record.backendKind == .xray else {
            throw RuntimeConfigurationError.unsupportedProtocol
        }
        guard record.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false,
              record.endpoint.host.contains(" ") == false,
              (1...65_535).contains(record.endpoint.port) else {
            throw RuntimeConfigurationError.invalidEndpoint
        }
        try validate(transport: record.transport)
        try validate(security: record.security)
    }

    private func validate(transport: SharedRuntimeTransport) throws {
        switch transport.kind {
        case .tcp, .websocket, .grpc, .httpUpgrade:
            return
        case .xhttp:
            try XHTTPParametersValidator.validate(transport: transport)
        case .hysteria:
            return
        }
    }

    private func validateProtocolPayload(_ record: SharedRuntimeProfileRecord) throws {
        switch record.protocolKind {
        case .vless:
            return
        case .vmess:
            guard record.vmess != nil else { throw RuntimeConfigurationError.profileRecordMalformed }
        case .trojan:
            guard record.trojan != nil else { throw RuntimeConfigurationError.profileRecordMalformed }
        case .shadowsocks:
            guard record.shadowsocks != nil else { throw RuntimeConfigurationError.profileRecordMalformed }
        case .hysteria2:
            guard record.hysteria2 != nil else { throw RuntimeConfigurationError.profileRecordMalformed }
        }
    }

    private func validateCredential(_ credential: SensitiveRuntimeCredential, for protocolKind: SharedRuntimeProtocolKind) throws {
        switch protocolKind {
        case .vless, .vmess:
            guard credential.isValidUUID else {
                throw RuntimeConfigurationError.credentialMalformed
            }
        case .trojan, .shadowsocks, .hysteria2:
            guard credential.isNonEmptySecret else {
                throw RuntimeConfigurationError.credentialMalformed
            }
        }
    }

    private func resolveHysteria2ObfsPasswordIfNeeded(from record: SharedRuntimeProfileRecord) async throws -> SensitiveRuntimeCredential? {
        guard record.protocolKind == .hysteria2,
              let reference = record.hysteria2?.obfsPasswordReference else {
            return nil
        }
        guard CredentialReferenceValidator.isValid(reference) else {
            throw RuntimeConfigurationError.malformedCredentialReference
        }
        guard let secret = try await credentialResolver.credential(for: reference) else {
            throw RuntimeConfigurationError.credentialUnavailable
        }
        let sensitive = SensitiveRuntimeCredential(secret)
        guard sensitive.isNonEmptySecret else {
            throw RuntimeConfigurationError.credentialMalformed
        }
        return sensitive
    }

    private func validate(security: SharedRuntimeSecurity) throws {
        switch security.kind {
        case .none, .tls:
            return
        case .reality:
            guard let reality = security.reality else {
                throw RuntimeConfigurationError.invalidSecurityConfiguration
            }
            try RealityPublicParametersValidator.validate(reality)
        }
    }

    private static func stage(for error: any Error) -> TunnelRuntimeConfigurationValidationStage {
        guard let error = error as? RuntimeConfigurationError else {
            return .unknown
        }
        switch error {
        case .missingProviderConfiguration, .malformedProviderConfiguration,
             .providerConfigurationUnknownKey, .providerConfigurationMissingSchemaVersion,
             .providerConfigurationWrongSchemaVersionType, .providerConfigurationUnsupportedSchemaVersion,
             .providerConfigurationMissingProfileID, .providerConfigurationWrongProfileIDType,
             .providerConfigurationMalformedProfileID, .providerConfigurationMissingRecordRevision,
             .providerConfigurationWrongRecordRevisionType, .providerConfigurationInvalidRecordRevision,
             .providerConfigurationPersistedMismatch, .providerConfigurationContractMismatch,
             .providerConfigurationStaleSession, .unsupportedProviderSchema, .missingProfileID,
             .invalidProfileID, .missingRevision, .invalidRevision:
            return .providerConfiguration
        case .profileRecordNotFound, .profileRecordTooLarge, .profileRecordMalformed, .profileRecordCountExceeded,
             .profileSchemaMismatch, .profileIdentityMismatch, .profileRevisionMismatch,
             .profileDisabled, .profileIncomplete, .unsupportedProtocol, .invalidEndpoint,
             .unsupportedTransport, .invalidTransportConfiguration, .invalidXHTTPConfiguration,
             .invalidXHTTPMode, .invalidXHTTPPath, .invalidXHTTPHost, .invalidSecurityConfiguration,
             .sharedContainerUnavailable, .writeFailed, .deleteFailed:
            return .sharedRecord
        case .missingCredentialReference, .malformedCredentialReference:
            return .credentialReference
        case .credentialUnavailable, .credentialMalformed, .sharedKeychainConfigurationInvalid:
            return .credential
        }
    }

    private static func category(for error: any Error) -> TunnelRuntimeConfigurationValidationCategory {
        guard let error = error as? RuntimeConfigurationError else {
            return .unknown
        }
        return TunnelRuntimeConfigurationValidationCategory(rawValue: error.rawValue) ?? .unknown
    }
}

nonisolated protocol RuntimeConfigurationValidationLoading: Sendable {
    func validateRuntimeConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelRuntimeConfigurationValidationResponse
}

protocol XrayConfigurationValidating: Sendable {
    func validateXrayConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayConfigurationValidationResponse
}

extension RuntimeConfigurationLoader: RuntimeConfigurationValidationLoading {
    func validateRuntimeConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelRuntimeConfigurationValidationResponse {
        await validateRuntimeConfiguration(
            providerConfiguration: nil,
            correlationID: correlationID,
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken
        )
    }
}
