//
//  NativeWireGuardRuntime.swift
//  VPN
//
//  Secret-free WireGuard/AmneziaWG runtime records. The application owns
//  import, validation, and publication; only the packet-tunnel extension
//  resolves keychain references and links the native engine.
//

import Foundation
import Network

nonisolated enum NativeWireGuardRuntimeProtocol {
    static let profileSchemaVersion: UInt32 = 1
    static let collectionSchemaVersion: UInt32 = 1
    static let maximumRecordBytes = 64 * 1_024
    static let maximumCollectionBytes = 512 * 1_024
    static let maximumRecordCount = 256
    static let maximumPeerCount = 64
}

nonisolated enum NativeWireGuardMode: String, Codable, Equatable, Sendable {
    case wireGuard
    case amneziaWG
}

nonisolated enum NativeWireGuardRuntimeError: LocalizedError, Equatable, Sendable {
    case unsupportedProtocol
    case protocolConfigurationMismatch
    case profileDisabled
    case profileIncomplete
    case missingPrivateKeyReference
    case malformedCredentialReference
    case credentialUnavailable
    case missingInterfaceAddress
    case invalidInterfaceAddress(String)
    case invalidDNSServer(String)
    case invalidDNSSearchDomain(String)
    case missingPeer
    case tooManyPeers
    case duplicatePeer
    case invalidPublicKey
    case invalidPresharedKeyReference
    case missingAllowedIP
    case invalidAllowedIP(String)
    case invalidExcludedIP(String)
    case invalidEndpoint
    case missingEndpoint
    case invalidPersistentKeepAlive
    case amneziaParametersRequired
    case amneziaParametersForbidden
    case invalidAmneziaParameters
    case recordNotFound
    case recordMalformed
    case recordTooLarge
    case recordCountExceeded
    case schemaMismatch
    case revisionMismatch
    case sharedContainerUnavailable
    case writeFailed

    var errorDescription: String? {
        switch self {
        case .unsupportedProtocol:
            "This profile is not a WireGuard or AmneziaWG profile."
        case .protocolConfigurationMismatch:
            "The selected protocol does not match the native tunnel configuration."
        case .profileDisabled:
            "The profile is disabled."
        case .profileIncomplete:
            "The native tunnel profile is incomplete."
        case .missingPrivateKeyReference:
            "The interface private key is missing."
        case .malformedCredentialReference:
            "A native tunnel credential reference is malformed."
        case .credentialUnavailable:
            "A native tunnel credential is unavailable in the shared keychain."
        case .missingInterfaceAddress:
            "At least one interface address is required."
        case .invalidInterfaceAddress(let value):
            "Invalid interface address: \(value)."
        case .invalidDNSServer(let value):
            "Invalid DNS server: \(value)."
        case .invalidDNSSearchDomain(let value):
            "Invalid DNS search domain: \(value)."
        case .missingPeer:
            "At least one peer is required."
        case .tooManyPeers:
            "The profile contains too many peers."
        case .duplicatePeer:
            "Peer public keys must be unique."
        case .invalidPublicKey:
            "A peer public key is invalid."
        case .invalidPresharedKeyReference:
            "A peer preshared-key reference is invalid."
        case .missingAllowedIP:
            "Each peer must contain at least one allowed IP range."
        case .invalidAllowedIP(let value):
            "Invalid allowed IP range: \(value)."
        case .invalidExcludedIP(let value):
            "Invalid excluded IP range: \(value)."
        case .invalidEndpoint:
            "A peer endpoint is invalid."
        case .missingEndpoint:
            "At least one peer endpoint is required."
        case .invalidPersistentKeepAlive:
            "Persistent keepalive must be a valid value for the selected protocol."
        case .amneziaParametersRequired:
            "AmneziaWG requires at least one Amnezia protocol parameter."
        case .amneziaParametersForbidden:
            "Plain WireGuard cannot contain Amnezia protocol parameters."
        case .invalidAmneziaParameters:
            "The AmneziaWG protocol parameters are inconsistent."
        case .recordNotFound:
            "The native runtime record was not found."
        case .recordMalformed:
            "The native runtime record is malformed."
        case .recordTooLarge:
            "The native runtime record is too large."
        case .recordCountExceeded:
            "The native runtime record limit was exceeded."
        case .schemaMismatch:
            "The native runtime record schema is unsupported."
        case .revisionMismatch:
            "The native runtime record revision does not match."
        case .sharedContainerUnavailable:
            "The shared runtime container is unavailable."
        case .writeFailed:
            "The native runtime record could not be written."
        }
    }
}

nonisolated struct NativeWireGuardProfileRecord: Codable, Equatable, Sendable, CustomDebugStringConvertible {
    var schemaVersion: UInt32
    var profileID: UUID
    var recordRevision: String
    var updatedAt: Date
    var enabled: Bool
    var mode: NativeWireGuardMode
    var privateKeyReference: String
    var interfaceAddresses: [String]
    var dnsServers: [String]
    var dnsSearchDomains: [String]
    var listenPort: UInt16?
    var mtu: UInt16?
    var peers: [WireGuardPeerProfileConfiguration]
    var headerProtectionKeyReference: String?
    var amnezia: AmneziaWGProfileParameters?

    var credentialReferences: Set<String> {
        var references: Set<String> = [privateKeyReference]
        references.formUnion(peers.compactMap(\.presharedKeyReference))
        if let headerProtectionKeyReference {
            references.insert(headerProtectionKeyReference)
        }
        return references
    }

    var debugDescription: String {
        "NativeWireGuardProfileRecord(profileID: \(profileID.uuidString), revision: \(recordRevision), mode: \(mode.rawValue), peers: \(peers.count), credentials: <redacted>)"
    }
}

nonisolated struct NativeWireGuardProfileCollection: Codable, Equatable, Sendable {
    var schemaVersion: UInt32
    var records: [NativeWireGuardProfileRecord]

    init(
        schemaVersion: UInt32 = NativeWireGuardRuntimeProtocol.collectionSchemaVersion,
        records: [NativeWireGuardProfileRecord]
    ) {
        self.schemaVersion = schemaVersion
        self.records = records.sorted { $0.profileID.uuidString < $1.profileID.uuidString }
    }
}

nonisolated enum NativeWireGuardProfileValidator {
    static func capability(for profile: VPNProfile) -> VPNRuntimeCapability {
        do {
            _ = try validatedConfiguration(for: profile)
            return .ready
        } catch let error as NativeWireGuardRuntimeError {
            switch error {
            case .profileIncomplete, .missingPrivateKeyReference, .missingInterfaceAddress, .missingPeer, .missingAllowedIP, .missingEndpoint:
                return .incomplete(profile.missingRequiredFields.isEmpty ? [error.localizedDescription] : profile.missingRequiredFields)
            case .amneziaParametersForbidden, .amneziaParametersRequired:
                return .unsupported(.unsupportedFeature(
                    protocolType: profile.protocolType,
                    feature: .nativeProtocolMode
                ))
            default:
                return .invalid(.invalidConfiguration(
                    protocolType: profile.protocolType,
                    component: "native tunnel"
                ))
            }
        } catch {
            return .invalid(.invalidConfiguration(protocolType: profile.protocolType, component: "native tunnel"))
        }
    }

    static func validatedConfiguration(for profile: VPNProfile) throws -> (NativeWireGuardMode, WireGuardProfileConfiguration) {
        guard profile.isEnabled else {
            throw NativeWireGuardRuntimeError.profileDisabled
        }
        guard let privateKeyReference = profile.credentialReference,
              CredentialReferenceValidator.isValid(privateKeyReference) else {
            throw NativeWireGuardRuntimeError.missingPrivateKeyReference
        }

        let mode: NativeWireGuardMode
        let configuration: WireGuardProfileConfiguration
        switch (profile.protocolType, profile.protocolConfiguration) {
        case (.wireGuard, .wireGuard(let value)):
            mode = .wireGuard
            configuration = value
        case (.amneziaWG, .amneziaWG(let value)):
            mode = .amneziaWG
            configuration = value
        case (.wireGuard, _), (.amneziaWG, _):
            throw NativeWireGuardRuntimeError.protocolConfigurationMismatch
        default:
            throw NativeWireGuardRuntimeError.unsupportedProtocol
        }

        guard configuration.interfaceAddresses.isEmpty == false else {
            throw NativeWireGuardRuntimeError.missingInterfaceAddress
        }
        for address in configuration.interfaceAddresses {
            guard isValidIPRange(address) else {
                throw NativeWireGuardRuntimeError.invalidInterfaceAddress(address)
            }
        }
        for server in configuration.dnsServers where isValidIPAddress(server) == false {
            throw NativeWireGuardRuntimeError.invalidDNSServer(server)
        }
        for domain in configuration.dnsSearchDomains where isValidSearchDomain(domain) == false {
            throw NativeWireGuardRuntimeError.invalidDNSSearchDomain(domain)
        }

        guard configuration.peers.isEmpty == false else {
            throw NativeWireGuardRuntimeError.missingPeer
        }
        guard configuration.peers.count <= NativeWireGuardRuntimeProtocol.maximumPeerCount else {
            throw NativeWireGuardRuntimeError.tooManyPeers
        }
        let publicKeys = configuration.peers.map { normalized($0.publicKey) }
        guard publicKeys.allSatisfy(isValidKey), Set(publicKeys).count == publicKeys.count else {
            throw publicKeys.allSatisfy(isValidKey)
                ? NativeWireGuardRuntimeError.duplicatePeer
                : NativeWireGuardRuntimeError.invalidPublicKey
        }

        var hasEndpoint = false
        for peer in configuration.peers {
            if let reference = peer.presharedKeyReference,
               CredentialReferenceValidator.isValid(reference) == false {
                throw NativeWireGuardRuntimeError.invalidPresharedKeyReference
            }
            guard peer.allowedIPs.isEmpty == false else {
                throw NativeWireGuardRuntimeError.missingAllowedIP
            }
            for allowedIP in peer.allowedIPs where isValidIPRange(allowedIP) == false {
                throw NativeWireGuardRuntimeError.invalidAllowedIP(allowedIP)
            }
            for excludedIP in peer.excludedIPs where isValidIPRange(excludedIP) == false {
                throw NativeWireGuardRuntimeError.invalidExcludedIP(excludedIP)
            }
            if let endpoint = peer.endpoint {
                guard isValidEndpointHost(endpoint.host), endpoint.port > 0 else {
                    throw NativeWireGuardRuntimeError.invalidEndpoint
                }
                hasEndpoint = true
            }
            if let keepAlive = normalizedOptional(peer.persistentKeepAlive),
               isValidPersistentKeepAlive(keepAlive, mode: mode) == false {
                throw NativeWireGuardRuntimeError.invalidPersistentKeepAlive
            }
        }
        guard hasEndpoint else {
            throw NativeWireGuardRuntimeError.missingEndpoint
        }

        switch mode {
        case .wireGuard:
            guard configuration.headerProtectionKeyReference == nil,
                  configuration.amnezia?.hasAnyValue != true else {
                throw NativeWireGuardRuntimeError.amneziaParametersForbidden
            }
        case .amneziaWG:
            guard configuration.amnezia?.hasAnyValue == true || configuration.headerProtectionKeyReference != nil else {
                throw NativeWireGuardRuntimeError.amneziaParametersRequired
            }
            if let reference = configuration.headerProtectionKeyReference,
               CredentialReferenceValidator.isValid(reference) == false {
                throw NativeWireGuardRuntimeError.malformedCredentialReference
            }
            if let minimum = configuration.amnezia?.junkPacketMinSize,
               let maximum = configuration.amnezia?.junkPacketMaxSize,
               minimum > maximum {
                throw NativeWireGuardRuntimeError.invalidAmneziaParameters
            }
        }

        return (mode, configuration)
    }

    static func isValidKey(_ value: String) -> Bool {
        let key = normalized(value)
        return Data(base64Encoded: key)?.count == 32
    }

    static func isValidIPRange(_ value: String) -> Bool {
        let pieces = normalized(value).split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.count == 2,
              let prefix = UInt8(pieces[1]) else {
            return false
        }
        let address = String(pieces[0])
        if IPv4Address(address) != nil {
            return prefix <= 32
        }
        if IPv6Address(address) != nil {
            return prefix <= 128
        }
        return false
    }

    static func isValidIPAddress(_ value: String) -> Bool {
        let value = normalized(value)
        return IPv4Address(value) != nil || IPv6Address(value) != nil
    }

    private static func isValidEndpointHost(_ value: String) -> Bool {
        let host = normalized(value)
        return host.isEmpty == false
            && host.utf8.count <= 255
            && host.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
            && host.rangeOfCharacter(from: .controlCharacters) == nil
    }

    private static func isValidSearchDomain(_ value: String) -> Bool {
        let domain = normalized(value)
        return domain.isEmpty == false
            && domain.utf8.count <= 253
            && domain.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
            && domain.rangeOfCharacter(from: .controlCharacters) == nil
    }

    private static func isValidPersistentKeepAlive(_ value: String, mode: NativeWireGuardMode) -> Bool {
        let values = value.split(separator: "-", omittingEmptySubsequences: false)
        switch mode {
        case .wireGuard:
            return values.count == 1 && UInt16(values[0]) != nil
        case .amneziaWG:
            guard values.count == 1 || values.count == 2,
                  let lower = UInt16(values[0]) else {
                return false
            }
            guard values.count == 2 else {
                return true
            }
            guard let upper = UInt16(values[1]) else {
                return false
            }
            return lower <= upper
        }
    }

    private static func normalized(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func normalizedOptional(_ value: String?) -> String? {
        guard let value else { return nil }
        let normalized = normalized(value)
        return normalized.isEmpty ? nil : normalized
    }
}

nonisolated struct NativeWireGuardProfileMapper {
    private let now: @Sendable () -> Date

    init(now: @escaping @Sendable () -> Date = Date.init) {
        self.now = now
    }

    func record(from profile: VPNProfile) throws -> NativeWireGuardProfileRecord {
        let (mode, configuration) = try NativeWireGuardProfileValidator.validatedConfiguration(for: profile)
        guard let privateKeyReference = profile.credentialReference else {
            throw NativeWireGuardRuntimeError.missingPrivateKeyReference
        }

        let canonicalPeers = configuration.peers.map { peer in
            WireGuardPeerProfileConfiguration(
                publicKey: peer.publicKey.trimmingCharacters(in: .whitespacesAndNewlines),
                presharedKeyReference: peer.presharedKeyReference?.trimmingCharacters(in: .whitespacesAndNewlines),
                allowedIPs: peer.allowedIPs
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .sorted(),
                excludedIPs: peer.excludedIPs
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .sorted(),
                endpoint: peer.endpoint.map {
                    WireGuardEndpointProfileConfiguration(
                        host: $0.host.trimmingCharacters(in: .whitespacesAndNewlines),
                        port: $0.port
                    )
                },
                persistentKeepAlive: peer.persistentKeepAlive?.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        let sortedPeers = canonicalPeers.sorted { lhs, rhs in
            let lhsKey = lhs.publicKey.trimmingCharacters(in: .whitespacesAndNewlines)
            let rhsKey = rhs.publicKey.trimmingCharacters(in: .whitespacesAndNewlines)
            if lhsKey != rhsKey {
                return lhsKey < rhsKey
            }
            return (lhs.endpoint?.host ?? "") < (rhs.endpoint?.host ?? "")
        }
        var record = NativeWireGuardProfileRecord(
            schemaVersion: NativeWireGuardRuntimeProtocol.profileSchemaVersion,
            profileID: profile.id,
            recordRevision: "",
            updatedAt: now(),
            enabled: profile.isEnabled,
            mode: mode,
            privateKeyReference: privateKeyReference.trimmingCharacters(in: .whitespacesAndNewlines),
            interfaceAddresses: configuration.interfaceAddresses
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .sorted(),
            dnsServers: configuration.dnsServers
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .sorted(),
            dnsSearchDomains: configuration.dnsSearchDomains
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .sorted(),
            listenPort: configuration.listenPort,
            mtu: configuration.mtu,
            peers: sortedPeers,
            headerProtectionKeyReference: configuration.headerProtectionKeyReference?
                .trimmingCharacters(in: .whitespacesAndNewlines),
            amnezia: configuration.amnezia
        )
        record.recordRevision = try NativeWireGuardRevisionCalculator.revision(for: record)
        return record
    }
}

nonisolated enum NativeWireGuardRevisionCalculator {
    static func revision(for record: NativeWireGuardProfileRecord) throws -> String {
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

nonisolated protocol NativeWireGuardProfileStoring: Sendable {
    func write(_ record: NativeWireGuardProfileRecord) async throws
    func read(profileID: UUID) async throws -> NativeWireGuardProfileRecord
    func records() async throws -> [NativeWireGuardProfileRecord]
    func delete(profileID: UUID) async throws
}

actor FileNativeWireGuardProfileStore: NativeWireGuardProfileStoring {
    private let fileURL: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let fileManager: FileManager

    init(fileURL: URL, fileManager: FileManager = .default) {
        self.fileURL = fileURL
        self.fileManager = fileManager
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    static func appGroupStore(fileManager: FileManager = .default) -> FileNativeWireGuardProfileStore? {
        guard let container = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier
        ) else {
            return nil
        }
        return FileNativeWireGuardProfileStore(
            fileURL: container
                .appendingPathComponent("NativeProfiles", isDirectory: true)
                .appendingPathComponent("native-wireguard-profiles-v1.json"),
            fileManager: fileManager
        )
    }

    func write(_ record: NativeWireGuardProfileRecord) async throws {
        var current = try loadCollection().records
        current.removeAll { $0.profileID == record.profileID }
        current.append(record)
        try writeCollection(NativeWireGuardProfileCollection(records: current))
    }

    func read(profileID: UUID) async throws -> NativeWireGuardProfileRecord {
        guard let record = try loadCollection().records.first(where: { $0.profileID == profileID }) else {
            throw NativeWireGuardRuntimeError.recordNotFound
        }
        return record
    }

    func records() async throws -> [NativeWireGuardProfileRecord] {
        try loadCollection().records
    }

    func delete(profileID: UUID) async throws {
        var current = try loadCollection().records
        current.removeAll { $0.profileID == profileID }
        try writeCollection(NativeWireGuardProfileCollection(records: current))
    }

    private func loadCollection() throws -> NativeWireGuardProfileCollection {
        guard fileManager.fileExists(atPath: fileURL.path) else {
            return NativeWireGuardProfileCollection(records: [])
        }
        do {
            let values = try fileURL.resourceValues(forKeys: [.fileSizeKey])
            if let size = values.fileSize, size > NativeWireGuardRuntimeProtocol.maximumCollectionBytes {
                throw NativeWireGuardRuntimeError.recordTooLarge
            }
            let data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
            guard data.count <= NativeWireGuardRuntimeProtocol.maximumCollectionBytes else {
                throw NativeWireGuardRuntimeError.recordTooLarge
            }
            let collection = try decoder.decode(NativeWireGuardProfileCollection.self, from: data)
            try validate(collection)
            return collection
        } catch let error as NativeWireGuardRuntimeError {
            throw error
        } catch {
            throw NativeWireGuardRuntimeError.recordMalformed
        }
    }

    private func writeCollection(_ collection: NativeWireGuardProfileCollection) throws {
        try validate(collection)
        do {
            let data = try encoder.encode(collection)
            guard data.count <= NativeWireGuardRuntimeProtocol.maximumCollectionBytes else {
                throw NativeWireGuardRuntimeError.recordTooLarge
            }
            try fileManager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: fileURL, options: [.atomic])
            #if os(iOS)
            try? fileManager.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: fileURL.path
            )
            #endif
        } catch let error as NativeWireGuardRuntimeError {
            throw error
        } catch {
            throw NativeWireGuardRuntimeError.writeFailed
        }
    }

    private func validate(_ collection: NativeWireGuardProfileCollection) throws {
        guard collection.schemaVersion == NativeWireGuardRuntimeProtocol.collectionSchemaVersion else {
            throw NativeWireGuardRuntimeError.schemaMismatch
        }
        guard collection.records.count <= NativeWireGuardRuntimeProtocol.maximumRecordCount else {
            throw NativeWireGuardRuntimeError.recordCountExceeded
        }
        guard Set(collection.records.map(\.profileID)).count == collection.records.count else {
            throw NativeWireGuardRuntimeError.recordMalformed
        }
        for record in collection.records {
            guard record.schemaVersion == NativeWireGuardRuntimeProtocol.profileSchemaVersion else {
                throw NativeWireGuardRuntimeError.schemaMismatch
            }
            guard record.recordRevision == (try NativeWireGuardRevisionCalculator.revision(for: record)) else {
                throw NativeWireGuardRuntimeError.revisionMismatch
            }
            guard try encoder.encode(record).count <= NativeWireGuardRuntimeProtocol.maximumRecordBytes else {
                throw NativeWireGuardRuntimeError.recordTooLarge
            }
        }
    }
}

actor NativeWireGuardProfilePublisher {
    private let mapper: NativeWireGuardProfileMapper
    private let store: any NativeWireGuardProfileStoring
    private let credentialStore: any CredentialStoring

    init(
        mapper: NativeWireGuardProfileMapper = NativeWireGuardProfileMapper(),
        store: any NativeWireGuardProfileStoring,
        credentialStore: any CredentialStoring
    ) {
        self.mapper = mapper
        self.store = store
        self.credentialStore = credentialStore
    }

    static func appGroupPublisher(
        credentialStore: any CredentialStoring = KeychainCredentialStore()
    ) -> NativeWireGuardProfilePublisher? {
        guard let store = FileNativeWireGuardProfileStore.appGroupStore() else {
            return nil
        }
        return NativeWireGuardProfilePublisher(store: store, credentialStore: credentialStore)
    }

    func publish(_ profile: VPNProfile) async throws -> NativeWireGuardProfileRecord {
        let record = try mapper.record(from: profile)
        for reference in record.credentialReferences.sorted() {
            guard CredentialReferenceValidator.isValid(reference) else {
                throw NativeWireGuardRuntimeError.malformedCredentialReference
            }
            guard let value = try await credentialStore.secret(for: reference),
                  value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false else {
                throw NativeWireGuardRuntimeError.credentialUnavailable
            }
        }
        try await store.write(record)
        return record
    }

    func delete(profileID: UUID) async throws {
        try await store.delete(profileID: profileID)
    }

    func snapshot(profileID: UUID) async throws -> NativeWireGuardProfileRecord? {
        do {
            return try await store.read(profileID: profileID)
        } catch NativeWireGuardRuntimeError.recordNotFound {
            return nil
        }
    }

    func restore(_ record: NativeWireGuardProfileRecord?, profileID: UUID) async throws {
        if let record {
            try await store.write(record)
        } else {
            try await store.delete(profileID: profileID)
        }
    }

    func credentialReferences() async throws -> Set<String> {
        try await store.records().reduce(into: Set<String>()) { references, record in
            references.formUnion(record.credentialReferences)
        }
    }
}

actor NativeWireGuardRuntimeProfileSynchronizer: RuntimeProfileSynchronizing {
    private let publisher: NativeWireGuardProfilePublisher

    init(publisher: NativeWireGuardProfilePublisher) {
        self.publisher = publisher
    }

    func profileSaved(_ profile: VPNProfile) async throws -> RuntimeProfileSynchronizationSummary {
        guard profile.protocolType == .wireGuard || profile.protocolType == .amneziaWG else {
            try await publisher.delete(profileID: profile.id)
            return RuntimeProfileSynchronizationSummary(publishedProfileIDs: [], omissions: [])
        }
        let record = try await publisher.publish(profile)
        return RuntimeProfileSynchronizationSummary(publishedProfileIDs: [record.profileID], omissions: [])
    }

    func profileDeleted(id: UUID) async throws {
        try await publisher.delete(profileID: id)
    }

    func credentialReferences() async throws -> Set<String> {
        try await publisher.credentialReferences()
    }
}

actor CompositeRuntimeProfileSynchronizer: RuntimeProfileSynchronizing {
    private let xray: any RuntimeProfileSynchronizing
    private let native: any RuntimeProfileSynchronizing

    init(xray: any RuntimeProfileSynchronizing, native: any RuntimeProfileSynchronizing) {
        self.xray = xray
        self.native = native
    }

    func profileSaved(_ profile: VPNProfile) async throws -> RuntimeProfileSynchronizationSummary {
        if profile.protocolType == .wireGuard || profile.protocolType == .amneziaWG {
            try await xray.profileDeleted(id: profile.id)
            return try await native.profileSaved(profile)
        }
        try await native.profileDeleted(id: profile.id)
        return try await xray.profileSaved(profile)
    }

    func profileDeleted(id: UUID) async throws {
        try await xray.profileDeleted(id: id)
        try await native.profileDeleted(id: id)
    }

    func credentialReferences() async throws -> Set<String> {
        let xrayReferences = try await xray.credentialReferences()
        let nativeReferences = try await native.credentialReferences()
        return xrayReferences.union(nativeReferences)
    }
}
