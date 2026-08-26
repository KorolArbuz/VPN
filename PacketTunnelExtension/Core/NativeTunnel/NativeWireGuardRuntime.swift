//
//  NativeWireGuardRuntime.swift
//  PacketTunnelExtension
//
//  Extension-owned WireGuard/AmneziaWG configuration loading and adapter
//  lifecycle. This is the only application target seam that imports
//  WireGuardKit and resolves native tunnel secrets.
//

import Foundation
import Darwin
import Network
import NetworkExtension
import OSLog
import os
@preconcurrency import WireGuardKit

nonisolated enum NativeWireGuardMode: String, Codable, Equatable, Sendable {
    case wireGuard
    case amneziaWG

    var telemetryProtocolKind: TunnelProtocolKind {
        switch self {
        case .wireGuard:
            .wireguard
        case .amneziaWG:
            .amneziawg
        }
    }
}

nonisolated enum NativeWireGuardTrace {
    private static let diagnosticsStore = TunnelStartupDiagnosticsStore.appGroupStore()
    private static let extensionBuild = TunnelBuildIdentity.current()
    private static let startupProgress = NativeWireGuardStartupProgress()
    private static let providerLogger = Logger(
        subsystem: "su.24kvn.kvn-app",
        category: "Tunnel.Provider"
    )
    private static let awgLogger = Logger(
        subsystem: "su.24kvn.kvn-app",
        category: "Tunnel.AWG"
    )

    @discardableResult
    static func event(
        _ stage: TunnelStartupStage,
        outcome: TunnelDiagnosticOutcome = .succeeded,
        attemptID: UUID,
        profileID: UUID? = nil,
        mode: NativeWireGuardMode? = nil,
        revision: String? = nil,
        error: (any Error)? = nil,
        failureCategory: NativeTunnelFailureCategory? = nil,
        safeConfiguration: NativeTunnelSafeConfigurationSummary? = nil,
        nativeStatus: Int32? = nil,
        systemErrorDomain: String? = nil,
        systemErrorCode: Int? = nil,
        additionalDetails: [String: String] = [:]
    ) -> Task<Void, Never> {
        let category = failureCategory ?? error.map(category)
        var details = additionalDetails
        details["backend"] = "nativeWireGuardAdapter"
        if let profileID { details["profileID"] = profileID.uuidString }
        if let mode { details["protocol"] = mode.rawValue }
        if let revision { details["runtimeRevision"] = revision }
        if let category { details["failureCategory"] = category.rawValue }
        if let nativeStatus { details["nativeCode"] = String(nativeStatus) }
        if let systemErrorDomain { details["systemErrorDomain"] = systemErrorDomain }
        if let systemErrorCode { details["systemErrorCode"] = String(systemErrorCode) }

        let event = TunnelDiagnosticEvent(
            attemptID: attemptID,
            source: .provider,
            stage: stage,
            outcome: outcome,
            details: details,
            failureCategory: category,
            error: error.map { TunnelDiagnosticError(error: $0) },
            safeConfiguration: safeConfiguration
        )
        startupProgress.record(stage, for: attemptID)
        let logger = mode == .amneziaWG ? awgLogger : providerLogger
        logger.notice(
            "\(stage.rawValue, privacy: .public) attempt=\(attemptID.uuidString, privacy: .public) profile=\(profileID?.uuidString ?? "-", privacy: .public) protocol=\(mode?.rawValue ?? "-", privacy: .public) revision=\(revision ?? "-", privacy: .public) category=\(category?.rawValue ?? "-", privacy: .public) nativeStatus=\(nativeStatus.map(String.init) ?? "-", privacy: .public) systemError=\(systemErrorDomain ?? "-", privacy: .public)/\(systemErrorCode.map(String.init) ?? "-", privacy: .public)"
        )
        return Task {
            guard let diagnosticsStore else {
                providerLogger.error(
                    "startup diagnostics App Group unavailable attempt=\(attemptID.uuidString, privacy: .public)"
                )
                return
            }
            do {
                try await diagnosticsStore.record(event, build: extensionBuild)
            } catch {
                let nsError = error as NSError
                providerLogger.error(
                    "startup diagnostics write failed attempt=\(attemptID.uuidString, privacy: .public) error=\(nsError.domain, privacy: .public)/\(nsError.code, privacy: .public)"
                )
            }
        }
    }

    static func lastRecordedStage(for attemptID: UUID) -> TunnelStartupStage? {
        startupProgress.lastStage(for: attemptID)
    }

    /// Persists a bounded checkpoint without making provider startup wait for
    /// the actor-backed diagnostics timeline. OSLog is emitted before the
    /// synchronous sidecar write so a blocked file operation remains visible.
    static func controllerConstructionCheckpoint(
        _ stage: TunnelStartupStage,
        outcome: TunnelDiagnosticOutcome = .succeeded,
        attemptID: UUID,
        mode: NativeWireGuardMode
    ) {
        let details = [
            "backend": "nativeWireGuardAdapter",
            "protocol": mode.rawValue
        ]
        let event = TunnelDiagnosticEvent(
            attemptID: attemptID,
            source: .provider,
            stage: stage,
            outcome: outcome,
            details: details
        )
        startupProgress.record(stage, for: attemptID)
        let logger = mode == .amneziaWG ? awgLogger : providerLogger
        logger.notice(
            "\(stage.rawValue, privacy: .public) attempt=\(attemptID.uuidString, privacy: .public) protocol=\(mode.rawValue, privacy: .public)"
        )
        do {
            try TunnelNativeConstructionCheckpointJournal.appendToAppGroup(
                event,
                build: extensionBuild
            )
        } catch {
            let nsError = error as NSError
            providerLogger.error(
                "controller construction checkpoint write failed attempt=\(attemptID.uuidString, privacy: .public) error=\(nsError.domain, privacy: .public)/\(nsError.code, privacy: .public)"
            )
        }
        Task {
            guard let diagnosticsStore else { return }
            try? await diagnosticsStore.record(event, build: extensionBuild)
        }
    }

    static func adapterInitializationCheckpoint(
        _ checkpoint: WireGuardAdapterInitializationCheckpoint,
        attemptID: UUID,
        mode: NativeWireGuardMode
    ) {
        guard let stage = TunnelStartupStage(rawValue: checkpoint.rawValue) else {
            providerLogger.error(
                "unknown WireGuardAdapter checkpoint attempt=\(attemptID.uuidString, privacy: .public) checkpoint=\(checkpoint.rawValue, privacy: .public)"
            )
            return
        }
        var details: [String: String] = [
            "backend": "nativeWireGuardAdapter",
            "protocol": mode.rawValue
        ]
        if checkpoint == .wireGuardAdapterWGTurnOnCallStarted
            || checkpoint == .wireGuardAdapterWGSetLoggerCallStarted {
            details.merge(NativeWireGuardProcessMemorySnapshot.current().diagnosticDetails) { _, new in new }
        }
        if checkpoint == .wireGuardAdapterLoggerInstallationBypassed {
            details["loggerInstallationBypassed"] = "true"
        }
        let event = TunnelDiagnosticEvent(
            attemptID: attemptID,
            source: .provider,
            stage: stage,
            outcome: checkpoint == .wireGuardAdapterWGSetLoggerCallStarted
                || checkpoint == .wireGuardAdapterWGTurnOnCallStarted
                ? .started
                : .succeeded,
            details: details
        )
        startupProgress.record(stage, for: attemptID)
        let logger = mode == .amneziaWG ? awgLogger : providerLogger
        logger.notice(
            "\(stage.rawValue, privacy: .public) attempt=\(attemptID.uuidString, privacy: .public) protocol=\(mode.rawValue, privacy: .public) physicalFootprintBytes=\(details["physicalFootprintBytes"] ?? "-", privacy: .public) residentSizeBytes=\(details["residentSizeBytes"] ?? "-", privacy: .public) availableMemoryBytes=\(details["availableMemoryBytes"] ?? "-", privacy: .public)"
        )
        do {
            try TunnelNativeConstructionCheckpointJournal.appendToAppGroup(
                event,
                build: extensionBuild
            )
        } catch {
            let nsError = error as NSError
            providerLogger.error(
                "native construction checkpoint write failed attempt=\(attemptID.uuidString, privacy: .public) error=\(nsError.domain, privacy: .public)/\(nsError.code, privacy: .public)"
            )
        }
        Task {
            guard let diagnosticsStore else { return }
            try? await diagnosticsStore.record(event, build: extensionBuild)
        }
    }

    private static func category(for error: any Error) -> NativeTunnelFailureCategory {
        if let failure = error as? NativeWireGuardStartupFailure {
            return category(for: failure.category)
        }
        guard let error = error as? NativeWireGuardExtensionError else {
            return .unknown
        }
        return category(for: error)
    }

    static func category(for error: NativeWireGuardExtensionError) -> NativeTunnelFailureCategory {
        switch error {
        case .sharedContainerUnavailable, .recordUnavailable:
            .runtimeProfileUnavailable
        case .providerConfigurationInvalid:
            .invalidProviderConfiguration
        case .recordMalformed:
            .runtimeProfileMalformed
        case .schemaMismatch:
            .runtimeSchemaMismatch
        case .revisionMismatch:
            .runtimeRevisionMismatch
        case .modeMismatch:
            .runtimeModeMismatch
        case .profileDisabled:
            .profileDisabled
        case .credentialUnavailable:
            .sharedCredentialUnavailable
        case .configurationInvalid:
            .awgConfigurationInvalid
        case .alreadyRunning, .adapterInvalidState:
            .adapterInvalidState
        case .adapterStartFailed, .backendStartFailed:
            .nativeBackendStartupFailed
        case .cancelled:
            .cancelled
        case .cannotLocateTunnelFileDescriptor:
            .tunnelFileDescriptorUnavailable
        case .endpointDNSResolutionFailed:
            .dnsResolutionFailed
        case .networkSettingsRejected:
            .networkSettingsRejected
        case .startupCompletionTimeout:
            .providerStartupStalled
        case .adapterStartTimeout:
            .adapterStartTimeout
        case .nativeBackendControllerUnavailable:
            .nativeBackendControllerUnavailable
        case .runtimeLoaderUnavailable:
            .runtimeLoaderUnavailable
        case .providerStartupStalled:
            .providerStartupStalled
        }
    }
}

nonisolated struct NativeWireGuardProcessMemorySnapshot: Equatable, Sendable {
    var physicalFootprintBytes: UInt64?
    var residentSizeBytes: UInt64?
    var availableMemoryBytes: UInt64?

    var diagnosticDetails: [String: String] {
        var details: [String: String] = [:]
        if let physicalFootprintBytes {
            details["physicalFootprintBytes"] = String(physicalFootprintBytes)
        }
        if let residentSizeBytes {
            details["residentSizeBytes"] = String(residentSizeBytes)
        }
        if let availableMemoryBytes {
            details["availableMemoryBytes"] = String(availableMemoryBytes)
        }
        return details
    }

    static func current() -> NativeWireGuardProcessMemorySnapshot {
        NativeWireGuardProcessMemorySnapshot(
            physicalFootprintBytes: physicalFootprint(),
            residentSizeBytes: residentSize(),
            availableMemoryBytes: UInt64(os_proc_available_memory())
        )
    }

    private static func physicalFootprint() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size
        )
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                task_info(
                    mach_task_self_,
                    task_flavor_t(TASK_VM_INFO),
                    rebound,
                    &count
                )
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        return UInt64(info.phys_footprint)
    }

    private static func residentSize() -> UInt64? {
        var info = mach_task_basic_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<mach_task_basic_info_data_t>.size / MemoryLayout<integer_t>.size
        )
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                task_info(
                    mach_task_self_,
                    task_flavor_t(MACH_TASK_BASIC_INFO),
                    rebound,
                    &count
                )
            }
        }
        guard result == KERN_SUCCESS else { return nil }
        return UInt64(info.resident_size)
    }
}

nonisolated enum NativeWireGuardLoggerDiagnosticSwitch {
    #if DEBUG
    // Keep the one-shot control compiled only in DEBUG. The current physical-
    // device build has not yet proved that WireGuardAdapter.init is entered,
    // so the bypass remains disabled until the controller-make boundary returns.
    static let bypassSetupLogHandler = false
    #else
    static let bypassSetupLogHandler = false
    #endif
}

private nonisolated final class NativeWireGuardStartupProgress: @unchecked Sendable {
    private let lock = NSLock()
    private var stages: [UUID: TunnelStartupStage] = [:]

    func record(_ stage: TunnelStartupStage, for attemptID: UUID) {
        lock.withLock {
            stages[attemptID] = stage
        }
    }

    func lastStage(for attemptID: UUID) -> TunnelStartupStage? {
        lock.withLock { stages[attemptID] }
    }
}

nonisolated struct NativeWireGuardEndpointRecord: Codable, Equatable, Sendable {
    var host: String
    var port: UInt16
}

nonisolated struct NativeWireGuardPeerRecord: Codable, Equatable, Sendable {
    var publicKey: String
    var presharedKeyReference: String?
    var allowedIPs: [String]
    var excludedIPs: [String]
    var endpoint: NativeWireGuardEndpointRecord?
    var persistentKeepAlive: String?
}

nonisolated struct NativeAmneziaWGParameters: Codable, Equatable, Sendable {
    var junkPacketCount: UInt16?
    var junkPacketMinSize: UInt16?
    var junkPacketMaxSize: UInt16?
    var initPacketJunkSize: UInt16?
    var responsePacketJunkSize: UInt16?
    var cookieReplyPacketJunkSize: UInt16?
    var transportPacketJunkSize: UInt16?
    var initPacketMagicHeader: String?
    var responsePacketMagicHeader: String?
    var underloadPacketMagicHeader: String?
    var transportPacketMagicHeader: String?
    var specialJunk1: String?
    var specialJunk2: String?
    var specialJunk3: String?
    var specialJunk4: String?
    var specialJunk5: String?
    var contentPaddingAddition: String?
    var rekeyAfterTime: String?
    var rekeyTimeout: String?
    var rejectAfterTime: String?
    var keepaliveTimeout: String?
    var maxHandshakeAttempts: String?
    var randomTrailers: String?
    var disableCookies: String?

    var hasAnyValue: Bool {
        junkPacketCount != nil
            || junkPacketMinSize != nil
            || junkPacketMaxSize != nil
            || initPacketJunkSize != nil
            || responsePacketJunkSize != nil
            || cookieReplyPacketJunkSize != nil
            || transportPacketJunkSize != nil
            || initPacketMagicHeader != nil
            || responsePacketMagicHeader != nil
            || underloadPacketMagicHeader != nil
            || transportPacketMagicHeader != nil
            || specialJunk1 != nil
            || specialJunk2 != nil
            || specialJunk3 != nil
            || specialJunk4 != nil
            || specialJunk5 != nil
            || contentPaddingAddition != nil
            || rekeyAfterTime != nil
            || rekeyTimeout != nil
            || rejectAfterTime != nil
            || keepaliveTimeout != nil
            || maxHandshakeAttempts != nil
            || randomTrailers != nil
            || disableCookies != nil
    }
}

nonisolated struct NativeWireGuardProfileRecord: Codable, Equatable, Sendable {
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
    var peers: [NativeWireGuardPeerRecord]
    var headerProtectionKeyReference: String?
    var amnezia: NativeAmneziaWGParameters?
}

nonisolated struct NativeWireGuardProfileCollection: Codable, Equatable, Sendable {
    var schemaVersion: UInt32
    var records: [NativeWireGuardProfileRecord]
}

nonisolated enum NativeWireGuardExtensionError: Int, LocalizedError, Equatable, Sendable {
    case sharedContainerUnavailable = 1
    case providerConfigurationInvalid
    case recordUnavailable
    case recordMalformed
    case schemaMismatch
    case revisionMismatch
    case modeMismatch
    case profileDisabled
    case credentialUnavailable
    case configurationInvalid
    case alreadyRunning
    case adapterStartFailed
    case cancelled
    case cannotLocateTunnelFileDescriptor
    case adapterInvalidState
    case endpointDNSResolutionFailed
    case networkSettingsRejected
    case backendStartFailed
    case startupCompletionTimeout
    case adapterStartTimeout
    case nativeBackendControllerUnavailable
    case runtimeLoaderUnavailable
    case providerStartupStalled

    var errorDescription: String? {
        switch self {
        case .sharedContainerUnavailable:
            "The shared native tunnel container is unavailable."
        case .providerConfigurationInvalid:
            "The native tunnel provider configuration is invalid."
        case .recordUnavailable:
            "The native tunnel runtime record is unavailable."
        case .recordMalformed:
            "The native tunnel runtime record is malformed."
        case .schemaMismatch:
            "The native tunnel runtime schema is unsupported."
        case .revisionMismatch:
            "The native tunnel runtime revision does not match."
        case .modeMismatch:
            "The requested native protocol mode does not match the runtime record."
        case .profileDisabled:
            "The native tunnel profile is disabled."
        case .credentialUnavailable:
            "A native tunnel credential is unavailable."
        case .configurationInvalid:
            "The native tunnel configuration is invalid."
        case .alreadyRunning:
            "A native tunnel is already running."
        case .adapterStartFailed:
            "The native WireGuard adapter could not start."
        case .cancelled:
            "Native tunnel startup was cancelled."
        case .cannotLocateTunnelFileDescriptor:
            "The native WireGuard tunnel interface is unavailable."
        case .adapterInvalidState:
            "The native WireGuard adapter is in an invalid state."
        case .endpointDNSResolutionFailed:
            "WireGuard endpoint DNS resolution failed."
        case .networkSettingsRejected:
            "iOS rejected tunnel network settings."
        case .backendStartFailed:
            "WireGuard native backend failed to start."
        case .startupCompletionTimeout:
            "The packet tunnel provider did not complete native startup in time."
        case .adapterStartTimeout:
            "The native WireGuard adapter did not complete startup in time."
        case .nativeBackendControllerUnavailable:
            "The native WireGuard controller could not be constructed."
        case .runtimeLoaderUnavailable:
            "The native runtime configuration loader is unavailable."
        case .providerStartupStalled:
            "The packet tunnel provider stalled during native startup."
        }
    }

    var nsError: NSError {
        nsError(underlying: nil, nativeStatus: nil)
    }

    func nsError(underlying: NSError?, nativeStatus: Int32?) -> NSError {
        var userInfo: [String: Any] = [NSLocalizedDescriptionKey: localizedDescription]
        if let underlying {
            userInfo[NSUnderlyingErrorKey] = underlying
        }
        if let nativeStatus {
            userInfo["KVNNativeStatus"] = NSNumber(value: nativeStatus)
        }
        return NSError(
            domain: "su.24kvn.packet-tunnel.native-wireguard",
            code: rawValue,
            userInfo: userInfo
        )
    }
}

nonisolated struct NativeWireGuardStartupFailure: LocalizedError, @unchecked Sendable {
    var category: NativeWireGuardExtensionError
    var nativeStatus: Int32?
    var underlyingError: NSError?

    var errorDescription: String? { category.errorDescription }

    var nsError: NSError {
        category.nsError(underlying: underlyingError, nativeStatus: nativeStatus)
    }
}

nonisolated struct ResolvedNativeWireGuardConfiguration: @unchecked Sendable {
    var profileID: UUID
    var recordRevision: String
    var mode: NativeWireGuardMode
    var tunnelConfiguration: TunnelConfiguration
    var summary: NativeWireGuardConfigurationSummary
}

typealias NativeWireGuardConfigurationSummary = NativeTunnelSafeConfigurationSummary

final class NativeWireGuardConfigurationLoader: @unchecked Sendable {
    private static let profileSchemaVersion: UInt32 = 1
    private static let collectionSchemaVersion: UInt32 = 1
    private static let maximumRecordBytes = 64 * 1_024
    private static let maximumCollectionBytes = 512 * 1_024
    private static let maximumRecordCount = 256
    private static let maximumPeerCount = 64

    private weak var provider: NETunnelProvider?
    private let credentialResolver: any RuntimeCredentialResolving
    private let fileManager: FileManager

    init(
        provider: NETunnelProvider,
        credentialResolver: any RuntimeCredentialResolving = KeychainRuntimeCredentialResolver(),
        fileManager: FileManager = .default
    ) {
        self.provider = provider
        self.credentialResolver = credentialResolver
        self.fileManager = fileManager
    }

    func load(
        expectedMode: NativeWireGuardMode,
        attemptID: UUID
    ) async throws -> ResolvedNativeWireGuardConfiguration {
        await NativeWireGuardTrace.event(
            .runtimeProfileLoadStarted,
            outcome: .started,
            attemptID: attemptID,
            mode: expectedMode
        ).value
        guard let protocolConfiguration = provider?.protocolConfiguration as? NETunnelProviderProtocol else {
            throw NativeWireGuardExtensionError.providerConfigurationInvalid
        }
        let providerConfiguration: RuntimeProviderConfiguration
        do {
            providerConfiguration = try RuntimeProviderConfiguration.parse(protocolConfiguration.providerConfiguration)
        } catch {
            throw NativeWireGuardExtensionError.providerConfigurationInvalid
        }
        NativeWireGuardTrace.event(
            .providerProtocolValidated,
            attemptID: attemptID,
            profileID: providerConfiguration.profileID,
            mode: expectedMode,
            additionalDetails: [
                "requestedProfileID": providerConfiguration.profileID.uuidString,
                "expectedPublicationRevision": String(providerConfiguration.recordRevision)
            ]
        )

        let record = try readRecord(profileID: providerConfiguration.profileID)
        guard record.mode == expectedMode else {
            throw NativeWireGuardExtensionError.modeMismatch
        }
        guard record.enabled else {
            throw NativeWireGuardExtensionError.profileDisabled
        }
        guard record.schemaVersion == Self.profileSchemaVersion else {
            throw NativeWireGuardExtensionError.schemaMismatch
        }
        let computedRevision = try Self.revision(for: record)
        guard record.recordRevision == computedRevision else {
            throw NativeWireGuardExtensionError.revisionMismatch
        }
        let expectedToken: Int64
        do {
            expectedToken = try RuntimeProviderConfiguration.revisionToken(for: record.recordRevision)
        } catch {
            throw NativeWireGuardExtensionError.revisionMismatch
        }
        guard providerConfiguration.recordRevision == expectedToken else {
            throw NativeWireGuardExtensionError.revisionMismatch
        }
        NativeWireGuardTrace.event(
            .runtimeProfileLoaded,
            attemptID: attemptID,
            profileID: record.profileID,
            mode: record.mode,
            revision: record.recordRevision,
            additionalDetails: [
                "requestedProfileID": providerConfiguration.profileID.uuidString,
                "runtimeProfileID": record.profileID.uuidString,
                "runtimeSnapshotExists": "true",
                "runtimeProfileMatchesSelected": String(record.profileID == providerConfiguration.profileID),
                "expectedPublicationRevision": String(providerConfiguration.recordRevision)
            ]
        )

        NativeWireGuardTrace.event(
            .credentialResolutionStarted,
            outcome: .started,
            attemptID: attemptID,
            profileID: record.profileID,
            mode: record.mode,
            revision: record.recordRevision
        )
        let privateKeyText = try await credential(reference: record.privateKeyReference)
        let privateKeyDecodedLength = Data(base64Encoded: privateKeyText)?.count
        guard let privateKey = PrivateKey(base64Key: privateKeyText) else {
            throw NativeWireGuardExtensionError.configurationInvalid
        }
        NativeWireGuardTrace.event(
            .awgConfigurationBuildStarted,
            outcome: .started,
            attemptID: attemptID,
            profileID: record.profileID,
            mode: record.mode,
            revision: record.recordRevision
        )
        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = try record.interfaceAddresses.map { value in
            guard Self.isValidIPRange(value), let range = IPAddressRange(from: value) else {
                throw NativeWireGuardExtensionError.configurationInvalid
            }
            return range
        }
        guard interface.addresses.isEmpty == false else {
            throw NativeWireGuardExtensionError.configurationInvalid
        }
        interface.dns = try record.dnsServers.map { value in
            guard let server = DNSServer(from: value) else {
                throw NativeWireGuardExtensionError.configurationInvalid
            }
            return server
        }
        guard record.dnsSearchDomains.allSatisfy(Self.isValidSearchDomain) else {
            throw NativeWireGuardExtensionError.configurationInvalid
        }
        interface.dnsSearch = record.dnsSearchDomains
        interface.listenPort = record.listenPort
        interface.mtu = record.mtu

        var headerProtectionKeyDecodedLength: Int?
        switch record.mode {
        case .wireGuard:
            guard record.amnezia?.hasAnyValue != true, record.headerProtectionKeyReference == nil else {
                throw NativeWireGuardExtensionError.configurationInvalid
            }
        case .amneziaWG:
            guard record.amnezia?.hasAnyValue == true || record.headerProtectionKeyReference != nil else {
                throw NativeWireGuardExtensionError.configurationInvalid
            }
            Self.apply(record.amnezia, to: &interface)
            if let headerReference = record.headerProtectionKeyReference {
                let value = try await credential(reference: headerReference)
                headerProtectionKeyDecodedLength = Data(base64Encoded: value)?.count
                guard let key = PrivateKey(base64Key: value) else {
                    throw NativeWireGuardExtensionError.configurationInvalid
                }
                interface.headerProtectionKey = key
            }
        }

        guard record.peers.isEmpty == false, record.peers.count <= Self.maximumPeerCount else {
            throw NativeWireGuardExtensionError.configurationInvalid
        }
        var publicKeys = Set<String>()
        var hasEndpoint = false
        var publicKeyDecodedLength: Int?
        var presharedKeyDecodedLength: Int?
        var peers: [PeerConfiguration] = []
        peers.reserveCapacity(record.peers.count)
        for peerRecord in record.peers {
            publicKeyDecodedLength = publicKeyDecodedLength ?? Data(base64Encoded: peerRecord.publicKey)?.count
            guard publicKeys.insert(peerRecord.publicKey).inserted,
                  let publicKey = PublicKey(base64Key: peerRecord.publicKey) else {
                throw NativeWireGuardExtensionError.configurationInvalid
            }
            var peer = PeerConfiguration(publicKey: publicKey)
            if let reference = peerRecord.presharedKeyReference {
                let value = try await credential(reference: reference)
                presharedKeyDecodedLength = presharedKeyDecodedLength ?? Data(base64Encoded: value)?.count
                guard let key = PreSharedKey(base64Key: value) else {
                    throw NativeWireGuardExtensionError.configurationInvalid
                }
                peer.preSharedKey = key
            }
            peer.allowedIPs = try peerRecord.allowedIPs.map { value in
                guard Self.isValidIPRange(value), let range = IPAddressRange(from: value) else {
                    throw NativeWireGuardExtensionError.configurationInvalid
                }
                return range
            }
            guard peer.allowedIPs.isEmpty == false else {
                throw NativeWireGuardExtensionError.configurationInvalid
            }
            peer.excludeIPs = try peerRecord.excludedIPs.map { value in
                guard Self.isValidIPRange(value), let range = IPAddressRange(from: value) else {
                    throw NativeWireGuardExtensionError.configurationInvalid
                }
                return range
            }
            if let endpointRecord = peerRecord.endpoint {
                let endpointText = endpointRecord.host.contains(":")
                    ? "[\(endpointRecord.host)]:\(endpointRecord.port)"
                    : "\(endpointRecord.host):\(endpointRecord.port)"
                guard endpointRecord.port > 0, let endpoint = Endpoint(from: endpointText) else {
                    throw NativeWireGuardExtensionError.configurationInvalid
                }
                peer.endpoint = endpoint
                hasEndpoint = true
            }
            guard Self.isValidKeepAlive(peerRecord.persistentKeepAlive, mode: record.mode) else {
                throw NativeWireGuardExtensionError.configurationInvalid
            }
            peer.persistentKeepAlive = Self.normalized(peerRecord.persistentKeepAlive)
            peers.append(peer)
        }
        guard hasEndpoint else {
            throw NativeWireGuardExtensionError.configurationInvalid
        }

        let safeSummary = NativeWireGuardConfigurationSummary(
            protocolName: record.mode.rawValue,
            interfaceAddressCount: record.interfaceAddresses.count,
            dnsServerCount: record.dnsServers.count,
            mtu: record.mtu,
            junkPacketCount: record.amnezia?.junkPacketCount,
            junkPacketMinSize: record.amnezia?.junkPacketMinSize,
            junkPacketMaxSize: record.amnezia?.junkPacketMaxSize,
            s1: record.amnezia?.initPacketJunkSize,
            s2: record.amnezia?.responsePacketJunkSize,
            s3: record.amnezia?.cookieReplyPacketJunkSize,
            s4: record.amnezia?.transportPacketJunkSize,
            h1Present: Self.normalized(record.amnezia?.initPacketMagicHeader) != nil,
            h2Present: Self.normalized(record.amnezia?.responsePacketMagicHeader) != nil,
            h3Present: Self.normalized(record.amnezia?.underloadPacketMagicHeader) != nil,
            h4Present: Self.normalized(record.amnezia?.transportPacketMagicHeader) != nil,
            i1Present: Self.normalized(record.amnezia?.specialJunk1) != nil,
            i2Present: Self.normalized(record.amnezia?.specialJunk2) != nil,
            i3Present: Self.normalized(record.amnezia?.specialJunk3) != nil,
            i4Present: Self.normalized(record.amnezia?.specialJunk4) != nil,
            i5Present: Self.normalized(record.amnezia?.specialJunk5) != nil,
            peerCount: record.peers.count,
            allowedIPCount: record.peers.reduce(0) { $0 + $1.allowedIPs.count },
            endpointHostPresent: record.peers.contains { Self.normalized($0.endpoint?.host) != nil },
            endpointPort: record.peers.compactMap(\.endpoint?.port).first,
            privateKeyPresent: true,
            privateKeyDecodedLength: privateKeyDecodedLength,
            publicKeyPresent: record.peers.isEmpty == false,
            publicKeyDecodedLength: publicKeyDecodedLength,
            presharedKeyPresent: record.peers.contains { $0.presharedKeyReference != nil },
            presharedKeyDecodedLength: presharedKeyDecodedLength,
            headerProtectionKeyPresent: record.headerProtectionKeyReference != nil,
            headerProtectionKeyDecodedLength: headerProtectionKeyDecodedLength,
            persistentKeepalivePresent: record.peers.contains { Self.normalized($0.persistentKeepAlive) != nil },
            maskingEnabled: record.mode == .amneziaWG && (
                record.amnezia?.hasAnyValue == true || record.headerProtectionKeyReference != nil
            )
        )
        NativeWireGuardTrace.event(
            .credentialsResolved,
            attemptID: attemptID,
            profileID: record.profileID,
            mode: record.mode,
            revision: record.recordRevision
        )
        NativeWireGuardTrace.event(
            .awgConfigurationBuilt,
            attemptID: attemptID,
            profileID: record.profileID,
            mode: record.mode,
            revision: record.recordRevision,
            safeConfiguration: safeSummary
        )

        return ResolvedNativeWireGuardConfiguration(
            profileID: record.profileID,
            recordRevision: record.recordRevision,
            mode: record.mode,
            tunnelConfiguration: TunnelConfiguration(
                name: record.mode == .wireGuard ? "WireGuard" : "AmneziaWG",
                interface: interface,
                peers: peers
            ),
            summary: safeSummary
        )
    }

    private func readRecord(profileID: UUID) throws -> NativeWireGuardProfileRecord {
        guard let container = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier
        ) else {
            throw NativeWireGuardExtensionError.sharedContainerUnavailable
        }
        let fileURL = container
            .appendingPathComponent("NativeProfiles", isDirectory: true)
            .appendingPathComponent("native-wireguard-profiles-v1.json")
        guard fileManager.fileExists(atPath: fileURL.path) else {
            throw NativeWireGuardExtensionError.recordUnavailable
        }
        do {
            let size = try fileURL.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size <= Self.maximumCollectionBytes else {
                throw NativeWireGuardExtensionError.recordMalformed
            }
            let data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
            guard data.count <= Self.maximumCollectionBytes else {
                throw NativeWireGuardExtensionError.recordMalformed
            }
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let collection = try decoder.decode(NativeWireGuardProfileCollection.self, from: data)
            guard collection.schemaVersion == Self.collectionSchemaVersion,
                  collection.records.count <= Self.maximumRecordCount,
                  Set(collection.records.map(\.profileID)).count == collection.records.count,
                  let record = collection.records.first(where: { $0.profileID == profileID }) else {
                throw NativeWireGuardExtensionError.recordUnavailable
            }
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            guard try encoder.encode(record).count <= Self.maximumRecordBytes else {
                throw NativeWireGuardExtensionError.recordMalformed
            }
            return record
        } catch let error as NativeWireGuardExtensionError {
            throw error
        } catch {
            throw NativeWireGuardExtensionError.recordMalformed
        }
    }

    private func credential(reference: String) async throws -> String {
        do {
            guard let value = try await credentialResolver.credential(for: reference),
                  let normalized = Self.normalized(value) else {
                throw NativeWireGuardExtensionError.credentialUnavailable
            }
            return normalized
        } catch let error as NativeWireGuardExtensionError {
            throw error
        } catch {
            throw NativeWireGuardExtensionError.credentialUnavailable
        }
    }

    private static func apply(_ values: NativeAmneziaWGParameters?, to interface: inout InterfaceConfiguration) {
        guard let values else { return }
        interface.junkPacketCount = values.junkPacketCount
        interface.junkPacketMinSize = values.junkPacketMinSize
        interface.junkPacketMaxSize = values.junkPacketMaxSize
        interface.initPacketJunkSize = values.initPacketJunkSize
        interface.responsePacketJunkSize = values.responsePacketJunkSize
        interface.cookieReplyPacketJunkSize = values.cookieReplyPacketJunkSize
        interface.transportPacketJunkSize = values.transportPacketJunkSize
        interface.initPacketMagicHeader = values.initPacketMagicHeader
        interface.responsePacketMagicHeader = values.responsePacketMagicHeader
        interface.underloadPacketMagicHeader = values.underloadPacketMagicHeader
        interface.transportPacketMagicHeader = values.transportPacketMagicHeader
        interface.specialJunk1 = values.specialJunk1
        interface.specialJunk2 = values.specialJunk2
        interface.specialJunk3 = values.specialJunk3
        interface.specialJunk4 = values.specialJunk4
        interface.specialJunk5 = values.specialJunk5
        interface.contentPaddingAddition = values.contentPaddingAddition
        interface.rekeyAfterTime = values.rekeyAfterTime
        interface.rekeyTimeout = values.rekeyTimeout
        interface.rejectAfterTime = values.rejectAfterTime
        interface.keepaliveTimeout = values.keepaliveTimeout
        interface.maxHandshakeAttempts = values.maxHandshakeAttempts
        interface.randomTrailers = values.randomTrailers
        interface.disableCookies = values.disableCookies
    }

    private static func revision(for record: NativeWireGuardProfileRecord) throws -> String {
        var input = record
        input.recordRevision = ""
        input.updatedAt = Date(timeIntervalSince1970: 0)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(input)
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in data {
            hash ^= UInt64(byte)
            hash &*= 0x100000001b3
        }
        return "v1-\(String(hash, radix: 16))"
    }

    private static func isValidIPRange(_ value: String) -> Bool {
        let pieces = value.split(separator: "/", omittingEmptySubsequences: false)
        guard pieces.count == 2, let prefix = UInt8(pieces[1]) else { return false }
        if IPv4Address(String(pieces[0])) != nil { return prefix <= 32 }
        if IPv6Address(String(pieces[0])) != nil { return prefix <= 128 }
        return false
    }

    private static func isValidSearchDomain(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty == false
            && trimmed.utf8.count <= 253
            && trimmed.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
            && trimmed.rangeOfCharacter(from: .controlCharacters) == nil
    }

    private static func isValidKeepAlive(_ value: String?, mode: NativeWireGuardMode) -> Bool {
        guard let value = normalized(value) else { return true }
        let parts = value.split(separator: "-", omittingEmptySubsequences: false)
        switch mode {
        case .wireGuard:
            return parts.count == 1 && UInt16(parts[0]) != nil
        case .amneziaWG:
            guard parts.count == 1 || parts.count == 2, let lower = UInt16(parts[0]) else { return false }
            guard parts.count == 2 else { return true }
            guard let upper = UInt16(parts[1]) else { return false }
            return lower <= upper
        }
    }

    private static func normalized(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }
}

actor NativeWireGuardTunnelController {
    private struct ActiveSession: Sendable {
        var profileID: UUID
        var recordRevision: String
        var mode: NativeWireGuardMode
    }

    private let loader: NativeWireGuardConfigurationLoader
    private let adapter: WireGuardAdapter
    private let telemetryStore: TunnelTelemetryStore
    private var activeSession: ActiveSession?
    private var isStarting = false
    private var adapterStopRequired = false
    private var stopRequested = false

    private init(
        loader: NativeWireGuardConfigurationLoader,
        adapter: WireGuardAdapter,
        telemetryStore: TunnelTelemetryStore
    ) {
        self.loader = loader
        self.telemetryStore = telemetryStore
        self.adapter = adapter
    }

    nonisolated static func make(
        provider: NEPacketTunnelProvider,
        telemetryStore: TunnelTelemetryStore,
        attemptID: UUID,
        mode: NativeWireGuardMode
    ) async -> NativeWireGuardTunnelController {
        NativeWireGuardTrace.controllerConstructionCheckpoint(
            .nativeBackendControllerMakeEntered,
            outcome: .started,
            attemptID: attemptID,
            mode: mode
        )
        NativeWireGuardTrace.controllerConstructionCheckpoint(
            .runtimeLoaderResolutionStarted,
            outcome: .started,
            attemptID: attemptID,
            mode: mode
        )
        let loader = NativeWireGuardConfigurationLoader(provider: provider)
        NativeWireGuardTrace.controllerConstructionCheckpoint(
            .runtimeLoaderResolved,
            attemptID: attemptID,
            mode: mode
        )

        NativeWireGuardTrace.controllerConstructionCheckpoint(
            .nativeFrameworkReferenceStarted,
            outcome: .started,
            attemptID: attemptID,
            mode: mode
        )
        NativeWireGuardTrace.controllerConstructionCheckpoint(
            .nativeAdapterConstructionStarted,
            outcome: .started,
            attemptID: attemptID,
            mode: mode
        )
        let initializationObserver: WireGuardAdapter.InitializationObserver = { checkpoint in
            NativeWireGuardTrace.adapterInitializationCheckpoint(
                checkpoint,
                attemptID: attemptID,
                mode: mode
            )
        }
        #if DEBUG
        let adapter = WireGuardAdapter(
            diagnosticWith: provider,
            logHandler: { level, _ in
                // Adapter messages may include resolved endpoints. Runtime telemetry
                // records only the fixed level token and never forwards message text.
                _ = level
            },
            initializationObserver: initializationObserver,
            bypassLoggerInstallation: NativeWireGuardLoggerDiagnosticSwitch.bypassSetupLogHandler
        )
        #else
        let adapter = WireGuardAdapter(
            with: provider,
            logHandler: { level, _ in
                // Adapter messages may include resolved endpoints. Runtime telemetry
                // records only the fixed level token and never forwards message text.
                _ = level
            },
            initializationObserver: initializationObserver
        )
        #endif
        await NativeWireGuardTrace.event(
            .nativeAdapterConstructed,
            attemptID: attemptID,
            mode: mode
        ).value
        await NativeWireGuardTrace.event(
            .nativeFrameworkReferenceCompleted,
            attemptID: attemptID,
            mode: mode
        ).value
        return NativeWireGuardTunnelController(
            loader: loader,
            adapter: adapter,
            telemetryStore: telemetryStore
        )
    }

    func start(expectedMode: NativeWireGuardMode, attemptID: UUID) async throws {
        await NativeWireGuardTrace.event(
            .nativeBackendControllerStartEntered,
            outcome: .started,
            attemptID: attemptID,
            mode: expectedMode
        ).value
        guard activeSession == nil, isStarting == false else {
            throw NativeWireGuardExtensionError.alreadyRunning
        }
        isStarting = true
        adapterStopRequired = false
        stopRequested = false
        await NativeWireGuardTrace.event(
            .providerTelemetryUpdateStarted,
            outcome: .started,
            attemptID: attemptID,
            mode: expectedMode
        ).value
        await telemetryStore.markNativeStarting(
            protocolKind: expectedMode.telemetryProtocolKind
        )
        await NativeWireGuardTrace.event(
            .providerTelemetryUpdated,
            attemptID: attemptID,
            mode: expectedMode
        ).value
        defer {
            isStarting = false
        }
        do {
            try Task.checkCancellation()
            await NativeWireGuardTrace.event(
                .startupCancellationCheckPassed,
                attemptID: attemptID,
                mode: expectedMode
            ).value
            let resolved: ResolvedNativeWireGuardConfiguration
            do {
                resolved = try await loader.load(
                    expectedMode: expectedMode,
                    attemptID: attemptID
                )
            } catch let error as NativeWireGuardExtensionError {
                await NativeWireGuardTrace.event(
                    Self.resolutionFailureStage(for: error),
                    outcome: .failed,
                    attemptID: attemptID,
                    mode: expectedMode,
                    error: error
                ).value
                throw error
            }
            guard stopRequested == false, Task.isCancelled == false else {
                throw NativeWireGuardExtensionError.cancelled
            }
            await telemetryStore.markNativeProfileResolved(profileID: resolved.profileID)
            adapterStopRequired = true
            await NativeWireGuardTrace.event(
                .adapterStartRequested,
                outcome: .started,
                attemptID: attemptID,
                profileID: resolved.profileID,
                mode: resolved.mode,
                revision: resolved.recordRevision
            ).value
            do {
                try await startAdapter(
                    resolved.tunnelConfiguration,
                    attemptID: attemptID,
                    resolved: resolved
                )
            } catch let adapterError as WireGuardAdapterError {
                let failure = Self.adapterFailure(for: adapterError)
                let startupFailure = NativeWireGuardStartupFailure(
                    category: failure.category,
                    nativeStatus: failure.nativeStatus,
                    underlyingError: failure.underlyingError
                )
                await NativeWireGuardTrace.event(
                    .adapterStartRequested,
                    outcome: .failed,
                    attemptID: attemptID,
                    profileID: resolved.profileID,
                    mode: resolved.mode,
                    revision: resolved.recordRevision,
                    error: startupFailure,
                    nativeStatus: failure.nativeStatus,
                    systemErrorDomain: failure.systemErrorDomain,
                    systemErrorCode: failure.systemErrorCode
                ).value
                throw startupFailure
            } catch let timeout as NativeWireGuardExtensionError where timeout == .adapterStartTimeout {
                await NativeWireGuardTrace.event(
                    .adapterStartTimeout,
                    outcome: .failed,
                    attemptID: attemptID,
                    profileID: resolved.profileID,
                    mode: resolved.mode,
                    revision: resolved.recordRevision,
                    error: timeout,
                    failureCategory: .adapterStartTimeout
                ).value
                throw timeout
            }
            await NativeWireGuardTrace.event(
                .networkSettingsApplied,
                attemptID: attemptID,
                profileID: resolved.profileID,
                mode: resolved.mode,
                revision: resolved.recordRevision
            ).value
            await NativeWireGuardTrace.event(
                .adapterStarted,
                attemptID: attemptID,
                profileID: resolved.profileID,
                mode: resolved.mode,
                revision: resolved.recordRevision,
                safeConfiguration: resolved.summary
            ).value
            if stopRequested || Task.isCancelled {
                await stopAdapterIfNeeded()
                throw NativeWireGuardExtensionError.cancelled
            }
            activeSession = ActiveSession(
                profileID: resolved.profileID,
                recordRevision: resolved.recordRevision,
                mode: resolved.mode
            )
            await telemetryStore.markNativeRunning()
        } catch {
            await stopAdapterIfNeeded()
            activeSession = nil
            if stopRequested
                || error is CancellationError
                || (error as? NativeWireGuardExtensionError) == .cancelled {
                await telemetryStore.markStopped()
                throw NativeWireGuardExtensionError.cancelled
            }
            await telemetryStore.markNativeFailure()
            if let error = error as? NativeWireGuardStartupFailure {
                throw error
            }
            if let error = error as? NativeWireGuardExtensionError {
                throw error
            }
            throw NativeWireGuardExtensionError.adapterStartFailed
        }
    }

    func stopIfActive() async -> Bool {
        guard activeSession != nil || isStarting || adapterStopRequired else { return false }
        stopRequested = true
        await stopAdapterIfNeeded()
        activeSession = nil
        await telemetryStore.markStopped()
        return true
    }

    func isActive() -> Bool {
        activeSession != nil
    }

    private func startAdapter(
        _ configuration: TunnelConfiguration,
        attemptID: UUID,
        resolved: ResolvedNativeWireGuardConfiguration
    ) async throws {
        await NativeWireGuardTrace.event(
            .nativeAdapterStartInvocationStarted,
            outcome: .started,
            attemptID: attemptID,
            profileID: resolved.profileID,
            mode: resolved.mode,
            revision: resolved.recordRevision
        ).value
        let gate = NativeAdapterContinuationGate()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                gate.install(continuation)
                let timeoutTask = Task { [gate] in
                    do {
                        try await Task.sleep(for: .seconds(20))
                        gate.complete(.failure(NativeWireGuardExtensionError.adapterStartTimeout))
                    } catch {
                        // Cancellation means callback/cancellation already completed the gate.
                    }
                }
                gate.setTimeoutTask(timeoutTask)
                // The event before this call is awaited because WireGuardAdapter.start
                // crosses into the statically linked Go backend and cannot be protected
                // from a native crash with do/catch.
                adapter.start(tunnelConfiguration: configuration) { error in
                    if let error {
                        gate.complete(.failure(error))
                    } else {
                        gate.complete(.success(()))
                    }
                }
            }
        } onCancel: {
            gate.complete(.failure(NativeWireGuardExtensionError.cancelled))
        }
        await NativeWireGuardTrace.event(
            .nativeAdapterStartInvocationReturned,
            attemptID: attemptID,
            profileID: resolved.profileID,
            mode: resolved.mode,
            revision: resolved.recordRevision
        ).value
    }

    private func stopAdapter() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            adapter.stop { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    private func stopAdapterIfNeeded() async {
        guard adapterStopRequired else { return }

        // Clear the flag before suspension so actor reentrancy cannot issue a
        // second adapter stop while this one is still awaiting completion.
        adapterStopRequired = false
        try? await stopAdapter()
    }

    private static func resolutionFailureStage(for error: NativeWireGuardExtensionError) -> TunnelStartupStage {
        switch error {
        case .sharedContainerUnavailable,
             .providerConfigurationInvalid,
             .recordUnavailable,
             .recordMalformed,
             .schemaMismatch,
             .revisionMismatch,
             .modeMismatch,
             .profileDisabled:
            .runtimeProfileLoadStarted
        case .credentialUnavailable:
            .credentialResolutionStarted
        case .configurationInvalid:
            .awgConfigurationBuildStarted
        case .nativeBackendControllerUnavailable:
            .nativeBackendControllerResolutionStarted
        case .runtimeLoaderUnavailable:
            .runtimeLoaderResolutionStarted
        case .providerStartupStalled:
            .providerStartupWatchdogFired
        case .alreadyRunning,
             .adapterStartFailed,
             .cancelled,
             .cannotLocateTunnelFileDescriptor,
             .adapterInvalidState,
             .endpointDNSResolutionFailed,
             .networkSettingsRejected,
             .backendStartFailed,
             .startupCompletionTimeout,
             .adapterStartTimeout:
            .adapterStartRequested
        }
    }

    private static func adapterFailure(
        for error: WireGuardAdapterError
    ) -> (
        category: NativeWireGuardExtensionError,
        nativeStatus: Int32?,
        systemErrorDomain: String?,
        systemErrorCode: Int?,
        underlyingError: NSError?
    ) {
        switch error {
        case .cannotLocateTunnelFileDescriptor:
            return (.cannotLocateTunnelFileDescriptor, nil, nil, nil, nil)
        case .invalidState:
            return (.adapterInvalidState, nil, nil, nil, nil)
        case .dnsResolution:
            return (.endpointDNSResolutionFailed, nil, nil, nil, nil)
        case .setNetworkSettings(let underlyingError):
            let nsError = underlyingError as NSError
            return (.networkSettingsRejected, nil, nsError.domain, nsError.code, nsError)
        case .startWireGuardBackend(let status):
            return (.backendStartFailed, status, nil, nil, nil)
        }
    }
}

private nonisolated final class NativeAdapterContinuationGate: @unchecked Sendable {
    private enum State {
        case waiting(CheckedContinuation<Void, any Error>?)
        case completed(Result<Void, any Error>?)
    }

    private let lock = NSLock()
    private var state: State = .waiting(nil)
    private var timeoutTask: Task<Void, Never>?

    func install(_ continuation: CheckedContinuation<Void, any Error>) {
        let pending: Result<Void, any Error>? = lock.withLock {
            switch state {
            case .waiting(nil):
                state = .waiting(continuation)
                return nil
            case .waiting(.some):
                state = .completed(.failure(NativeWireGuardExtensionError.adapterInvalidState))
                return .failure(NativeWireGuardExtensionError.adapterInvalidState)
            case .completed(let result):
                return result
            }
        }
        if let pending {
            continuation.resume(with: pending)
        }
    }

    func setTimeoutTask(_ task: Task<Void, Never>) {
        let shouldCancel = lock.withLock {
            switch state {
            case .waiting:
                timeoutTask = task
                return false
            case .completed:
                return true
            }
        }
        if shouldCancel {
            task.cancel()
        }
    }

    func complete(_ result: Result<Void, any Error>) {
        let action: (CheckedContinuation<Void, any Error>?, Task<Void, Never>?) = lock.withLock {
            switch state {
            case .waiting(let continuation):
                state = .completed(continuation == nil ? result : nil)
                let timeoutTask = timeoutTask
                self.timeoutTask = nil
                return (continuation, timeoutTask)
            case .completed:
                return (nil, nil)
            }
        }
        action.1?.cancel()
        action.0?.resume(with: result)
    }
}
