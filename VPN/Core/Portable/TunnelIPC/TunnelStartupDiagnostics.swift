//
//  TunnelStartupDiagnostics.swift
//  VPN
//
//  Secret-free, cross-process diagnostics for one PacketTunnel activation.
//  App and PacketTunnelExtension intentionally write different files so that
//  neither process can overwrite the other process' events.
//

import Foundation
import Dispatch

nonisolated enum TunnelDiagnosticSource: String, Codable, CaseIterable, Sendable {
    case app
    case provider
}

nonisolated enum TunnelStartupStage: String, Codable, CaseIterable, Sendable {
    case appConnectRequested
    case appProfileSelected
    case managerLoadStarted
    case managerLoaded
    case managerConfigurationValidated
    case runtimePublishStarted
    case runtimePublished
    case managerSaveStarted
    case managerSaved
    case managerReloadStarted
    case managerReloaded
    case sessionStartRequested
    case networkExtensionStatusChanged

    case providerProcessEntered
    case activationContextDecodeStarted
    case activationContextDecoded
    case providerStartTunnelEntered
    case providerProtocolValidated
    case nativeBackendSelectionStarted
    case nativeBackendSelected
    case startupWatchdogStarted
    case startupTaskCreationStarted
    case startupTaskCreated
    case startupTaskEntered
    case nativeBackendControllerResolutionStarted
    case nativeBackendControllerMakeArgumentsStarted
    case nativeBackendControllerMakeArgumentsPrepared
    case nativeBackendControllerMakeCallStarted
    case nativeBackendControllerMakeEntered
    case nativeBackendControllerMakeCallReturned
    case runtimeLoaderResolutionStarted
    case runtimeLoaderResolved
    case nativeFrameworkReferenceStarted
    case nativeFrameworkReferenceCompleted
    case nativeAdapterConstructionStarted
    case wireGuardAdapterInitEntered
    case wireGuardAdapterProviderReferenceStored
    case wireGuardAdapterSwiftLogHandlerStored
    case wireGuardAdapterSetupLogHandlerEntered
    case wireGuardAdapterLoggerContextPreparationStarted
    case wireGuardAdapterLoggerContextPrepared
    case wireGuardAdapterLoggerCallbackPreparationStarted
    case wireGuardAdapterLoggerCallbackPrepared
    case wireGuardAdapterWGSetLoggerCallStarted
    case wireGuardAdapterWGSetLoggerCallReturned
    case wireGuardAdapterLoggerInstallationBypassed
    case wireGuardAdapterLoggerInstallationDeferred
    case wireGuardAdapterSetupLogHandlerReturned
    case wireGuardAdapterInitCompleted
    case wireGuardAdapterWGTurnOnCallStarted
    case wireGuardAdapterWGTurnOnCallReturned
    case nativeAdapterConstructed
    case nativeBackendControllerResolved
    case nativeBackendControllerStartEntered
    case providerTelemetryUpdateStarted
    case providerTelemetryUpdated
    case startupCancellationCheckPassed

    case runtimeProfileLoadStarted
    case runtimeProfileLoaded
    case credentialResolutionStarted
    case credentialsResolved
    case awgConfigurationBuildStarted
    case awgConfigurationBuilt
    case adapterStartRequested
    case nativeAdapterStartInvocationStarted
    case nativeAdapterStartInvocationReturned
    case networkSettingsApplied
    case adapterStarted
    case providerStartupCompleted
    case providerStartupFailed
    case providerStartupWatchdogFired
    case connectionObservationFailed
    case appStopRequested
    case appStopCompleted
    case tunnelStartCompleted
    case tunnelStartFailed
    case tunnelStartCancelled
    case providerStartTimeout
    case adapterStartTimeout
    case completionDuplicateIgnored
}

nonisolated enum TunnelDiagnosticOutcome: String, Codable, Sendable {
    case started
    case succeeded
    case failed
    case informational
}

nonisolated enum NativeTunnelFailureCategory: String, Codable, Sendable {
    case invalidProviderConfiguration
    case runtimeProfileUnavailable
    case runtimeProfileMalformed
    case runtimeSchemaMismatch
    case runtimeRevisionMismatch
    case runtimeModeMismatch
    case profileDisabled
    case sharedCredentialUnavailable
    case awgConfigurationInvalid
    case dnsResolutionFailed
    case tunnelFileDescriptorUnavailable
    case networkSettingsRejected
    case nativeBackendStartupFailed
    case adapterInvalidState
    case providerActivationFailure
    case providerStartTimeout
    case adapterStartTimeout
    case providerWasNeverLaunched
    case providerStartTunnelNotEntered
    case providerStartupStalled
    case providerExitedDuringStartup
    case providerStartupAbortedBeforeRuntimeLoad
    case activationContextInvalid
    case runtimeLoaderUnavailable
    case startupTaskNeverEntered
    case nativeBackendControllerUnavailable
    case appConnectionObservationTimeout
    case unknownProviderStartupFailure
    case cancelled
    case unknown
}

nonisolated struct TunnelBuildIdentity: Codable, Equatable, Sendable {
    var version: String
    var build: String
    var bundleIdentifier: String
    var sourceRevision: String? = nil

    static func current(bundle: Bundle = .main) -> TunnelBuildIdentity {
        TunnelBuildIdentity(
            version: bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown",
            build: bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown",
            bundleIdentifier: bundle.bundleIdentifier ?? "unknown",
            sourceRevision: bundle.object(forInfoDictionaryKey: "SecureLinkSourceRevision") as? String
        )
    }
}

nonisolated struct NativeTunnelSafeConfigurationSummary: Codable, Equatable, Sendable {
    var protocolName: String
    var interfaceAddressCount: Int
    var dnsServerCount: Int
    var mtu: UInt16?
    var junkPacketCount: UInt16?
    var junkPacketMinSize: UInt16?
    var junkPacketMaxSize: UInt16?
    var s1: UInt16?
    var s2: UInt16?
    var s3: UInt16?
    var s4: UInt16?
    var h1Present: Bool
    var h2Present: Bool
    var h3Present: Bool
    var h4Present: Bool
    var i1Present: Bool
    var i2Present: Bool
    var i3Present: Bool
    var i4Present: Bool
    var i5Present: Bool
    var peerCount: Int
    var allowedIPCount: Int
    var endpointHostPresent: Bool
    var endpointPort: UInt16?
    var privateKeyPresent: Bool
    var privateKeyDecodedLength: Int?
    var publicKeyPresent: Bool
    var publicKeyDecodedLength: Int?
    var presharedKeyPresent: Bool
    var presharedKeyDecodedLength: Int?
    var headerProtectionKeyPresent: Bool
    var headerProtectionKeyDecodedLength: Int?
    var persistentKeepalivePresent: Bool
    var maskingEnabled: Bool
}

nonisolated struct TunnelDiagnosticError: Codable, Equatable, Sendable {
    var domain: String
    var code: Int
    var description: String
    var failureReason: String?
    var recoverySuggestion: String?
    var underlying: [TunnelDiagnosticError]

    init(error: any Error, maximumUnderlyingDepth: Int = 8) {
        self = Self.capture(error as NSError, depthRemaining: max(0, maximumUnderlyingDepth))
    }

    init(
        error: any Error,
        supplementalUnderlying: TunnelDiagnosticError?,
        maximumUnderlyingDepth: Int = 8
    ) {
        var captured = Self.capture(error as NSError, depthRemaining: max(0, maximumUnderlyingDepth))
        if captured.underlying.isEmpty, let supplementalUnderlying {
            captured.underlying = [supplementalUnderlying]
        }
        self = captured
    }

    private static func capture(_ error: NSError, depthRemaining: Int) -> TunnelDiagnosticError {
        let underlying: [TunnelDiagnosticError]
        if depthRemaining > 0,
           let nested = error.userInfo[NSUnderlyingErrorKey] as? NSError,
           nested !== error {
            underlying = [capture(nested, depthRemaining: depthRemaining - 1)]
        } else {
            underlying = []
        }

        return TunnelDiagnosticError(
            domain: TunnelDiagnosticSanitizer.safeToken(error.domain, maximumLength: 160) ?? "unknown",
            code: error.code,
            description: TunnelDiagnosticSanitizer.redactedText(error.localizedDescription),
            failureReason: error.localizedFailureReason.map(TunnelDiagnosticSanitizer.redactedText),
            recoverySuggestion: error.localizedRecoverySuggestion.map(TunnelDiagnosticSanitizer.redactedText),
            underlying: underlying
        )
    }

    private init(
        domain: String,
        code: Int,
        description: String,
        failureReason: String?,
        recoverySuggestion: String?,
        underlying: [TunnelDiagnosticError]
    ) {
        self.domain = domain
        self.code = code
        self.description = description
        self.failureReason = failureReason
        self.recoverySuggestion = recoverySuggestion
        self.underlying = underlying
    }
}

nonisolated struct TunnelDiagnosticEvent: Codable, Equatable, Identifiable, Sendable {
    var id: UUID
    var timestamp: Date
    var monotonicNanoseconds: UInt64?
    var sourceSequence: UInt64?
    var attemptID: UUID
    var source: TunnelDiagnosticSource
    var stage: TunnelStartupStage
    var outcome: TunnelDiagnosticOutcome
    var message: String?
    var details: [String: String]
    var failureCategory: NativeTunnelFailureCategory?
    var error: TunnelDiagnosticError?
    var safeConfiguration: NativeTunnelSafeConfigurationSummary?

    init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        monotonicNanoseconds: UInt64? = DispatchTime.now().uptimeNanoseconds,
        sourceSequence: UInt64? = nil,
        attemptID: UUID,
        source: TunnelDiagnosticSource,
        stage: TunnelStartupStage,
        outcome: TunnelDiagnosticOutcome,
        message: String? = nil,
        details: [String: String] = [:],
        failureCategory: NativeTunnelFailureCategory? = nil,
        error: TunnelDiagnosticError? = nil,
        safeConfiguration: NativeTunnelSafeConfigurationSummary? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.monotonicNanoseconds = monotonicNanoseconds
        self.sourceSequence = sourceSequence ?? TunnelDiagnosticSequenceGenerator.shared.next(for: source)
        self.attemptID = attemptID
        self.source = source
        self.stage = stage
        self.outcome = outcome
        self.message = message.map(TunnelDiagnosticSanitizer.redactedText)
        self.details = TunnelDiagnosticSanitizer.safeDetails(details)
        self.failureCategory = failureCategory
        self.error = error
        self.safeConfiguration = safeConfiguration
    }
}

nonisolated enum TunnelDiagnosticEventOrdering {
    static func areInIncreasingOrder(_ lhs: TunnelDiagnosticEvent, _ rhs: TunnelDiagnosticEvent) -> Bool {
        if lhs.timestamp != rhs.timestamp {
            return lhs.timestamp < rhs.timestamp
        }
        if let lhsMonotonic = lhs.monotonicNanoseconds,
           let rhsMonotonic = rhs.monotonicNanoseconds,
           lhsMonotonic != rhsMonotonic {
            return lhsMonotonic < rhsMonotonic
        }
        if lhs.source == rhs.source,
           let lhsSequence = lhs.sourceSequence,
           let rhsSequence = rhs.sourceSequence,
           lhsSequence != rhsSequence {
            return lhsSequence < rhsSequence
        }
        if lhs.source != rhs.source {
            return lhs.source.rawValue < rhs.source.rawValue
        }
        return lhs.id.uuidString < rhs.id.uuidString
    }

    static func crossProcessOrderIsUnproven(
        _ lhs: TunnelDiagnosticEvent,
        _ rhs: TunnelDiagnosticEvent
    ) -> Bool {
        guard lhs.source != rhs.source else { return false }
        return abs(lhs.timestamp.timeIntervalSince(rhs.timestamp)) < 0.001
    }
}

private nonisolated final class TunnelDiagnosticSequenceGenerator: @unchecked Sendable {
    static let shared = TunnelDiagnosticSequenceGenerator()

    private let lock = NSLock()
    private var appSequence: UInt64 = 0
    private var providerSequence: UInt64 = 0

    func next(for source: TunnelDiagnosticSource) -> UInt64 {
        lock.withLock {
            switch source {
            case .app:
                appSequence &+= 1
                return appSequence
            case .provider:
                providerSequence &+= 1
                return providerSequence
            }
        }
    }
}

nonisolated enum TunnelDiagnosticDateCodec {
    private static let fractionalFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
    private static let legacyFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    static func configure(_ encoder: JSONEncoder) {
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(string(from: date))
        }
    }

    static func configure(_ decoder: JSONDecoder) {
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self)
            guard let date = fractionalFormatter.date(from: value) ?? legacyFormatter.date(from: value) else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "Invalid tunnel diagnostic timestamp"
                )
            }
            return date
        }
    }

    static func string(from date: Date) -> String {
        fractionalFormatter.string(from: date)
    }
}

nonisolated struct TunnelDiagnosticAttemptMetadata: Codable, Equatable, Sendable {
    var schemaVersion: UInt32
    var attemptID: UUID
    var startedAt: Date
    var profileID: UUID?
    var protocolName: String?
    var appBuild: TunnelBuildIdentity
}

nonisolated struct TunnelDiagnosticAttemptSnapshot: Codable, Equatable, Sendable {
    var metadata: TunnelDiagnosticAttemptMetadata
    var appBuild: TunnelBuildIdentity
    var extensionBuild: TunnelBuildIdentity?
    var events: [TunnelDiagnosticEvent]

    var buildMismatch: Bool {
        guard let extensionBuild else { return false }
        return appBuild.version != extensionBuild.version || appBuild.build != extensionBuild.build
    }

    var lastEvent: TunnelDiagnosticEvent? {
        events.max(by: TunnelDiagnosticEventOrdering.areInIncreasingOrder)
    }

    var lastSuccessfulStage: TunnelStartupStage? {
        events.last(where: { $0.outcome == .succeeded })?.stage
    }
}

private nonisolated struct TunnelDiagnosticSourceEnvelope: Codable, Sendable {
    var schemaVersion: UInt32
    var source: TunnelDiagnosticSource
    var build: TunnelBuildIdentity
    var events: [TunnelDiagnosticEvent]
}

nonisolated struct TunnelNativeConstructionCheckpointEnvelope: Codable, Sendable {
    var schemaVersion: UInt32
    var source: TunnelDiagnosticSource
    var build: TunnelBuildIdentity
    var events: [TunnelDiagnosticEvent]
}

nonisolated enum TunnelNativeConstructionCheckpointJournal {
    static let fileName = "provider-native-construction.json"
    private static let maximumEventCount = 32
    private static let lock = NSLock()

    static func append(
        _ event: TunnelDiagnosticEvent,
        build: TunnelBuildIdentity,
        rootDirectoryURL: URL,
        fileManager: FileManager = .default
    ) throws {
        try lock.withLock {
            let attemptURL = rootDirectoryURL
                .appendingPathComponent("attempts", isDirectory: true)
                .appendingPathComponent(event.attemptID.uuidString.lowercased(), isDirectory: true)
            try fileManager.createDirectory(at: attemptURL, withIntermediateDirectories: true)
            let fileURL = attemptURL.appendingPathComponent(fileName)
            let decoder = JSONDecoder()
            TunnelDiagnosticDateCodec.configure(decoder)
            var envelope: TunnelNativeConstructionCheckpointEnvelope
            if let data = try? Data(contentsOf: fileURL, options: [.mappedIfSafe]),
               data.count <= 64 * 1_024,
               let stored = try? decoder.decode(TunnelNativeConstructionCheckpointEnvelope.self, from: data),
               stored.schemaVersion == TunnelStartupDiagnosticsStore.schemaVersion,
               stored.source == .provider {
                envelope = stored
            } else {
                envelope = TunnelNativeConstructionCheckpointEnvelope(
                    schemaVersion: TunnelStartupDiagnosticsStore.schemaVersion,
                    source: .provider,
                    build: build,
                    events: []
                )
            }
            envelope.build = build
            if envelope.events.contains(where: { $0.id == event.id }) == false {
                envelope.events.append(event)
            }
            envelope.events.sort(by: TunnelDiagnosticEventOrdering.areInIncreasingOrder)
            if envelope.events.count > maximumEventCount {
                envelope.events.removeFirst(envelope.events.count - maximumEventCount)
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            TunnelDiagnosticDateCodec.configure(encoder)
            try encoder.encode(envelope).write(to: fileURL, options: [.atomic])
            try? fileManager.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: fileURL.path
            )
        }
    }

    static func read(
        attemptID: UUID,
        rootDirectoryURL: URL,
        fileManager: FileManager = .default
    ) throws -> TunnelNativeConstructionCheckpointEnvelope? {
        let fileURL = rootDirectoryURL
            .appendingPathComponent("attempts", isDirectory: true)
            .appendingPathComponent(attemptID.uuidString.lowercased(), isDirectory: true)
            .appendingPathComponent(fileName)
        guard fileManager.fileExists(atPath: fileURL.path) else { return nil }
        let data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
        guard data.count <= 64 * 1_024 else {
            throw TunnelStartupDiagnosticsStoreError.invalidStoredData
        }
        let decoder = JSONDecoder()
        TunnelDiagnosticDateCodec.configure(decoder)
        let envelope = try decoder.decode(TunnelNativeConstructionCheckpointEnvelope.self, from: data)
        guard envelope.schemaVersion == TunnelStartupDiagnosticsStore.schemaVersion,
              envelope.source == .provider,
              envelope.events.allSatisfy({ $0.attemptID == attemptID && $0.source == .provider }) else {
            throw TunnelStartupDiagnosticsStoreError.invalidStoredData
        }
        return envelope
    }
}

actor TunnelStartupDiagnosticsStore {
    static let schemaVersion: UInt32 = 1

    private let rootDirectoryURL: URL
    private let maximumAttemptCount: Int
    private let maximumEventsPerSource: Int
    private let fileManager: FileManager
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    init(
        rootDirectoryURL: URL,
        maximumAttemptCount: Int = 20,
        maximumEventsPerSource: Int = 128,
        fileManager: FileManager = .default
    ) {
        self.rootDirectoryURL = rootDirectoryURL
        self.maximumAttemptCount = max(1, maximumAttemptCount)
        self.maximumEventsPerSource = max(1, maximumEventsPerSource)
        self.fileManager = fileManager
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        TunnelDiagnosticDateCodec.configure(encoder)
        TunnelDiagnosticDateCodec.configure(decoder)
    }

    static func appGroupStore(fileManager: FileManager = .default) -> TunnelStartupDiagnosticsStore? {
        guard let containerURL = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier
        ) else {
            return nil
        }
        return TunnelStartupDiagnosticsStore(
            rootDirectoryURL: containerURL.appendingPathComponent("TunnelDiagnostics", isDirectory: true),
            fileManager: fileManager
        )
    }

    func beginAttempt(
        attemptID: UUID,
        profileID: UUID?,
        protocolName: String?,
        appBuild: TunnelBuildIdentity = .current(),
        startedAt: Date = Date()
    ) throws {
        try createProtectedDirectory(rootDirectoryURL)
        let attemptsURL = rootDirectoryURL.appendingPathComponent("attempts", isDirectory: true)
        try createProtectedDirectory(attemptsURL)
        let attemptURL = directoryURL(for: attemptID)
        try createProtectedDirectory(attemptURL)

        let metadata = TunnelDiagnosticAttemptMetadata(
            schemaVersion: Self.schemaVersion,
            attemptID: attemptID,
            startedAt: startedAt,
            profileID: profileID,
            protocolName: TunnelDiagnosticSanitizer.safeToken(protocolName),
            appBuild: appBuild
        )
        try write(metadata, to: attemptURL.appendingPathComponent("metadata.json"))
        try write(metadata, to: rootDirectoryURL.appendingPathComponent("latest-attempt.json"))
        try pruneAttempts(keeping: attemptID)
    }

    func record(_ event: TunnelDiagnosticEvent, build: TunnelBuildIdentity = .current()) throws {
        guard event.attemptID.uuidString.isEmpty == false else { return }
        let attemptURL = directoryURL(for: event.attemptID)
        try createProtectedDirectory(attemptURL)
        let fileURL = sourceFileURL(source: event.source, attemptURL: attemptURL)
        var envelope = (try? read(TunnelDiagnosticSourceEnvelope.self, from: fileURL))
            ?? TunnelDiagnosticSourceEnvelope(
                schemaVersion: Self.schemaVersion,
                source: event.source,
                build: build,
                events: []
            )
        guard envelope.schemaVersion == Self.schemaVersion, envelope.source == event.source else {
            throw TunnelStartupDiagnosticsStoreError.invalidStoredData
        }
        if event.stage.isAuthoritativeTerminal,
           envelope.events.contains(where: { $0.stage.isAuthoritativeTerminal }) {
            return
        }
        envelope.build = build
        envelope.events.append(event)
        envelope.events.sort(by: TunnelDiagnosticEventOrdering.areInIncreasingOrder)
        if envelope.events.count > maximumEventsPerSource {
            envelope.events.removeFirst(envelope.events.count - maximumEventsPerSource)
        }
        try write(envelope, to: fileURL)
    }

    func latestAttempt() throws -> TunnelDiagnosticAttemptSnapshot? {
        let latestURL = rootDirectoryURL.appendingPathComponent("latest-attempt.json")
        guard fileManager.fileExists(atPath: latestURL.path) else { return nil }
        let metadata = try read(TunnelDiagnosticAttemptMetadata.self, from: latestURL)
        return try attempt(id: metadata.attemptID)
    }

    func attempt(id: UUID) throws -> TunnelDiagnosticAttemptSnapshot? {
        let attemptURL = directoryURL(for: id)
        let metadataURL = attemptURL.appendingPathComponent("metadata.json")
        guard fileManager.fileExists(atPath: metadataURL.path) else { return nil }
        let metadata = try read(TunnelDiagnosticAttemptMetadata.self, from: metadataURL)
        guard metadata.schemaVersion == Self.schemaVersion, metadata.attemptID == id else {
            throw TunnelStartupDiagnosticsStoreError.invalidStoredData
        }

        let appEnvelope = try optionalEnvelope(source: .app, attemptURL: attemptURL)
        let providerEnvelope = try optionalEnvelope(source: .provider, attemptURL: attemptURL)
        let constructionEnvelope = try? TunnelNativeConstructionCheckpointJournal.read(
            attemptID: id,
            rootDirectoryURL: rootDirectoryURL,
            fileManager: fileManager
        )
        var seenEventIDs: Set<UUID> = []
        let events = ((appEnvelope?.events ?? [])
            + (providerEnvelope?.events ?? [])
            + (constructionEnvelope?.events ?? []))
            .filter { seenEventIDs.insert($0.id).inserted }
        return TunnelDiagnosticAttemptSnapshot(
            metadata: metadata,
            appBuild: appEnvelope?.build ?? metadata.appBuild,
            extensionBuild: providerEnvelope?.build ?? constructionEnvelope?.build,
            events: events.sorted(by: TunnelDiagnosticEventOrdering.areInIncreasingOrder)
        )
    }

    private func optionalEnvelope(
        source: TunnelDiagnosticSource,
        attemptURL: URL
    ) throws -> TunnelDiagnosticSourceEnvelope? {
        let fileURL = sourceFileURL(source: source, attemptURL: attemptURL)
        guard fileManager.fileExists(atPath: fileURL.path) else { return nil }
        let envelope = try read(TunnelDiagnosticSourceEnvelope.self, from: fileURL)
        guard envelope.schemaVersion == Self.schemaVersion, envelope.source == source else {
            throw TunnelStartupDiagnosticsStoreError.invalidStoredData
        }
        return envelope
    }

    private func sourceFileURL(source: TunnelDiagnosticSource, attemptURL: URL) -> URL {
        attemptURL.appendingPathComponent(source == .app ? "app.json" : "provider.json")
    }

    private func directoryURL(for attemptID: UUID) -> URL {
        rootDirectoryURL
            .appendingPathComponent("attempts", isDirectory: true)
            .appendingPathComponent(attemptID.uuidString.lowercased(), isDirectory: true)
    }

    private func write<Value: Encodable>(_ value: Value, to fileURL: URL) throws {
        try createProtectedDirectory(fileURL.deletingLastPathComponent())
        let data = try encoder.encode(value)
        try data.write(to: fileURL, options: [.atomic])
        try? fileManager.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: fileURL.path
        )
    }

    private func read<Value: Decodable>(_ type: Value.Type, from fileURL: URL) throws -> Value {
        let data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
        guard data.count <= 512 * 1_024 else {
            throw TunnelStartupDiagnosticsStoreError.invalidStoredData
        }
        return try decoder.decode(type, from: data)
    }

    private func createProtectedDirectory(_ url: URL) throws {
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        try? fileManager.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: url.path
        )
    }

    private func pruneAttempts(keeping currentAttemptID: UUID) throws {
        let attemptsURL = rootDirectoryURL.appendingPathComponent("attempts", isDirectory: true)
        let keys: Set<URLResourceKey> = [.isDirectoryKey]
        let directories = try fileManager.contentsOfDirectory(
            at: attemptsURL,
            includingPropertiesForKeys: Array(keys),
            options: [.skipsHiddenFiles]
        ).filter { url in
            (try? url.resourceValues(forKeys: keys).isDirectory) == true
        }.map { url in
            let metadataURL = url.appendingPathComponent("metadata.json")
            let startedAt = (try? read(TunnelDiagnosticAttemptMetadata.self, from: metadataURL).startedAt)
                ?? .distantPast
            return (url: url, startedAt: startedAt)
        }.sorted { lhs, rhs in
            if lhs.startedAt == rhs.startedAt {
                return lhs.url.lastPathComponent > rhs.url.lastPathComponent
            }
            return lhs.startedAt > rhs.startedAt
        }

        guard directories.count > maximumAttemptCount else { return }
        for entry in directories.dropFirst(maximumAttemptCount) {
            let url = entry.url
            guard url.lastPathComponent.caseInsensitiveCompare(currentAttemptID.uuidString) != .orderedSame else {
                continue
            }
            try? fileManager.removeItem(at: url)
        }
    }
}

nonisolated enum TunnelStartupDiagnosticsStoreError: Error, Equatable, Sendable {
    case invalidStoredData
}

private nonisolated extension TunnelStartupStage {
    var isAuthoritativeTerminal: Bool {
        switch self {
        case .tunnelStartCompleted, .tunnelStartFailed, .tunnelStartCancelled:
            true
        default:
            false
        }
    }
}

nonisolated enum TunnelDiagnosticSanitizer {
    private static let allowedDetailKeys: Set<String> = [
        "profileID", "protocol", "backend", "runtimeRevision", "neStatus", "providerBundleID",
        "failureCategory", "nativeCode", "systemErrorDomain", "systemErrorCode", "completionResult",
        "runtimeRecordPresent", "credentialReferenceResolved", "managerCount", "managerAction",
        "requestedProfileID", "runtimeProfileID", "expectedRuntimeRevision", "expectedPublicationRevision",
        "runtimeSnapshotExists", "runtimeProfileMatchesSelected", "lastProviderStage", "elapsedMilliseconds",
        "lastNEVPNStatus", "nativeConnectionErrorCase", "triggeringCondition", "appStopRequested",
        "appStopTimedOut", "startupTaskCancelled", "crossProcessOrderUnproven", "watchdogIntervalSeconds",
        "physicalFootprintBytes", "residentSizeBytes", "availableMemoryBytes", "loggerInstallationBypassed",
        "neConnectionErrorCase", "providerTerminationEvidence", "providerErrorRecovered"
    ]

    static func safeDetails(_ details: [String: String]) -> [String: String] {
        var result: [String: String] = [:]
        for (key, value) in details where allowedDetailKeys.contains(key) {
            if let safeValue = safeToken(value, maximumLength: 180) {
                result[key] = safeValue
            }
        }
        return result
    }

    static func safeToken(_ value: String?, maximumLength: Int = 96) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false else { return nil }
        return String(redactedText(trimmed).prefix(maximumLength))
    }

    static func redactedText(_ value: String) -> String {
        let clipped = String(value.prefix(512))
        let separators = CharacterSet.whitespacesAndNewlines.union(
            CharacterSet(charactersIn: ",;()[]{}<>\"'")
        )
        let sensitiveNames = [
            "privatekey", "private_key", "presharedkey", "preshared_key", "psk",
            "headerprotectionkey", "header_protection_key", "password", "token", "credential="
        ]
        if sensitiveNames.contains(where: { clipped.lowercased().contains($0) }) {
            return "<redacted diagnostic text>"
        }

        var result = clipped
        for token in clipped.components(separatedBy: separators) where token.count >= 32 {
            let scalars = token.unicodeScalars
            let looksEncoded = scalars.allSatisfy { scalar in
                CharacterSet.alphanumerics.contains(scalar) || "+/=_-".unicodeScalars.contains(scalar)
            }
            if looksEncoded {
                result = result.replacingOccurrences(of: token, with: "<redacted>")
            }
        }
        return result
    }
}

nonisolated enum TunnelDiagnosticReportExporter {
    static func report(for snapshot: TunnelDiagnosticAttemptSnapshot) -> String {
        var lines = [
            "SecureLink Tunnel Diagnostic Report",
            "",
            "App:",
            "version: \(snapshot.appBuild.version)",
            "build: \(snapshot.appBuild.build)",
            "bundleID: \(snapshot.appBuild.bundleIdentifier)",
            "sourceRevision: \(snapshot.appBuild.sourceRevision ?? "unknown")",
            "",
            "PacketTunnelExtension:"
        ]
        if let extensionBuild = snapshot.extensionBuild {
            lines += [
                "version: \(extensionBuild.version)",
                "build: \(extensionBuild.build)",
                "bundleID: \(extensionBuild.bundleIdentifier)",
                "sourceRevision: \(extensionBuild.sourceRevision ?? "unknown")"
            ]
        } else {
            lines.append("NOT REACHED")
        }
        lines += [
            "",
            "Attempt:",
            "id: \(snapshot.metadata.attemptID.uuidString)",
            "started: \(TunnelDiagnosticDateCodec.string(from: snapshot.metadata.startedAt))",
            "profileID: \(snapshot.metadata.profileID?.uuidString ?? "unknown")",
            "protocol: \(snapshot.metadata.protocolName ?? "unknown")",
            "",
            "Startup:",
            "orderingNote: cross-process order uses wall-clock time; adjacent ambiguous events are marked crossProcessOrder=unproven"
        ]

        for (index, event) in snapshot.events.enumerated() {
            let time = TunnelDiagnosticDateCodec.string(from: event.timestamp)
            var line = "\(time) [\(event.source.rawValue)#\(event.sourceSequence.map(String.init) ?? "legacy")] \(event.stage.rawValue) \(event.outcome.rawValue) attempt=\(event.attemptID.uuidString) mono=\(event.monotonicNanoseconds.map(String.init) ?? "legacy")"
            if index > 0,
               TunnelDiagnosticEventOrdering.crossProcessOrderIsUnproven(snapshot.events[index - 1], event) {
                line += " crossProcessOrder=unproven"
            }
            if let category = event.failureCategory {
                line += " category=\(category.rawValue)"
            }
            if let nativeCode = event.details["nativeCode"] {
                line += " nativeCode=\(nativeCode)"
            }
            for key in event.details.keys.sorted() where key != "nativeCode" {
                if let value = event.details[key] {
                    line += " \(key)=\(value)"
                }
            }
            lines.append(line)
            append(error: event.error, indentation: "  ", to: &lines)
            if let summary = event.safeConfiguration {
                lines += safeConfigurationLines(summary).map { "  \($0)" }
            }
        }

        return lines.joined(separator: "\n")
    }

    private static func append(
        error: TunnelDiagnosticError?,
        indentation: String,
        to lines: inout [String]
    ) {
        guard let error else { return }
        lines.append("\(indentation)error: \(error.domain) / \(error.code) / \(error.description)")
        if let reason = error.failureReason {
            lines.append("\(indentation)failureReason: \(reason)")
        }
        if let suggestion = error.recoverySuggestion {
            lines.append("\(indentation)recoverySuggestion: \(suggestion)")
        }
        if let underlying = error.underlying.first {
            lines.append("\(indentation)underlying:")
            append(error: underlying, indentation: indentation + "  ", to: &lines)
        }
    }

    private static func safeConfigurationLines(_ value: NativeTunnelSafeConfigurationSummary) -> [String] {
        [
            "safeConfiguration.protocol: \(value.protocolName)",
            "interfaceAddressCount: \(value.interfaceAddressCount)",
            "dnsServerCount: \(value.dnsServerCount)",
            "mtu: \(value.mtu.map(String.init) ?? "automatic")",
            "jc/jmin/jmax present: \(value.junkPacketCount != nil)/\(value.junkPacketMinSize != nil)/\(value.junkPacketMaxSize != nil)",
            "s1-s4 present: \(value.s1 != nil)/\(value.s2 != nil)/\(value.s3 != nil)/\(value.s4 != nil)",
            "h1-h4 present: \(value.h1Present)/\(value.h2Present)/\(value.h3Present)/\(value.h4Present)",
            "peerCount: \(value.peerCount)",
            "allowedIPCount: \(value.allowedIPCount)",
            "endpointHostPresent: \(value.endpointHostPresent)",
            "endpointPort: \(value.endpointPort.map(String.init) ?? "none")",
            "privateKey: \(value.privateKeyPresent ? "present" : "missing") length=\(value.privateKeyDecodedLength.map(String.init) ?? "unknown")",
            "publicKey: \(value.publicKeyPresent ? "present" : "missing") length=\(value.publicKeyDecodedLength.map(String.init) ?? "unknown")",
            "presharedKey: \(value.presharedKeyPresent ? "present" : "absent") length=\(value.presharedKeyDecodedLength.map(String.init) ?? "n/a")",
            "headerProtectionKey: \(value.headerProtectionKeyPresent ? "present" : "absent") length=\(value.headerProtectionKeyDecodedLength.map(String.init) ?? "n/a")",
            "maskingEnabled: \(value.maskingEnabled)"
        ]
    }
}

nonisolated final class TunnelStartCompletionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var completion: ((Error?) -> Void)?
    private var watchdogTask: Task<Void, Never>?
    private let duplicateHandler: @Sendable () -> Void

    init(
        completion: @escaping (Error?) -> Void,
        duplicateHandler: @escaping @Sendable () -> Void = {}
    ) {
        self.completion = completion
        self.duplicateHandler = duplicateHandler
    }

    var hasCompleted: Bool {
        lock.withLock { completion == nil }
    }

    @discardableResult
    func complete(_ error: Error?) -> Bool {
        guard let claim = claimCompletion() else { return false }
        claim.finish(error)
        return true
    }

    func claimCompletion() -> TunnelStartCompletionClaim? {
        let action: (((Error?) -> Void)?, Task<Void, Never>?) = lock.withLock {
            let action = completion
            completion = nil
            let watchdog = watchdogTask
            watchdogTask = nil
            return (action, watchdog)
        }
        guard let completion = action.0 else {
            duplicateHandler()
            return nil
        }
        action.1?.cancel()
        return TunnelStartCompletionClaim(completion: completion)
    }

    func setWatchdog(_ task: Task<Void, Never>) {
        let shouldCancel = lock.withLock {
            guard completion != nil else { return true }
            watchdogTask?.cancel()
            watchdogTask = task
            return false
        }
        if shouldCancel {
            task.cancel()
        }
    }
}

nonisolated struct TunnelStartCompletionClaim: @unchecked Sendable {
    private let completion: (Error?) -> Void

    fileprivate init(completion: @escaping (Error?) -> Void) {
        self.completion = completion
    }

    func finish(_ error: Error?) {
        completion(error)
    }
}
