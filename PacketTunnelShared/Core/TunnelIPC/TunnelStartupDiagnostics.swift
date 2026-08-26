//
//  TunnelStartupDiagnostics.swift
//  PacketTunnelExtension
//
//  Provider-side half of the secret-free activation timeline. Its JSON model
//  mirrors the app target while the provider writes only provider.json.
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

/// A synchronous, bounded sidecar used only around native constructor calls.
/// It survives a provider process termination that can prevent an actor Task
/// from flushing the regular provider timeline.
nonisolated enum TunnelNativeConstructionCheckpointJournal {
    static let fileName = "provider-native-construction.json"
    private static let maximumEventCount = 32
    private static let lock = NSLock()

    static func appendToAppGroup(
        _ event: TunnelDiagnosticEvent,
        build: TunnelBuildIdentity = .current(),
        fileManager: FileManager = .default
    ) throws {
        guard let containerURL = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier
        ) else {
            return
        }
        try append(
            event,
            build: build,
            rootDirectoryURL: containerURL.appendingPathComponent("TunnelDiagnostics", isDirectory: true),
            fileManager: fileManager
        )
    }

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
}

actor TunnelStartupDiagnosticsStore {
    static let schemaVersion: UInt32 = 1

    private let rootDirectoryURL: URL
    private let maximumEventsPerSource: Int
    private let fileManager: FileManager
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    init(
        rootDirectoryURL: URL,
        maximumEventsPerSource: Int = 128,
        fileManager: FileManager = .default
    ) {
        self.rootDirectoryURL = rootDirectoryURL
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

    func record(_ event: TunnelDiagnosticEvent, build: TunnelBuildIdentity = .current()) throws {
        let attemptURL = rootDirectoryURL
            .appendingPathComponent("attempts", isDirectory: true)
            .appendingPathComponent(event.attemptID.uuidString.lowercased(), isDirectory: true)
        try createProtectedDirectory(attemptURL)
        let fileURL = attemptURL.appendingPathComponent("provider.json")
        var envelope = (try? read(from: fileURL)) ?? TunnelDiagnosticSourceEnvelope(
            schemaVersion: Self.schemaVersion,
            source: .provider,
            build: build,
            events: []
        )
        guard envelope.schemaVersion == Self.schemaVersion, envelope.source == .provider else {
            throw TunnelStartupDiagnosticsStoreError.invalidStoredData
        }
        envelope.build = build
        envelope.events.append(event)
        envelope.events.sort(by: TunnelDiagnosticEventOrdering.areInIncreasingOrder)
        if envelope.events.count > maximumEventsPerSource {
            envelope.events.removeFirst(envelope.events.count - maximumEventsPerSource)
        }
        let data = try encoder.encode(envelope)
        try data.write(to: fileURL, options: [.atomic])
        try? fileManager.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: fileURL.path
        )
    }

    private func read(from fileURL: URL) throws -> TunnelDiagnosticSourceEnvelope {
        let data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
        guard data.count <= 512 * 1_024 else {
            throw TunnelStartupDiagnosticsStoreError.invalidStoredData
        }
        return try decoder.decode(TunnelDiagnosticSourceEnvelope.self, from: data)
    }

    private func createProtectedDirectory(_ url: URL) throws {
        try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        try? fileManager.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: url.path
        )
    }
}

nonisolated enum TunnelStartupDiagnosticsStoreError: Error, Equatable, Sendable {
    case invalidStoredData
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
        let sensitiveNames = [
            "privatekey", "private_key", "presharedkey", "preshared_key", "psk",
            "headerprotectionkey", "header_protection_key", "password", "token", "credential="
        ]
        if sensitiveNames.contains(where: { clipped.lowercased().contains($0) }) {
            return "<redacted diagnostic text>"
        }
        let separators = CharacterSet.whitespacesAndNewlines.union(
            CharacterSet(charactersIn: ",;()[]{}<>\"'")
        )
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
