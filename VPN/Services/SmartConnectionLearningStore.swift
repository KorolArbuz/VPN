//
//  SmartConnectionLearningStore.swift
//  VPN
//
//  Bounded, non-secret aggregate persistence for Smart Connection.
//

import Foundation

nonisolated struct SmartConnectionStatistics: Codable, Equatable, Sendable {
    // Statistical units are intentionally explicit:
    // - reliability: all connection attempts
    // - connect duration: successful connection attempts
    // - latency/loss: completed provider sessions with that valid quality metric
    // - stability: completed provider sessions
    var attemptCount = 0
    var successfulConnectionCount = 0
    var failedConnectionCount = 0
    var consecutiveFailures = 0

    var ewmaConnectDurationSeconds: Double?
    var connectDurationSampleCount = 0
    var ewmaLatencyMilliseconds: Double?
    var latencySampleCount = 0
    var ewmaPacketLossPercent: Double?
    var packetLossSampleCount = 0

    var successfulSessionSeconds: TimeInterval = 0
    var completedSessionCount = 0
    var unexpectedDisconnectCount = 0

    var lastAttemptAt: Date?
    var lastSuccessAt: Date?
    var lastFailureAt: Date?
    var lastUpdatedAt: Date?

    mutating func recordConnectionSuccess(
        connectDuration: TimeInterval,
        at date: Date
    ) {
        attemptCount += 1
        successfulConnectionCount += 1
        consecutiveFailures = 0
        ewmaConnectDurationSeconds = Self.ewma(
            previous: ewmaConnectDurationSeconds,
            observation: max(0, connectDuration)
        )
        connectDurationSampleCount += 1
        lastAttemptAt = date
        lastSuccessAt = date
        lastUpdatedAt = date
    }

    mutating func recordConnectionFailure(at date: Date) {
        attemptCount += 1
        failedConnectionCount += 1
        consecutiveFailures += 1
        lastAttemptAt = date
        lastFailureAt = date
        lastUpdatedAt = date
    }

    mutating func recordSessionSummary(
        _ summary: SmartConnectionSessionSummary,
        at date: Date
    ) {
        successfulSessionSeconds += max(
            0,
            summary.additionalSuccessfulSessionSeconds
        )
        // Checkpoints may add runtime for crash resilience, but quality is one
        // independent observation per completed provider session.
        if summary.sessionEnded, let latency = summary.latencyMilliseconds {
            ewmaLatencyMilliseconds = Self.ewma(
                previous: ewmaLatencyMilliseconds,
                observation: max(0, latency)
            )
            latencySampleCount += 1
        }
        if summary.sessionEnded, let loss = summary.packetLossPercent {
            ewmaPacketLossPercent = Self.ewma(
                previous: ewmaPacketLossPercent,
                observation: min(100, max(0, loss))
            )
            packetLossSampleCount += 1
        }
        if summary.sessionEnded {
            completedSessionCount += 1
        }
        if summary.unexpectedDisconnect {
            unexpectedDisconnectCount += 1
            consecutiveFailures += 1
            lastFailureAt = date
        }
        lastUpdatedAt = date
    }

    private static func ewma(
        previous: Double?,
        observation: Double,
        alpha: Double = 0.25
    ) -> Double {
        guard let previous else {
            return observation
        }
        return alpha * observation + (1 - alpha) * previous
    }
}

nonisolated struct SmartConnectionContextProfileRecord: Codable, Equatable, Sendable {
    var context: NetworkContext
    var profileID: UUID
    var protocolType: VPNProtocol
    var statistics: SmartConnectionStatistics
}

nonisolated struct SmartConnectionProfileRecord: Codable, Equatable, Sendable {
    var profileID: UUID
    var protocolType: VPNProtocol
    var statistics: SmartConnectionStatistics
}

nonisolated struct SmartConnectionProtocolRecord: Codable, Equatable, Sendable {
    var protocolType: VPNProtocol
    var statistics: SmartConnectionStatistics
}

nonisolated struct SmartConnectionExplorationRecord: Codable, Equatable, Sendable {
    var profileID: UUID
    var protocolType: VPNProtocol
    var context: NetworkContext
    var attemptedAt: Date
}

nonisolated struct SmartConnectionLearningSnapshot: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    var schemaVersion: Int
    var contextProfileRecords: [SmartConnectionContextProfileRecord]
    var profileRecords: [SmartConnectionProfileRecord]
    var protocolRecords: [SmartConnectionProtocolRecord]
    // Optional fields preserve decoding compatibility with Build 7 schema-v1
    // files. Empty metadata is normalized back to nil.
    var explorationRecords: [SmartConnectionExplorationRecord]?
    var committedSessionIDs: [String]?

    init(
        schemaVersion: Int = Self.currentSchemaVersion,
        contextProfileRecords: [SmartConnectionContextProfileRecord] = [],
        profileRecords: [SmartConnectionProfileRecord] = [],
        protocolRecords: [SmartConnectionProtocolRecord] = [],
        explorationRecords: [SmartConnectionExplorationRecord] = [],
        committedSessionIDs: [String] = []
    ) {
        self.schemaVersion = schemaVersion
        self.contextProfileRecords = contextProfileRecords
        self.profileRecords = profileRecords
        self.protocolRecords = protocolRecords
        self.explorationRecords = explorationRecords.isEmpty ? nil : explorationRecords
        self.committedSessionIDs = committedSessionIDs.isEmpty ? nil : committedSessionIDs
    }

    static let empty = SmartConnectionLearningSnapshot()

    func contextStatistics(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext
    ) -> SmartConnectionStatistics {
        contextProfileRecords.first {
            $0.profileID == profileID
                && $0.protocolType == protocolType
                && $0.context == context
        }?.statistics ?? SmartConnectionStatistics()
    }

    func profileStatistics(
        profileID: UUID,
        protocolType: VPNProtocol
    ) -> SmartConnectionStatistics {
        profileRecords.first {
            $0.profileID == profileID && $0.protocolType == protocolType
        }?.statistics ?? SmartConnectionStatistics()
    }

    func protocolStatistics(
        _ protocolType: VPNProtocol
    ) -> SmartConnectionStatistics {
        protocolRecords.first {
            $0.protocolType == protocolType
        }?.statistics ?? SmartConnectionStatistics()
    }

    func lastExplorationAt(context: NetworkContext) -> Date? {
        explorationRecords?
            .filter { $0.context == context }
            .map(\.attemptedAt)
            .max()
    }
}

nonisolated protocol SmartConnectionLearningStoring: Sendable {
    /// nil means the profile inventory is not loaded and must never trigger
    /// profile-deletion pruning. [] means authoritatively loaded and empty.
    func snapshot(for profiles: [VPNProfile]?) async -> SmartConnectionLearningSnapshot

    func recordConnectionSuccess(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        connectDuration: TimeInterval,
        at date: Date
    ) async

    func recordConnectionFailure(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) async

    func recordSessionSummary(
        _ summary: SmartConnectionSessionSummary,
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) async

    func recordExploration(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) async

    func prune(profiles: [VPNProfile]) async
}

/// One pure transformation owns production and test-store semantics.
nonisolated enum SmartConnectionLearningTransform {
    static let maximumContextsPerProfile = 8
    static let maximumExplorationRecords = 32
    static let maximumCommittedSessionIDs = 128

    static func sanitized(
        _ input: SmartConnectionLearningSnapshot,
        profileInventory: [VPNProfile]?
    ) -> SmartConnectionLearningSnapshot {
        guard input.schemaVersion == SmartConnectionLearningSnapshot.currentSchemaVersion else {
            return .empty
        }

        var snapshot = input
        snapshot.protocolRecords.removeAll {
            VPNProtocol.allCases.contains($0.protocolType) == false
        }

        if let profileInventory {
            let protocolsByProfile = Dictionary(
                uniqueKeysWithValues: profileInventory.map { ($0.id, $0.protocolType) }
            )
            snapshot.contextProfileRecords.removeAll { record in
                protocolsByProfile[record.profileID] != record.protocolType
            }
            snapshot.profileRecords.removeAll { record in
                protocolsByProfile[record.profileID] != record.protocolType
            }
            snapshot.explorationRecords?.removeAll { record in
                protocolsByProfile[record.profileID] != record.protocolType
            }
        }

        let profileIDs = Set(snapshot.contextProfileRecords.map(\.profileID))
        for profileID in profileIDs {
            boundContexts(&snapshot, profileID: profileID)
        }
        boundMetadata(&snapshot)
        return snapshot
    }

    static func mutateStatistics(
        _ input: SmartConnectionLearningSnapshot,
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        mutation: (inout SmartConnectionStatistics) -> Void
    ) -> SmartConnectionLearningSnapshot {
        var snapshot = sanitized(input, profileInventory: nil)
        snapshot.contextProfileRecords.removeAll {
            $0.profileID == profileID && $0.protocolType != protocolType
        }
        snapshot.profileRecords.removeAll {
            $0.profileID == profileID && $0.protocolType != protocolType
        }
        snapshot.explorationRecords?.removeAll {
            $0.profileID == profileID && $0.protocolType != protocolType
        }

        if let index = snapshot.contextProfileRecords.firstIndex(where: {
            $0.profileID == profileID
                && $0.protocolType == protocolType
                && $0.context == context
        }) {
            mutation(&snapshot.contextProfileRecords[index].statistics)
        } else {
            var statistics = SmartConnectionStatistics()
            mutation(&statistics)
            snapshot.contextProfileRecords.append(
                SmartConnectionContextProfileRecord(
                    context: context,
                    profileID: profileID,
                    protocolType: protocolType,
                    statistics: statistics
                )
            )
        }

        if let index = snapshot.profileRecords.firstIndex(where: {
            $0.profileID == profileID && $0.protocolType == protocolType
        }) {
            mutation(&snapshot.profileRecords[index].statistics)
        } else {
            var statistics = SmartConnectionStatistics()
            mutation(&statistics)
            snapshot.profileRecords.append(
                SmartConnectionProfileRecord(
                    profileID: profileID,
                    protocolType: protocolType,
                    statistics: statistics
                )
            )
        }

        if let index = snapshot.protocolRecords.firstIndex(where: {
            $0.protocolType == protocolType
        }) {
            mutation(&snapshot.protocolRecords[index].statistics)
        } else {
            var statistics = SmartConnectionStatistics()
            mutation(&statistics)
            snapshot.protocolRecords.append(
                SmartConnectionProtocolRecord(
                    protocolType: protocolType,
                    statistics: statistics
                )
            )
        }

        boundContexts(&snapshot, profileID: profileID)
        boundMetadata(&snapshot)
        return snapshot
    }

    static func recordSessionSummary(
        _ summary: SmartConnectionSessionSummary,
        in input: SmartConnectionLearningSnapshot,
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) -> SmartConnectionLearningSnapshot {
        let normalizedSessionID = summary.sessionID?.trimmingCharacters(
            in: .whitespacesAndNewlines
        )
        // Provider IDs are stable within a session. Scope them to the immutable
        // learning identity so two providers reusing the same opaque ID cannot
        // suppress one another. The bounded key list makes finalization
        // idempotent across app restoration without creating raw-sample history.
        let commitKey = normalizedSessionID.map {
            "\(profileID.uuidString)|\(protocolType.rawValue)|\(context.stableKey)|\($0)"
        }
        if summary.sessionEnded,
           let normalizedSessionID,
           normalizedSessionID.isEmpty == false,
           let commitKey,
           input.committedSessionIDs?.contains(commitKey) == true {
            return input
        }

        var snapshot = mutateStatistics(
            input,
            profileID: profileID,
            protocolType: protocolType,
            context: context
        ) { statistics in
            statistics.recordSessionSummary(summary, at: date)
        }

        if summary.sessionEnded,
           let normalizedSessionID,
           normalizedSessionID.isEmpty == false,
           let commitKey {
            var committed = snapshot.committedSessionIDs ?? []
            committed.removeAll { $0 == commitKey }
            committed.append(commitKey)
            snapshot.committedSessionIDs = committed
        }
        boundMetadata(&snapshot)
        return snapshot
    }

    static func recordExploration(
        in input: SmartConnectionLearningSnapshot,
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) -> SmartConnectionLearningSnapshot {
        var snapshot = sanitized(input, profileInventory: nil)
        var records = snapshot.explorationRecords ?? []
        records.removeAll {
            $0.profileID == profileID
                && $0.protocolType == protocolType
                && $0.context == context
        }
        records.append(SmartConnectionExplorationRecord(
            profileID: profileID,
            protocolType: protocolType,
            context: context,
            attemptedAt: date
        ))
        snapshot.explorationRecords = records
        boundMetadata(&snapshot)
        return snapshot
    }

    private static func boundContexts(
        _ snapshot: inout SmartConnectionLearningSnapshot,
        profileID: UUID
    ) {
        let matching = snapshot.contextProfileRecords
            .filter { $0.profileID == profileID }
            .sorted {
                ($0.statistics.lastUpdatedAt ?? .distantPast)
                    > ($1.statistics.lastUpdatedAt ?? .distantPast)
            }
        guard matching.count > maximumContextsPerProfile else {
            return
        }
        let retainedContexts = Set(
            matching.prefix(maximumContextsPerProfile).map(\.context)
        )
        snapshot.contextProfileRecords.removeAll {
            $0.profileID == profileID
                && retainedContexts.contains($0.context) == false
        }
    }

    private static func boundMetadata(_ snapshot: inout SmartConnectionLearningSnapshot) {
        if var explorations = snapshot.explorationRecords {
            explorations.sort { $0.attemptedAt > $1.attemptedAt }
            explorations = Array(explorations.prefix(maximumExplorationRecords))
            snapshot.explorationRecords = explorations.isEmpty ? nil : explorations
        }
        if var sessionIDs = snapshot.committedSessionIDs {
            sessionIDs = Array(sessionIDs.suffix(maximumCommittedSessionIDs))
            snapshot.committedSessionIDs = sessionIDs.isEmpty ? nil : sessionIDs
        }
    }
}

nonisolated enum SmartConnectionLearningLocation {
    static let appGroupIdentifier = "group.su.24kvn.kvn-app"
    static let fileName = "smart-connection-learning-v1.json"

    static func appGroupFileURL(containerURL: URL) -> URL {
        containerURL
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("VPN", isDirectory: true)
            .appendingPathComponent("SmartConnection", isDirectory: true)
            .appendingPathComponent(fileName)
    }

    static func legacyFileURL(fileManager: FileManager) -> URL {
        let applicationSupportURL = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? fileManager.temporaryDirectory
        return applicationSupportURL
            .appendingPathComponent("VPN", isDirectory: true)
            .appendingPathComponent(fileName)
    }
}

actor FileSmartConnectionLearningStore: SmartConnectionLearningStoring {
    // Retained as an inspectable source contract; the shared transform owns it.
    private static let maximumContextsPerProfile = 8

    private let primaryFileURL: URL
    private let legacyFileURL: URL?
    private let fileManager: FileManager
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder
    private var cachedSnapshot: SmartConnectionLearningSnapshot?
    private var usesLegacyFallback = false

    init(
        fileURL: URL? = nil,
        legacyFileURL: URL? = nil,
        fileManager: FileManager = .default
    ) {
        self.fileManager = fileManager
        if let fileURL {
            primaryFileURL = fileURL
            self.legacyFileURL = legacyFileURL
        } else {
            let legacyURL = SmartConnectionLearningLocation.legacyFileURL(
                fileManager: fileManager
            )
            if let containerURL = fileManager.containerURL(
                forSecurityApplicationGroupIdentifier:
                    SmartConnectionLearningLocation.appGroupIdentifier
            ) {
                primaryFileURL = SmartConnectionLearningLocation.appGroupFileURL(
                    containerURL: containerURL
                )
                self.legacyFileURL = legacyURL
            } else {
                // Learning is optional; a missing entitlement/container must not
                // block VPN use. Keep the exact Build-7 location as fallback.
                primaryFileURL = legacyURL
                self.legacyFileURL = nil
            }
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        self.decoder = decoder

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.encoder = encoder
    }

    func snapshot(for profiles: [VPNProfile]?) async -> SmartConnectionLearningSnapshot {
        let original = loadSnapshot()
        let snapshot = SmartConnectionLearningTransform.sanitized(
            original,
            profileInventory: profiles
        )
        cachedSnapshot = snapshot
        if snapshot != original {
            persist(snapshot)
        }
        return snapshot
    }

    func recordConnectionSuccess(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        connectDuration: TimeInterval,
        at date: Date
    ) async {
        mutate(
            profileID: profileID,
            protocolType: protocolType,
            context: context
        ) { statistics in
            statistics.recordConnectionSuccess(
                connectDuration: connectDuration,
                at: date
            )
        }
    }

    func recordConnectionFailure(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) async {
        mutate(
            profileID: profileID,
            protocolType: protocolType,
            context: context
        ) { statistics in
            statistics.recordConnectionFailure(at: date)
        }
    }

    func recordSessionSummary(
        _ summary: SmartConnectionSessionSummary,
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) async {
        let original = loadSnapshot()
        let snapshot = SmartConnectionLearningTransform.recordSessionSummary(
            summary,
            in: original,
            profileID: profileID,
            protocolType: protocolType,
            context: context,
            at: date
        )
        cachedSnapshot = snapshot
        if snapshot != original {
            persist(snapshot)
        }
    }

    func recordExploration(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) async {
        let snapshot = SmartConnectionLearningTransform.recordExploration(
            in: loadSnapshot(),
            profileID: profileID,
            protocolType: protocolType,
            context: context,
            at: date
        )
        cachedSnapshot = snapshot
        persist(snapshot)
    }

    func prune(profiles: [VPNProfile]) async {
        let original = loadSnapshot()
        let snapshot = SmartConnectionLearningTransform.sanitized(
            original,
            profileInventory: profiles
        )
        cachedSnapshot = snapshot
        if snapshot != original {
            persist(snapshot)
        }
    }

    private func mutate(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        mutation: (inout SmartConnectionStatistics) -> Void
    ) {
        let snapshot = SmartConnectionLearningTransform.mutateStatistics(
            loadSnapshot(),
            profileID: profileID,
            protocolType: protocolType,
            context: context,
            mutation: mutation
        )
        cachedSnapshot = snapshot
        persist(snapshot)
    }

    private func loadSnapshot() -> SmartConnectionLearningSnapshot {
        if let cachedSnapshot {
            return cachedSnapshot
        }

        if fileManager.fileExists(atPath: primaryFileURL.path) {
            let snapshot = decodeSnapshot(at: primaryFileURL) ?? .empty
            cachedSnapshot = snapshot
            return snapshot
        }

        if let legacyFileURL,
           legacyFileURL.standardizedFileURL != primaryFileURL.standardizedFileURL,
           fileManager.fileExists(atPath: legacyFileURL.path),
           let legacySnapshot = decodeSnapshot(at: legacyFileURL) {
            let sanitized = SmartConnectionLearningTransform.sanitized(
                legacySnapshot,
                profileInventory: nil
            )
            if migrateToPrimary(sanitized) {
                try? fileManager.removeItem(at: legacyFileURL)
            } else {
                usesLegacyFallback = true
            }
            cachedSnapshot = sanitized
            return sanitized
        }

        let empty = SmartConnectionLearningSnapshot.empty
        cachedSnapshot = empty
        return empty
    }

    private func decodeSnapshot(at fileURL: URL) -> SmartConnectionLearningSnapshot? {
        guard let data = try? Data(contentsOf: fileURL),
              let decoded = try? decoder.decode(
                SmartConnectionLearningSnapshot.self,
                from: data
              ),
              decoded.schemaVersion == SmartConnectionLearningSnapshot.currentSchemaVersion else {
            return nil
        }
        return decoded
    }

    private func migrateToPrimary(_ snapshot: SmartConnectionLearningSnapshot) -> Bool {
        do {
            try write(snapshot, to: primaryFileURL)
            guard decodeSnapshot(at: primaryFileURL) == snapshot else {
                try? fileManager.removeItem(at: primaryFileURL)
                return false
            }
            usesLegacyFallback = false
            return true
        } catch {
            return false
        }
    }

    private func persist(_ snapshot: SmartConnectionLearningSnapshot) {
        do {
            try write(snapshot, to: primaryFileURL)
            usesLegacyFallback = false
        } catch {
            guard usesLegacyFallback, let legacyFileURL else {
                // Learning is an optimization. Persistence must never block VPN use.
                return
            }
            try? write(snapshot, to: legacyFileURL)
        }
    }

    private func write(
        _ snapshot: SmartConnectionLearningSnapshot,
        to fileURL: URL
    ) throws {
        let directoryURL = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true
        )
        let data = try encoder.encode(snapshot)
        try data.write(to: fileURL, options: [.atomic])
    }

}

actor InMemorySmartConnectionLearningStore: SmartConnectionLearningStoring {
    private var value: SmartConnectionLearningSnapshot

    init(snapshot: SmartConnectionLearningSnapshot = .empty) {
        value = SmartConnectionLearningTransform.sanitized(
            snapshot,
            profileInventory: nil
        )
    }

    func snapshot(for profiles: [VPNProfile]?) async -> SmartConnectionLearningSnapshot {
        value = SmartConnectionLearningTransform.sanitized(
            value,
            profileInventory: profiles
        )
        return value
    }

    func recordConnectionSuccess(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        connectDuration: TimeInterval,
        at date: Date
    ) async {
        mutate(profileID: profileID, protocolType: protocolType, context: context) {
            $0.recordConnectionSuccess(connectDuration: connectDuration, at: date)
        }
    }

    func recordConnectionFailure(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) async {
        mutate(profileID: profileID, protocolType: protocolType, context: context) {
            $0.recordConnectionFailure(at: date)
        }
    }

    func recordSessionSummary(
        _ summary: SmartConnectionSessionSummary,
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) async {
        value = SmartConnectionLearningTransform.recordSessionSummary(
            summary,
            in: value,
            profileID: profileID,
            protocolType: protocolType,
            context: context,
            at: date
        )
    }

    func recordExploration(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        at date: Date
    ) async {
        value = SmartConnectionLearningTransform.recordExploration(
            in: value,
            profileID: profileID,
            protocolType: protocolType,
            context: context,
            at: date
        )
    }

    func prune(profiles: [VPNProfile]) async {
        value = SmartConnectionLearningTransform.sanitized(
            value,
            profileInventory: profiles
        )
    }

    private func mutate(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        mutation: (inout SmartConnectionStatistics) -> Void
    ) {
        value = SmartConnectionLearningTransform.mutateStatistics(
            value,
            profileID: profileID,
            protocolType: protocolType,
            context: context,
            mutation: mutation
        )
    }
}
