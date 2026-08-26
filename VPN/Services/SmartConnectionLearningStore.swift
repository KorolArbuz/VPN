//
//  SmartConnectionLearningStore.swift
//  VPN
//
//  Bounded, non-secret aggregate persistence for Smart Connection.
//

import Foundation

nonisolated struct SmartConnectionStatistics: Codable, Equatable, Sendable {
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
        if let latency = summary.latencyMilliseconds {
            ewmaLatencyMilliseconds = Self.ewma(
                previous: ewmaLatencyMilliseconds,
                observation: max(0, latency)
            )
            latencySampleCount += 1
        }
        if let loss = summary.packetLossPercent {
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

nonisolated struct SmartConnectionLearningSnapshot: Codable, Equatable, Sendable {
    static let currentSchemaVersion = 1

    var schemaVersion: Int
    var contextProfileRecords: [SmartConnectionContextProfileRecord]
    var profileRecords: [SmartConnectionProfileRecord]
    var protocolRecords: [SmartConnectionProtocolRecord]

    init(
        schemaVersion: Int = Self.currentSchemaVersion,
        contextProfileRecords: [SmartConnectionContextProfileRecord] = [],
        profileRecords: [SmartConnectionProfileRecord] = [],
        protocolRecords: [SmartConnectionProtocolRecord] = []
    ) {
        self.schemaVersion = schemaVersion
        self.contextProfileRecords = contextProfileRecords
        self.profileRecords = profileRecords
        self.protocolRecords = protocolRecords
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
}

nonisolated protocol SmartConnectionLearningStoring: Sendable {
    func snapshot(for profiles: [VPNProfile]) async -> SmartConnectionLearningSnapshot

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

    func prune(profiles: [VPNProfile]) async
}

actor FileSmartConnectionLearningStore: SmartConnectionLearningStoring {
    private static let maximumContextsPerProfile = 8

    private let fileURL: URL
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder
    private var cachedSnapshot: SmartConnectionLearningSnapshot?

    init(fileURL: URL? = nil) {
        if let fileURL {
            self.fileURL = fileURL
        } else {
            let applicationSupportURL = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first ?? FileManager.default.temporaryDirectory
            self.fileURL = applicationSupportURL
                .appendingPathComponent("VPN", isDirectory: true)
                .appendingPathComponent("smart-connection-learning-v1.json")
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        self.decoder = decoder

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.encoder = encoder
    }

    func snapshot(for profiles: [VPNProfile]) async -> SmartConnectionLearningSnapshot {
        var snapshot = loadSnapshot()
        let original = snapshot
        Self.prune(&snapshot, profiles: profiles)
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
        mutate(
            profileID: profileID,
            protocolType: protocolType,
            context: context
        ) { statistics in
            statistics.recordSessionSummary(summary, at: date)
        }
    }

    func prune(profiles: [VPNProfile]) async {
        var snapshot = loadSnapshot()
        let original = snapshot
        Self.prune(&snapshot, profiles: profiles)
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
        var snapshot = loadSnapshot()

        snapshot.contextProfileRecords.removeAll {
            $0.profileID == profileID && $0.protocolType != protocolType
        }
        snapshot.profileRecords.removeAll {
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

        Self.boundContexts(&snapshot, profileID: profileID)
        cachedSnapshot = snapshot
        persist(snapshot)
    }

    private func loadSnapshot() -> SmartConnectionLearningSnapshot {
        if let cachedSnapshot {
            return cachedSnapshot
        }
        guard FileManager.default.fileExists(atPath: fileURL.path),
              let data = try? Data(contentsOf: fileURL),
              let decoded = try? decoder.decode(
                SmartConnectionLearningSnapshot.self,
                from: data
              ),
              decoded.schemaVersion == SmartConnectionLearningSnapshot.currentSchemaVersion else {
            let empty = SmartConnectionLearningSnapshot.empty
            cachedSnapshot = empty
            return empty
        }
        cachedSnapshot = decoded
        return decoded
    }

    private func persist(_ snapshot: SmartConnectionLearningSnapshot) {
        do {
            let directoryURL = fileURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true
            )
            let data = try encoder.encode(snapshot)
            try data.write(to: fileURL, options: [.atomic])
        } catch {
            // Learning is an optimization. Persistence must never block VPN use.
        }
    }

    private static func prune(
        _ snapshot: inout SmartConnectionLearningSnapshot,
        profiles: [VPNProfile]
    ) {
        let protocolsByProfile = Dictionary(
            uniqueKeysWithValues: profiles.map { ($0.id, $0.protocolType) }
        )
        snapshot.contextProfileRecords.removeAll { record in
            protocolsByProfile[record.profileID] != record.protocolType
        }
        snapshot.profileRecords.removeAll { record in
            protocolsByProfile[record.profileID] != record.protocolType
        }
        for profileID in protocolsByProfile.keys {
            boundContexts(&snapshot, profileID: profileID)
        }
        snapshot.protocolRecords.removeAll {
            VPNProtocol.allCases.contains($0.protocolType) == false
        }
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
}

actor InMemorySmartConnectionLearningStore: SmartConnectionLearningStoring {
    private var value: SmartConnectionLearningSnapshot

    init(snapshot: SmartConnectionLearningSnapshot = .empty) {
        value = snapshot
    }

    func snapshot(for profiles: [VPNProfile]) async -> SmartConnectionLearningSnapshot {
        value
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
        mutate(profileID: profileID, protocolType: protocolType, context: context) {
            $0.recordSessionSummary(summary, at: date)
        }
    }

    func prune(profiles: [VPNProfile]) async {
        let protocolsByProfile = Dictionary(
            uniqueKeysWithValues: profiles.map { ($0.id, $0.protocolType) }
        )
        value.contextProfileRecords.removeAll {
            protocolsByProfile[$0.profileID] != $0.protocolType
        }
        value.profileRecords.removeAll {
            protocolsByProfile[$0.profileID] != $0.protocolType
        }
    }

    private func mutate(
        profileID: UUID,
        protocolType: VPNProtocol,
        context: NetworkContext,
        mutation: (inout SmartConnectionStatistics) -> Void
    ) {
        if let index = value.contextProfileRecords.firstIndex(where: {
            $0.profileID == profileID
                && $0.protocolType == protocolType
                && $0.context == context
        }) {
            mutation(&value.contextProfileRecords[index].statistics)
        } else {
            var statistics = SmartConnectionStatistics()
            mutation(&statistics)
            value.contextProfileRecords.append(
                SmartConnectionContextProfileRecord(
                    context: context,
                    profileID: profileID,
                    protocolType: protocolType,
                    statistics: statistics
                )
            )
        }

        if let index = value.profileRecords.firstIndex(where: {
            $0.profileID == profileID && $0.protocolType == protocolType
        }) {
            mutation(&value.profileRecords[index].statistics)
        } else {
            var statistics = SmartConnectionStatistics()
            mutation(&statistics)
            value.profileRecords.append(
                SmartConnectionProfileRecord(
                    profileID: profileID,
                    protocolType: protocolType,
                    statistics: statistics
                )
            )
        }

        if let index = value.protocolRecords.firstIndex(where: {
            $0.protocolType == protocolType
        }) {
            mutation(&value.protocolRecords[index].statistics)
        } else {
            var statistics = SmartConnectionStatistics()
            mutation(&statistics)
            value.protocolRecords.append(
                SmartConnectionProtocolRecord(
                    protocolType: protocolType,
                    statistics: statistics
                )
            )
        }
    }
}
