//
//  TunnelTelemetrySnapshotStore.swift
//  VPN
//
//  Sanitized last-known PacketTunnelExtension telemetry snapshot storage.
//  App Group data is a fallback/history mechanism; it is never treated as live
//  tunnel truth.
//

import Foundation

nonisolated enum TunnelTelemetryAppGroup {
    static let identifier = "group.su.24kvn.kvn-app"
}

actor TunnelTelemetrySnapshotStore {
    private let fileURL: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let maximumEventCount: Int

    init(fileURL: URL, maximumEventCount: Int = 32) {
        self.fileURL = fileURL
        self.maximumEventCount = max(1, maximumEventCount)
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    static func appGroupStore(fileManager: FileManager = .default) -> TunnelTelemetrySnapshotStore? {
        guard let containerURL = fileManager.containerURL(forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier) else {
            return nil
        }

        let fileURL = containerURL
            .appendingPathComponent("TunnelTelemetry", isDirectory: true)
            .appendingPathComponent("last-runtime-snapshot.json")
        return TunnelTelemetrySnapshotStore(fileURL: fileURL)
    }

    func write(runtime: TunnelRuntimeSnapshot, events: [TunnelEventSnapshot], now: Date = Date()) throws {
        let stored = TunnelStoredTelemetrySnapshot(
            schemaVersion: TunnelMessageProtocol.schemaVersion,
            generatedAt: now,
            runtime: runtime,
            events: Array(events.suffix(maximumEventCount))
        )
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try encoder.encode(stored)
        try data.write(to: fileURL, options: [.atomic])
    }

    func read(now: Date = Date(), staleAfter: TimeInterval = 30) throws -> TunnelTelemetrySnapshotRead? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return nil
        }

        let data = try Data(contentsOf: fileURL)
        var stored = try decoder.decode(TunnelStoredTelemetrySnapshot.self, from: data)
        guard stored.schemaVersion == TunnelMessageProtocol.schemaVersion else {
            throw TunnelMessageErrorCode.schemaMismatch
        }

        stored.runtime.origin = .appGroupLastKnownSnapshot
        stored.runtime.health.origin = .appGroupLastKnownSnapshot
        stored.runtime.health.isLive = false

        let age = now.timeIntervalSince(stored.generatedAt)
        return TunnelTelemetrySnapshotRead(stored: stored, isStale: age > staleAfter)
    }
}
