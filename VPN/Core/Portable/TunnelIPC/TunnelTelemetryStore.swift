//
//  TunnelTelemetryStore.swift
//  VPN
//
//  Serialized runtime telemetry owner. The app copy is used for unit tests and
//  DTO validation; PacketTunnelExtension has the same read-only store locally.
//

import Foundation

actor TunnelTelemetryStore {
    private let maximumEventCount: Int
    private var runtime: TunnelRuntimeSnapshot
    private var events: [TunnelEventSnapshot] = []

    init(initialRuntime: TunnelRuntimeSnapshot = .notRunning(), maximumEventCount: Int = 32) {
        self.runtime = initialRuntime
        self.maximumEventCount = max(1, maximumEventCount)
    }

    func runtimeSnapshot() -> TunnelRuntimeSnapshot {
        runtime
    }

    func healthSnapshot() -> TunnelHealthSnapshot {
        runtime.health
    }

    func recentEvents(limit: Int = 32) -> [TunnelEventSnapshot] {
        Array(events.suffix(max(0, min(limit, maximumEventCount))))
    }

    func markStarting(
        profileID: String?,
        candidateID: String?,
        backendKind: TunnelBackendKind,
        protocolKind: TunnelProtocolKind,
        transportKind: String?,
        now: Date = Date()
    ) {
        runtime.runtimeGeneration += 1
        runtime.runtimeState = .starting
        runtime.activeProfileID = TunnelTelemetrySanitizer.safeIdentifier(profileID)
        runtime.candidateID = TunnelTelemetrySanitizer.safeIdentifier(candidateID)
        runtime.backendKind = backendKind
        runtime.protocolKind = protocolKind
        runtime.transportKind = TunnelTelemetrySanitizer.safeToken(transportKind)
        runtime.sessionID = UUID().uuidString
        runtime.startedAt = now
        runtime.stoppedAt = nil
        runtime.uptimeSeconds = nil
        runtime.lastStateChangeAt = now
        runtime.generatedAt = now
        runtime.origin = .packetTunnelExtension
        runtime.health = TunnelHealthSnapshot(
            state: .starting,
            generatedAt: now,
            origin: .packetTunnelExtension,
            lastSuccessfulTrafficAt: runtime.lastSuccessfulTrafficAt,
            lastFailure: runtime.lastFailure,
            isLive: true
        )
        appendEvent(category: "starting", state: .starting, failure: nil, now: now)
    }

    func markNetworkSettingsApplied(now: Date = Date()) {
        runtime.runtimeState = .networkSettingsApplied
        runtime.networkSettingsState = .running
        updateGenerated(now)
        appendEvent(category: "network_settings_applied", state: .networkSettingsApplied, failure: nil, now: now)
    }

    func markRunning(now: Date = Date()) {
        runtime.runtimeState = .running
        runtime.startedAt = now
        runtime.stoppedAt = nil
        runtime.uptimeSeconds = 0
        runtime.xrayState = runtime.xrayState == .unavailable ? .unavailable : .running
        runtime.tun2SocksState = runtime.tun2SocksState == .unavailable ? .unavailable : .running
        runtime.health = TunnelHealthSnapshot(
            state: .healthy,
            generatedAt: now,
            origin: .packetTunnelExtension,
            lastSuccessfulTrafficAt: runtime.lastSuccessfulTrafficAt,
            lastFailure: runtime.lastFailure,
            isLive: true
        )
        updateGenerated(now)
        appendEvent(category: "running", state: .running, failure: nil, now: now)
    }

    func updateCounters(_ counters: TunnelTrafficCounters, now: Date = Date()) {
        runtime.counters = counters
        if counters.bytesDownloaded != nil || counters.bytesUploaded != nil || counters.packetsDownloaded != nil || counters.packetsUploaded != nil {
            runtime.lastSuccessfulTrafficAt = now
            runtime.health.lastSuccessfulTrafficAt = now
        }
        updateGenerated(now)
    }

    func markFailure(_ failure: TunnelFailureSnapshot, now: Date = Date()) {
        runtime.runtimeState = .failed
        runtime.lastFailure = failure
        runtime.health = TunnelHealthSnapshot(
            state: .failed,
            generatedAt: now,
            origin: .packetTunnelExtension,
            lastSuccessfulTrafficAt: runtime.lastSuccessfulTrafficAt,
            lastFailure: failure,
            isLive: true
        )
        updateGenerated(now)
        appendEvent(category: "failure", state: .failed, failure: failure.category, now: now)
    }

    func markStopped(now: Date = Date()) {
        runtime.runtimeState = .stopped
        runtime.stoppedAt = now
        runtime.xrayState = .stopped
        runtime.tun2SocksState = .stopped
        runtime.networkSettingsState = .stopped
        runtime.health = TunnelHealthSnapshot(
            state: .stopped,
            generatedAt: now,
            origin: .packetTunnelExtension,
            lastSuccessfulTrafficAt: runtime.lastSuccessfulTrafficAt,
            lastFailure: runtime.lastFailure,
            isLive: false
        )
        updateGenerated(now)
        appendEvent(category: "stopped", state: .stopped, failure: nil, now: now)
    }

    private func updateGenerated(_ now: Date) {
        runtime.lastStateChangeAt = now
        runtime.generatedAt = now
        if let startedAt = runtime.startedAt {
            runtime.uptimeSeconds = max(0, now.timeIntervalSince(startedAt))
        }
        runtime.health.generatedAt = now
    }

    private func appendEvent(category: String, state: TunnelRuntimeState, failure: TunnelFailureCategory?, now: Date) {
        events.append(TunnelEventSnapshot(generatedAt: now, category: category, runtimeState: state, failureCategory: failure))
        if events.count > maximumEventCount {
            events.removeFirst(events.count - maximumEventCount)
        }
    }
}

nonisolated enum TunnelTelemetrySanitizer {
    static func safeIdentifier(_ value: String?) -> String? {
        guard let value else {
            return nil
        }

        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false else {
            return nil
        }

        let lowercased = trimmed.lowercased()
        let forbiddenMarkers = ["://", "@", "password", "private", "token", "credential", "uuid=", "key="]
        guard forbiddenMarkers.contains(where: lowercased.contains) == false else {
            return nil
        }

        return trimmed
    }

    static func safeToken(_ value: String?) -> String? {
        guard let value else {
            return nil
        }

        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false, trimmed.count <= 64 else {
            return nil
        }

        let lowercased = trimmed.lowercased()
        guard lowercased.contains("://") == false,
              lowercased.contains("@") == false,
              lowercased.contains("password") == false,
              lowercased.contains("private") == false,
              lowercased.contains("token") == false,
              lowercased.contains("credential") == false else {
            return nil
        }

        return trimmed
    }
}
