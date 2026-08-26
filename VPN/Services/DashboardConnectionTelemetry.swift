//
//  DashboardConnectionTelemetry.swift
//  VPN
//
//  Live dashboard runtime and one shared latency/loss probe pipeline.
//

import Foundation
import OSLog

nonisolated struct ProviderTunnelSession: Equatable, Sendable {
    var sessionID: String
    var profileID: UUID
    var provider: PacketTunnelProviderKind
    var protocolKind: TunnelProtocolKind
    var connectedStartedAt: Date
}

nonisolated protocol ProviderTunnelSessionReading: Sendable {
    func session(
        matching connection: VPNAuthoritativeConnection
    ) async -> ProviderTunnelSession?
}

actor AppGroupProviderTunnelSessionReader: ProviderTunnelSessionReading {
    private static let logger = Logger(
        subsystem: "su.24kvn.kvn-app",
        category: "DashboardTelemetry"
    )

    private let snapshotStore: TunnelTelemetrySnapshotStore?

    init(
        snapshotStore: TunnelTelemetrySnapshotStore? =
            TunnelTelemetrySnapshotStore.appGroupStore()
    ) {
        self.snapshotStore = snapshotStore
    }

    func session(
        matching connection: VPNAuthoritativeConnection
    ) async -> ProviderTunnelSession? {
        guard connection.systemStatus == .connected || connection.systemStatus == .reasserting,
              let profileID = connection.profileID,
              let provider = connection.provider,
              let snapshotStore,
              let read = try? await snapshotStore.read(
                staleAfter: .greatestFiniteMagnitude
              ) else {
            return nil
        }

        let runtime = read.stored.runtime
        guard runtime.runtimeState == .running,
              runtime.activeProfileID == profileID.uuidString,
              runtime.backendKind == backendKind(for: provider),
              let sessionID = runtime.sessionID,
              let connectedStartedAt = runtime.startedAt else {
            return nil
        }

        let session = ProviderTunnelSession(
            sessionID: sessionID,
            profileID: profileID,
            provider: provider,
            protocolKind: runtime.protocolKind,
            connectedStartedAt: connectedStartedAt
        )
        Self.logger.notice(
            "providerSessionTelemetryRestored session=\(sessionID, privacy: .public) profile=\(profileID.uuidString, privacy: .public) provider=\(provider.rawValue, privacy: .public)"
        )
        return session
    }

    private func backendKind(for provider: PacketTunnelProviderKind) -> TunnelBackendKind {
        switch provider {
        case .wireGuard:
            .wireguard
        case .xray:
            .xray
        }
    }
}

nonisolated enum TunnelLatencyProbeOutcome: Equatable, Sendable {
    case success(milliseconds: Double)
    case failure
    case cancelled
}

nonisolated protocol TunnelLatencyProbing: Sendable {
    func probe() async -> TunnelLatencyProbeOutcome
}

nonisolated final class NetworkTunnelLatencyProbe: TunnelLatencyProbing, @unchecked Sendable {
    private let endpointProber: any EndpointProbing
    private let timeout: Duration
    private let request: TransportProbeRequest

    init(
        endpointProber: any EndpointProbing = NetworkEndpointProber(),
        timeout: Duration = .seconds(3),
        host: String = "www.apple.com",
        port: UInt16 = 443
    ) {
        self.endpointProber = endpointProber
        self.timeout = timeout
        request = TransportProbeRequest(
            candidateID: "dashboard-current-system-route",
            profileID: "dashboard",
            displayName: "Dashboard latency probe",
            protocolType: .wireGuard,
            host: host,
            port: port,
            transport: "tcp",
            security: "tls",
            kind: .tlsHandshake,
            serverName: host
        )
    }

    func probe() async -> TunnelLatencyProbeOutcome {
        let attempt = await endpointProber.probe(
            request,
            attemptIndex: 0,
            timeout: timeout
        )
        if attempt.failure == .cancelled || Task.isCancelled {
            return .cancelled
        }
        if attempt.failure != nil {
            return .failure
        }
        guard let milliseconds = attempt.handshakeLatencyMs ?? attempt.connectLatencyMs else {
            return .failure
        }
        return .success(milliseconds: milliseconds)
    }
}

nonisolated struct RollingTunnelProbeWindow: Equatable, Sendable {
    nonisolated enum Sample: Equatable, Sendable {
        case success(milliseconds: Double)
        case failure
    }

    private(set) var samples: [Sample] = []
    let capacity: Int
    let minimumSamplesForLoss: Int

    init(capacity: Int = 10, minimumSamplesForLoss: Int = 3) {
        self.capacity = max(1, capacity)
        self.minimumSamplesForLoss = max(1, minimumSamplesForLoss)
    }

    mutating func record(_ outcome: TunnelLatencyProbeOutcome) {
        switch outcome {
        case .success(let milliseconds):
            samples.append(.success(milliseconds: max(0, milliseconds)))
        case .failure:
            samples.append(.failure)
        case .cancelled:
            return
        }
        if samples.count > capacity {
            samples.removeFirst(samples.count - capacity)
        }
    }

    var latencyMilliseconds: Int? {
        let successful = samples.compactMap { sample -> Double? in
            guard case .success(let milliseconds) = sample else {
                return nil
            }
            return milliseconds
        }
        guard successful.isEmpty == false else {
            return nil
        }
        return Int((successful.reduce(0, +) / Double(successful.count)).rounded())
    }

    var packetLossPercent: Double? {
        guard samples.count >= minimumSamplesForLoss else {
            return nil
        }
        let failures = samples.reduce(into: 0) { count, sample in
            if case .failure = sample {
                count += 1
            }
        }
        return Double(failures) / Double(samples.count) * 100
    }
}

nonisolated struct DashboardConnectionTelemetrySnapshot: Equatable, Sendable {
    var sessionID: String?
    var connectedStartedAt: Date?
    var runtimeSeconds: TimeInterval?
    var latencyMilliseconds: Int?
    var packetLossPercent: Double?

    static let unavailable = DashboardConnectionTelemetrySnapshot(
        sessionID: nil,
        connectedStartedAt: nil,
        runtimeSeconds: nil,
        latencyMilliseconds: nil,
        packetLossPercent: nil
    )
}

nonisolated protocol DashboardConnectionTelemetryManaging: Sendable {
    func updates() -> AsyncStream<DashboardConnectionTelemetrySnapshot>
    func reconcile(with connection: VPNAuthoritativeConnection) async
    func stop() async
}

actor DisabledDashboardConnectionTelemetryManager: DashboardConnectionTelemetryManaging {
    nonisolated func updates() -> AsyncStream<DashboardConnectionTelemetrySnapshot> {
        AsyncStream { continuation in
            continuation.yield(.unavailable)
            continuation.finish()
        }
    }

    func reconcile(with connection: VPNAuthoritativeConnection) async {}

    func stop() async {}
}

nonisolated protocol DashboardTelemetryClock: Sendable {
    func now() -> Date
    func sleep(for duration: Duration) async throws
}

nonisolated struct SystemDashboardTelemetryClock: DashboardTelemetryClock {
    func now() -> Date {
        Date()
    }

    func sleep(for duration: Duration) async throws {
        try await Task.sleep(for: duration)
    }
}

actor DashboardConnectionTelemetryController: DashboardConnectionTelemetryManaging {
    private static let logger = Logger(
        subsystem: "su.24kvn.kvn-app",
        category: "DashboardTelemetry"
    )

    private let sessionReader: any ProviderTunnelSessionReading
    private let probe: any TunnelLatencyProbing
    private let clock: any DashboardTelemetryClock
    private let probeInterval: TimeInterval
    private let runtimeUpdateInterval: Duration
    private let rollingWindowCapacity: Int
    private let minimumSamplesForLoss: Int

    private var activeSession: ProviderTunnelSession?
    private var samplingTask: Task<Void, Never>?
    private var probeWindow: RollingTunnelProbeWindow
    private var currentSnapshot: DashboardConnectionTelemetrySnapshot = .unavailable
    private var continuations:
        [UUID: AsyncStream<DashboardConnectionTelemetrySnapshot>.Continuation] = [:]

    init(
        sessionReader: any ProviderTunnelSessionReading =
            AppGroupProviderTunnelSessionReader(),
        probe: any TunnelLatencyProbing = NetworkTunnelLatencyProbe(),
        clock: any DashboardTelemetryClock = SystemDashboardTelemetryClock(),
        probeInterval: TimeInterval = 5,
        runtimeUpdateInterval: Duration = .seconds(1),
        rollingWindowCapacity: Int = 10,
        minimumSamplesForLoss: Int = 3
    ) {
        self.sessionReader = sessionReader
        self.probe = probe
        self.clock = clock
        self.probeInterval = max(1, probeInterval)
        self.runtimeUpdateInterval = runtimeUpdateInterval
        self.rollingWindowCapacity = max(1, rollingWindowCapacity)
        self.minimumSamplesForLoss = max(1, minimumSamplesForLoss)
        probeWindow = RollingTunnelProbeWindow(
            capacity: rollingWindowCapacity,
            minimumSamplesForLoss: minimumSamplesForLoss
        )
    }

    nonisolated func updates() -> AsyncStream<DashboardConnectionTelemetrySnapshot> {
        AsyncStream { continuation in
            Task {
                let id = UUID()
                await addContinuation(continuation, id: id)
                continuation.onTermination = { _ in
                    Task {
                        await self.removeContinuation(id: id)
                    }
                }
            }
        }
    }

    func reconcile(with connection: VPNAuthoritativeConnection) async {
        switch connection.systemStatus {
        case .connected, .reasserting:
            guard let profileID = connection.profileID,
                  let provider = connection.provider else {
                await stop()
                return
            }
            let providerSession = await sessionReader.session(matching: connection)
            let session = providerSession ?? ProviderTunnelSession(
                sessionID: "pending|" + provider.rawValue + "|" + profileID.uuidString,
                profileID: profileID,
                provider: provider,
                protocolKind: .unknown,
                connectedStartedAt: clock.now()
            )
            await start(session: session, runtimeIsAuthoritative: providerSession != nil)
        case .connecting, .disconnecting, .disconnected, .invalid, nil:
            await stop()
        }
    }

    func snapshot() -> DashboardConnectionTelemetrySnapshot {
        currentSnapshot
    }

    func isSampling() -> Bool {
        samplingTask != nil
    }

    func stop() async {
        guard samplingTask != nil || currentSnapshot != .unavailable else {
            return
        }
        samplingTask?.cancel()
        samplingTask = nil
        activeSession = nil
        probeWindow = RollingTunnelProbeWindow(
            capacity: rollingWindowCapacity,
            minimumSamplesForLoss: minimumSamplesForLoss
        )
        publish(.unavailable)
        Self.logger.notice("telemetryProbeStopped")
    }

    private func start(
        session: ProviderTunnelSession,
        runtimeIsAuthoritative: Bool
    ) async {
        if activeSession?.sessionID == session.sessionID, samplingTask != nil {
            return
        }

        samplingTask?.cancel()
        activeSession = session
        probeWindow = RollingTunnelProbeWindow(
            capacity: rollingWindowCapacity,
            minimumSamplesForLoss: minimumSamplesForLoss
        )
        let initialRuntime = runtimeIsAuthoritative
            ? max(0, clock.now().timeIntervalSince(session.connectedStartedAt))
            : nil
        publish(
            DashboardConnectionTelemetrySnapshot(
                sessionID: runtimeIsAuthoritative ? session.sessionID : nil,
                connectedStartedAt: runtimeIsAuthoritative
                    ? session.connectedStartedAt
                    : nil,
                runtimeSeconds: initialRuntime,
                latencyMilliseconds: nil,
                packetLossPercent: nil
            )
        )

        let sessionID = session.sessionID
        samplingTask = Task { [weak self] in
            await self?.sample(
                session: session,
                sessionID: sessionID,
                runtimeIsAuthoritative: runtimeIsAuthoritative
            )
        }
        Self.logger.notice(
            "telemetryProbeStarted session=\(session.sessionID, privacy: .public) profile=\(session.profileID.uuidString, privacy: .public) provider=\(session.provider.rawValue, privacy: .public)"
        )
    }

    private func sample(
        session: ProviderTunnelSession,
        sessionID: String,
        runtimeIsAuthoritative: Bool
    ) async {
        var nextProbeAt = clock.now()
        while Task.isCancelled == false, activeSession?.sessionID == sessionID {
            let now = clock.now()
            updateRuntime(
                session: session,
                now: now,
                runtimeIsAuthoritative: runtimeIsAuthoritative
            )

            if now >= nextProbeAt {
                let outcome = await probe.probe()
                guard Task.isCancelled == false,
                      activeSession?.sessionID == sessionID else {
                    return
                }
                probeWindow.record(outcome)
                publishCurrentProbeValues()
                nextProbeAt = clock.now().addingTimeInterval(probeInterval)
            }

            do {
                try await clock.sleep(for: runtimeUpdateInterval)
            } catch {
                return
            }
        }
    }

    private func updateRuntime(
        session: ProviderTunnelSession,
        now: Date,
        runtimeIsAuthoritative: Bool
    ) {
        guard runtimeIsAuthoritative else {
            return
        }
        var snapshot = currentSnapshot
        snapshot.runtimeSeconds = max(0, now.timeIntervalSince(session.connectedStartedAt))
        publish(snapshot)
    }

    private func publishCurrentProbeValues() {
        var snapshot = currentSnapshot
        snapshot.latencyMilliseconds = probeWindow.latencyMilliseconds
        snapshot.packetLossPercent = probeWindow.packetLossPercent
        publish(snapshot)

        let latency = snapshot.latencyMilliseconds.map(String.init) ?? "unavailable"
        let loss = snapshot.packetLossPercent.map { String(format: "%.1f", $0) }
            ?? "unavailable"
        Self.logger.debug(
            "telemetryProbeSample latencyMs=\(latency, privacy: .public) lossPercent=\(loss, privacy: .public)"
        )
    }

    private func publish(_ snapshot: DashboardConnectionTelemetrySnapshot) {
        guard currentSnapshot != snapshot else {
            return
        }
        currentSnapshot = snapshot
        continuations.values.forEach { $0.yield(snapshot) }
    }

    private func addContinuation(
        _ continuation: AsyncStream<DashboardConnectionTelemetrySnapshot>.Continuation,
        id: UUID
    ) {
        continuations[id] = continuation
        continuation.yield(currentSnapshot)
    }

    private func removeContinuation(id: UUID) {
        continuations[id] = nil
    }
}
