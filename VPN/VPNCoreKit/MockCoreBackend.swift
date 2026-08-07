//
//  MockCoreBackend.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

actor MockCoreBackend: VPNCoreBackend {
    nonisolated let identifier = "mock-core-backend"
    nonisolated let supportedProtocols: Set<CoreProtocol>
    private let shouldFail: Bool
    private let delay: Duration
    private var configuration: CoreConfiguration?
    private var state: CoreState = .idle
    private var stats: CoreStatistics = .empty
    private var statsTask: Task<Void, Never>?
    private var continuations: [UUID: AsyncStream<CoreEvent>.Continuation] = [:]

    init(supportedProtocols: Set<CoreProtocol> = Set(CoreProtocol.allCases), shouldFail: Bool = false, delay: Duration = .milliseconds(180)) {
        self.supportedProtocols = supportedProtocols
        self.shouldFail = shouldFail
        self.delay = delay
    }

    nonisolated var events: AsyncStream<CoreEvent> {
        AsyncStream { continuation in
            Task {
                let id = UUID()
                await self.addContinuation(continuation, id: id)
                continuation.onTermination = { _ in
                    Task { await self.removeContinuation(id: id) }
                }
            }
        }
    }

    func prepare(configuration: CoreConfiguration) async throws {
        guard supportedProtocols.contains(configuration.protocolType) else {
            throw CoreError.unsupportedProtocol(configuration.protocolType)
        }
        try await Task.sleep(for: delay)
        try Task.checkCancellation()
        self.configuration = configuration
        await publish(.stateChanged(.ready))
    }

    func start() async throws {
        guard configuration != nil else {
            throw CoreError.preparationFailed("Missing prepared configuration.")
        }
        await publish(.stateChanged(.starting))
        try await Task.sleep(for: delay)
        try Task.checkCancellation()
        if shouldFail {
            throw CoreError.startupFailed("Mock backend configured to fail.")
        }
        stats = CoreStatistics(startedAt: Date(), bytesSent: 0, bytesReceived: 0, currentLatency: 0.035, packetLoss: 0.01, reconnectCount: 0)
        await publish(.stateChanged(.running))
        startStatisticsUpdates()
    }

    func stop() async {
        statsTask?.cancel()
        await publish(.stateChanged(.stopping))
        try? await Task.sleep(for: .milliseconds(80))
        configuration = nil
        stats = .empty
        await publish(.stateChanged(.stopped))
    }

    func statistics() async -> CoreStatistics {
        stats
    }

    private func startStatisticsUpdates() {
        statsTask?.cancel()
        statsTask = Task {
            while Task.isCancelled == false {
                try? await Task.sleep(for: .milliseconds(120))
                await incrementStatistics()
            }
        }
    }

    private func incrementStatistics() {
        stats.bytesSent += 1_024
        stats.bytesReceived += 2_048
        publish(.statisticsUpdated(stats))
    }

    private func addContinuation(_ continuation: AsyncStream<CoreEvent>.Continuation, id: UUID) {
        continuations[id] = continuation
        continuation.yield(.stateChanged(state))
    }

    private func removeContinuation(id: UUID) {
        continuations[id] = nil
    }

    private func publish(_ event: CoreEvent) {
        if case .stateChanged(let newState) = event {
            state = newState
        }
        for continuation in continuations.values {
            continuation.yield(event)
        }
    }
}

nonisolated struct MockCoreBackendFactory: VPNCoreBackendFactory {
    let identifier = "mock-core-backend-factory"
    let supportedProtocols: Set<CoreProtocol>
    let shouldFail: Bool
    let delay: Duration

    init(supportedProtocols: Set<CoreProtocol> = Set(CoreProtocol.allCases), shouldFail: Bool = false, delay: Duration = .milliseconds(180)) {
        self.supportedProtocols = supportedProtocols
        self.shouldFail = shouldFail
        self.delay = delay
    }

    func makeBackend() -> VPNCoreBackend {
        MockCoreBackend(supportedProtocols: supportedProtocols, shouldFail: shouldFail, delay: delay)
    }
}
