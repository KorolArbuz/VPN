//
//  PortableHealthCoordinator.swift
//  VPN
//
//  Runs bounded, cancellable app-process transport probes and feeds truthful,
//  sanitized samples into the existing PortableCoreService. Recommendations are
//  passive diagnostics only; this code never connects, disconnects, or changes
//  activeProfileID.
//

import Foundation

nonisolated struct PortableCoreProbeFeature: Sendable, Equatable {
    static let storageKey = "portable.core.probing.enabled"

    var isEnabled: Bool

    init(isEnabled: Bool = false) {
        self.isEnabled = isEnabled
    }

    static func fromDefaults(_ defaults: UserDefaults = .standard) -> PortableCoreProbeFeature {
        PortableCoreProbeFeature(isEnabled: defaults.bool(forKey: storageKey))
    }

    static let disabled = PortableCoreProbeFeature(isEnabled: false)
}

nonisolated protocol PortableCoreHealthServicing: Sendable {
    func syncCandidates(from profiles: [VPNProfile]) async throws
    func updateHealth(candidateID: String, sample: KVNHealthSampleDTO) async throws
    func setNetworkType(_ type: KVNNetworkType) async throws
    func selectBest(now: Date) async throws -> KVNSelectionDecisionDTO
}

extension PortableCoreService: PortableCoreHealthServicing {}

actor PortableHealthCoordinator {
    private let runner: TransportProbeBatchRunner
    private var generation = 0
    private var activeTask: Task<TransportHealthReport, Error>?
    private(set) var isRunning = false

    init(
        coreService: any PortableCoreHealthServicing,
        planner: any ProbePlanning = DefaultProbePlanner(),
        prober: any EndpointProbing = NetworkEndpointProber(),
        pathMonitor: any NetworkPathMonitoring = AppleNetworkPathMonitor(),
        sleeper: any ProbeSleeping = TaskProbeSleeper(),
        configuration: ProbeSeriesConfiguration = ProbeSeriesConfiguration()
    ) {
        self.runner = TransportProbeBatchRunner(
            coreService: coreService,
            planner: planner,
            prober: prober,
            pathMonitor: pathMonitor,
            sleeper: sleeper,
            configuration: configuration
        )
    }

    func runHealthCheck(
        profiles: [VPNProfile],
        connectionState: VPNConnectionState,
        feature: PortableCoreProbeFeature
    ) async throws -> TransportHealthReport {
        generation += 1
        let currentGeneration = generation
        activeTask?.cancel()

        guard feature.isEnabled else {
            isRunning = false
            activeTask = nil
            return TransportHealthReport(
                generatedAt: Date(),
                context: ProbeContext(),
                summaries: [],
                recommendation: nil,
                wasSkippedBecauseDisabled: true
            )
        }

        isRunning = true
        let runner = runner
        let task = Task<TransportHealthReport, Error> {
            try await runner.run(
                profiles: profiles,
                connectionState: connectionState,
                shouldApply: { [weak self] in
                    await self?.isCurrentGeneration(currentGeneration) == true
                }
            )
        }
        activeTask = task

        do {
            let report = try await task.value
            guard isCurrentGeneration(currentGeneration) else {
                throw TransportProbeFailure.staleResultDiscarded
            }
            clearCurrentGeneration(currentGeneration)
            return report
        } catch is CancellationError {
            clearCurrentGeneration(currentGeneration)
            throw TransportProbeFailure.cancelled
        } catch {
            clearCurrentGeneration(currentGeneration)
            throw error
        }
    }

    func cancel() {
        generation += 1
        activeTask?.cancel()
        activeTask = nil
        isRunning = false
    }

    func currentNetworkType() async -> KVNNetworkType {
        await runner.currentNetworkType()
    }

    private func isCurrentGeneration(_ value: Int) -> Bool {
        generation == value
    }

    private func clearCurrentGeneration(_ value: Int) {
        guard isCurrentGeneration(value) else {
            return
        }

        isRunning = false
        activeTask = nil
    }
}

nonisolated struct TransportProbeBatchRunner: Sendable {
    let coreService: any PortableCoreHealthServicing
    let planner: any ProbePlanning
    let prober: any EndpointProbing
    let pathMonitor: any NetworkPathMonitoring
    let sleeper: any ProbeSleeping
    let configuration: ProbeSeriesConfiguration
    let aggregator = ProbeResultAggregator()

    func currentNetworkType() async -> KVNNetworkType {
        await pathMonitor.currentNetworkType()
    }

    func run(
        profiles: [VPNProfile],
        connectionState: VPNConnectionState,
        shouldApply: @escaping @Sendable () async -> Bool
    ) async throws -> TransportHealthReport {
        let now = Date()
        let networkType = await pathMonitor.currentNetworkType()
        let context = ProbeContext(
            networkType: networkType,
            routeContext: connectionState == .connected ? .currentSystemPath : .directSystemPath
        )

        try await coreService.setNetworkType(networkType)
        try await coreService.syncCandidates(from: profiles)

        var requests: [TransportProbeRequest] = []
        var summaries: [TransportProbeSummary] = []
        var seenCandidateIDs: Set<String> = []

        for profile in profiles {
            switch planner.plan(profile: profile, context: context, now: now) {
            case .request(let request):
                guard seenCandidateIDs.insert(request.candidateID).inserted else {
                    continue
                }
                requests.append(request)
            case .skipped(let summary):
                guard seenCandidateIDs.insert(summary.candidateID).inserted else {
                    continue
                }
                summaries.append(summary)
            }
        }

        let semaphore = AsyncProbeSemaphore(value: configuration.maxConcurrentProbes)
        try await withThrowingTaskGroup(of: TransportProbeSummary.self) { group in
            for request in requests {
                group.addTask {
                    try Task.checkCancellation()
                    await semaphore.acquire()
                    do {
                        let summary = try await runSeries(request: request, context: context)
                        await semaphore.release()
                        return summary
                    } catch {
                        await semaphore.release()
                        throw error
                    }
                }
            }

            for try await summary in group {
                guard await shouldApply() else {
                    throw TransportProbeFailure.staleResultDiscarded
                }
                try await coreService.updateHealth(candidateID: summary.candidateID, sample: summary.healthSample)
                summaries.append(summary)
            }
        }

        guard await shouldApply() else {
            throw TransportProbeFailure.staleResultDiscarded
        }

        let recommendation = try await coreService.selectBest(now: Date())
        return TransportHealthReport(
            generatedAt: Date(),
            context: context,
            summaries: summaries.sorted { $0.displayName.localizedCaseInsensitiveCompare($1.displayName) == .orderedAscending },
            recommendation: recommendation,
            wasSkippedBecauseDisabled: false
        )
    }

    private func runSeries(request: TransportProbeRequest, context: ProbeContext) async throws -> TransportProbeSummary {
        var attempts: [TransportProbeAttempt] = []

        for attemptIndex in 0..<configuration.attemptCount {
            try Task.checkCancellation()
            let attempt = await prober.probe(request, attemptIndex: attemptIndex, timeout: configuration.perAttemptTimeout)
            attempts.append(attempt)

            if attemptIndex < configuration.attemptCount - 1 {
                try await sleeper.sleep(for: configuration.delayBetweenAttempts)
            }
        }

        return aggregator.summarize(request: request, attempts: attempts, context: context, now: Date())
    }
}

private actor AsyncProbeSemaphore {
    private var permits: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(value: Int) {
        self.permits = max(1, value)
    }

    func acquire() async {
        if permits > 0 {
            permits -= 1
            return
        }

        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func release() {
        if waiters.isEmpty {
            permits += 1
            return
        }

        let continuation = waiters.removeFirst()
        continuation.resume()
    }
}
