//
//  PortableHealthDiagnosticsViewModel.swift
//  VPN
//
//  MainActor UI adapter for manual Phase F1 diagnostics. It owns no connection
//  truth and never calls connect/disconnect.
//

import Foundation
import Observation

@MainActor
@Observable
final class PortableHealthDiagnosticsViewModel {
    private let coordinator: PortableHealthCoordinator?
    private var runTask: Task<Void, Never>?

    var isRunning = false
    var summaries: [TransportProbeSummary] = []
    var recommendation: KVNSelectionDecisionDTO?
    var errorKey: String?
    var lastRunContext: ProbeContext?
    var lastCheckedAt: Date?

    init(coordinator: PortableHealthCoordinator? = nil) {
        if let coordinator {
            self.coordinator = coordinator
        } else {
            self.coordinator = Self.makeDefaultCoordinator()
        }
    }

    func runHealthCheck(
        profiles: [VPNProfile],
        connectionState: VPNConnectionState,
        probingEnabled: Bool
    ) {
        guard isRunning == false else {
            return
        }

        guard let coordinator else {
            errorKey = "diagnostics.probe.error.failed"
            return
        }

        isRunning = true
        errorKey = nil
        recommendation = nil

        runTask = Task { [weak self, coordinator] in
            do {
                let report = try await coordinator.runHealthCheck(
                    profiles: profiles,
                    connectionState: connectionState,
                    feature: PortableCoreProbeFeature(isEnabled: probingEnabled)
                )
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    self?.apply(report)
                }
            } catch let failure as TransportProbeFailure {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    self?.isRunning = false
                    self?.errorKey = failure == .cancelled ? nil : failure.localizationKey
                }
            } catch {
                guard Task.isCancelled == false else { return }
                await MainActor.run {
                    self?.isRunning = false
                    self?.errorKey = "diagnostics.probe.error.failed"
                }
            }
        }
    }

    func cancel() {
        runTask?.cancel()
        runTask = nil
        isRunning = false
        Task { [coordinator] in
            await coordinator?.cancel()
        }
    }

    private func apply(_ report: TransportHealthReport) {
        summaries = report.summaries
        recommendation = report.recommendation
        lastRunContext = report.context
        lastCheckedAt = report.generatedAt
        isRunning = false
        errorKey = report.wasSkippedBecauseDisabled ? "diagnostics.probe.error.disabled" : nil
    }

    private static func makeDefaultCoordinator() -> PortableHealthCoordinator? {
        do {
            return PortableHealthCoordinator(coreService: try PortableCoreService(feature: .disabled))
        } catch {
            return nil
        }
    }
}
