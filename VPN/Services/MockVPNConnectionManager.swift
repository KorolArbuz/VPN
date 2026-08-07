//
//  MockVPNConnectionManager.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

actor MockVPNConnectionManager: VPNConnectionManaging {
    private var state: VPNConnectionState = .disconnected
    private var continuations: [UUID: AsyncStream<VPNConnectionState>.Continuation] = [:]
    private let coordinator: VPNCoreCoordinator

    init(shouldFail: Bool = false) {
        let registry = VPNCoreBackendRegistry(factories: [
            MockCoreBackendFactory(shouldFail: shouldFail, delay: .milliseconds(160))
        ])
        self.coordinator = VPNCoreCoordinator(
            compiler: CompositeProfileConfigurationCompiler(),
            registry: registry,
            credentialResolver: NonSecretReferenceCredentialResolver()
        )
    }

    func currentState() async -> VPNConnectionState {
        state
    }

    nonisolated func stateUpdates() -> AsyncStream<VPNConnectionState> {
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

    func connect(using profile: VPNProfile) async throws -> ConnectionMetrics {
        guard profile.isEnabled else {
            await publish(.failed)
            throw MockVPNError.incompleteProfile(["enabled profile"])
        }

        guard profile.isComplete else {
            await publish(.failed)
            throw MockVPNError.incompleteProfile(profile.missingRequiredFields)
        }

        await publish(.connecting)
        do {
            try await coordinator.start(profile: profile)
        } catch {
            await publish(.failed)
            throw error
        }

        let statistics = await coordinator.statistics()
        await publish(.connected)

        return ConnectionMetrics(
            latency: Int(((statistics.currentLatency ?? 0.035) * 1_000).rounded()),
            packetLoss: statistics.packetLoss,
            serverLoad: 0.35,
            connectionTime: 0.45
        )
    }

    func disconnect() async {
        await publish(.disconnecting)
        await coordinator.stop()

        if Task.isCancelled {
            return
        }

        await publish(.disconnected)
    }

    private func addContinuation(_ continuation: AsyncStream<VPNConnectionState>.Continuation, id: UUID) {
        continuations[id] = continuation
        continuation.yield(state)
    }

    private func removeContinuation(id: UUID) {
        continuations[id] = nil
    }

    private func publish(_ newState: VPNConnectionState) async {
        state = newState
        for continuation in continuations.values {
            continuation.yield(newState)
        }
    }
}
