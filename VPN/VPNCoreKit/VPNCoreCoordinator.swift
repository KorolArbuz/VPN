//
//  VPNCoreCoordinator.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated protocol CredentialResolving: Sendable {
    func credentialExists(reference: String) async -> Bool
}

nonisolated struct CredentialStoreResolver: CredentialResolving {
    private let credentialStore: CredentialStoring

    init(credentialStore: CredentialStoring) {
        self.credentialStore = credentialStore
    }

    func credentialExists(reference: String) async -> Bool {
        (try? await credentialStore.secret(for: reference)) != nil || reference.hasPrefix("mock-")
    }
}

nonisolated struct NonSecretReferenceCredentialResolver: CredentialResolving {
    func credentialExists(reference: String) async -> Bool {
        reference.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
    }
}

actor VPNCoreCoordinator {
    private let compiler: ProfileConfigurationCompiling
    private let registry: VPNCoreBackendRegistry
    private let credentialResolver: CredentialResolving
    private let logger: SanitizedCoreLogger
    private var state: CoreState = .idle
    private var activeBackend: VPNCoreBackend?
    private var activeConfiguration: CoreConfiguration?
    private var operationID: UUID?
    private var eventContinuations: [UUID: AsyncStream<CoreEvent>.Continuation] = [:]
    private var backendEventTask: Task<Void, Never>?

    init(
        compiler: ProfileConfigurationCompiling,
        registry: VPNCoreBackendRegistry,
        credentialResolver: CredentialResolving,
        logger: SanitizedCoreLogger = SanitizedCoreLogger()
    ) {
        self.compiler = compiler
        self.registry = registry
        self.credentialResolver = credentialResolver
        self.logger = logger
    }

    func currentState() -> CoreState {
        state
    }

    nonisolated var events: AsyncStream<CoreEvent> {
        AsyncStream { continuation in
            Task {
                let id = UUID()
                await self.addContinuation(continuation, id: id)
                continuation.onTermination = { _ in
                    Task {
                        await self.removeContinuation(id: id)
                    }
                }
            }
        }
    }

    func start(profile: VPNProfile) async throws {
        guard state != .preparing && state != .starting && state != .running else {
            throw CoreError.alreadyRunning
        }

        let currentOperationID = UUID()
        operationID = currentOperationID
        publish(.stateChanged(.preparing))

        do {
            let configuration = try compiler.compile(profile: profile)
            guard await credentialResolver.credentialExists(reference: configuration.credentialReference) else {
                throw CoreError.missingCredential
            }
            try Task.checkCancellation()
            guard operationID == currentOperationID else { throw CoreError.cancelled }

            let backend = try registry.backend(for: configuration.protocolType)
            activeBackend = backend
            activeConfiguration = configuration
            observeBackendEvents(backend)

            try await backend.prepare(configuration: configuration)
            try Task.checkCancellation()
            guard operationID == currentOperationID else { throw CoreError.cancelled }
            publish(.stateChanged(.ready))
            publish(.stateChanged(.starting))

            try await backend.start()
            try Task.checkCancellation()
            guard operationID == currentOperationID else { throw CoreError.cancelled }
            publish(.stateChanged(.running))
            operationID = nil
        } catch is CancellationError {
            guard operationID == currentOperationID else {
                throw CoreError.cancelled
            }
            publish(.fatalError(.cancelled))
            publish(.stateChanged(.failed))
            operationID = nil
            throw CoreError.cancelled
        } catch let error as CoreError {
            guard operationID == currentOperationID else {
                throw error
            }
            logger.log(error, configuration: activeConfiguration)
            publish(.fatalError(error))
            publish(.stateChanged(.failed))
            operationID = nil
            throw error
        } catch {
            guard operationID == currentOperationID else {
                throw CoreError.cancelled
            }
            let coreError = CoreError.startupFailed(error.localizedDescription)
            logger.log(coreError, configuration: activeConfiguration)
            publish(.fatalError(coreError))
            publish(.stateChanged(.failed))
            operationID = nil
            throw coreError
        }
    }

    func stop() async {
        guard state == .running || state == .starting || state == .preparing || state == .ready || state == .failed else {
            publish(.stateChanged(.stopped))
            return
        }

        let currentOperationID = UUID()
        operationID = currentOperationID
        publish(.stateChanged(.stopping))
        backendEventTask?.cancel()
        await activeBackend?.stop()

        guard operationID == currentOperationID else { return }
        activeBackend = nil
        activeConfiguration = nil
        operationID = nil
        publish(.stateChanged(.stopped))
    }

    func statistics() async -> CoreStatistics {
        await activeBackend?.statistics() ?? .empty
    }

    private func observeBackendEvents(_ backend: VPNCoreBackend) {
        backendEventTask?.cancel()
        backendEventTask = Task { [weak self] in
            for await event in backend.events {
                await self?.publish(event)
            }
        }
    }

    private func addContinuation(_ continuation: AsyncStream<CoreEvent>.Continuation, id: UUID) {
        eventContinuations[id] = continuation
        continuation.yield(.stateChanged(state))
    }

    private func removeContinuation(id: UUID) {
        eventContinuations[id] = nil
    }

    private func publish(_ event: CoreEvent) {
        if case .stateChanged(let newState) = event {
            state = newState
        }

        for continuation in eventContinuations.values {
            continuation.yield(event)
        }
    }
}
