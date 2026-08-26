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
            compiler: BundledMockProfileConfigurationCompiler(),
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

    func connect(using profile: VPNProfile) async throws {
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

        await publish(.connected)
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

nonisolated private struct BundledMockProfileConfigurationCompiler: ProfileConfigurationCompiling {
    private let productionCompiler = CompositeProfileConfigurationCompiler()

    func compile(profile: VPNProfile) throws -> CoreConfiguration {
        guard profile.source == .bundledMock else {
            return try productionCompiler.compile(profile: profile)
        }

        let host = profile.serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard host.isEmpty == false, host.contains(" ") == false else {
            throw CoreError.invalidConfiguration("Host is missing or malformed.")
        }
        guard let port = profile.port, (1...65_535).contains(port) else {
            throw CoreError.invalidConfiguration("Port must be in range 1...65535.")
        }
        guard let credentialReference = profile.credentialReference, credentialReference.isEmpty == false else {
            throw CoreError.missingCredential
        }

        return CoreConfiguration(
            profileID: profile.id,
            protocolType: CoreProtocol(vpnProtocol: profile.protocolType),
            endpoint: CoreEndpoint(host: host, port: port),
            transport: .tcp(options: profile.transportSettings.metadata),
            security: mockSecurity(for: profile),
            dns: CoreDNSConfiguration(servers: profile.routingSettings.dnsServers),
            routing: CoreRoutingConfiguration(
                routeAllTraffic: profile.routingSettings.routeAllTraffic,
                excludedRoutes: profile.routingSettings.excludedRoutes
            ),
            credentialReference: credentialReference,
            metadata: profile.metadata
        )
    }

    private func mockSecurity(for profile: VPNProfile) -> CoreSecurityConfiguration {
        guard profile.tlsSettings.isEnabled else {
            return .none
        }

        return .tls(CoreTLSConfiguration(
            serverName: profile.tlsSettings.serverName,
            allowInsecure: profile.tlsSettings.allowInsecure,
            fingerprint: profile.tlsSettings.fingerprint,
            alpn: profile.tlsSettings.alpn
        ))
    }
}
