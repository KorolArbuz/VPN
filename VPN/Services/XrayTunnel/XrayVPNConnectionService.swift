//
//  XrayVPNConnectionService.swift
//  VPN
//
//  Production connection adapter for the isolated Xray/Tun2Socks provider.
//

import Foundation

nonisolated protocol XrayDataPlaneServicing: Sendable {
    func start(profile: VPNProfile) async throws -> TunnelXrayLifecycleSmokeTestResponse
    func stop() async throws -> TunnelXrayLifecycleSmokeTestResponse
}

extension DataPlanePacketTunnelService: XrayDataPlaneServicing {}

nonisolated enum XrayTunnelConnectionError: Error, Equatable, Sendable {
    case unsupportedProtocol(VPNProtocol)
    case sharedRuntimeStoreUnavailable
    case startupFailed
    case stopFailed
}

actor XrayVPNConnectionService: VPNConnectionManaging {
    private let service: (any XrayDataPlaneServicing)?
    private var state: VPNConnectionState = .disconnected
    private var continuations: [UUID: AsyncStream<VPNConnectionState>.Continuation] = [:]

    init(service: (any XrayDataPlaneServicing)? = DataPlanePacketTunnelService.appGroupService()) {
        self.service = service
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
                    Task { await self.removeContinuation(id: id) }
                }
            }
        }
    }

    nonisolated func routesTrafficThroughProductionCore(using profile: VPNProfile) -> Bool {
        PacketTunnelProviderRouting.provider(for: profile.protocolType) == .xray
    }

    func connect(using profile: VPNProfile) async throws {
        guard PacketTunnelProviderRouting.provider(for: profile.protocolType) == .xray else {
            throw XrayTunnelConnectionError.unsupportedProtocol(profile.protocolType)
        }
        guard let service else {
            throw XrayTunnelConnectionError.sharedRuntimeStoreUnavailable
        }

        publish(.connecting)
        do {
            let response = try await service.start(profile: profile)
            try Task.checkCancellation()
            guard response.success else {
                throw XrayTunnelConnectionError.startupFailed
            }

            publish(.connected)
        } catch {
            if error is CancellationError {
                _ = try? await service.stop()
                publish(.disconnected)
            } else {
                publish(.failed)
            }
            throw error
        }
    }

    func disconnect() async {
        guard let service else {
            publish(.disconnected)
            return
        }
        guard state != .disconnected else {
            return
        }

        publish(.disconnecting)
        do {
            let response = try await service.stop()
            publish(response.success ? .disconnected : .failed)
        } catch {
            publish(.failed)
        }
    }

    private func addContinuation(
        _ continuation: AsyncStream<VPNConnectionState>.Continuation,
        id: UUID
    ) {
        continuations[id] = continuation
        continuation.yield(state)
    }

    private func removeContinuation(id: UUID) {
        continuations[id] = nil
    }

    private func publish(_ newState: VPNConnectionState) {
        guard state != newState else {
            return
        }
        state = newState
        continuations.values.forEach { $0.yield(newState) }
    }
}
