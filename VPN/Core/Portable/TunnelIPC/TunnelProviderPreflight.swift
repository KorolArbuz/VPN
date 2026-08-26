//
//  TunnelProviderPreflight.swift
//  VPN
//

import Foundation
import NetworkExtension
import OSLog

nonisolated enum TunnelProviderPreflightState: String, Equatable, Sendable {
    case notRequested
    case managerNotFound
    case managerLoadFailed
    case sessionUnavailable
    case providerMessageSendFailed
    case providerResponseTimeout
    case providerResponseMalformed
    case startupFailedBeforeIPCReachable
    case systemSessionDisconnected
    case providerAlive
}

nonisolated struct TunnelProviderPreflightResult: Equatable, Sendable {
    var state: TunnelProviderPreflightState
    var sessionStatus: TunnelProviderSessionStatus
    var errorDomain: String?
    var errorCode: Int?
}

nonisolated final class TunnelProviderPreflightService: @unchecked Sendable {
    private let providerBundleIdentifier: String
    private let messenger: NetworkExtensionTunnelMessenger
    private let logger = Logger(subsystem: "su.24kvn.kvn-app", category: "Tunnel.IPC")

    init(
        providerBundleIdentifier: String = "su.24kvn.kvn-app.PacketTunnelExtension",
        messenger: NetworkExtensionTunnelMessenger = NetworkExtensionTunnelMessenger()
    ) {
        self.providerBundleIdentifier = providerBundleIdentifier
        self.messenger = messenger
    }

    func run() async -> TunnelProviderPreflightResult {
        let managers: [NETunnelProviderManager]
        do {
            managers = try await loadManagers()
        } catch {
            return result(.managerLoadFailed, status: .unknown, error: error)
        }

        let matching = await MainActor.run {
            managers.filter { manager in
                (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == providerBundleIdentifier
            }
        }
        guard let manager = matching.first else {
            return result(.managerNotFound, status: .invalid)
        }
        guard matching.count == 1 else {
            return result(.managerLoadFailed, status: .unknown)
        }
        guard await MainActor.run(body: { manager.connection is NETunnelProviderSession }) else {
            return result(.sessionUnavailable, status: .invalid)
        }

        let sessionStatus = await messenger.status()
        do {
            let response = try await messenger.sendDiagnostic(TunnelMessageRequest(kind: .ping))
            guard case .pong(let pong) = response.payload,
                  pong.extensionProcessAlive,
                  pong.schemaVersion == TunnelMessageProtocol.schemaVersion else {
                return result(.providerResponseMalformed, status: sessionStatus)
            }
            return result(.providerAlive, status: sessionStatus)
        } catch let error as TunnelMessageErrorCode {
            switch error {
            case .timeout:
                return result(.providerResponseTimeout, status: sessionStatus, error: error)
            case .invalidResponse, .providerResponseMissing, .requestIDMismatch, .schemaMismatch:
                return result(.providerResponseMalformed, status: sessionStatus, error: error)
            case .providerUnavailable:
                return result(.sessionUnavailable, status: sessionStatus, error: error)
            case .providerStatusNotConnected:
                return result(.systemSessionDisconnected, status: sessionStatus, error: error)
            case .malformedRequest, .unsupportedRequest, .payloadTooLarge, .keychainUnavailable, .unknown:
                return result(.providerMessageSendFailed, status: sessionStatus, error: error)
            }
        } catch {
            let state: TunnelProviderPreflightState = sessionStatus == .disconnected || sessionStatus == .invalid
                ? .startupFailedBeforeIPCReachable
                : .providerMessageSendFailed
            return result(state, status: sessionStatus, error: error)
        }
    }

    private func loadManagers() async throws -> [NETunnelProviderManager] {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<[NETunnelProviderManager], any Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }
    }

    private func result(
        _ state: TunnelProviderPreflightState,
        status: TunnelProviderSessionStatus,
        error: (any Error)? = nil
    ) -> TunnelProviderPreflightResult {
        let nsError = error.map { $0 as NSError }
        logger.notice(
            "provider preflight state=\(state.rawValue, privacy: .public) status=\(status.diagnosticValue, privacy: .public) error=\(nsError?.domain ?? "-", privacy: .public)/\(nsError?.code ?? 0, privacy: .public)"
        )
        return TunnelProviderPreflightResult(
            state: state,
            sessionStatus: status,
            errorDomain: nsError?.domain,
            errorCode: nsError?.code
        )
    }
}
