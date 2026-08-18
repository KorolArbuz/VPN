//
//  NetworkEndpointProber.swift
//  VPN
//
//  Real app-process transport probes built on Network.framework. These probes
//  measure connection readiness, not ICMP ping and not packet-level loss.
//

import Foundation
import Network
import Security

nonisolated protocol EndpointProbing: Sendable {
    func probe(_ request: TransportProbeRequest, attemptIndex: Int, timeout: Duration) async -> TransportProbeAttempt
}

nonisolated final class NetworkEndpointProber: EndpointProbing, @unchecked Sendable {
    private let queue = DispatchQueue(label: "su.24kvn.transport-probe", qos: .utility)

    init() {}

    func probe(_ request: TransportProbeRequest, attemptIndex: Int, timeout: Duration) async -> TransportProbeAttempt {
        let startedAt = Date()
        let parameters = parameters(for: request)
        let connection = NWConnection(
            host: NWEndpoint.Host(request.host),
            port: NWEndpoint.Port(rawValue: request.port) ?? .https,
            using: parameters
        )
        let box = ProbeCompletionBox()

        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        let finishedAt = Date()
                        let latency = finishedAt.timeIntervalSince(startedAt) * 1_000
                        let handshake = request.kind == .tlsHandshake ? latency : nil
                        box.resume(
                            continuation,
                            with: TransportProbeAttempt(
                                candidateID: request.candidateID,
                                attemptIndex: attemptIndex,
                                startedAt: startedAt,
                                finishedAt: finishedAt,
                                connectLatencyMs: latency,
                                handshakeLatencyMs: handshake,
                                failure: nil
                            ),
                            cleanup: {
                                connection.cancel()
                            }
                        )
                    case .failed(let error):
                        box.resume(
                            continuation,
                            with: self.failedAttempt(request: request, attemptIndex: attemptIndex, startedAt: startedAt, error: error),
                            cleanup: {
                                connection.cancel()
                            }
                        )
                    case .waiting(let error):
                        box.resume(
                            continuation,
                            with: self.failedAttempt(request: request, attemptIndex: attemptIndex, startedAt: startedAt, error: error),
                            cleanup: {
                                connection.cancel()
                            }
                        )
                    case .cancelled:
                        box.resume(
                            continuation,
                            with: self.failedAttempt(request: request, attemptIndex: attemptIndex, startedAt: startedAt, failure: .cancelled),
                            cleanup: {}
                        )
                    case .setup, .preparing:
                        break
                    @unknown default:
                        break
                    }
                }

                connection.start(queue: queue)

                Task {
                    do {
                        try await Task.sleep(for: timeout)
                        box.resume(
                            continuation,
                            with: self.failedAttempt(request: request, attemptIndex: attemptIndex, startedAt: startedAt, failure: .connectionTimedOut),
                            cleanup: {
                                connection.cancel()
                            }
                        )
                    } catch {
                        box.resume(
                            continuation,
                            with: self.failedAttempt(request: request, attemptIndex: attemptIndex, startedAt: startedAt, failure: .cancelled),
                            cleanup: {
                                connection.cancel()
                            }
                        )
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private func parameters(for request: TransportProbeRequest) -> NWParameters {
        switch request.kind {
        case .tcpConnect:
            return .tcp
        case .tlsHandshake:
            let tls = NWProtocolTLS.Options()
            if let serverName = request.serverName {
                serverName.withCString { pointer in
                    sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, pointer)
                }
            }
            return NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        }
    }

    private func failedAttempt(
        request: TransportProbeRequest,
        attemptIndex: Int,
        startedAt: Date,
        error: NWError
    ) -> TransportProbeAttempt {
        failedAttempt(
            request: request,
            attemptIndex: attemptIndex,
            startedAt: startedAt,
            failure: failure(from: error, request: request)
        )
    }

    private func failedAttempt(
        request: TransportProbeRequest,
        attemptIndex: Int,
        startedAt: Date,
        failure: TransportProbeFailure
    ) -> TransportProbeAttempt {
        TransportProbeAttempt(
            candidateID: request.candidateID,
            attemptIndex: attemptIndex,
            startedAt: startedAt,
            finishedAt: Date(),
            connectLatencyMs: nil,
            handshakeLatencyMs: nil,
            failure: failure
        )
    }

    private func failure(from error: NWError, request: TransportProbeRequest) -> TransportProbeFailure {
        switch error {
        case .dns:
            return .dnsResolutionFailed
        case .tls:
            return .tlsHandshakeFailed
        case .posix(let code):
            switch code {
            case .ETIMEDOUT:
                return .connectionTimedOut
            case .ECONNREFUSED:
                return .connectionRefused
            default:
                return request.kind == .tlsHandshake ? .tlsHandshakeFailed : .connectionFailed
            }
        default:
            return request.kind == .tlsHandshake ? .tlsHandshakeFailed : .connectionFailed
        }
    }
}

private nonisolated final class ProbeCompletionBox: @unchecked Sendable {
    private let lock = NSLock()
    private var didResume = false

    func resume(
        _ continuation: CheckedContinuation<TransportProbeAttempt, Never>,
        with attempt: TransportProbeAttempt,
        cleanup: () -> Void
    ) {
        lock.lock()
        let shouldResume = didResume == false
        if shouldResume {
            didResume = true
        }
        lock.unlock()

        guard shouldResume else {
            return
        }

        cleanup()
        continuation.resume(returning: attempt)
    }
}
