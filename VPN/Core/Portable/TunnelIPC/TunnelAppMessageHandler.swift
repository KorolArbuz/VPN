//
//  TunnelAppMessageHandler.swift
//  VPN
//
//  Read-only PacketTunnelExtension message router. The app-target copy exists
//  for deterministic unit tests; the extension target owns the real instance.
//

import Foundation

actor TunnelAppMessageHandler {
    private let telemetryStore: TunnelTelemetryStore
    private let snapshotStore: TunnelTelemetrySnapshotStore?
    private let keychainSentinelStore: (any TunnelKeychainSentinelStoring)?
    private let runtimeValidationLoader: (any RuntimeConfigurationValidationLoading)?
    private let xrayConfigurationValidator: (any XrayConfigurationValidating)?
    private let diagnosticProviderModeProvider: (any DiagnosticProviderModeProviding)?
    private let providerProcess: TunnelProviderProcessIdentity
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(
        telemetryStore: TunnelTelemetryStore = TunnelTelemetryStore(),
        snapshotStore: TunnelTelemetrySnapshotStore? = nil,
        keychainSentinelStore: (any TunnelKeychainSentinelStoring)? = nil,
        runtimeValidationLoader: (any RuntimeConfigurationValidationLoading)? = nil,
        xrayConfigurationValidator: (any XrayConfigurationValidating)? = nil,
        diagnosticProviderModeProvider: (any DiagnosticProviderModeProviding)? = nil,
        providerProcess: TunnelProviderProcessIdentity = .unknown
    ) {
        self.telemetryStore = telemetryStore
        self.snapshotStore = snapshotStore
        self.keychainSentinelStore = keychainSentinelStore
        self.runtimeValidationLoader = runtimeValidationLoader
        self.xrayConfigurationValidator = xrayConfigurationValidator
        self.diagnosticProviderModeProvider = diagnosticProviderModeProvider
        self.providerProcess = providerProcess
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    func handle(_ messageData: Data) async -> Data {
        let request: TunnelMessageRequest
        do {
            request = try decoder.decode(TunnelMessageRequest.self, from: messageData)
        } catch {
            return encodeFailure(requestID: TunnelMessageProtocol.invalidRequestID, code: .malformedRequest)
        }

        guard request.schemaVersion == TunnelMessageProtocol.schemaVersion else {
            return encodeFailure(requestID: request.requestID, code: .schemaMismatch)
        }

        let response: TunnelMessageResponse
        switch request.kind {
        case .ping:
            response = .success(
                request: request,
                payload: .pong(
                    TunnelPongSnapshot(
                        extensionProcessAlive: true,
                        schemaVersion: TunnelMessageProtocol.schemaVersion,
                        providerProcess: providerProcess
                    )
                )
            )
        case .getCapabilities:
            response = .success(request: request, payload: .capabilities(capabilitySnapshot()))
        case .getRuntimeSnapshot:
            let snapshot = await telemetryStore.runtimeSnapshot()
            await persistFallbackSnapshot(runtime: snapshot)
            response = .success(request: request, payload: .runtime(snapshot))
        case .getHealthSnapshot:
            response = .success(request: request, payload: .health(await telemetryStore.healthSnapshot()))
        case .getRecentEvents:
            response = .success(request: request, payload: .events(await telemetryStore.recentEvents()))
        case .verifyKeychainSentinel:
            #if DEBUG
            response = await keychainSentinelResponse(for: request)
            #else
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
            #endif
        case .validateRuntimeConfiguration:
            #if DEBUG
            response = await runtimeConfigurationValidationResponse(for: request)
            #else
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
            #endif
        case .validateXrayConfiguration:
            #if DEBUG
            response = await xrayConfigurationValidationResponse(for: request)
            #else
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
            #endif
        case .runXrayLifecycleSmokeTest:
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
        case .runXrayRemoteEgressProbe:
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
        case .probeActiveXrayEgress:
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
        case .runUDPControlProbe:
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
        case .runLibXrayPingProbe:
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
        case .getDiagnosticProviderMode:
            #if DEBUG
            response = await diagnosticProviderModeResponse(for: request)
            #else
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
            #endif
        case .unknown:
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
        }

        return encode(response)
    }

    private func capabilitySnapshot() -> TunnelCapabilitySnapshot {
        var snapshot = TunnelCapabilitySnapshot.current
        snapshot.providerProcess = providerProcess

        switch providerProcess {
        case .wireGuard:
            snapshot.supportedRequests.removeAll { kind in
                switch kind {
                case .validateRuntimeConfiguration,
                     .validateXrayConfiguration,
                     .runXrayLifecycleSmokeTest,
                     .runXrayRemoteEgressProbe,
                     .probeActiveXrayEgress,
                     .runUDPControlProbe,
                     .runLibXrayPingProbe:
                    return true
                default:
                    return false
                }
            }
            snapshot.supportsLiveTun2SocksStats = false
            snapshot.supportsXrayState = false
        case .xray:
            snapshot.supportsLiveTun2SocksStats = true
            snapshot.supportsXrayState = true
        case .unknown:
            snapshot.supportedRequests = []
            snapshot.supportsRuntimeSnapshot = false
            snapshot.supportsHealthSnapshot = false
            snapshot.supportsRecentEvents = false
            snapshot.supportsLiveTun2SocksStats = false
            snapshot.supportsXrayState = false
        }

        return snapshot
    }

    #if DEBUG
    private func keychainSentinelResponse(for request: TunnelMessageRequest) async -> TunnelMessageResponse {
        guard case .keychainSentinel(let payload)? = request.payload else {
            return .failure(requestID: request.requestID, code: .malformedRequest)
        }
        guard let keychainSentinelStore else {
            return .success(
                request: request,
                payload: .keychainSentinel(
                    TunnelKeychainSentinelResponse(
                        found: false,
                        correlationID: payload.correlationID,
                        diagnostic: TunnelKeychainSentinelDiagnostic(
                            stage: .extensionKeychainRead,
                            status: .failed,
                            category: .keychainUnavailable,
                            extensionRequestReached: true,
                            correlationIDPrefix: String(payload.correlationID.uuidString.prefix(8))
                        )
                    )
                )
            )
        }

        do {
            let found = try await keychainSentinelStore.verifySentinel(correlationID: payload.correlationID)
            let diagnostic = TunnelKeychainSentinelDiagnostic(
                stage: found ? .extensionKeychainRead : .extensionSentinelMissing,
                status: found ? .succeeded : .failed,
                category: found ? .none : .sentinelMissing,
                extensionRequestReached: true,
                correlationIDPrefix: String(payload.correlationID.uuidString.prefix(8))
            )
            return .success(
                request: request,
                payload: .keychainSentinel(
                    TunnelKeychainSentinelResponse(
                        found: found,
                        correlationID: payload.correlationID,
                        diagnostic: diagnostic
                    )
                )
            )
        } catch {
            let diagnostic = Self.keychainDiagnostic(error: error, correlationID: payload.correlationID)
            return .success(
                request: request,
                payload: .keychainSentinel(
                    TunnelKeychainSentinelResponse(
                        found: false,
                        correlationID: payload.correlationID,
                        diagnostic: diagnostic
                    )
                )
            )
        }
    }

    private static func keychainDiagnostic(
        error: any Error,
        correlationID: UUID
    ) -> TunnelKeychainSentinelDiagnostic {
        var diagnostic = TunnelKeychainSentinelDiagnostic(
            stage: .extensionKeychainRead,
            status: .failed,
            category: keychainDiagnosticCategory(for: error),
            extensionRequestReached: true,
            correlationIDPrefix: String(correlationID.uuidString.prefix(8))
        )
        if case CredentialStoreError.keychainFailed(let status) = error {
            diagnostic.osStatus = status
        }
        return diagnostic
    }

    private static func keychainDiagnosticCategory(for error: any Error) -> TunnelKeychainSentinelDiagnosticCategory {
        if let credentialError = error as? CredentialStoreError {
            switch credentialError {
            case .accessGroupUnavailable:
                return .accessGroupUnavailable
            case .invalidAccessGroup:
                return .invalidAccessGroup
            case .keychainFailed:
                return .keychainStatus
            case .encodingFailed, .migrationVerificationFailed:
                return .unknown
            }
        }
        return .unknown
    }

    private func runtimeConfigurationValidationResponse(for request: TunnelMessageRequest) async -> TunnelMessageResponse {
        guard case .runtimeConfigurationValidation(let payload)? = request.payload else {
            return .failure(requestID: request.requestID, code: .malformedRequest)
        }
        guard let runtimeValidationLoader else {
            return .success(
                request: request,
                payload: .runtimeConfigurationValidation(
                    .failure(
                        correlationID: payload.correlationID,
                        stage: .sharedRecord,
                        category: .sharedContainerUnavailable
                    )
                )
            )
        }
        let validation = await runtimeValidationLoader.validateRuntimeConfiguration(
            correlationID: payload.correlationID,
            expectedProfileID: payload.expectedProfileID,
            expectedRevisionToken: payload.expectedRevisionToken,
            requestGeneration: payload.requestGeneration
        )
        return .success(request: request, payload: .runtimeConfigurationValidation(validation))
    }

    private func xrayConfigurationValidationResponse(for request: TunnelMessageRequest) async -> TunnelMessageResponse {
        guard case .xrayConfigurationValidation(let payload)? = request.payload else {
            return .failure(requestID: request.requestID, code: .malformedRequest)
        }
        guard let xrayConfigurationValidator else {
            return .success(
                request: request,
                payload: .xrayConfigurationValidation(
                    .failure(
                        correlationID: payload.correlationID,
                        stage: .runtimeConfiguration,
                        category: .runtimeConfigurationInvalid
                    )
                )
            )
        }
        let validation = await xrayConfigurationValidator.validateXrayConfiguration(
            correlationID: payload.correlationID,
            expectedProfileID: payload.expectedProfileID,
            expectedRevisionToken: payload.expectedRevisionToken,
            requestGeneration: payload.requestGeneration
        )
        return .success(request: request, payload: .xrayConfigurationValidation(validation))
    }

    private func diagnosticProviderModeResponse(for request: TunnelMessageRequest) async -> TunnelMessageResponse {
        guard request.payload == nil else {
            return .failure(requestID: request.requestID, code: .malformedRequest)
        }
        let mode = await diagnosticProviderModeProvider?.diagnosticProviderMode() ?? .unknown
        return .success(
            request: request,
            payload: .diagnosticProviderMode(
                TunnelDiagnosticProviderModeResponse(
                    mode: mode,
                    providerProcess: providerProcess
                )
            )
        )
    }
    #endif

    private func persistFallbackSnapshot(runtime: TunnelRuntimeSnapshot) async {
        guard let snapshotStore else {
            return
        }

        let events = await telemetryStore.recentEvents()
        try? await snapshotStore.write(runtime: runtime, events: events)
    }

    private func encodeFailure(requestID: UUID, code: TunnelMessageErrorCode) -> Data {
        encode(.failure(requestID: requestID, code: code))
    }

    private func encode(_ response: TunnelMessageResponse) -> Data {
        (try? encoder.encode(response)) ?? Data()
    }
}
