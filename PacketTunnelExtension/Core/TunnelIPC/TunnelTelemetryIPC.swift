//
//  TunnelTelemetryIPC.swift
//  PacketTunnelExtension
//
//  Extension-local telemetry store and read-only app-message handler.
//

import Foundation

nonisolated enum TunnelTelemetryAppGroup {
    static let identifier = "group.su.24kvn.kvn-app"
}

actor TunnelTelemetrySnapshotStore {
    private let fileURL: URL
    private let encoder = JSONEncoder()
    private let maximumEventCount: Int

    init(fileURL: URL, maximumEventCount: Int = 32) {
        self.fileURL = fileURL
        self.maximumEventCount = max(1, maximumEventCount)
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
    }

    static func appGroupStore(fileManager: FileManager = .default) -> TunnelTelemetrySnapshotStore? {
        guard let containerURL = fileManager.containerURL(forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier) else {
            return nil
        }

        let fileURL = containerURL
            .appendingPathComponent("TunnelTelemetry", isDirectory: true)
            .appendingPathComponent("last-runtime-snapshot.json")
        return TunnelTelemetrySnapshotStore(fileURL: fileURL)
    }

    func write(runtime: TunnelRuntimeSnapshot, events: [TunnelEventSnapshot], now: Date = Date()) throws {
        let stored = TunnelStoredTelemetrySnapshot(
            schemaVersion: TunnelMessageProtocol.schemaVersion,
            generatedAt: now,
            runtime: runtime,
            events: Array(events.suffix(maximumEventCount))
        )
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(stored).write(to: fileURL, options: [.atomic])
    }
}

actor TunnelTelemetryStore {
    private let maximumEventCount: Int
    private var runtime: TunnelRuntimeSnapshot
    private var events: [TunnelEventSnapshot] = []

    init(initialRuntime: TunnelRuntimeSnapshot = .notRunning(), maximumEventCount: Int = 32) {
        self.runtime = initialRuntime
        self.maximumEventCount = max(1, maximumEventCount)
    }

    func runtimeSnapshot() -> TunnelRuntimeSnapshot {
        runtime
    }

    func healthSnapshot() -> TunnelHealthSnapshot {
        runtime.health
    }

    func recentEvents(limit: Int = 32) -> [TunnelEventSnapshot] {
        Array(events.suffix(max(0, min(limit, maximumEventCount))))
    }

    func markStopped(now: Date = Date()) {
        runtime = .notRunning(generatedAt: now)
        appendEvent(category: "stopped", state: .stopped, failure: nil, now: now)
    }

    func markDataPlaneStarting(
        protocolName: String? = nil,
        transportName: String? = nil,
        now: Date = Date()
    ) {
        runtime.runtimeGeneration += 1
        runtime.runtimeState = .starting
        runtime.backendKind = .xray
        runtime.protocolKind = TunnelProtocolKind(rawValue: protocolName ?? "") ?? .unknown
        runtime.transportKind = safeToken(transportName)
        runtime.startedAt = now
        runtime.lastStateChangeAt = now
        runtime.generatedAt = now
        runtime.origin = .packetTunnelExtension
        runtime.xrayState = .starting
        runtime.tun2SocksState = .notRunning
        runtime.networkSettingsState = .notRunning
        runtime.counters = .unavailable
        runtime.health = TunnelHealthSnapshot(
            state: .starting,
            generatedAt: now,
            origin: .packetTunnelExtension,
            lastSuccessfulTrafficAt: nil,
            lastFailure: runtime.lastFailure,
            isLive: true
        )
        appendEvent(category: "dataPlaneStarting", state: .starting, failure: nil, now: now)
    }

    func markTun2SocksStarted(now: Date = Date()) {
        runtime.tun2SocksState = .running
        updateGenerated(now)
        appendEvent(category: "tun2SocksStarted", state: .starting, failure: nil, now: now)
    }

    func markTun2SocksStopped(now: Date = Date()) {
        runtime.tun2SocksState = .stopped
        updateGenerated(now)
        appendEvent(category: "tun2SocksStopped", state: .stopping, failure: nil, now: now)
    }

    func markNetworkSettingsApplied(now: Date = Date()) {
        runtime.runtimeState = .networkSettingsApplied
        runtime.networkSettingsState = .running
        updateGenerated(now)
        appendEvent(category: "networkSettingsApplied", state: .networkSettingsApplied, failure: nil, now: now)
    }

    func markDataPlaneRunning(counters: TunnelTrafficCounters, now: Date = Date()) {
        runtime.runtimeState = .running
        runtime.xrayState = .running
        runtime.tun2SocksState = .running
        runtime.networkSettingsState = .running
        runtime.counters = counters
        runtime.health = TunnelHealthSnapshot(
            state: .healthy,
            generatedAt: now,
            origin: .packetTunnelExtension,
            lastSuccessfulTrafficAt: nil,
            lastFailure: runtime.lastFailure,
            isLive: true
        )
        updateGenerated(now)
        appendEvent(category: "dataPlaneRunning", state: .running, failure: nil, now: now)
    }

    func markDataPlaneFailure(category: TunnelFailureCategory, now: Date = Date()) {
        let failure = TunnelFailureSnapshot(category: category, occurredAt: now, errorDomain: nil, errorCode: nil)
        runtime.runtimeState = .failed
        runtime.lastFailure = failure
        runtime.health = TunnelHealthSnapshot(
            state: .failed,
            generatedAt: now,
            origin: .packetTunnelExtension,
            lastSuccessfulTrafficAt: runtime.lastSuccessfulTrafficAt,
            lastFailure: failure,
            isLive: true
        )
        updateGenerated(now)
        appendEvent(category: "dataPlaneFailure", state: .failed, failure: category, now: now)
    }

    func markXrayLifecycleEvent(
        category: String,
        state: TunnelRuntimeState,
        failure: TunnelFailureCategory? = nil,
        now: Date = Date()
    ) {
        appendEvent(category: category, state: state, failure: failure, now: now)
    }

    private func updateGenerated(_ now: Date) {
        runtime.lastStateChangeAt = now
        runtime.generatedAt = now
        if let startedAt = runtime.startedAt {
            runtime.uptimeSeconds = max(0, now.timeIntervalSince(startedAt))
        }
        runtime.health.generatedAt = now
    }

    private func safeToken(_ value: String?) -> String? {
        guard let value else {
            return nil
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false, trimmed.count <= 64 else {
            return nil
        }
        let lowercased = trimmed.lowercased()
        guard lowercased.contains("://") == false,
              lowercased.contains("@") == false,
              lowercased.contains("password") == false,
              lowercased.contains("private") == false,
              lowercased.contains("token") == false,
              lowercased.contains("credential") == false else {
            return nil
        }
        return trimmed
    }

    private func appendEvent(category: String, state: TunnelRuntimeState, failure: TunnelFailureCategory?, now: Date) {
        events.append(TunnelEventSnapshot(generatedAt: now, category: category, runtimeState: state, failureCategory: failure))
        if events.count > maximumEventCount {
            events.removeFirst(events.count - maximumEventCount)
        }
    }
}

actor TunnelAppMessageHandler {
    private let telemetryStore: TunnelTelemetryStore
    private let snapshotStore: TunnelTelemetrySnapshotStore?
    private let keychainSentinelReader: (any TunnelKeychainSentinelReading)?
    private let runtimeValidationLoader: (any RuntimeConfigurationValidationLoading)?
    private let xrayConfigurationValidator: (any XrayConfigurationValidating)?
    private let xrayLifecycleSmokeTester: (any XrayLifecycleSmokeTesting)?
    private let xrayRemoteEgressProbe: (any XrayRemoteEgressProbing)?
    private let udpControlProbe: (any PacketTunnelUDPControlProbing)?
    private let libXrayPingProbe: (any LibXrayPingProbing)?
    private let diagnosticProviderModeProvider: (any DiagnosticProviderModeProviding)?
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init(
        telemetryStore: TunnelTelemetryStore = TunnelTelemetryStore(),
        snapshotStore: TunnelTelemetrySnapshotStore? = nil,
        keychainSentinelReader: (any TunnelKeychainSentinelReading)? = nil,
        runtimeValidationLoader: (any RuntimeConfigurationValidationLoading)? = nil,
        xrayConfigurationValidator: (any XrayConfigurationValidating)? = nil,
        xrayLifecycleSmokeTester: (any XrayLifecycleSmokeTesting)? = nil,
        xrayRemoteEgressProbe: (any XrayRemoteEgressProbing)? = nil,
        udpControlProbe: (any PacketTunnelUDPControlProbing)? = nil,
        libXrayPingProbe: (any LibXrayPingProbing)? = nil,
        diagnosticProviderModeProvider: (any DiagnosticProviderModeProviding)? = nil
    ) {
        self.telemetryStore = telemetryStore
        self.snapshotStore = snapshotStore
        self.keychainSentinelReader = keychainSentinelReader
        self.runtimeValidationLoader = runtimeValidationLoader
        self.xrayConfigurationValidator = xrayConfigurationValidator
        self.xrayLifecycleSmokeTester = xrayLifecycleSmokeTester
        self.xrayRemoteEgressProbe = xrayRemoteEgressProbe
        self.udpControlProbe = udpControlProbe
        self.libXrayPingProbe = libXrayPingProbe
        self.diagnosticProviderModeProvider = diagnosticProviderModeProvider
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
                payload: .pong(TunnelPongSnapshot(extensionProcessAlive: true, schemaVersion: TunnelMessageProtocol.schemaVersion))
            )
        case .getCapabilities:
            response = .success(request: request, payload: .capabilities(.current))
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
            #if DEBUG
            response = await xrayLifecycleSmokeTestResponse(for: request)
            #else
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
            #endif
        case .runXrayRemoteEgressProbe:
            #if DEBUG
            response = await xrayRemoteEgressProbeResponse(for: request, useActiveDataPlaneSession: false)
            #else
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
            #endif
        case .probeActiveXrayEgress:
            #if DEBUG
            response = await xrayRemoteEgressProbeResponse(for: request, useActiveDataPlaneSession: true)
            #else
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
            #endif
        case .runUDPControlProbe:
            #if DEBUG
            response = await udpControlProbeResponse(for: request)
            #else
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
            #endif
        case .runLibXrayPingProbe:
            #if DEBUG
            response = await libXrayPingProbeResponse(for: request)
            #else
            response = .failure(requestID: request.requestID, code: .unsupportedRequest)
            #endif
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

    #if DEBUG
    private func keychainSentinelResponse(for request: TunnelMessageRequest) async -> TunnelMessageResponse {
        guard case .keychainSentinel(let payload)? = request.payload else {
            return .failure(requestID: request.requestID, code: .malformedRequest)
        }
        guard let keychainSentinelReader else {
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

        let lookup = await keychainSentinelReader.lookupSentinel(correlationID: payload.correlationID)
        return .success(
            request: request,
            payload: .keychainSentinel(
                TunnelKeychainSentinelResponse(
                    found: lookup.found,
                    correlationID: payload.correlationID,
                    diagnostic: lookup.diagnostic
                )
            )
        )
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

    private func xrayLifecycleSmokeTestResponse(for request: TunnelMessageRequest) async -> TunnelMessageResponse {
        guard case .xrayLifecycleSmokeTest(let payload)? = request.payload else {
            return .failure(requestID: request.requestID, code: .malformedRequest)
        }
        guard let xrayLifecycleSmokeTester else {
            return .success(
                request: request,
                payload: .xrayLifecycleSmokeTest(
                    .failure(
                        correlationID: payload.correlationID,
                        stage: .runtimeConfiguration,
                        category: .runtimeConfigurationInvalid
                    )
                )
            )
        }
        let validation = await xrayLifecycleSmokeTester.runXrayLifecycleSmokeTest(
            correlationID: payload.correlationID,
            expectedProfileID: payload.expectedProfileID,
            expectedRevisionToken: payload.expectedRevisionToken,
            requestGeneration: payload.requestGeneration
        )
        return .success(request: request, payload: .xrayLifecycleSmokeTest(validation))
    }

    private func xrayRemoteEgressProbeResponse(
        for request: TunnelMessageRequest,
        useActiveDataPlaneSession: Bool
    ) async -> TunnelMessageResponse {
        guard case .xrayRemoteEgressProbe(let payload)? = request.payload else {
            return .failure(requestID: request.requestID, code: .malformedRequest)
        }
        guard let xrayRemoteEgressProbe else {
            return .success(
                request: request,
                payload: .xrayRemoteEgressProbe(
                    .failure(
                        correlationID: payload.correlationID,
                        stage: .runtimeConfiguration,
                        category: .providerUnavailable
                    )
                )
            )
        }
        let validation: TunnelXrayRemoteEgressProbeResponse
        if useActiveDataPlaneSession {
            validation = await xrayRemoteEgressProbe.probeActiveXrayEgress(
                correlationID: payload.correlationID,
                expectedProfileID: payload.expectedProfileID,
                expectedRevisionToken: payload.expectedRevisionToken,
                requestGeneration: payload.requestGeneration
            )
        } else {
            validation = await xrayRemoteEgressProbe.runXrayRemoteEgressProbe(
                correlationID: payload.correlationID,
                expectedProfileID: payload.expectedProfileID,
                expectedRevisionToken: payload.expectedRevisionToken,
                requestGeneration: payload.requestGeneration
            )
        }
        return .success(request: request, payload: .xrayRemoteEgressProbe(validation))
    }

    private func udpControlProbeResponse(for request: TunnelMessageRequest) async -> TunnelMessageResponse {
        guard case .udpControlProbe(let payload)? = request.payload else {
            return .failure(requestID: request.requestID, code: .malformedRequest)
        }
        guard let udpControlProbe else {
            return .success(
                request: request,
                payload: .udpControlProbe(
                    .failure(
                        correlationID: payload.correlationID,
                        category: .providerUnavailable
                    )
                )
            )
        }
        let validation = await udpControlProbe.runUDPControlProbe(
            correlationID: payload.correlationID,
            requestGeneration: payload.requestGeneration
        )
        return .success(request: request, payload: .udpControlProbe(validation))
    }

    private func libXrayPingProbeResponse(for request: TunnelMessageRequest) async -> TunnelMessageResponse {
        guard case .libXrayPingProbe(let payload)? = request.payload else {
            return .failure(requestID: request.requestID, code: .malformedRequest)
        }
        guard let libXrayPingProbe else {
            return .success(
                request: request,
                payload: .libXrayPingProbe(
                    .failure(
                        correlationID: payload.correlationID,
                        stage: .preStartState,
                        category: .providerUnavailable
                    )
                )
            )
        }
        let validation = await libXrayPingProbe.runLibXrayPingProbe(
            correlationID: payload.correlationID,
            expectedProfileID: payload.expectedProfileID,
            expectedRevisionToken: payload.expectedRevisionToken,
            requestGeneration: payload.requestGeneration
        )
        return .success(request: request, payload: .libXrayPingProbe(validation))
    }

    private func diagnosticProviderModeResponse(for request: TunnelMessageRequest) async -> TunnelMessageResponse {
        guard request.payload == nil else {
            return .failure(requestID: request.requestID, code: .malformedRequest)
        }
        let mode = await diagnosticProviderModeProvider?.diagnosticProviderMode() ?? .unknown
        return .success(
            request: request,
            payload: .diagnosticProviderMode(TunnelDiagnosticProviderModeResponse(mode: mode))
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
