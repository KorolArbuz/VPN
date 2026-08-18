//
//  TunnelMessageModels.swift
//  PacketTunnelExtension
//
//  Versioned, read-only app <-> extension telemetry contracts. These DTOs
//  intentionally contain no credentials, raw VPN URIs, subscription URLs, or
//  full backend configuration.
//

import Foundation

nonisolated enum TunnelMessageProtocol {
    static let schemaVersion: UInt32 = 1
    static let maximumResponseBytes = 256 * 1_024
    static let invalidRequestID = UUID(uuidString: "00000000-0000-0000-0000-000000000000") ?? UUID()
}

nonisolated enum TunnelMessageKind: Equatable, Codable, Sendable {
    case ping
    case getCapabilities
    case getRuntimeSnapshot
    case getHealthSnapshot
    case getRecentEvents
    case verifyKeychainSentinel
    case validateRuntimeConfiguration
    case validateXrayConfiguration
    case runXrayLifecycleSmokeTest
    case runXrayRemoteEgressProbe
    case probeActiveXrayEgress
    case runUDPControlProbe
    case runLibXrayPingProbe
    case getDiagnosticProviderMode
    case unknown(String)

    static var allSupportedCases: [TunnelMessageKind] {
        var cases: [TunnelMessageKind] = [
            .ping,
            .getCapabilities,
            .getRuntimeSnapshot,
            .getHealthSnapshot,
            .getRecentEvents
        ]
        #if DEBUG
        cases.append(.verifyKeychainSentinel)
        cases.append(.validateRuntimeConfiguration)
        cases.append(.validateXrayConfiguration)
        cases.append(.runXrayLifecycleSmokeTest)
        cases.append(.runXrayRemoteEgressProbe)
        cases.append(.probeActiveXrayEgress)
        cases.append(.runUDPControlProbe)
        cases.append(.runLibXrayPingProbe)
        cases.append(.getDiagnosticProviderMode)
        #endif
        return cases
    }

    var rawValue: String {
        switch self {
        case .ping: "ping"
        case .getCapabilities: "getCapabilities"
        case .getRuntimeSnapshot: "getRuntimeSnapshot"
        case .getHealthSnapshot: "getHealthSnapshot"
        case .getRecentEvents: "getRecentEvents"
        case .verifyKeychainSentinel: "verifyKeychainSentinel"
        case .validateRuntimeConfiguration: "validateRuntimeConfiguration"
        case .validateXrayConfiguration: "validateXrayConfiguration"
        case .runXrayLifecycleSmokeTest: "runXrayLifecycleSmokeTest"
        case .runXrayRemoteEgressProbe: "runXrayRemoteEgressProbe"
        case .probeActiveXrayEgress: "probeActiveXrayEgress"
        case .runUDPControlProbe: "runUDPControlProbe"
        case .runLibXrayPingProbe: "runLibXrayPingProbe"
        case .getDiagnosticProviderMode: "getDiagnosticProviderMode"
        case .unknown(let value): value
        }
    }

    init(rawValue: String) {
        switch rawValue {
        case "ping": self = .ping
        case "getCapabilities": self = .getCapabilities
        case "getRuntimeSnapshot": self = .getRuntimeSnapshot
        case "getHealthSnapshot": self = .getHealthSnapshot
        case "getRecentEvents": self = .getRecentEvents
        case "verifyKeychainSentinel": self = .verifyKeychainSentinel
        case "validateRuntimeConfiguration": self = .validateRuntimeConfiguration
        case "validateXrayConfiguration": self = .validateXrayConfiguration
        case "runXrayLifecycleSmokeTest": self = .runXrayLifecycleSmokeTest
        case "runXrayRemoteEgressProbe": self = .runXrayRemoteEgressProbe
        case "probeActiveXrayEgress": self = .probeActiveXrayEgress
        case "runUDPControlProbe": self = .runUDPControlProbe
        case "runLibXrayPingProbe": self = .runLibXrayPingProbe
        case "getDiagnosticProviderMode": self = .getDiagnosticProviderMode
        default: self = .unknown(rawValue)
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self = TunnelMessageKind(rawValue: try container.decode(String.self))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

nonisolated struct TunnelMessageRequest: Codable, Equatable, Sendable {
    var schemaVersion: UInt32
    var requestID: UUID
    var kind: TunnelMessageKind
    var payload: TunnelMessageRequestPayload?

    init(
        schemaVersion: UInt32 = TunnelMessageProtocol.schemaVersion,
        requestID: UUID = UUID(),
        kind: TunnelMessageKind,
        payload: TunnelMessageRequestPayload? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.requestID = requestID
        self.kind = kind
        self.payload = payload
    }
}

nonisolated enum TunnelMessageRequestPayload: Codable, Equatable, Sendable {
    case keychainSentinel(TunnelKeychainSentinelRequest)
    case runtimeConfigurationValidation(TunnelRuntimeConfigurationValidationRequest)
    case xrayConfigurationValidation(TunnelXrayConfigurationValidationRequest)
    case xrayLifecycleSmokeTest(TunnelXrayLifecycleSmokeTestRequest)
    case xrayRemoteEgressProbe(TunnelXrayRemoteEgressProbeRequest)
    case udpControlProbe(TunnelUDPControlProbeRequest)
    case libXrayPingProbe(TunnelLibXrayPingProbeRequest)

    enum CodingKeys: String, CodingKey { case kind, data }
    enum Kind: String, Codable { case keychainSentinel, runtimeConfigurationValidation, xrayConfigurationValidation, xrayLifecycleSmokeTest, xrayRemoteEgressProbe, udpControlProbe, libXrayPingProbe }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .keychainSentinel(let data):
            try container.encode(Kind.keychainSentinel, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .runtimeConfigurationValidation(let data):
            try container.encode(Kind.runtimeConfigurationValidation, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .xrayConfigurationValidation(let data):
            try container.encode(Kind.xrayConfigurationValidation, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .xrayLifecycleSmokeTest(let data):
            try container.encode(Kind.xrayLifecycleSmokeTest, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .xrayRemoteEgressProbe(let data):
            try container.encode(Kind.xrayRemoteEgressProbe, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .udpControlProbe(let data):
            try container.encode(Kind.udpControlProbe, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .libXrayPingProbe(let data):
            try container.encode(Kind.libXrayPingProbe, forKey: .kind)
            try container.encode(data, forKey: .data)
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .kind) {
        case .keychainSentinel:
            self = try .keychainSentinel(container.decode(TunnelKeychainSentinelRequest.self, forKey: .data))
        case .runtimeConfigurationValidation:
            self = try .runtimeConfigurationValidation(container.decode(TunnelRuntimeConfigurationValidationRequest.self, forKey: .data))
        case .xrayConfigurationValidation:
            self = try .xrayConfigurationValidation(container.decode(TunnelXrayConfigurationValidationRequest.self, forKey: .data))
        case .xrayLifecycleSmokeTest:
            self = try .xrayLifecycleSmokeTest(container.decode(TunnelXrayLifecycleSmokeTestRequest.self, forKey: .data))
        case .xrayRemoteEgressProbe:
            self = try .xrayRemoteEgressProbe(container.decode(TunnelXrayRemoteEgressProbeRequest.self, forKey: .data))
        case .udpControlProbe:
            self = try .udpControlProbe(container.decode(TunnelUDPControlProbeRequest.self, forKey: .data))
        case .libXrayPingProbe:
            self = try .libXrayPingProbe(container.decode(TunnelLibXrayPingProbeRequest.self, forKey: .data))
        }
    }
}

nonisolated struct TunnelMessageResponse: Codable, Sendable {
    var schemaVersion: UInt32
    var requestID: UUID
    var success: Bool
    var generatedAt: Date
    var payload: TunnelMessagePayload?
    var error: TunnelMessageFailure?

    static func success(request: TunnelMessageRequest, payload: TunnelMessagePayload, generatedAt: Date = Date()) -> TunnelMessageResponse {
        TunnelMessageResponse(
            schemaVersion: TunnelMessageProtocol.schemaVersion,
            requestID: request.requestID,
            success: true,
            generatedAt: generatedAt,
            payload: payload,
            error: nil
        )
    }

    static func failure(requestID: UUID, code: TunnelMessageErrorCode, generatedAt: Date = Date()) -> TunnelMessageResponse {
        TunnelMessageResponse(
            schemaVersion: TunnelMessageProtocol.schemaVersion,
            requestID: requestID,
            success: false,
            generatedAt: generatedAt,
            payload: nil,
            error: TunnelMessageFailure(code: code)
        )
    }
}

nonisolated enum TunnelMessagePayload: Codable, Sendable {
    case pong(TunnelPongSnapshot)
    case capabilities(TunnelCapabilitySnapshot)
    case runtime(TunnelRuntimeSnapshot)
    case health(TunnelHealthSnapshot)
    case events([TunnelEventSnapshot])
    case keychainSentinel(TunnelKeychainSentinelResponse)
    case runtimeConfigurationValidation(TunnelRuntimeConfigurationValidationResponse)
    case xrayConfigurationValidation(TunnelXrayConfigurationValidationResponse)
    case xrayLifecycleSmokeTest(TunnelXrayLifecycleSmokeTestResponse)
    case xrayRemoteEgressProbe(TunnelXrayRemoteEgressProbeResponse)
    case udpControlProbe(TunnelUDPControlProbeResponse)
    case libXrayPingProbe(TunnelLibXrayPingProbeResponse)
    case diagnosticProviderMode(TunnelDiagnosticProviderModeResponse)

    enum CodingKeys: String, CodingKey { case kind, data }
    enum Kind: String, Codable { case pong, capabilities, runtime, health, events, keychainSentinel, runtimeConfigurationValidation, xrayConfigurationValidation, xrayLifecycleSmokeTest, xrayRemoteEgressProbe, udpControlProbe, libXrayPingProbe, diagnosticProviderMode }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .pong(let data):
            try container.encode(Kind.pong, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .capabilities(let data):
            try container.encode(Kind.capabilities, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .runtime(let data):
            try container.encode(Kind.runtime, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .health(let data):
            try container.encode(Kind.health, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .events(let data):
            try container.encode(Kind.events, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .keychainSentinel(let data):
            try container.encode(Kind.keychainSentinel, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .runtimeConfigurationValidation(let data):
            try container.encode(Kind.runtimeConfigurationValidation, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .xrayConfigurationValidation(let data):
            try container.encode(Kind.xrayConfigurationValidation, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .xrayLifecycleSmokeTest(let data):
            try container.encode(Kind.xrayLifecycleSmokeTest, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .xrayRemoteEgressProbe(let data):
            try container.encode(Kind.xrayRemoteEgressProbe, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .udpControlProbe(let data):
            try container.encode(Kind.udpControlProbe, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .libXrayPingProbe(let data):
            try container.encode(Kind.libXrayPingProbe, forKey: .kind)
            try container.encode(data, forKey: .data)
        case .diagnosticProviderMode(let data):
            try container.encode(Kind.diagnosticProviderMode, forKey: .kind)
            try container.encode(data, forKey: .data)
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .kind) {
        case .pong:
            self = try .pong(container.decode(TunnelPongSnapshot.self, forKey: .data))
        case .capabilities:
            self = try .capabilities(container.decode(TunnelCapabilitySnapshot.self, forKey: .data))
        case .runtime:
            self = try .runtime(container.decode(TunnelRuntimeSnapshot.self, forKey: .data))
        case .health:
            self = try .health(container.decode(TunnelHealthSnapshot.self, forKey: .data))
        case .events:
            self = try .events(container.decode([TunnelEventSnapshot].self, forKey: .data))
        case .keychainSentinel:
            self = try .keychainSentinel(container.decode(TunnelKeychainSentinelResponse.self, forKey: .data))
        case .runtimeConfigurationValidation:
            self = try .runtimeConfigurationValidation(container.decode(TunnelRuntimeConfigurationValidationResponse.self, forKey: .data))
        case .xrayConfigurationValidation:
            self = try .xrayConfigurationValidation(container.decode(TunnelXrayConfigurationValidationResponse.self, forKey: .data))
        case .xrayLifecycleSmokeTest:
            self = try .xrayLifecycleSmokeTest(container.decode(TunnelXrayLifecycleSmokeTestResponse.self, forKey: .data))
        case .xrayRemoteEgressProbe:
            self = try .xrayRemoteEgressProbe(container.decode(TunnelXrayRemoteEgressProbeResponse.self, forKey: .data))
        case .udpControlProbe:
            self = try .udpControlProbe(container.decode(TunnelUDPControlProbeResponse.self, forKey: .data))
        case .libXrayPingProbe:
            self = try .libXrayPingProbe(container.decode(TunnelLibXrayPingProbeResponse.self, forKey: .data))
        case .diagnosticProviderMode:
            self = try .diagnosticProviderMode(container.decode(TunnelDiagnosticProviderModeResponse.self, forKey: .data))
        }
    }
}

nonisolated enum TunnelDiagnosticProviderMode: String, Codable, Equatable, Sendable {
    case idle
    case runtimeOnly
    case dataPlane
    case libXrayPingOnly
    case lifecycleSmoke
    case unknown
}

nonisolated struct TunnelDiagnosticProviderModeResponse: Codable, Equatable, Sendable {
    var mode: TunnelDiagnosticProviderMode

    init(mode: TunnelDiagnosticProviderMode) {
        self.mode = mode
    }
}

protocol DiagnosticProviderModeProviding: Sendable {
    func diagnosticProviderMode() async -> TunnelDiagnosticProviderMode
}

nonisolated enum TunnelMessageErrorCode: String, Codable, Error, Equatable, Sendable {
    case malformedRequest
    case unsupportedRequest
    case schemaMismatch
    case providerUnavailable
    case providerResponseMissing
    case providerStatusNotConnected
    case timeout
    case payloadTooLarge
    case requestIDMismatch
    case invalidResponse
    case keychainUnavailable
    case unknown
}

nonisolated struct TunnelMessageFailure: Codable, Equatable, Sendable {
    var code: TunnelMessageErrorCode
}

nonisolated struct TunnelPongSnapshot: Codable, Equatable, Sendable {
    var extensionProcessAlive: Bool
    var schemaVersion: UInt32
}

nonisolated struct TunnelKeychainSentinelRequest: Codable, Equatable, Sendable {
    var correlationID: UUID
    var diagnosticPurpose: String

    init(
        correlationID: UUID,
        diagnosticPurpose: String = "sharedKeychainSentinel"
    ) {
        self.correlationID = correlationID
        self.diagnosticPurpose = diagnosticPurpose
    }
}

nonisolated struct TunnelKeychainSentinelResponse: Codable, Equatable, Sendable {
    var found: Bool
    var correlationID: UUID
    var diagnostic: TunnelKeychainSentinelDiagnostic?

    init(
        found: Bool,
        correlationID: UUID,
        diagnostic: TunnelKeychainSentinelDiagnostic? = nil
    ) {
        self.found = found
        self.correlationID = correlationID
        self.diagnostic = diagnostic
    }
}

nonisolated struct TunnelRuntimeConfigurationValidationRequest: Codable, Equatable, Sendable {
    var correlationID: UUID
    var expectedProfileID: UUID?
    var expectedRevisionToken: Int64?
    var requestGeneration: UInt64?

    init(
        correlationID: UUID,
        expectedProfileID: UUID? = nil,
        expectedRevisionToken: Int64? = nil,
        requestGeneration: UInt64? = nil
    ) {
        self.correlationID = correlationID
        self.expectedProfileID = expectedProfileID
        self.expectedRevisionToken = expectedRevisionToken
        self.requestGeneration = requestGeneration
    }
}

nonisolated enum TunnelRuntimeConfigurationValidationStage: String, Codable, Equatable, Sendable {
    case providerConfiguration
    case sharedRecord
    case credentialReference
    case credential
    case responseValidation
    case unknown
}

nonisolated enum TunnelRuntimeConfigurationValidationCategory: String, Codable, Equatable, Sendable {
    case none
    case missingProviderConfiguration
    case malformedProviderConfiguration
    case providerConfigurationUnknownKey
    case providerConfigurationMissingSchemaVersion
    case providerConfigurationWrongSchemaVersionType
    case providerConfigurationUnsupportedSchemaVersion
    case providerConfigurationMissingProfileID
    case providerConfigurationWrongProfileIDType
    case providerConfigurationMalformedProfileID
    case providerConfigurationMissingRecordRevision
    case providerConfigurationWrongRecordRevisionType
    case providerConfigurationInvalidRecordRevision
    case providerConfigurationPersistedMismatch
    case providerConfigurationContractMismatch
    case providerConfigurationStaleSession
    case unsupportedProviderSchema
    case missingProfileID
    case invalidProfileID
    case missingRevision
    case invalidRevision
    case profileRecordNotFound
    case profileRecordTooLarge
    case profileRecordMalformed
    case profileRecordCountExceeded
    case profileSchemaMismatch
    case profileIdentityMismatch
    case profileRevisionMismatch
    case profileDisabled
    case profileIncomplete
    case unsupportedProtocol
    case invalidEndpoint
    case unsupportedTransport
    case invalidTransportConfiguration
    case invalidXHTTPConfiguration
    case invalidXHTTPMode
    case invalidXHTTPPath
    case invalidXHTTPHost
    case invalidSecurityConfiguration
    case missingCredentialReference
    case malformedCredentialReference
    case credentialUnavailable
    case credentialMalformed
    case sharedContainerUnavailable
    case sharedKeychainConfigurationInvalid
    case writeFailed
    case deleteFailed
    case providerUnavailable
    case providerTimeout
    case invalidResponse
    case requestIDMismatch
    case correlationMismatch
    case unknown
}

nonisolated struct TunnelProviderConfigurationDiagnostic: Codable, Equatable, Sendable {
    var keyCount: Int?
    var keyNames: [String]?
    var valueTypesByKey: [String: String]?
    var parseSubreason: TunnelRuntimeConfigurationValidationCategory?
    var appPersistedMatchesIntent: Bool? = nil
    var extensionMatchesPersisted: Bool? = nil
    var extensionMatchesRequest: Bool? = nil
    var staleK1ConfigurationObserved: Bool? = nil
    var staleProfileConfigurationObserved: Bool? = nil
    var configurationPropagationTimedOut: Bool? = nil
}

nonisolated struct TunnelRuntimeConfigurationValidationDiagnostic: Codable, Equatable, Sendable {
    var stage: TunnelRuntimeConfigurationValidationStage
    var category: TunnelRuntimeConfigurationValidationCategory
    var extensionRequestReached: Bool?
    var correlationIDPrefix: String?
    var providerConfiguration: TunnelProviderConfigurationDiagnostic?

    init(
        stage: TunnelRuntimeConfigurationValidationStage,
        category: TunnelRuntimeConfigurationValidationCategory,
        extensionRequestReached: Bool?,
        correlationIDPrefix: String? = nil,
        providerConfiguration: TunnelProviderConfigurationDiagnostic? = nil
    ) {
        self.stage = stage
        self.category = category
        self.extensionRequestReached = extensionRequestReached
        self.correlationIDPrefix = correlationIDPrefix
        self.providerConfiguration = providerConfiguration
    }
}

nonisolated struct TunnelRuntimeConfigurationValidationResponse: Codable, Equatable, Sendable {
    var correlationID: UUID
    var success: Bool
    var providerConfigurationValid: Bool
    var profileFound: Bool
    var profileIdentityMatched: Bool
    var revisionMatched: Bool
    var schemaValid: Bool
    var profileEnabled: Bool
    var profileComplete: Bool
    var supportedProtocol: Bool
    var credentialReferenceValid: Bool
    var credentialFound: Bool
    var credentialFormatValid: Bool
    var protocolName: String?
    var transportName: String?
    var securityName: String?
    var diagnostic: TunnelRuntimeConfigurationValidationDiagnostic?

    static func success(
        correlationID: UUID,
        protocolName: String?,
        transportName: String? = nil,
        securityName: String? = nil
    ) -> TunnelRuntimeConfigurationValidationResponse {
        TunnelRuntimeConfigurationValidationResponse(
            correlationID: correlationID,
            success: true,
            providerConfigurationValid: true,
            profileFound: true,
            profileIdentityMatched: true,
            revisionMatched: true,
            schemaValid: true,
            profileEnabled: true,
            profileComplete: true,
            supportedProtocol: true,
            credentialReferenceValid: true,
            credentialFound: true,
            credentialFormatValid: true,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            diagnostic: TunnelRuntimeConfigurationValidationDiagnostic(
                stage: .credential,
                category: .none,
                extensionRequestReached: true,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    static func failure(
        correlationID: UUID,
        stage: TunnelRuntimeConfigurationValidationStage,
        category: TunnelRuntimeConfigurationValidationCategory,
        providerConfigurationValid: Bool = false,
        extensionRequestReached: Bool = true,
        providerConfigurationDiagnostic: TunnelProviderConfigurationDiagnostic? = nil
    ) -> TunnelRuntimeConfigurationValidationResponse {
        TunnelRuntimeConfigurationValidationResponse(
            correlationID: correlationID,
            success: false,
            providerConfigurationValid: providerConfigurationValid,
            profileFound: ![.profileRecordNotFound, .profileRecordMalformed, .profileRecordTooLarge, .profileRecordCountExceeded].contains(category),
            profileIdentityMatched: category != .profileIdentityMismatch,
            revisionMatched: category != .profileRevisionMismatch,
            schemaValid: ![.unsupportedProviderSchema, .providerConfigurationUnsupportedSchemaVersion, .profileSchemaMismatch].contains(category),
            profileEnabled: category != .profileDisabled,
            profileComplete: category != .profileIncomplete,
            supportedProtocol: category != .unsupportedProtocol,
            credentialReferenceValid: ![.missingCredentialReference, .malformedCredentialReference].contains(category),
            credentialFound: category != .credentialUnavailable,
            credentialFormatValid: category != .credentialMalformed,
            protocolName: nil,
            transportName: nil,
            securityName: nil,
            diagnostic: TunnelRuntimeConfigurationValidationDiagnostic(
                stage: stage,
                category: category,
                extensionRequestReached: extensionRequestReached,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8)),
                providerConfiguration: providerConfigurationDiagnostic
            )
        )
    }
}

nonisolated struct TunnelRuntimeConfigurationValidationFailure: Error, Sendable {
    var diagnostic: TunnelRuntimeConfigurationValidationDiagnostic
}

nonisolated struct TunnelXrayConfigurationValidationRequest: Codable, Equatable, Sendable {
    var correlationID: UUID
    var expectedProfileID: UUID?
    var expectedRevisionToken: Int64?
    var requestGeneration: UInt64?

    init(
        correlationID: UUID,
        expectedProfileID: UUID? = nil,
        expectedRevisionToken: Int64? = nil,
        requestGeneration: UInt64? = nil
    ) {
        self.correlationID = correlationID
        self.expectedProfileID = expectedProfileID
        self.expectedRevisionToken = expectedRevisionToken
        self.requestGeneration = requestGeneration
    }
}

nonisolated enum TunnelXrayConfigurationValidationStage: String, Codable, Equatable, Sendable {
    case runtimeConfiguration
    case builder
    case libXrayAPI
    case libXrayInvocation
    case responseValidation
    case unknown
}

nonisolated enum TunnelXrayConfigurationValidationCategory: String, Codable, Equatable, Sendable {
    case none
    case runtimeConfigurationInvalid
    case providerConfigurationStaleSession
    case profileIdentityMismatch
    case profileRevisionMismatch
    case unsupportedProtocol
    case unsupportedTransport
    case unsupportedSecurity
    case invalidEndpoint
    case invalidCredential
    case invalidTLSConfiguration
    case invalidRealityConfiguration
    case invalidXHTTPConfiguration
    case invalidXHTTPMode
    case invalidXHTTPPath
    case invalidXHTTPHost
    case encodingFailed
    case unsupportedLibXrayAPIVersion
    case requestEncodingFailed
    case invocationFailed
    case emptyResponse
    case malformedResponse
    case configurationRejected
    case unsupportedBundledXrayFeature
    case internalLibXrayError
    case unknownLibXrayError
    case runtimeAlreadyRunning
    case providerUnavailable
    case providerTimeout
    case invalidResponse
    case requestIDMismatch
    case correlationMismatch
    case unknown
}

nonisolated struct TunnelXrayConfigurationValidationDiagnostic: Codable, Equatable, Sendable {
    var stage: TunnelXrayConfigurationValidationStage
    var category: TunnelXrayConfigurationValidationCategory
    var extensionRequestReached: Bool?
    var correlationIDPrefix: String?

    init(
        stage: TunnelXrayConfigurationValidationStage,
        category: TunnelXrayConfigurationValidationCategory,
        extensionRequestReached: Bool?,
        correlationIDPrefix: String? = nil
    ) {
        self.stage = stage
        self.category = category
        self.extensionRequestReached = extensionRequestReached
        self.correlationIDPrefix = correlationIDPrefix
    }
}

nonisolated struct TunnelXrayConfigurationValidationResponse: Codable, Equatable, Sendable {
    var correlationID: UUID
    var success: Bool
    var runtimeConfigurationValid: Bool
    var builderSucceeded: Bool
    var libXrayAvailable: Bool
    var libXrayAPIVersionSupported: Bool
    var testXrayInvoked: Bool
    var testXrayPassed: Bool
    var protocolName: String?
    var transportName: String?
    var securityName: String?
    var h3ALPNConfigured: Bool?
    var sniConfigured: Bool?
    var durationMs: Double?
    var diagnostic: TunnelXrayConfigurationValidationDiagnostic?

    static func success(
        correlationID: UUID,
        protocolName: String?,
        transportName: String?,
        securityName: String?,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        durationMs: Double? = nil
    ) -> TunnelXrayConfigurationValidationResponse {
        TunnelXrayConfigurationValidationResponse(
            correlationID: correlationID,
            success: true,
            runtimeConfigurationValid: true,
            builderSucceeded: true,
            libXrayAvailable: true,
            libXrayAPIVersionSupported: true,
            testXrayInvoked: true,
            testXrayPassed: true,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            durationMs: durationMs,
            diagnostic: TunnelXrayConfigurationValidationDiagnostic(
                stage: .libXrayInvocation,
                category: .none,
                extensionRequestReached: true,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    static func failure(
        correlationID: UUID,
        stage: TunnelXrayConfigurationValidationStage,
        category: TunnelXrayConfigurationValidationCategory,
        runtimeConfigurationValid: Bool = false,
        builderSucceeded: Bool = false,
        libXrayAvailable: Bool = true,
        libXrayAPIVersionSupported: Bool = true,
        testXrayInvoked: Bool = false,
        testXrayPassed: Bool = false,
        protocolName: String? = nil,
        transportName: String? = nil,
        securityName: String? = nil,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        durationMs: Double? = nil,
        extensionRequestReached: Bool = true
    ) -> TunnelXrayConfigurationValidationResponse {
        TunnelXrayConfigurationValidationResponse(
            correlationID: correlationID,
            success: false,
            runtimeConfigurationValid: runtimeConfigurationValid,
            builderSucceeded: builderSucceeded,
            libXrayAvailable: libXrayAvailable,
            libXrayAPIVersionSupported: libXrayAPIVersionSupported,
            testXrayInvoked: testXrayInvoked,
            testXrayPassed: testXrayPassed,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            durationMs: durationMs,
            diagnostic: TunnelXrayConfigurationValidationDiagnostic(
                stage: stage,
                category: category,
                extensionRequestReached: extensionRequestReached,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }
}

nonisolated struct TunnelXrayConfigurationValidationFailure: Error, Sendable {
    var diagnostic: TunnelXrayConfigurationValidationDiagnostic
}

nonisolated struct TunnelXrayLifecycleSmokeTestRequest: Codable, Equatable, Sendable {
    var correlationID: UUID
    var expectedProfileID: UUID?
    var expectedRevisionToken: Int64?
    var requestGeneration: UInt64?

    init(
        correlationID: UUID,
        expectedProfileID: UUID? = nil,
        expectedRevisionToken: Int64? = nil,
        requestGeneration: UInt64? = nil
    ) {
        self.correlationID = correlationID
        self.expectedProfileID = expectedProfileID
        self.expectedRevisionToken = expectedRevisionToken
        self.requestGeneration = requestGeneration
    }
}

nonisolated enum TunnelXrayLifecycleSmokeTestStage: String, Codable, Equatable, Sendable {
    case providerConfiguration
    case runtimeConfiguration
    case xrayBuild
    case testXray
    case preStartState
    case runXray
    case runningState
    case socksReadiness
    case socksGreeting
    case tun2SocksStart
    case tun2SocksStop
    case networkSettings
    case dataPlane
    case stopXray
    case stoppedState
    case portClosure
    case rollback
    case responseValidation
    case unknown
}

nonisolated enum TunnelXrayLifecycleSmokeTestCategory: String, Codable, Equatable, Sendable {
    case none
    case unsupportedProfileForRuntimeSmoke
    case runtimeConfigurationInvalid
    case providerConfigurationStaleSession
    case profileIdentityMismatch
    case profileRevisionMismatch
    case xrayBuildFailed
    case testXrayRejected
    case unsupportedLibXrayAPIVersion
    case requestEncodingFailed
    case invocationFailed
    case emptyResponse
    case malformedLibXrayResponse
    case runtimeAlreadyRunning
    case runXrayRejected
    case xrayDidNotReachRunningState
    case localPortUnavailable
    case socksReadinessTimeout
    case socksConnectionFailed
    case socksGreetingRejected
    case tun2SocksConfigurationInvalid
    case tun2SocksStartupFailed
    case tun2SocksUnexpectedExit
    case tun2SocksDidNotStop
    case networkSettingsFailed
    case stopXrayRejected
    case xrayDidNotStop
    case localPortStillOpen
    case operationSuperseded
    case rollbackFailed
    case providerUnavailable
    case providerTimeout
    case invalidResponse
    case requestIDMismatch
    case correlationMismatch
    case internalRuntimeError
    case unknown
}

nonisolated struct TunnelXrayLifecycleSmokeTestDiagnostic: Codable, Equatable, Sendable {
    var stage: TunnelXrayLifecycleSmokeTestStage
    var category: TunnelXrayLifecycleSmokeTestCategory
    var extensionRequestReached: Bool?
    var correlationIDPrefix: String?

    init(
        stage: TunnelXrayLifecycleSmokeTestStage,
        category: TunnelXrayLifecycleSmokeTestCategory,
        extensionRequestReached: Bool?,
        correlationIDPrefix: String? = nil
    ) {
        self.stage = stage
        self.category = category
        self.extensionRequestReached = extensionRequestReached
        self.correlationIDPrefix = correlationIDPrefix
    }
}

nonisolated struct TunnelXrayLifecycleSmokeTestResponse: Codable, Equatable, Sendable {
    var correlationID: UUID
    var success: Bool
    var runtimeConfigurationLoaded: Bool
    var xrayConfigurationBuilt: Bool
    var testXrayPassed: Bool
    var runXrayInvoked: Bool
    var runningStateObserved: Bool
    var socksListenerReady: Bool
    var socksGreetingAccepted: Bool
    var stopXrayInvoked: Bool
    var stoppedStateObserved: Bool
    var localPortClosed: Bool
    var rollbackAttempted: Bool
    var rollbackSucceeded: Bool
    var protocolName: String?
    var transportName: String?
    var securityName: String?
    var h3ALPNConfigured: Bool?
    var sniConfigured: Bool?
    var failureStage: TunnelXrayLifecycleSmokeTestStage?
    var failureCategory: TunnelXrayLifecycleSmokeTestCategory?
    var startDurationMs: Double?
    var readinessDurationMs: Double?
    var stopDurationMs: Double?
    var totalDurationMs: Double?
    var diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic?

    static func success(
        correlationID: UUID,
        protocolName: String?,
        transportName: String?,
        securityName: String?,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        startDurationMs: Double?,
        readinessDurationMs: Double?,
        stopDurationMs: Double?,
        totalDurationMs: Double?
    ) -> TunnelXrayLifecycleSmokeTestResponse {
        TunnelXrayLifecycleSmokeTestResponse(
            correlationID: correlationID,
            success: true,
            runtimeConfigurationLoaded: true,
            xrayConfigurationBuilt: true,
            testXrayPassed: true,
            runXrayInvoked: true,
            runningStateObserved: true,
            socksListenerReady: true,
            socksGreetingAccepted: true,
            stopXrayInvoked: true,
            stoppedStateObserved: true,
            localPortClosed: true,
            rollbackAttempted: false,
            rollbackSucceeded: true,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            failureStage: nil,
            failureCategory: nil,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            stopDurationMs: stopDurationMs,
            totalDurationMs: totalDurationMs,
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .portClosure,
                category: .none,
                extensionRequestReached: true,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    static func runtimeOnlyStarted(
        correlationID: UUID,
        protocolName: String?,
        transportName: String?,
        securityName: String?,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        startDurationMs: Double?,
        readinessDurationMs: Double?,
        totalDurationMs: Double?
    ) -> TunnelXrayLifecycleSmokeTestResponse {
        TunnelXrayLifecycleSmokeTestResponse(
            correlationID: correlationID,
            success: true,
            runtimeConfigurationLoaded: true,
            xrayConfigurationBuilt: true,
            testXrayPassed: true,
            runXrayInvoked: true,
            runningStateObserved: true,
            socksListenerReady: true,
            socksGreetingAccepted: true,
            stopXrayInvoked: false,
            stoppedStateObserved: false,
            localPortClosed: false,
            rollbackAttempted: false,
            rollbackSucceeded: true,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            failureStage: nil,
            failureCategory: nil,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            stopDurationMs: nil,
            totalDurationMs: totalDurationMs,
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .socksGreeting,
                category: .none,
                extensionRequestReached: true,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    static func failure(
        correlationID: UUID,
        stage: TunnelXrayLifecycleSmokeTestStage,
        category: TunnelXrayLifecycleSmokeTestCategory,
        runtimeConfigurationLoaded: Bool = false,
        xrayConfigurationBuilt: Bool = false,
        testXrayPassed: Bool = false,
        runXrayInvoked: Bool = false,
        runningStateObserved: Bool = false,
        socksListenerReady: Bool = false,
        socksGreetingAccepted: Bool = false,
        stopXrayInvoked: Bool = false,
        stoppedStateObserved: Bool = false,
        localPortClosed: Bool = false,
        rollbackAttempted: Bool = false,
        rollbackSucceeded: Bool = false,
        protocolName: String? = nil,
        transportName: String? = nil,
        securityName: String? = nil,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        startDurationMs: Double? = nil,
        readinessDurationMs: Double? = nil,
        stopDurationMs: Double? = nil,
        totalDurationMs: Double? = nil,
        extensionRequestReached: Bool = true
    ) -> TunnelXrayLifecycleSmokeTestResponse {
        TunnelXrayLifecycleSmokeTestResponse(
            correlationID: correlationID,
            success: false,
            runtimeConfigurationLoaded: runtimeConfigurationLoaded,
            xrayConfigurationBuilt: xrayConfigurationBuilt,
            testXrayPassed: testXrayPassed,
            runXrayInvoked: runXrayInvoked,
            runningStateObserved: runningStateObserved,
            socksListenerReady: socksListenerReady,
            socksGreetingAccepted: socksGreetingAccepted,
            stopXrayInvoked: stopXrayInvoked,
            stoppedStateObserved: stoppedStateObserved,
            localPortClosed: localPortClosed,
            rollbackAttempted: rollbackAttempted,
            rollbackSucceeded: rollbackSucceeded,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            failureStage: stage,
            failureCategory: category,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            stopDurationMs: stopDurationMs,
            totalDurationMs: totalDurationMs,
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: stage,
                category: category,
                extensionRequestReached: extensionRequestReached,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }
}

nonisolated struct TunnelXrayLifecycleSmokeTestFailure: Error, Sendable {
    var diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic
}

nonisolated struct TunnelXrayRemoteEgressProbeRequest: Codable, Equatable, Sendable {
    var correlationID: UUID
    var expectedProfileID: UUID?
    var expectedRevisionToken: Int64?
    var requestGeneration: UInt64?

    init(
        correlationID: UUID,
        expectedProfileID: UUID? = nil,
        expectedRevisionToken: Int64? = nil,
        requestGeneration: UInt64? = nil
    ) {
        self.correlationID = correlationID
        self.expectedProfileID = expectedProfileID
        self.expectedRevisionToken = expectedRevisionToken
        self.requestGeneration = requestGeneration
    }
}

nonisolated enum TunnelXrayRemoteEgressProbeStage: String, Codable, Equatable, Sendable {
    case providerConfiguration
    case runtimeConfiguration
    case xrayBuild
    case testXray
    case preStartState
    case runXray
    case runningState
    case socksReadiness
    case socksGreeting
    case remoteConnect
    case remotePayload
    case remoteFirstByte
    case remoteResponse
    case stopXray
    case stoppedState
    case portClosure
    case rollback
    case responseValidation
    case unknown
}

nonisolated enum TunnelXrayRemoteEgressProbeCategory: String, Codable, Equatable, Sendable {
    case none
    case success
    case timeout
    case socksRejected
    case socksHandshakeRejected
    case socksConnectRejected
    case payloadWriteFailed
    case remoteFirstByteTimeout
    case remoteReadFailed
    case remoteResponseInvalid
    case xrayExited
    case configurationRejected
    case networkUnavailable
    case runtimeBusy
    case cleanupFailed
    case providerUnavailable
    case providerTimeout
    case invalidResponse
    case requestIDMismatch
    case correlationMismatch
    case unknown
}

nonisolated struct TunnelXrayRemoteEgressProbeDiagnostic: Codable, Equatable, Sendable {
    var stage: TunnelXrayRemoteEgressProbeStage
    var category: TunnelXrayRemoteEgressProbeCategory
    var extensionRequestReached: Bool?
    var correlationIDPrefix: String?

    init(
        stage: TunnelXrayRemoteEgressProbeStage,
        category: TunnelXrayRemoteEgressProbeCategory,
        extensionRequestReached: Bool?,
        correlationIDPrefix: String? = nil
    ) {
        self.stage = stage
        self.category = category
        self.extensionRequestReached = extensionRequestReached
        self.correlationIDPrefix = correlationIDPrefix
    }
}

nonisolated enum TunnelXrayRemoteEgressProbeContext: String, Codable, Equatable, Sendable {
    case runtimeOnly
    case dataPlane
}

nonisolated struct TunnelXrayRemoteEgressProbeResponse: Codable, Equatable, Sendable {
    var correlationID: UUID
    var success: Bool
    var probeContext: TunnelXrayRemoteEgressProbeContext?
    var xrayBuildPassed: Bool
    var testXrayPassed: Bool
    var xrayRunning: Bool
    var localSocksReady: Bool
    var remoteConnectAttempted: Bool
    var remoteConnectSucceeded: Bool
    var remoteConnectCategory: TunnelXrayRemoteEgressProbeCategory
    var socksConnectRequested: Bool
    var socksConnectAccepted: Bool
    var payloadWriteSucceeded: Bool
    var remoteFirstByteReceived: Bool
    var remoteResponseValidated: Bool
    var remoteEgressSucceeded: Bool
    var cleanupSucceeded: Bool
    var protocolName: String?
    var transportName: String?
    var securityName: String?
    var h3ALPNConfigured: Bool?
    var sniConfigured: Bool?
    var allowInsecureConfigured: Bool?
    var startDurationMs: Double?
    var readinessDurationMs: Double?
    var remoteConnectDurationMs: Double?
    var stopDurationMs: Double?
    var totalDurationMs: Double?
    var failureStage: TunnelXrayRemoteEgressProbeStage?
    var failureCategory: TunnelXrayRemoteEgressProbeCategory?
    var diagnostic: TunnelXrayRemoteEgressProbeDiagnostic?

    static func success(
        correlationID: UUID,
        protocolName: String?,
        transportName: String?,
        securityName: String?,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        allowInsecureConfigured: Bool? = nil,
        probeContext: TunnelXrayRemoteEgressProbeContext? = nil,
        cleanupSucceeded: Bool = true,
        startDurationMs: Double?,
        readinessDurationMs: Double?,
        remoteConnectDurationMs: Double?,
        stopDurationMs: Double?,
        totalDurationMs: Double?
    ) -> TunnelXrayRemoteEgressProbeResponse {
        TunnelXrayRemoteEgressProbeResponse(
            correlationID: correlationID,
            success: true,
            probeContext: probeContext,
            xrayBuildPassed: true,
            testXrayPassed: true,
            xrayRunning: true,
            localSocksReady: true,
            remoteConnectAttempted: true,
            remoteConnectSucceeded: true,
            remoteConnectCategory: .success,
            socksConnectRequested: true,
            socksConnectAccepted: true,
            payloadWriteSucceeded: true,
            remoteFirstByteReceived: true,
            remoteResponseValidated: true,
            remoteEgressSucceeded: true,
            cleanupSucceeded: cleanupSucceeded,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            allowInsecureConfigured: allowInsecureConfigured,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            remoteConnectDurationMs: remoteConnectDurationMs,
            stopDurationMs: stopDurationMs,
            totalDurationMs: totalDurationMs,
            failureStage: nil,
            failureCategory: nil,
            diagnostic: TunnelXrayRemoteEgressProbeDiagnostic(
                stage: .portClosure,
                category: .success,
                extensionRequestReached: true,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    static func failure(
        correlationID: UUID,
        stage: TunnelXrayRemoteEgressProbeStage,
        category: TunnelXrayRemoteEgressProbeCategory,
        xrayBuildPassed: Bool = false,
        testXrayPassed: Bool = false,
        xrayRunning: Bool = false,
        localSocksReady: Bool = false,
        remoteConnectAttempted: Bool = false,
        remoteConnectSucceeded: Bool = false,
        remoteConnectCategory: TunnelXrayRemoteEgressProbeCategory? = nil,
        socksConnectRequested: Bool? = nil,
        socksConnectAccepted: Bool = false,
        payloadWriteSucceeded: Bool = false,
        remoteFirstByteReceived: Bool = false,
        remoteResponseValidated: Bool = false,
        remoteEgressSucceeded: Bool = false,
        cleanupSucceeded: Bool = false,
        protocolName: String? = nil,
        transportName: String? = nil,
        securityName: String? = nil,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        allowInsecureConfigured: Bool? = nil,
        probeContext: TunnelXrayRemoteEgressProbeContext? = nil,
        startDurationMs: Double? = nil,
        readinessDurationMs: Double? = nil,
        remoteConnectDurationMs: Double? = nil,
        stopDurationMs: Double? = nil,
        totalDurationMs: Double? = nil,
        extensionRequestReached: Bool = true
    ) -> TunnelXrayRemoteEgressProbeResponse {
        TunnelXrayRemoteEgressProbeResponse(
            correlationID: correlationID,
            success: false,
            probeContext: probeContext,
            xrayBuildPassed: xrayBuildPassed,
            testXrayPassed: testXrayPassed,
            xrayRunning: xrayRunning,
            localSocksReady: localSocksReady,
            remoteConnectAttempted: remoteConnectAttempted,
            remoteConnectSucceeded: remoteConnectSucceeded,
            remoteConnectCategory: remoteConnectCategory ?? category,
            socksConnectRequested: socksConnectRequested ?? remoteConnectAttempted,
            socksConnectAccepted: socksConnectAccepted,
            payloadWriteSucceeded: payloadWriteSucceeded,
            remoteFirstByteReceived: remoteFirstByteReceived,
            remoteResponseValidated: remoteResponseValidated,
            remoteEgressSucceeded: remoteEgressSucceeded,
            cleanupSucceeded: cleanupSucceeded,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            allowInsecureConfigured: allowInsecureConfigured,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            remoteConnectDurationMs: remoteConnectDurationMs,
            stopDurationMs: stopDurationMs,
            totalDurationMs: totalDurationMs,
            failureStage: stage,
            failureCategory: category,
            diagnostic: TunnelXrayRemoteEgressProbeDiagnostic(
                stage: stage,
                category: category,
                extensionRequestReached: extensionRequestReached,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }
}

nonisolated struct TunnelXrayRemoteEgressProbeFailure: Error, Sendable {
    var diagnostic: TunnelXrayRemoteEgressProbeDiagnostic
}

nonisolated struct TunnelUDPControlProbeRequest: Codable, Equatable, Sendable {
    var correlationID: UUID
    var requestGeneration: UInt64?

    init(correlationID: UUID, requestGeneration: UInt64? = nil) {
        self.correlationID = correlationID
        self.requestGeneration = requestGeneration
    }
}

nonisolated enum TunnelUDPControlProbePathStatus: String, Codable, Equatable, Sendable {
    case satisfied
    case unsatisfied
    case requiresConnection
    case unknown
}

nonisolated struct TunnelUDPControlProbePathSnapshot: Codable, Equatable, Sendable {
    var pathStatus: TunnelUDPControlProbePathStatus
    var usesWiFi: Bool
    var usesCellular: Bool
    var usesWiredEthernet: Bool
    var supportsIPv4: Bool
    var supportsIPv6: Bool
    var supportsDNS: Bool

    init(
        pathStatus: TunnelUDPControlProbePathStatus,
        usesWiFi: Bool,
        usesCellular: Bool,
        usesWiredEthernet: Bool,
        supportsIPv4: Bool,
        supportsIPv6: Bool,
        supportsDNS: Bool
    ) {
        self.pathStatus = pathStatus
        self.usesWiFi = usesWiFi
        self.usesCellular = usesCellular
        self.usesWiredEthernet = usesWiredEthernet
        self.supportsIPv4 = supportsIPv4
        self.supportsIPv6 = supportsIPv6
        self.supportsDNS = supportsDNS
    }
}

nonisolated enum TunnelUDPControlProbeCategory: String, Codable, Equatable, Sendable {
    case none
    case success
    case notRuntimeOnly
    case connectionFailed
    case pathUnsatisfied
    case writeFailed
    case readTimeout
    case readFailed
    case invalidResponse
    case cancelled
    case providerUnavailable
    case providerTimeout
    case requestIDMismatch
    case correlationMismatch
    case unknown
}

nonisolated struct TunnelUDPControlProbeDiagnostic: Codable, Equatable, Sendable {
    var category: TunnelUDPControlProbeCategory
    var extensionRequestReached: Bool?
    var correlationIDPrefix: String?

    init(
        category: TunnelUDPControlProbeCategory,
        extensionRequestReached: Bool?,
        correlationIDPrefix: String? = nil
    ) {
        self.category = category
        self.extensionRequestReached = extensionRequestReached
        self.correlationIDPrefix = correlationIDPrefix
    }
}

nonisolated struct TunnelUDPControlProbeResponse: Codable, Equatable, Sendable {
    var correlationID: UUID
    var success: Bool
    var udpControlStarted: Bool
    var udpConnectionReady: Bool
    var udpWriteSucceeded: Bool
    var udpResponseReceived: Bool
    var udpResponseValidated: Bool
    var udpControlSucceeded: Bool
    var failureCategory: TunnelUDPControlProbeCategory
    var pathSnapshot: TunnelUDPControlProbePathSnapshot?
    var durationMs: Double?
    var diagnostic: TunnelUDPControlProbeDiagnostic?

    static func success(
        correlationID: UUID,
        pathSnapshot: TunnelUDPControlProbePathSnapshot?,
        durationMs: Double?
    ) -> TunnelUDPControlProbeResponse {
        TunnelUDPControlProbeResponse(
            correlationID: correlationID,
            success: true,
            udpControlStarted: true,
            udpConnectionReady: true,
            udpWriteSucceeded: true,
            udpResponseReceived: true,
            udpResponseValidated: true,
            udpControlSucceeded: true,
            failureCategory: .success,
            pathSnapshot: pathSnapshot,
            durationMs: durationMs,
            diagnostic: TunnelUDPControlProbeDiagnostic(
                category: .success,
                extensionRequestReached: true,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    static func failure(
        correlationID: UUID,
        category: TunnelUDPControlProbeCategory,
        udpControlStarted: Bool = true,
        udpConnectionReady: Bool = false,
        udpWriteSucceeded: Bool = false,
        udpResponseReceived: Bool = false,
        udpResponseValidated: Bool = false,
        pathSnapshot: TunnelUDPControlProbePathSnapshot? = nil,
        durationMs: Double? = nil,
        extensionRequestReached: Bool = true
    ) -> TunnelUDPControlProbeResponse {
        TunnelUDPControlProbeResponse(
            correlationID: correlationID,
            success: false,
            udpControlStarted: udpControlStarted,
            udpConnectionReady: udpConnectionReady,
            udpWriteSucceeded: udpWriteSucceeded,
            udpResponseReceived: udpResponseReceived,
            udpResponseValidated: udpResponseValidated,
            udpControlSucceeded: false,
            failureCategory: category,
            pathSnapshot: pathSnapshot,
            durationMs: durationMs,
            diagnostic: TunnelUDPControlProbeDiagnostic(
                category: category,
                extensionRequestReached: extensionRequestReached,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }
}

nonisolated struct TunnelUDPControlProbeFailure: Error, Sendable {
    var diagnostic: TunnelUDPControlProbeDiagnostic
}

nonisolated struct TunnelLibXrayPingProbeRequest: Codable, Equatable, Sendable {
    var correlationID: UUID
    var expectedProfileID: UUID?
    var expectedRevisionToken: Int64?
    var requestGeneration: UInt64?

    init(
        correlationID: UUID,
        expectedProfileID: UUID? = nil,
        expectedRevisionToken: Int64? = nil,
        requestGeneration: UInt64? = nil
    ) {
        self.correlationID = correlationID
        self.expectedProfileID = expectedProfileID
        self.expectedRevisionToken = expectedRevisionToken
        self.requestGeneration = requestGeneration
    }
}

nonisolated enum TunnelLibXrayPingProbeStage: String, Codable, Equatable, Sendable {
    case providerConfiguration
    case runtimeConfiguration
    case xrayBuild
    case preStartState
    case libXrayPing
    case responseValidation
    case unknown
}

nonisolated enum TunnelLibXrayPingProbeCategory: String, Codable, Equatable, Sendable {
    case none
    case success
    case runtimeBusy
    case unsupportedLibXrayAPIVersion
    case requestEncodingFailed
    case invocationFailed
    case emptyResponse
    case malformedResponse
    case configurationRejected
    case quicFailure
    case tlsFailure
    case certificateFailure
    case authenticationFailure
    case dnsFailure
    case networkUnreachable
    case connectionRefused
    case connectionReset
    case timeout
    case protocolFailure
    case eof
    case providerUnavailable
    case providerTimeout
    case invalidResponse
    case requestIDMismatch
    case correlationMismatch
    case unknown
}

nonisolated struct TunnelLibXrayPingProbeDiagnostic: Codable, Equatable, Sendable {
    var stage: TunnelLibXrayPingProbeStage
    var category: TunnelLibXrayPingProbeCategory
    var extensionRequestReached: Bool?
    var correlationIDPrefix: String?

    init(
        stage: TunnelLibXrayPingProbeStage,
        category: TunnelLibXrayPingProbeCategory,
        extensionRequestReached: Bool?,
        correlationIDPrefix: String? = nil
    ) {
        self.stage = stage
        self.category = category
        self.extensionRequestReached = extensionRequestReached
        self.correlationIDPrefix = correlationIDPrefix
    }
}

nonisolated struct TunnelLibXrayPingProbeResponse: Codable, Equatable, Sendable {
    var correlationID: UUID
    var success: Bool
    var xrayConfigurationBuilt: Bool
    var pingAccepted: Bool
    var pingCompleted: Bool
    var pingSucceeded: Bool
    var delayMs: Int64?
    var timedOut: Bool
    var nativeErrorPresent: Bool
    var sanitizedFailureCategory: TunnelLibXrayPingProbeCategory
    var protocolName: String?
    var transportName: String?
    var securityName: String?
    var h3ALPNConfigured: Bool?
    var sniConfigured: Bool?
    var allowInsecureConfigured: Bool?
    var durationMs: Double?
    var failureStage: TunnelLibXrayPingProbeStage?
    var failureCategory: TunnelLibXrayPingProbeCategory?
    var diagnostic: TunnelLibXrayPingProbeDiagnostic?

    static func success(
        correlationID: UUID,
        delayMs: Int64?,
        protocolName: String?,
        transportName: String?,
        securityName: String?,
        h3ALPNConfigured: Bool?,
        sniConfigured: Bool?,
        allowInsecureConfigured: Bool?,
        durationMs: Double?
    ) -> TunnelLibXrayPingProbeResponse {
        TunnelLibXrayPingProbeResponse(
            correlationID: correlationID,
            success: true,
            xrayConfigurationBuilt: true,
            pingAccepted: true,
            pingCompleted: true,
            pingSucceeded: true,
            delayMs: delayMs,
            timedOut: false,
            nativeErrorPresent: false,
            sanitizedFailureCategory: .success,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            allowInsecureConfigured: allowInsecureConfigured,
            durationMs: durationMs,
            failureStage: nil,
            failureCategory: nil,
            diagnostic: TunnelLibXrayPingProbeDiagnostic(
                stage: .libXrayPing,
                category: .success,
                extensionRequestReached: true,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    static func failure(
        correlationID: UUID,
        stage: TunnelLibXrayPingProbeStage,
        category: TunnelLibXrayPingProbeCategory,
        xrayConfigurationBuilt: Bool = false,
        pingAccepted: Bool = false,
        pingCompleted: Bool = false,
        pingSucceeded: Bool = false,
        delayMs: Int64? = nil,
        timedOut: Bool? = nil,
        nativeErrorPresent: Bool = false,
        protocolName: String? = nil,
        transportName: String? = nil,
        securityName: String? = nil,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        allowInsecureConfigured: Bool? = nil,
        durationMs: Double? = nil,
        extensionRequestReached: Bool = true
    ) -> TunnelLibXrayPingProbeResponse {
        TunnelLibXrayPingProbeResponse(
            correlationID: correlationID,
            success: false,
            xrayConfigurationBuilt: xrayConfigurationBuilt,
            pingAccepted: pingAccepted,
            pingCompleted: pingCompleted,
            pingSucceeded: pingSucceeded,
            delayMs: delayMs,
            timedOut: timedOut ?? (category == .timeout),
            nativeErrorPresent: nativeErrorPresent,
            sanitizedFailureCategory: category,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            allowInsecureConfigured: allowInsecureConfigured,
            durationMs: durationMs,
            failureStage: stage,
            failureCategory: category,
            diagnostic: TunnelLibXrayPingProbeDiagnostic(
                stage: stage,
                category: category,
                extensionRequestReached: extensionRequestReached,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }
}

nonisolated struct TunnelLibXrayPingProbeFailure: Error, Sendable {
    var diagnostic: TunnelLibXrayPingProbeDiagnostic
}

nonisolated enum TunnelKeychainSentinelDiagnosticStage: String, Codable, Equatable, Sendable {
    case accessGroupResolution
    case appKeychainWrite
    case appKeychainVerify
    case managerLoad
    case managerCreate
    case managerSave
    case managerReload
    case providerSession
    case providerMessageSend
    case providerUnavailable
    case providerTimeout
    case extensionRequestDecode
    case extensionKeychainRead
    case extensionSentinelMissing
    case responseValidation
    case cleanup
    case cleanupVerification
}

nonisolated enum TunnelKeychainSentinelDiagnosticStatus: String, Codable, Equatable, Sendable {
    case succeeded
    case failed
}

nonisolated enum TunnelKeychainSentinelDiagnosticCategory: String, Codable, Equatable, Sendable {
    case none
    case accessGroupUnavailable
    case invalidAccessGroup
    case keychainStatus
    case keychainUnavailable
    case managerLoadFailed
    case managerCreateFailed
    case managerSaveFailed
    case managerReloadFailed
    case providerBundleMismatch
    case providerSessionUnavailable
    case providerUnavailable
    case providerNotRunningWhileDisconnected
    case providerMessageSendFailed
    case providerResponseMissing
    case providerTimeout
    case malformedRequest
    case schemaMismatch
    case invalidResponse
    case requestIDMismatch
    case correlationMismatch
    case sentinelMissing
    case cleanupFailed
    case cleanupVerificationFailed
    case unknown
}

nonisolated enum TunnelKeychainSentinelManagerAction: String, Codable, Equatable, Sendable {
    case none
    case reused
    case created
}

nonisolated struct TunnelKeychainSentinelDiagnostic: Codable, Equatable, Sendable {
    var stage: TunnelKeychainSentinelDiagnosticStage
    var status: TunnelKeychainSentinelDiagnosticStatus
    var category: TunnelKeychainSentinelDiagnosticCategory
    var vpnStatus: String?
    var managerAction: TunnelKeychainSentinelManagerAction
    var providerBundleIDMatches: Bool?
    var extensionRequestReached: Bool?
    var osStatus: Int32?
    var errorDomain: String?
    var errorCode: Int?
    var errorSymbol: String?
    var correlationIDPrefix: String?
    var cleanupSucceeded: Bool?
    var generatedAt: Date

    init(
        stage: TunnelKeychainSentinelDiagnosticStage,
        status: TunnelKeychainSentinelDiagnosticStatus,
        category: TunnelKeychainSentinelDiagnosticCategory = .none,
        vpnStatus: String? = nil,
        managerAction: TunnelKeychainSentinelManagerAction = .none,
        providerBundleIDMatches: Bool? = nil,
        extensionRequestReached: Bool? = nil,
        osStatus: Int32? = nil,
        errorDomain: String? = nil,
        errorCode: Int? = nil,
        errorSymbol: String? = nil,
        correlationIDPrefix: String? = nil,
        cleanupSucceeded: Bool? = nil,
        generatedAt: Date = Date()
    ) {
        self.stage = stage
        self.status = status
        self.category = category
        self.vpnStatus = vpnStatus
        self.managerAction = managerAction
        self.providerBundleIDMatches = providerBundleIDMatches
        self.extensionRequestReached = extensionRequestReached
        self.osStatus = osStatus
        self.errorDomain = errorDomain
        self.errorCode = errorCode
        self.errorSymbol = errorSymbol
        self.correlationIDPrefix = correlationIDPrefix
        self.cleanupSucceeded = cleanupSucceeded
        self.generatedAt = generatedAt
    }
}

nonisolated enum TunnelRuntimeState: String, Codable, Equatable, Sendable {
    case notRunning, starting, networkSettingsApplied, running, stopping, stopped, failed
}

nonisolated enum TunnelComponentState: String, Codable, Equatable, Sendable {
    case unavailable, notRunning, starting, running, stopped, failed, unknown
}

nonisolated enum TunnelHealthState: String, Codable, Equatable, Sendable {
    case unknown, starting, healthy, degraded, failed, stopped
}

nonisolated enum TunnelTelemetryOrigin: String, Codable, Equatable, Sendable {
    case packetTunnelExtension
    case appGroupLastKnownSnapshot
}

nonisolated enum TunnelFailureCategory: String, Codable, Equatable, Sendable {
    case profileUnavailable
    case credentialUnavailable
    case configurationInvalid
    case xrayValidationFailed
    case xrayStartupFailed
    case socksEndpointUnavailable
    case networkSettingsFailed
    case tun2SocksStartupFailed
    case runtimeExited
    case runtimeTimedOut
    case transportUnavailable
    case unknown
}

nonisolated enum TunnelProtocolKind: String, Codable, Equatable, Sendable {
    case vless, trojan, vmess, hysteria2, wireguard, shadowsocks, tuic, ikev2, unknown
}

nonisolated enum TunnelBackendKind: String, Codable, Equatable, Sendable {
    case xray, hysteria, wireguard, system, custom, unknown
}

nonisolated struct TunnelCapabilitySnapshot: Codable, Equatable, Sendable {
    var schemaVersion: UInt32
    var supportedRequests: [TunnelMessageKind]
    var supportsRuntimeSnapshot: Bool
    var supportsHealthSnapshot: Bool
    var supportsRecentEvents: Bool
    var supportsLiveTun2SocksStats: Bool
    var supportsXrayState: Bool
    var isReadOnly: Bool

    static var current: TunnelCapabilitySnapshot {
        TunnelCapabilitySnapshot(
            schemaVersion: TunnelMessageProtocol.schemaVersion,
            supportedRequests: TunnelMessageKind.allSupportedCases,
            supportsRuntimeSnapshot: true,
            supportsHealthSnapshot: true,
            supportsRecentEvents: true,
            supportsLiveTun2SocksStats: false,
            supportsXrayState: false,
            isReadOnly: true
        )
    }
}

nonisolated struct TunnelTrafficCounters: Codable, Equatable, Sendable {
    var bytesUploaded: UInt64?
    var bytesDownloaded: UInt64?
    var packetsUploaded: UInt64?
    var packetsDownloaded: UInt64?

    static let unavailable = TunnelTrafficCounters(bytesUploaded: nil, bytesDownloaded: nil, packetsUploaded: nil, packetsDownloaded: nil)
}

nonisolated struct TunnelFailureSnapshot: Codable, Equatable, Sendable {
    var category: TunnelFailureCategory
    var occurredAt: Date
    var errorDomain: String?
    var errorCode: Int?
}

nonisolated struct TunnelHealthSnapshot: Codable, Equatable, Sendable {
    var state: TunnelHealthState
    var generatedAt: Date
    var origin: TunnelTelemetryOrigin
    var lastSuccessfulTrafficAt: Date?
    var lastFailure: TunnelFailureSnapshot?
    var isLive: Bool
}

nonisolated struct TunnelRuntimeSnapshot: Codable, Equatable, Sendable {
    var runtimeState: TunnelRuntimeState
    var runtimeGeneration: UInt64
    var activeProfileID: String?
    var candidateID: String?
    var backendKind: TunnelBackendKind
    var protocolKind: TunnelProtocolKind
    var transportKind: String?
    var startedAt: Date?
    var lastStateChangeAt: Date
    var uptimeSeconds: Double?
    var xrayState: TunnelComponentState
    var tun2SocksState: TunnelComponentState
    var networkSettingsState: TunnelComponentState
    var counters: TunnelTrafficCounters
    var reconnectCount: UInt64
    var lastSuccessfulTrafficAt: Date?
    var lastFailure: TunnelFailureSnapshot?
    var health: TunnelHealthSnapshot
    var origin: TunnelTelemetryOrigin
    var generatedAt: Date

    static func notRunning(generatedAt: Date = Date(), origin: TunnelTelemetryOrigin = .packetTunnelExtension) -> TunnelRuntimeSnapshot {
        let health = TunnelHealthSnapshot(
            state: .stopped,
            generatedAt: generatedAt,
            origin: origin,
            lastSuccessfulTrafficAt: nil,
            lastFailure: nil,
            isLive: origin == .packetTunnelExtension
        )
        return TunnelRuntimeSnapshot(
            runtimeState: .notRunning,
            runtimeGeneration: 0,
            activeProfileID: nil,
            candidateID: nil,
            backendKind: .unknown,
            protocolKind: .unknown,
            transportKind: nil,
            startedAt: nil,
            lastStateChangeAt: generatedAt,
            uptimeSeconds: nil,
            xrayState: .unavailable,
            tun2SocksState: .unavailable,
            networkSettingsState: .notRunning,
            counters: .unavailable,
            reconnectCount: 0,
            lastSuccessfulTrafficAt: nil,
            lastFailure: nil,
            health: health,
            origin: origin,
            generatedAt: generatedAt
        )
    }
}

nonisolated struct TunnelEventSnapshot: Codable, Equatable, Sendable {
    var generatedAt: Date
    var category: String
    var runtimeState: TunnelRuntimeState
    var failureCategory: TunnelFailureCategory?
}

nonisolated struct TunnelStoredTelemetrySnapshot: Codable, Equatable, Sendable {
    var schemaVersion: UInt32
    var generatedAt: Date
    var runtime: TunnelRuntimeSnapshot
    var events: [TunnelEventSnapshot]
}
