//
//  KVNCoreDTO.swift
//  VPN
//
//  Codable DTOs mirroring the KVNCore JSON ABI schema (schema_version = 1).
//  All JSON is produced/consumed via JSONEncoder/JSONDecoder — never by string
//  concatenation. Explicit CodingKeys carry the exact snake_case wire names.
//
//  SECRET BOUNDARY: none of these types has a field capable of carrying a
//  credential (no password/UUID-credential/token/private-key/URI/metadata map).
//

import Foundation

// MARK: - Enumerations (raw values match Rust serde snake_case)

nonisolated enum KVNProtocolKind: String, Codable, Sendable {
    case vless, trojan, vmess, hysteria2, wireguard, shadowsocks, tuic, ikev2, unknown
}

nonisolated enum KVNBackendKind: String, Codable, Sendable {
    case xray, hysteria, wireguard, system, custom
}

nonisolated enum KVNNetworkType: String, Codable, Sendable {
    case wifi, cellular, ethernet, unknown
}

nonisolated enum KVNConnectionStateDTO: String, Codable, Sendable {
    case idle, selecting, preparing, connecting, connected, reconnecting, disconnecting, failed
}

nonisolated enum KVNSelectionReason: String, Codable, Sendable {
    case initialSelection = "initial_selection"
    case currentUnavailable = "current_unavailable"
    case significantlyBetter = "significantly_better"
    case failureThresholdReached = "failure_threshold_reached"
    case manualOverride = "manual_override"
    case policyChange = "policy_change"
    case noChange = "no_change"
    case noHealthyCandidates = "no_healthy_candidates"
}

nonisolated enum KVNRouteActionDTO: String, Codable, Sendable {
    case direct, vpn, block
}

// MARK: - Value DTOs

nonisolated struct KVNEndpointDTO: Codable, Equatable, Sendable {
    var host: String
    var port: UInt16
    var protocolKind: KVNProtocolKind
    var backend: KVNBackendKind
    var enabled: Bool
    var tags: [String]
    var region: String?
    var country: String?
    var manualPriority: Int32

    enum CodingKeys: String, CodingKey {
        case host, port
        case protocolKind = "protocol"
        case backend, enabled, tags, region, country
        case manualPriority = "manual_priority"
    }
}

nonisolated struct KVNCandidateDTO: Codable, Equatable, Sendable {
    var candidateID: String
    var profileID: String
    var endpoint: KVNEndpointDTO

    enum CodingKeys: String, CodingKey {
        case candidateID = "candidate_id"
        case profileID = "profile_id"
        case endpoint
    }
}

nonisolated struct KVNHealthSampleDTO: Codable, Sendable {
    var timestampMs: UInt64
    var reachable: Bool
    var latencyMs: Double?
    var jitterMs: Double?
    var packetLossPercent: Double?
    var handshakeMs: Double?
    var downloadBps: Double?
    var uploadBps: Double?
    var failure: String?

    enum CodingKeys: String, CodingKey {
        case timestampMs = "timestamp_ms"
        case reachable
        case latencyMs = "latency_ms"
        case jitterMs = "jitter_ms"
        case packetLossPercent = "packet_loss_percent"
        case handshakeMs = "handshake_ms"
        case downloadBps = "download_bps"
        case uploadBps = "upload_bps"
        case failure
    }

    init(
        timestampMs: UInt64,
        reachable: Bool,
        latencyMs: Double? = nil,
        jitterMs: Double? = nil,
        packetLossPercent: Double? = nil,
        handshakeMs: Double? = nil,
        downloadBps: Double? = nil,
        uploadBps: Double? = nil,
        failure: String? = nil
    ) {
        self.timestampMs = timestampMs
        self.reachable = reachable
        self.latencyMs = latencyMs
        self.jitterMs = jitterMs
        self.packetLossPercent = packetLossPercent
        self.handshakeMs = handshakeMs
        self.downloadBps = downloadBps
        self.uploadBps = uploadBps
        self.failure = failure
    }
}

nonisolated struct KVNCandidateScoreBreakdownDTO: Codable, Sendable {
    let total: Double
    let latency: Double
    let jitter: Double
    let loss: Double
    let handshake: Double
    let reliability: Double
    let throughput: Double
    let protocolPreference: Double
    let priority: Double
    let penalties: Double
    let confidence: Double

    enum CodingKeys: String, CodingKey {
        case total, latency, jitter, loss, handshake, reliability, throughput
        case protocolPreference = "protocol_preference"
        case priority, penalties, confidence
    }
}

nonisolated struct KVNSelectionDecisionDTO: Codable, Sendable {
    let selected: String?
    let current: String?
    let shouldSwitch: Bool
    let currentScore: Double?
    let selectedScore: Double?
    let reason: KVNSelectionReason
    let timestampMs: UInt64
    let breakdown: KVNCandidateScoreBreakdownDTO?

    enum CodingKeys: String, CodingKey {
        case selected, current
        case shouldSwitch = "should_switch"
        case currentScore = "current_score"
        case selectedScore = "selected_score"
        case reason
        case timestampMs = "timestamp_ms"
        case breakdown
    }
}

nonisolated struct KVNCoreStatisticsDTO: Codable, Sendable {
    let currentCandidate: String?
    let currentScore: Double?
    let connectedSinceMs: UInt64?
    let totalSwitches: UInt64
    let reconnectCount: UInt64
    let latencyMs: Double?
    let jitterMs: Double?
    let lossPercent: Double?
    let bytesSent: UInt64
    let bytesReceived: UInt64
    let networkType: KVNNetworkType

    enum CodingKeys: String, CodingKey {
        case currentCandidate = "current_candidate"
        case currentScore = "current_score"
        case connectedSinceMs = "connected_since_ms"
        case totalSwitches = "total_switches"
        case reconnectCount = "reconnect_count"
        case latencyMs = "latency_ms"
        case jitterMs = "jitter_ms"
        case lossPercent = "loss_percent"
        case bytesSent = "bytes_sent"
        case bytesReceived = "bytes_received"
        case networkType = "network_type"
    }
}

nonisolated struct KVNRouteQueryDTO: Codable, Sendable {
    var domain: String?
    var ip: String?
    var region: String?
    var app: String?

    init(domain: String? = nil, ip: String? = nil, region: String? = nil, app: String? = nil) {
        self.domain = domain
        self.ip = ip
        self.region = region
        self.app = app
    }
}

nonisolated enum KVNRouteMatcherDTO: Encodable, Sendable {
    case exactDomain(String)
    case suffixDomain(String)
    case cidr(String)
    case regionTag(String)
    case appTag(String)
    case catchAll

    enum CodingKeys: String, CodingKey {
        case kind, value
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .exactDomain(let v):
            try container.encode("exact_domain", forKey: .kind)
            try container.encode(v, forKey: .value)
        case .suffixDomain(let v):
            try container.encode("suffix_domain", forKey: .kind)
            try container.encode(v, forKey: .value)
        case .cidr(let v):
            try container.encode("cidr", forKey: .kind)
            try container.encode(v, forKey: .value)
        case .regionTag(let v):
            try container.encode("region_tag", forKey: .kind)
            try container.encode(v, forKey: .value)
        case .appTag(let v):
            try container.encode("app_tag", forKey: .kind)
            try container.encode(v, forKey: .value)
        case .catchAll:
            try container.encode("catch_all", forKey: .kind)
        }
    }
}

nonisolated struct KVNRouteRuleDTO: Encodable, Sendable {
    var matcher: KVNRouteMatcherDTO
    var action: KVNRouteActionDTO
    var priority: Int32
}

// MARK: - Response envelope

/// Generic typed response envelope matching the Rust ABI:
/// `{ "schema_version": N, "ok": Bool, "data": T?, "error": {code,message}? }`.
nonisolated struct KVNEnvelope<Data: Decodable>: Decodable {
    let schemaVersion: UInt32
    let ok: Bool
    let data: Data?
    let error: KVNEnvelopeError?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case ok, data, error
    }
}

/// Envelope decode used when the concrete `data` type is not needed (checks
/// ok/schema/error only).
nonisolated struct KVNEnvelopeMeta: Decodable {
    let schemaVersion: UInt32
    let ok: Bool
    let error: KVNEnvelopeError?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case ok, error
    }
}

nonisolated struct KVNEnvelopeError: Decodable, Sendable {
    let code: String
    let message: String
}

nonisolated struct KVNStateResponse: Decodable, Sendable {
    let state: KVNConnectionStateDTO
}

nonisolated struct KVNRouteResponse: Decodable, Sendable {
    let action: KVNRouteActionDTO?
}

// MARK: - Request bodies (Encodable; each carries schema_version)

nonisolated struct KVNRegisterRequest: Encodable {
    let schemaVersion: UInt32
    let candidateID: String
    let profileID: String
    let endpoint: KVNEndpointDTO

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case candidateID = "candidate_id"
        case profileID = "profile_id"
        case endpoint
    }
}

nonisolated struct KVNCandidateIDRequest: Encodable {
    let schemaVersion: UInt32
    let candidateID: String

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case candidateID = "candidate_id"
    }
}

nonisolated struct KVNUpdateHealthRequest: Encodable {
    let schemaVersion: UInt32
    let candidateID: String
    let sample: KVNHealthSampleDTO

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case candidateID = "candidate_id"
        case sample
    }
}

nonisolated struct KVNSetNetworkTypeRequest: Encodable {
    let schemaVersion: UInt32
    let networkType: KVNNetworkType

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case networkType = "network_type"
    }
}

nonisolated struct KVNSetCurrentRequest: Encodable {
    let schemaVersion: UInt32
    let candidateID: String?
    let nowMs: UInt64

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case candidateID = "candidate_id"
        case nowMs = "now_ms"
    }
}

nonisolated struct KVNReportRequest: Encodable {
    let schemaVersion: UInt32
    let candidateID: String
    let nowMs: UInt64

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case candidateID = "candidate_id"
        case nowMs = "now_ms"
    }
}

nonisolated struct KVNNowRequest: Encodable {
    let schemaVersion: UInt32
    let nowMs: UInt64

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case nowMs = "now_ms"
    }
}

nonisolated struct KVNSchemaOnlyRequest: Encodable {
    let schemaVersion: UInt32

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
    }
}

nonisolated struct KVNSetRoutingRulesRequest: Encodable {
    let schemaVersion: UInt32
    let rules: [KVNRouteRuleDTO]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case rules
    }
}

nonisolated struct KVNResolveRouteRequest: Encodable {
    let schemaVersion: UInt32
    let query: KVNRouteQueryDTO

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case query
    }
}
