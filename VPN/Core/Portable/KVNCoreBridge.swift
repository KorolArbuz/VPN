//
//  KVNCoreBridge.swift
//  VPN
//
//  Thin, typed Swift wrapper over the KVNCore C ABI. Owns exactly one opaque
//  KVNCoreHandle and is the ONLY place that talks to the C functions. SwiftUI
//  never calls the C API directly.
//
//  Ownership: the handle is created in init and destroyed exactly once in
//  deinit. Every response string returned by the core is released with
//  kvn_core_free_string. The static version string is never freed.
//
//  Threading: this type is `@unchecked Sendable` with `nonisolated` methods;
//  the underlying core serializes access with its own mutex. The higher-level
//  `PortableCoreService` actor provides the app-facing serialization boundary.
//

import Foundation
import KVNCore

nonisolated final class KVNCoreBridge: @unchecked Sendable {
    static let expectedABIVersion: UInt32 = 1
    static let expectedSchemaVersion: UInt32 = 1

    private typealias JSONFunction = (
        OpaquePointer?,
        UnsafePointer<CChar>?,
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
    ) -> Int32

    private let handle: OpaquePointer
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    /// Creates the core and validates ABI + schema compatibility. Throws a
    /// typed error (and never leaks the handle) on any mismatch.
    init() throws {
        guard let created = kvn_core_create() else {
            throw KVNCoreError.coreCreationFailed
        }

        let abi = kvn_core_abi_version()
        guard abi == Self.expectedABIVersion else {
            kvn_core_destroy(created)
            throw KVNCoreError.abiMismatch(expected: Self.expectedABIVersion, actual: abi)
        }

        let schema = kvn_core_schema_version()
        guard schema == Self.expectedSchemaVersion else {
            kvn_core_destroy(created)
            throw KVNCoreError.schemaMismatch(expected: Self.expectedSchemaVersion, actual: schema)
        }

        self.handle = created
    }

    deinit {
        kvn_core_destroy(handle)
    }

    /// Static version string owned by the library; not freed here.
    var coreVersion: String {
        guard let pointer = kvn_core_version() else { return "" }
        return String(cString: pointer)
    }

    var abiVersion: UInt32 { kvn_core_abi_version() }
    var schemaVersion: UInt32 { kvn_core_schema_version() }

    /// Most recent sanitized error message for this handle, if any.
    var lastError: String? {
        guard let pointer = kvn_core_last_error(handle) else { return nil }
        defer { kvn_core_free_string(pointer) }
        return String(cString: pointer)
    }

    // MARK: - Candidate lifecycle

    func registerCandidate(_ candidate: KVNCandidateDTO) throws {
        let request = KVNRegisterRequest(
            schemaVersion: Self.expectedSchemaVersion,
            candidateID: candidate.candidateID,
            profileID: candidate.profileID,
            endpoint: candidate.endpoint
        )
        try performVoid(kvn_core_register_candidate, request)
    }

    func updateCandidate(_ candidate: KVNCandidateDTO) throws {
        // Rust update_candidate takes { candidate_id, endpoint }; reuse register
        // shape minus profile_id via a dedicated request.
        struct UpdateRequest: Encodable {
            let schemaVersion: UInt32
            let candidateID: String
            let endpoint: KVNEndpointDTO
            enum CodingKeys: String, CodingKey {
                case schemaVersion = "schema_version"
                case candidateID = "candidate_id"
                case endpoint
            }
        }
        let request = UpdateRequest(
            schemaVersion: Self.expectedSchemaVersion,
            candidateID: candidate.candidateID,
            endpoint: candidate.endpoint
        )
        try performVoid(kvn_core_update_candidate, request)
    }

    func removeCandidate(id: String) throws {
        try performVoid(kvn_core_remove_candidate, candidateIDRequest(id))
    }

    // MARK: - Signals

    func updateHealth(candidateID: String, sample: KVNHealthSampleDTO) throws {
        let request = KVNUpdateHealthRequest(
            schemaVersion: Self.expectedSchemaVersion,
            candidateID: candidateID,
            sample: sample
        )
        try performVoid(kvn_core_update_health, request)
    }

    func setNetworkType(_ type: KVNNetworkType) throws {
        let request = KVNSetNetworkTypeRequest(schemaVersion: Self.expectedSchemaVersion, networkType: type)
        try performVoid(kvn_core_set_network_type, request)
    }

    func setCurrentCandidate(id: String?, nowMs: UInt64) throws {
        let request = KVNSetCurrentRequest(schemaVersion: Self.expectedSchemaVersion, candidateID: id, nowMs: nowMs)
        try performVoid(kvn_core_set_current_candidate, request)
    }

    func reportSuccess(candidateID: String, nowMs: UInt64) throws {
        try performVoid(kvn_core_report_success, reportRequest(candidateID, nowMs))
    }

    func reportFailure(candidateID: String, nowMs: UInt64) throws {
        try performVoid(kvn_core_report_failure, reportRequest(candidateID, nowMs))
    }

    // MARK: - Decisions / queries

    func selectBest(nowMs: UInt64) throws -> KVNSelectionDecisionDTO {
        try perform(kvn_core_select_best, nowRequest(nowMs), as: KVNSelectionDecisionDTO.self)
    }

    func state() throws -> KVNConnectionStateDTO {
        try perform(kvn_core_get_state, KVNSchemaOnlyRequest(schemaVersion: Self.expectedSchemaVersion), as: KVNStateResponse.self).state
    }

    func statistics(nowMs: UInt64) throws -> KVNCoreStatisticsDTO {
        try perform(kvn_core_get_statistics, nowRequest(nowMs), as: KVNCoreStatisticsDTO.self)
    }

    func setRoutingRules(_ rules: [KVNRouteRuleDTO]) throws {
        let request = KVNSetRoutingRulesRequest(schemaVersion: Self.expectedSchemaVersion, rules: rules)
        try performVoid(kvn_core_set_routing_rules, request)
    }

    func resolveRoute(_ query: KVNRouteQueryDTO) throws -> KVNRouteActionDTO? {
        let request = KVNResolveRouteRequest(schemaVersion: Self.expectedSchemaVersion, query: query)
        return try perform(kvn_core_resolve_route, request, as: KVNRouteResponse.self).action
    }

    // MARK: - Request helpers

    private func candidateIDRequest(_ id: String) -> KVNCandidateIDRequest {
        KVNCandidateIDRequest(schemaVersion: Self.expectedSchemaVersion, candidateID: id)
    }

    private func reportRequest(_ id: String, _ nowMs: UInt64) -> KVNReportRequest {
        KVNReportRequest(schemaVersion: Self.expectedSchemaVersion, candidateID: id, nowMs: nowMs)
    }

    private func nowRequest(_ nowMs: UInt64) -> KVNNowRequest {
        KVNNowRequest(schemaVersion: Self.expectedSchemaVersion, nowMs: nowMs)
    }

    // MARK: - Core dispatch

    /// Encodes a request, invokes the C function, validates the envelope, and
    /// returns the raw response body. Always frees the Rust-owned string.
    private func performData(_ function: JSONFunction, _ request: some Encodable) throws -> Data {
        let requestData = try encoder.encode(request)
        guard let requestString = String(data: requestData, encoding: .utf8) else {
            throw KVNCoreError.requestEncodingFailed
        }

        var out: UnsafeMutablePointer<CChar>?
        let status = requestString.withCString { cRequest in
            function(handle, cRequest, &out)
        }
        defer {
            if let out {
                kvn_core_free_string(out)
            }
        }

        guard let out else {
            if status == KVNCoreStatus.ok.rawValue {
                return Data()
            }
            throw KVNCoreError.from(status: status, message: nil)
        }

        let body = Data(String(cString: out).utf8)
        let meta = try decoder.decode(KVNEnvelopeMeta.self, from: body)

        guard meta.schemaVersion == Self.expectedSchemaVersion else {
            throw KVNCoreError.schemaMismatchResponse
        }
        guard status == KVNCoreStatus.ok.rawValue, meta.ok else {
            throw KVNCoreError.from(status: status, message: meta.error?.message)
        }
        return body
    }

    private func perform<Response: Decodable>(
        _ function: JSONFunction,
        _ request: some Encodable,
        as: Response.Type
    ) throws -> Response {
        let body = try performData(function, request)
        let envelope: KVNEnvelope<Response>
        do {
            envelope = try decoder.decode(KVNEnvelope<Response>.self, from: body)
        } catch {
            throw KVNCoreError.responseDecodingFailed(String(describing: Response.self))
        }
        guard let data = envelope.data else {
            throw KVNCoreError.malformedResponse("missing data for \(Response.self)")
        }
        return data
    }

    private func performVoid(_ function: JSONFunction, _ request: some Encodable) throws {
        _ = try performData(function, request)
    }
}
