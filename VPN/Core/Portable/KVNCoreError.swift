//
//  KVNCoreError.swift
//  VPN
//
//  Typed Swift errors for the KVNCore C ABI bridge. Mirrors the stable status
//  codes in kvn_core.h. Never surfaces raw Rust debug output.
//

import Foundation

/// Stable status codes from the C ABI (mirror of `KVN_CORE_*` in kvn_core.h).
/// Declared explicitly so the bridge does not depend on how the Clang importer
/// exposes the C `#define` macros.
nonisolated enum KVNCoreStatus: Int32, Sendable {
    case ok = 0
    case invalidArgument = 1
    case invalidHandle = 2
    case invalidUTF8 = 3
    case invalidJSON = 4
    case schemaMismatch = 5
    case notFound = 6
    case invalidState = 7
    case internalError = 8
    case panic = 9
}

nonisolated enum KVNCoreError: Error, Equatable, Sendable {
    /// `kvn_core_create` returned null.
    case coreCreationFailed
    /// The linked core's ABI version does not match what the bridge expects.
    case abiMismatch(expected: UInt32, actual: UInt32)
    /// The linked core's schema version does not match what the bridge expects.
    case schemaMismatch(expected: UInt32, actual: UInt32)

    // Mapped C status codes.
    case invalidArgument(String?)
    case invalidHandle
    case invalidUTF8
    case invalidJSON(String?)
    case schemaMismatchResponse
    case notFound(String?)
    case invalidState(String?)
    case internalError(String?)
    case panic

    // Bridge-side failures.
    case requestEncodingFailed
    case responseDecodingFailed(String)
    case malformedResponse(String)
    case unknownStatus(Int32)

    /// Maps a raw C status code (+ optional sanitized message) to a typed case.
    static func from(status: Int32, message: String?) -> KVNCoreError {
        switch KVNCoreStatus(rawValue: status) {
        case .ok: return .malformedResponse("ok status treated as error")
        case .invalidArgument: return .invalidArgument(message)
        case .invalidHandle: return .invalidHandle
        case .invalidUTF8: return .invalidUTF8
        case .invalidJSON: return .invalidJSON(message)
        case .schemaMismatch: return .schemaMismatchResponse
        case .notFound: return .notFound(message)
        case .invalidState: return .invalidState(message)
        case .internalError: return .internalError(message)
        case .panic: return .panic
        case nil: return .unknownStatus(status)
        }
    }
}
