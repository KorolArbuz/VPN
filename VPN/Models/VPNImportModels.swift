//
//  VPNImportModels.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum VPNImportKind: Codable, Hashable, Sendable {
    case profile(VPNProfile)
    case subscription(VPNSubscription)
}

nonisolated struct VPNImportResult: Identifiable, Codable, Hashable, Sendable {
    var id: UUID
    var kind: VPNImportKind
    var detectedScheme: String
    var displayName: String
    var warnings: [String]
    var sanitizedSummary: [String: String]

    init(
        id: UUID = UUID(),
        kind: VPNImportKind,
        detectedScheme: String,
        displayName: String,
        warnings: [String] = [],
        sanitizedSummary: [String: String] = [:]
    ) {
        self.id = id
        self.kind = kind
        self.detectedScheme = detectedScheme
        self.displayName = displayName
        self.warnings = warnings
        self.sanitizedSummary = sanitizedSummary
    }
}

nonisolated enum VPNImportError: LocalizedError, Equatable, Sendable {
    case emptyInput
    case malformedURL
    case unsupportedScheme(String)
    case missingRequiredComponent(String)
    case invalidPort
    case invalidBase64Payload
    case invalidPayload(String)

    var errorDescription: String? {
        switch self {
        case .emptyInput:
            "Enter a VPN link."
        case .malformedURL:
            "The link is malformed."
        case .unsupportedScheme(let scheme):
            "Unsupported scheme: \(scheme)."
        case .missingRequiredComponent(let component):
            "Missing required component: \(component)."
        case .invalidPort:
            "The port is invalid."
        case .invalidBase64Payload:
            "The Base64 payload is invalid."
        case .invalidPayload(let reason):
            reason
        }
    }
}
