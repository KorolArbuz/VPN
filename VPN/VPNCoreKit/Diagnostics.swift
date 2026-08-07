//
//  Diagnostics.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated struct SanitizedCoreLogger: Sendable {
    var isDeveloperMode: Bool

    init(isDeveloperMode: Bool = false) {
        self.isDeveloperMode = isDeveloperMode
    }

    func log(_ error: CoreError, configuration: CoreConfiguration?) {
        _ = sanitizedMessage(error, configuration: configuration)
    }

    func sanitizedMessage(_ error: CoreError, configuration: CoreConfiguration?) -> String {
        var components = ["error=\(error.localizedDescription)"]
        if let configuration {
            components.append("protocol=\(configuration.protocolType.rawValue)")
            if isDeveloperMode {
                components.append("host=\(configuration.endpoint.host)")
            }
            components.append("credential=\(SecretMasker.masked(configuration.credentialReference))")
            components.append("metadataKeys=\(configuration.metadata.keys.sorted().joined(separator: ","))")
        }
        return components.joined(separator: " ")
    }
}

nonisolated struct CoreDiagnosticSnapshot: Codable, Hashable, Sendable {
    var backendIdentifier: String?
    var protocolType: CoreProtocol?
    var state: CoreState
    var createdAt: Date
    var sanitizedError: String?
    var statistics: CoreStatistics
}
