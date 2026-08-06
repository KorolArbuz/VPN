//
//  CredentialStoring.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated protocol CredentialStoring: Sendable {
    func store(_ secret: String, label: String) async throws -> String
}

actor InMemoryCredentialStore: CredentialStoring {
    private var secrets: [String: String] = [:]

    func store(_ secret: String, label: String) async throws -> String {
        let reference = "memory://credential/\(UUID().uuidString)"
        secrets[reference] = secret
        return reference
    }

    func secret(for reference: String) -> String? {
        secrets[reference]
    }
}
