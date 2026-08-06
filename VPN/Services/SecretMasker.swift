//
//  SecretMasker.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum SecretMasker {
    static let sensitiveQueryNames: Set<String> = [
        "password", "pass", "passwd", "pwd", "key", "privatekey", "private_key",
        "token", "uuid", "id", "secret", "psk", "auth", "publickey", "pbk"
    ]

    static func masked(_ value: String?) -> String {
        guard let value, value.isEmpty == false else {
            return "None"
        }

        if value.count <= 4 {
            return "••••"
        }

        return "••••" + value.suffix(4)
    }

    static func sanitizedQuerySummary(from queryItems: [URLQueryItem]) -> [String: String] {
        var summary: [String: String] = [:]

        for item in queryItems {
            let key = item.name
            let lowercasedKey = key.lowercased()
            if sensitiveQueryNames.contains(lowercasedKey) {
                summary[key] = "••••"
            } else {
                summary[key] = item.value ?? ""
            }
        }

        return summary
    }
}

extension VPNProfile {
    var maskedCredentialText: String {
        credentialReference == nil ? "None" : "Stored securely"
    }
}
