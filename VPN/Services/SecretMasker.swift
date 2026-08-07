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

        if value.contains("-"), value.count >= 8 {
            return "••••••••-••••"
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

    static func sanitizedURLDisplay(_ url: URL) -> String {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return url.host ?? "Subscription URL"
        }

        components.user = components.user == nil ? nil : "••••"
        components.password = components.password == nil ? nil : "••••"
        components.queryItems = components.queryItems?.map { item in
            let lowercasedKey = item.name.lowercased()
            if sensitiveQueryNames.contains(lowercasedKey) {
                return URLQueryItem(name: item.name, value: "••••")
            }
            return item
        }

        return components.string ?? (url.host ?? "Subscription URL")
    }

    static func sanitizedHost(from url: URL) -> String {
        url.host ?? "Subscription"
    }
}

extension VPNProfile {
    var maskedCredentialText: String {
        credentialReference == nil ? "None" : "Stored securely"
    }
}
