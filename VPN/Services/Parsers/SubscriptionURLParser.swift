//
//  SubscriptionURLParser.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct SubscriptionURLParser {
    func parse(_ text: String) throws -> VPNImportResult {
        guard let url = URL(string: text), let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme) else {
            throw VPNImportError.malformedURL
        }

        guard url.host?.isEmpty == false else {
            throw VPNImportError.missingRequiredComponent("host")
        }

        let name = url.host ?? "Subscription"
        let subscription = VPNSubscription(name: name, url: url)

        return VPNImportResult(
            kind: .subscription(subscription),
            detectedScheme: scheme,
            displayName: name,
            warnings: ["Subscription URL recognized. Refresh is a separate explicit action."],
            sanitizedSummary: [
                "type": "Subscription",
                "host": url.host ?? ""
            ]
        )
    }
}
