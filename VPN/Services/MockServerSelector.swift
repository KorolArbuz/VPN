//
//  MockServerSelector.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct MockServerSelector: ServerSelecting {
    private let policy: ServerSelectionPolicy

    init(policy: ServerSelectionPolicy = .default) {
        self.policy = policy
    }

    func bestServer(from servers: [VPNServer], using prober: ServerProbing) async throws -> VPNServer {
        let availableServers = servers.filter(\.isAvailable)

        guard availableServers.isEmpty == false else {
            throw MockVPNError.noAvailableServers
        }

        var bestCandidate: (server: VPNServer, score: Double)?

        for server in availableServers {
            let metrics = try await prober.metrics(for: server)
            let score = policy.score(metrics: metrics, isAvailable: server.isAvailable)

            if let candidate = bestCandidate {
                if score < candidate.score {
                    bestCandidate = (server, score)
                }
            } else {
                bestCandidate = (server, score)
            }
        }

        guard let bestServer = bestCandidate?.server else {
            throw MockVPNError.noAvailableServers
        }

        return bestServer
    }

    func automaticProtocol(for server: VPNServer) -> VPNProtocol? {
        server.supportedProtocols.min { first, second in
            first.automaticPriority < second.automaticPriority
        }
    }

}
