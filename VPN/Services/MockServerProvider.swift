//
//  MockServerProvider.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct MockServerProvider: ServerProviding {
    let servers: [VPNServer]

    init(servers: [VPNServer] = MockServerCatalog.servers) {
        self.servers = servers
    }

    func fetchServers() async throws -> [VPNServer] {
        try await Task.sleep(for: .milliseconds(120))
        return servers
    }
}
