//
//  CoreBackend.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated protocol VPNCoreBackend: Sendable {
    var identifier: String { get }
    var supportedProtocols: Set<CoreProtocol> { get }
    var events: AsyncStream<CoreEvent> { get }

    func prepare(configuration: CoreConfiguration) async throws
    func start() async throws
    func stop() async
    func statistics() async -> CoreStatistics
}

nonisolated protocol VPNCoreBackendFactory: Sendable {
    var identifier: String { get }
    var supportedProtocols: Set<CoreProtocol> { get }
    func makeBackend() -> VPNCoreBackend
}

nonisolated struct VPNCoreBackendRegistry: Sendable {
    private let factories: [any VPNCoreBackendFactory]

    init(factories: [any VPNCoreBackendFactory]) {
        self.factories = factories
    }

    func backend(for coreProtocol: CoreProtocol) throws -> VPNCoreBackend {
        guard let factory = factories.first(where: { $0.supportedProtocols.contains(coreProtocol) }) else {
            throw CoreError.unsupportedProtocol(coreProtocol)
        }

        return factory.makeBackend()
    }
}
