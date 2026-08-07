//
//  PlaceholderBackends.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated struct UnavailableCoreBackend: VPNCoreBackend {
    let identifier: String
    let supportedProtocols: Set<CoreProtocol>
    let events: AsyncStream<CoreEvent> = AsyncStream { _ in }

    func prepare(configuration: CoreConfiguration) async throws {
        throw CoreError.backendUnavailable(identifier)
    }

    func start() async throws {
        throw CoreError.backendUnavailable(identifier)
    }

    func stop() async {}

    func statistics() async -> CoreStatistics {
        .empty
    }
}

nonisolated struct XrayCoreBackendFactory: VPNCoreBackendFactory {
    let identifier = "xray-core-backend"
    let supportedProtocols: Set<CoreProtocol> = [.vless, .trojan, .vmess]
    func makeBackend() -> VPNCoreBackend { UnavailableCoreBackend(identifier: identifier, supportedProtocols: supportedProtocols) }
}

nonisolated struct HysteriaCoreBackendFactory: VPNCoreBackendFactory {
    let identifier = "hysteria-core-backend"
    let supportedProtocols: Set<CoreProtocol> = [.hysteria2]
    func makeBackend() -> VPNCoreBackend { UnavailableCoreBackend(identifier: identifier, supportedProtocols: supportedProtocols) }
}

nonisolated struct WireGuardCoreBackendFactory: VPNCoreBackendFactory {
    let identifier = "wireguard-core-backend"
    let supportedProtocols: Set<CoreProtocol> = [.wireGuard]
    func makeBackend() -> VPNCoreBackend { UnavailableCoreBackend(identifier: identifier, supportedProtocols: supportedProtocols) }
}
