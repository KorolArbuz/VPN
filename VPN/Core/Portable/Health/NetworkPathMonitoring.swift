//
//  NetworkPathMonitoring.swift
//  VPN
//
//  App-process network type observation for feeding KVNCore policy. This does
//  not trigger reconnects in Phase F1.
//

import Foundation
import Network

nonisolated protocol NetworkPathMonitoring: Sendable {
    func currentNetworkType() async -> KVNNetworkType
    func cancel() async
}

nonisolated enum NetworkPathTypeMapper {
    static func type(usesWiFi: Bool, usesCellular: Bool, usesEthernet: Bool) -> KVNNetworkType {
        if usesWiFi {
            return .wifi
        }

        if usesCellular {
            return .cellular
        }

        if usesEthernet {
            return .ethernet
        }

        return .unknown
    }

    static func type(for path: NWPath) -> KVNNetworkType {
        type(
            usesWiFi: path.usesInterfaceType(.wifi),
            usesCellular: path.usesInterfaceType(.cellular),
            usesEthernet: path.usesInterfaceType(.wiredEthernet)
        )
    }
}

nonisolated final class AppleNetworkPathMonitor: NetworkPathMonitoring, @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "su.24kvn.network-path-monitor", qos: .utility)
    private let storage = NetworkPathTypeStorage()

    init() {
        let storage = storage
        monitor.pathUpdateHandler = { path in
            Task {
                await storage.set(NetworkPathTypeMapper.type(for: path))
            }
        }
        monitor.start(queue: queue)
        Task {
            await storage.set(NetworkPathTypeMapper.type(for: monitor.currentPath))
        }
    }

    func currentNetworkType() async -> KVNNetworkType {
        await storage.value
    }

    func cancel() async {
        monitor.cancel()
    }
}

private actor NetworkPathTypeStorage {
    private(set) var value: KVNNetworkType = .unknown

    func set(_ type: KVNNetworkType) {
        value = type
    }
}
