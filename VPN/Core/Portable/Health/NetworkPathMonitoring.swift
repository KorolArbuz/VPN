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

    static func smartConnectionContext(
        usesWiFi: Bool,
        usesCellular: Bool,
        usesEthernet: Bool,
        isExpensive: Bool,
        isConstrained: Bool,
        supportsIPv4: Bool,
        supportsIPv6: Bool
    ) -> NetworkContext {
        let interfaceClass: SmartConnectionInterfaceClass
        if usesWiFi {
            interfaceClass = .wifi
        } else if usesCellular {
            interfaceClass = .cellular
        } else if usesEthernet {
            interfaceClass = .wiredEthernet
        } else {
            interfaceClass = .other
        }

        return NetworkContext(
            interfaceClass: interfaceClass,
            isExpensive: isExpensive,
            isConstrained: isConstrained,
            supportsIPv4: supportsIPv4,
            supportsIPv6: supportsIPv6
        )
    }

    static func smartConnectionContext(for path: NWPath) -> NetworkContext {
        smartConnectionContext(
            usesWiFi: path.usesInterfaceType(.wifi),
            usesCellular: path.usesInterfaceType(.cellular),
            usesEthernet: path.usesInterfaceType(.wiredEthernet),
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained,
            supportsIPv4: path.supportsIPv4,
            supportsIPv6: path.supportsIPv6
        )
    }
}

nonisolated final class AppleNetworkPathMonitor:
    NetworkPathMonitoring,
    SmartConnectionNetworkContextProviding,
    @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "su.24kvn.network-path-monitor", qos: .utility)
    private let storage = NetworkPathTypeStorage()

    init() {
        let storage = storage
        monitor.pathUpdateHandler = { path in
            Task {
                await storage.set(
                    networkType: NetworkPathTypeMapper.type(for: path),
                    context: NetworkPathTypeMapper.smartConnectionContext(for: path)
                )
            }
        }
        monitor.start(queue: queue)
        Task {
            let path = monitor.currentPath
            await storage.set(
                networkType: NetworkPathTypeMapper.type(for: path),
                context: NetworkPathTypeMapper.smartConnectionContext(for: path)
            )
        }
    }

    func currentNetworkType() async -> KVNNetworkType {
        await storage.networkType
    }

    func currentNetworkContext() async -> NetworkContext {
        await storage.context
    }

    func networkContextUpdates() -> AsyncStream<NetworkContext> {
        let storage = storage
        return AsyncStream { continuation in
            let id = UUID()
            Task {
                await storage.addContinuation(continuation, id: id)
            }
            continuation.onTermination = { _ in
                Task {
                    await storage.removeContinuation(id: id)
                }
            }
        }
    }

    func cancel() async {
        monitor.cancel()
    }
}

private actor NetworkPathTypeStorage {
    private(set) var networkType: KVNNetworkType = .unknown
    private(set) var context: NetworkContext = .unknown
    private var contextContinuations: [UUID: AsyncStream<NetworkContext>.Continuation] = [:]

    func set(networkType: KVNNetworkType, context: NetworkContext) {
        self.networkType = networkType
        guard self.context != context else {
            return
        }
        self.context = context
        for continuation in contextContinuations.values {
            continuation.yield(context)
        }
    }

    func addContinuation(
        _ continuation: AsyncStream<NetworkContext>.Continuation,
        id: UUID
    ) {
        contextContinuations[id] = continuation
        continuation.yield(context)
    }

    func removeContinuation(id: UUID) {
        contextContinuations[id] = nil
    }
}
