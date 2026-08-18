//
//  PacketTunnelProvider.swift
//  PacketTunnelExtension
//
//  Created by Denis Chizhov on 07.08.2026.
//

import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let telemetryStore = TunnelTelemetryStore()
    private lazy var runtimeValidationLoader = PacketTunnelRuntimeConfigurationValidationLoader.appGroupLoader(provider: self)
    #if DEBUG
    private lazy var xrayRuntimeController: XrayRuntimeLifecycleController? = {
        guard let runtimeValidationLoader else {
            return nil
        }
        return XrayRuntimeLifecycleController(
            runtimeConfigurationLoader: runtimeValidationLoader,
            networkSettingsApplier: PacketTunnelNetworkSettingsApplier(provider: self),
            tunnelCancellationHandler: { [weak self] error in
                self?.cancelTunnelWithError(error)
            },
            telemetryStore: telemetryStore
        )
    }()
    private lazy var xrayConfigurationValidator: (any XrayConfigurationValidating)? = {
        xrayRuntimeController
    }()
    private lazy var xrayLifecycleSmokeTester: (any XrayLifecycleSmokeTesting)? = {
        guard let xrayRuntimeController else {
            return nil
        }
        return PacketTunnelXrayLifecycleSmokeTestService(controller: xrayRuntimeController)
    }()
    private lazy var xrayRemoteEgressProbe: (any XrayRemoteEgressProbing)? = {
        guard let xrayRuntimeController else {
            return nil
        }
        return PacketTunnelXrayRemoteEgressProbeService(controller: xrayRuntimeController)
    }()
    private lazy var udpControlProbe: (any PacketTunnelUDPControlProbing)? = {
        guard let xrayRuntimeController else {
            return nil
        }
        return PacketTunnelUDPControlProbeService(controller: xrayRuntimeController)
    }()
    private lazy var libXrayPingProbe: (any LibXrayPingProbing)? = {
        guard let xrayRuntimeController else {
            return nil
        }
        return PacketTunnelLibXrayPingProbeService(controller: xrayRuntimeController)
    }()
    #else
    private let xrayConfigurationValidator: (any XrayConfigurationValidating)? = nil
    private let xrayLifecycleSmokeTester: (any XrayLifecycleSmokeTesting)? = nil
    private let xrayRemoteEgressProbe: (any XrayRemoteEgressProbing)? = nil
    private let udpControlProbe: (any PacketTunnelUDPControlProbing)? = nil
    private let libXrayPingProbe: (any LibXrayPingProbing)? = nil
    #endif
    private lazy var appMessageHandler = TunnelAppMessageHandler(
        telemetryStore: telemetryStore,
        snapshotStore: TunnelTelemetrySnapshotStore.appGroupStore(),
        keychainSentinelReader: KeychainTunnelKeychainSentinelReader(),
        runtimeValidationLoader: runtimeValidationLoader,
        xrayConfigurationValidator: xrayConfigurationValidator,
        xrayLifecycleSmokeTester: xrayLifecycleSmokeTester,
        xrayRemoteEgressProbe: xrayRemoteEgressProbe,
        udpControlProbe: udpControlProbe,
        libXrayPingProbe: libXrayPingProbe,
        diagnosticProviderModeProvider: xrayRuntimeController
    )

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        #if DEBUG
        let libXrayPingOnlyOptions = LibXrayPingOnlyPacketTunnelStartOptions(options)
        if libXrayPingOnlyOptions.containsLibXrayPingOnlyConfiguration {
            guard libXrayPingOnlyOptions.isValid else {
                completionHandler(PacketTunnelRuntimeOnlyError.error(stage: .preStartState, category: .internalRuntimeError))
                return
            }
            guard let xrayRuntimeController else {
                completionHandler(PacketTunnelRuntimeOnlyError.error(stage: .runtimeConfiguration, category: .runtimeConfigurationInvalid))
                return
            }

            Task { [telemetryStore] in
                let result = await xrayRuntimeController.startPacketTunnelLibXrayPingOnly(correlationID: UUID())
                if result.success {
                    completionHandler(nil)
                } else {
                    await telemetryStore.markStopped()
                    completionHandler(PacketTunnelRuntimeOnlyError.error(
                        stage: result.failureStage ?? .unknown,
                        category: result.failureCategory ?? .unknown
                    ))
                }
            }
            return
        }

        let dataPlaneOptions = DataPlanePacketTunnelStartOptions(options)
        if dataPlaneOptions.containsDataPlaneConfiguration {
            guard dataPlaneOptions.isValid else {
                completionHandler(PacketTunnelRuntimeOnlyError.error(stage: .dataPlane, category: .internalRuntimeError))
                return
            }
            guard let xrayRuntimeController else {
                completionHandler(PacketTunnelRuntimeOnlyError.error(stage: .runtimeConfiguration, category: .runtimeConfigurationInvalid))
                return
            }

            Task { [telemetryStore] in
                let result = await xrayRuntimeController.startPacketTunnelDataPlane(correlationID: UUID())
                if result.success {
                    completionHandler(nil)
                } else {
                    await telemetryStore.markDataPlaneFailure(category: .tun2SocksStartupFailed)
                    completionHandler(PacketTunnelRuntimeOnlyError.error(
                        stage: result.failureStage ?? .unknown,
                        category: result.failureCategory ?? .unknown
                    ))
                }
            }
            return
        }

        let runtimeOnlyOptions = RuntimeOnlyPacketTunnelStartOptions(options)
        if runtimeOnlyOptions.containsRuntimeOnlyConfiguration {
            guard runtimeOnlyOptions.isValid else {
                completionHandler(PacketTunnelRuntimeOnlyError.error(stage: .preStartState, category: .internalRuntimeError))
                return
            }
            guard let xrayRuntimeController else {
                completionHandler(PacketTunnelRuntimeOnlyError.error(stage: .runtimeConfiguration, category: .runtimeConfigurationInvalid))
                return
            }

            Task { [telemetryStore] in
                let result = await xrayRuntimeController.startPacketTunnelRuntimeOnly(correlationID: UUID())
                if result.success {
                    completionHandler(nil)
                } else {
                    await telemetryStore.markStopped()
                    completionHandler(PacketTunnelRuntimeOnlyError.error(
                        stage: result.failureStage ?? .unknown,
                        category: result.failureCategory ?? .unknown
                    ))
                }
            }
            return
        }
        #endif
        // Add code here to start the process of connecting the tunnel.
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Add code here to start the process of stopping the tunnel.
        Task { [telemetryStore] in
            #if DEBUG
            if let xrayRuntimeController {
                _ = await xrayRuntimeController.stopActivePacketTunnelSession(correlationID: UUID())
            }
            #endif
            await telemetryStore.markStopped()
            completionHandler()
        }
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler else {
            return
        }

        let handler = appMessageHandler
        Task {
            let response = await handler.handle(messageData)
            completionHandler(response)
        }
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        // Add code here to get ready to sleep.
        completionHandler()
    }
    
    override func wake() {
        // Add code here to wake up.
    }
}

#if DEBUG
private struct DataPlanePacketTunnelStartOptions {
    static let dataPlaneKey = "kvn.debug.dataPlane"
    static let allowedKeys: Set<String> = [dataPlaneKey]

    let containsDataPlaneConfiguration: Bool
    let isValid: Bool

    init(_ options: [String: NSObject]?) {
        let options = options ?? [:]
        let containsKnownMarker = options.keys.contains(Self.dataPlaneKey)
        containsDataPlaneConfiguration = containsKnownMarker
        let unknownKeys = options.keys.filter { Self.allowedKeys.contains($0) == false && $0.hasPrefix("kvn.debug.") }
        guard unknownKeys.isEmpty, containsKnownMarker else {
            isValid = false
            return
        }
        guard let marker = options[Self.dataPlaneKey] as? NSNumber else {
            isValid = false
            return
        }
        isValid = marker.boolValue == true
    }
}

private struct RuntimeOnlyPacketTunnelStartOptions {
    static let runtimeOnlyKey = "kvn.debug.runtimeOnly"
    static let allowedKeys: Set<String> = [runtimeOnlyKey]

    let containsRuntimeOnlyConfiguration: Bool
    let isValid: Bool

    init(_ options: [String: NSObject]?) {
        let options = options ?? [:]
        let containsKnownMarker = options.keys.contains(Self.runtimeOnlyKey)
        let containsDebugOption = options.keys.contains { key in
            key.hasPrefix("kvn.debug.")
        }
        containsRuntimeOnlyConfiguration = containsKnownMarker || containsDebugOption
        let unknownKeys = options.keys.filter { Self.allowedKeys.contains($0) == false && $0.hasPrefix("kvn.debug.") }
        guard unknownKeys.isEmpty, containsKnownMarker else {
            isValid = false
            return
        }
        guard let marker = options[Self.runtimeOnlyKey] as? NSNumber else {
            isValid = false
            return
        }
        isValid = marker.boolValue == true
    }
}

private struct LibXrayPingOnlyPacketTunnelStartOptions {
    static let libXrayPingOnlyKey = "kvn.debug.libXrayPingOnly"
    static let allowedKeys: Set<String> = [libXrayPingOnlyKey]

    let containsLibXrayPingOnlyConfiguration: Bool
    let isValid: Bool

    init(_ options: [String: NSObject]?) {
        let options = options ?? [:]
        let containsKnownMarker = options.keys.contains(Self.libXrayPingOnlyKey)
        containsLibXrayPingOnlyConfiguration = containsKnownMarker
        let unknownKeys = options.keys.filter { Self.allowedKeys.contains($0) == false && $0.hasPrefix("kvn.debug.") }
        guard unknownKeys.isEmpty, containsKnownMarker else {
            isValid = false
            return
        }
        guard let marker = options[Self.libXrayPingOnlyKey] as? NSNumber else {
            isValid = false
            return
        }
        isValid = marker.boolValue == true
    }
}

private enum PacketTunnelRuntimeOnlyError {
    static func error(
        stage: TunnelXrayLifecycleSmokeTestStage,
        category: TunnelXrayLifecycleSmokeTestCategory
    ) -> NSError {
        NSError(
            domain: "su.24kvn.packet-tunnel.runtime-only",
            code: 1,
            userInfo: [
                NSLocalizedDescriptionKey: "Runtime-only tunnel failed at \(stage.rawValue) with \(category.rawValue)"
            ]
        )
    }
}
#endif
