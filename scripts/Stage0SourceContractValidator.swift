import Darwin
import Foundation

private struct ValidationFailure: Error, CustomStringConvertible {
    let description: String
}

private var assertionCount = 0

private func requireFile(_ root: URL, _ relativePath: String) throws -> String {
    let url = root.appendingPathComponent(relativePath)
    guard FileManager.default.fileExists(atPath: url.path) else {
        throw ValidationFailure(description: "Required repository file is missing: \(relativePath)")
    }
    do {
        return try String(contentsOf: url, encoding: .utf8)
    } catch {
        throw ValidationFailure(description: "Could not read \(relativePath): \(error)")
    }
}

private func requireContains(
    _ text: String,
    file: String,
    markers: [String]
) throws {
    for marker in markers {
        assertionCount += 1
        guard text.contains(marker) else {
            throw ValidationFailure(
                description: "\(file) no longer satisfies the Stage 0 source contract; missing marker: \(marker)"
            )
        }
    }
}

private func requireExcludes(
    _ text: String,
    file: String,
    markers: [String]
) throws {
    for marker in markers {
        assertionCount += 1
        guard !text.contains(marker) else {
            throw ValidationFailure(
                description: "\(file) no longer satisfies the Stage 0 source contract; forbidden marker: \(marker)"
            )
        }
    }
}

private enum DebugConditionalKind {
    case debugWhenTrue
    case debugWhenFalse
    case other
}

private struct DebugConditionalFrame {
    var kind: DebugConditionalKind
    var releaseBranchVisible: Bool
    var debugBranchActive: Bool
}

private func requireConditionalVisibility(
    _ text: String,
    file: String,
    markers: [String],
    visibleInRelease: Bool
) throws {
    for marker in markers {
        assertionCount += 1
        guard let markerRange = text.range(of: marker) else {
            throw ValidationFailure(
                description: "\(file) no longer satisfies the Stage 0 source contract; missing marker: \(marker)"
            )
        }

        var frames: [DebugConditionalFrame] = []
        let prefix = text[..<markerRange.lowerBound]
        for sourceLine in prefix.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = sourceLine.trimmingCharacters(in: .whitespaces)
            if line == "#if DEBUG" {
                frames.append(
                    DebugConditionalFrame(
                        kind: .debugWhenTrue,
                        releaseBranchVisible: false,
                        debugBranchActive: true
                    )
                )
            } else if line == "#if !DEBUG" {
                frames.append(
                    DebugConditionalFrame(
                        kind: .debugWhenFalse,
                        releaseBranchVisible: true,
                        debugBranchActive: false
                    )
                )
            } else if line.hasPrefix("#if ") {
                frames.append(
                    DebugConditionalFrame(
                        kind: .other,
                        releaseBranchVisible: true,
                        debugBranchActive: false
                    )
                )
            } else if line == "#elseif DEBUG", frames.isEmpty == false {
                frames[frames.count - 1].releaseBranchVisible = false
                frames[frames.count - 1].debugBranchActive = true
            } else if line == "#elseif !DEBUG", frames.isEmpty == false {
                frames[frames.count - 1].releaseBranchVisible = true
                frames[frames.count - 1].debugBranchActive = false
            } else if line == "#else", frames.isEmpty == false {
                switch frames[frames.count - 1].kind {
                case .debugWhenTrue, .debugWhenFalse:
                    frames[frames.count - 1].releaseBranchVisible.toggle()
                    frames[frames.count - 1].debugBranchActive.toggle()
                case .other:
                    break
                }
            } else if line == "#endif" {
                guard frames.popLast() != nil else {
                    throw ValidationFailure(description: "\(file) contains an unmatched #endif before \(marker)")
                }
            }
        }

        if visibleInRelease {
            guard frames.allSatisfy({ $0.releaseBranchVisible }) else {
                throw ValidationFailure(
                    description: "\(file) declaration must remain Release-visible: \(marker)"
                )
            }
        } else {
            guard frames.contains(where: { $0.debugBranchActive && !$0.releaseBranchVisible }) else {
                throw ValidationFailure(
                    description: "\(file) diagnostic declaration must remain DEBUG-only: \(marker)"
                )
            }
        }
    }
}

private func sourceSlice(
    _ text: String,
    file: String,
    from startMarker: String,
    to endMarker: String
) throws -> String {
    guard let start = text.range(of: startMarker) else {
        throw ValidationFailure(description: "\(file) is missing slice start marker: \(startMarker)")
    }
    let tail = text[start.lowerBound...]
    guard let end = tail.range(of: endMarker) else {
        throw ValidationFailure(description: "\(file) is missing slice end marker: \(endMarker)")
    }
    return String(tail[..<end.lowerBound])
}

private func sourceFunction(
    _ text: String,
    file: String,
    from startMarker: String
) throws -> String {
    guard let start = text.range(of: startMarker) else {
        throw ValidationFailure(description: "\(file) is missing function marker: \(startMarker)")
    }
    guard let openingBrace = text[start.lowerBound...].firstIndex(of: "{") else {
        throw ValidationFailure(description: "\(file) function has no opening brace: \(startMarker)")
    }

    var depth = 0
    var index = openingBrace
    while index < text.endIndex {
        switch text[index] {
        case "{":
            depth += 1
        case "}":
            depth -= 1
            if depth == 0 {
                return String(text[start.lowerBound...index])
            }
        default:
            break
        }
        index = text.index(after: index)
    }
    throw ValidationFailure(description: "\(file) function has no closing brace: \(startMarker)")
}

private func validate() throws {
    let scriptPath = URL(fileURLWithPath: #filePath).standardizedFileURL
    let repositoryRoot = scriptPath
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    let appModelsPath = "VPN/Core/Portable/TunnelIPC/TunnelMessageModels.swift"
    let appRuntimeModelsPath = "VPN/Core/Portable/TunnelIPC/RuntimeConfigurationModels.swift"
    let appMessagingPath = "VPN/Core/Portable/TunnelIPC/TunnelProviderMessaging.swift"
    let extensionModelsPath = "PacketTunnelShared/Core/TunnelIPC/TunnelMessageModels.swift"
    let extensionHandlerPath = "PacketTunnelShared/Core/TunnelIPC/TunnelTelemetryIPC.swift"
    let runtimeModelsPath = "PacketTunnelXrayExtension/Core/TunnelIPC/RuntimeConfigurationModels.swift"
    let providerPath = "PacketTunnelXrayExtension/PacketTunnelProvider.swift"
    let wireGuardProviderPath = "PacketTunnelExtension/PacketTunnelProvider.swift"
    let nativeRuntimePath = "PacketTunnelExtension/Core/NativeTunnel/NativeWireGuardRuntime.swift"
    let sharedInfrastructurePath = "PacketTunnelShared/Core/TunnelIPC/RuntimeProviderInfrastructure.swift"
    let sharedInterfacesPath = "PacketTunnelShared/Core/TunnelIPC/TunnelRuntimeInterfaces.swift"
    let providerIdentityPath = "PacketTunnelShared/Core/TunnelIPC/PacketTunnelProviderIdentity.swift"
    let routingPath = "VPN/Core/Portable/TunnelIPC/TunnelProviderRouting.swift"
    let settingsPath = "VPN/Views/SettingsView.swift"
    let diagnosticsPath = "VPN/Core/Portable/TunnelIPC/TunnelTelemetryDiagnosticsViewModel.swift"
    let wireGuardBuildScriptPath = "scripts/build-amneziawg-go.sh"
    let wireGuardBridgeMakefilePath = "scripts/patches/amneziawg-apple/WireGuardKitGo.Makefile"

    let appModels = try requireFile(repositoryRoot, appModelsPath)
    let appRuntimeModels = try requireFile(repositoryRoot, appRuntimeModelsPath)
    let appMessaging = try requireFile(repositoryRoot, appMessagingPath)
    let extensionModels = try requireFile(repositoryRoot, extensionModelsPath)
    let extensionHandler = try requireFile(repositoryRoot, extensionHandlerPath)
    let runtimeModels = try requireFile(repositoryRoot, runtimeModelsPath)
    let provider = try requireFile(repositoryRoot, providerPath)
    let wireGuardProvider = try requireFile(repositoryRoot, wireGuardProviderPath)
    let nativeRuntime = try requireFile(repositoryRoot, nativeRuntimePath)
    let sharedInfrastructure = try requireFile(repositoryRoot, sharedInfrastructurePath)
    let sharedInterfaces = try requireFile(repositoryRoot, sharedInterfacesPath)
    let providerIdentity = try requireFile(repositoryRoot, providerIdentityPath)
    let routing = try requireFile(repositoryRoot, routingPath)
    let settings = try requireFile(repositoryRoot, settingsPath)
    let diagnostics = try requireFile(repositoryRoot, diagnosticsPath)
    let wireGuardBuildScript = try requireFile(repositoryRoot, wireGuardBuildScriptPath)
    let wireGuardBridgeMakefile = try requireFile(repositoryRoot, wireGuardBridgeMakefilePath)

    // Runtime and provider revisions are persisted/cross-process identity. Keep
    // their exact stable inputs and FNV-1a implementation free of reflection,
    // randomized hashing, locale formatting, or unordered dictionary traversal.
    let recordRevisionCalculator = try sourceSlice(
        appRuntimeModels,
        file: appRuntimeModelsPath,
        from: "private nonisolated enum RuntimeProfileRevisionCalculator",
        to: "nonisolated enum RealityPublicKeyMigration"
    )
    try requireContains(
        recordRevisionCalculator,
        file: "\(appRuntimeModelsPath):RuntimeProfileRevisionCalculator",
        markers: [
            #"input.recordRevision = """#,
            "input.updatedAt = Date(timeIntervalSince1970: 0)",
            "encoder.outputFormatting = [.sortedKeys]",
            "encoder.dateEncodingStrategy = .iso8601",
            "let data = try encoder.encode(input)",
            #"return "v1-\(fnv1a64Hex(data))""#,
            "var hash: UInt64 = 0xcbf29ce484222325",
            "for byte in data",
            "hash ^= UInt64(byte)",
            "hash &*= 0x100000001b3",
            "String(hash, radix: 16)"
        ]
    )
    try requireExcludes(
        recordRevisionCalculator,
        file: "\(appRuntimeModelsPath):RuntimeProfileRevisionCalculator",
        markers: [
            "String(reflecting:",
            "String(describing: type(of:",
            "Hasher(",
            "hashValue",
            "Locale(",
            "localizedString",
            "Dictionary(",
            ".keys",
            ".values"
        ]
    )

    let providerRevisionToken = try sourceFunction(
        appRuntimeModels,
        file: appRuntimeModelsPath,
        from: "static func revisionToken(for sharedRecordRevision: String) throws -> Int64"
    )
    try requireContains(
        providerRevisionToken,
        file: "\(appRuntimeModelsPath):RuntimeProviderConfiguration.revisionToken",
        markers: [
            "sharedRecordRevision.trimmingCharacters(in: .whitespacesAndNewlines)",
            "var hash: UInt64 = 0xcbf29ce484222325",
            "for byte in trimmed.utf8",
            "hash ^= UInt64(byte)",
            "hash &*= 0x100000001b3",
            "Int64(hash & 0x7fff_ffff_ffff_ffff)",
            "return token == 0 ? 1 : token"
        ]
    )
    try requireExcludes(
        providerRevisionToken,
        file: "\(appRuntimeModelsPath):RuntimeProviderConfiguration.revisionToken",
        markers: [
            "String(reflecting:",
            "String(describing: type(of:",
            "Hasher(",
            "hashValue",
            "Locale(",
            "localizedString"
        ]
    )

    // App-side compilation keeps its portable implementations. The provider
    // split shares only provider configuration, Keychain resolution, and IPC
    // interfaces; Xray lifecycle/runtime implementation remains Xray-only.
    try requireContains(
        appRuntimeModels,
        file: appRuntimeModelsPath,
        markers: [
            "nonisolated protocol SharedRuntimeProfileStoring: Sendable",
            "nonisolated protocol XrayConfigurationBuilding: Sendable",
            "nonisolated protocol RuntimeCredentialResolving: Sendable",
            "nonisolated protocol RuntimeConfigurationValidationLoading: Sendable",
            "protocol XrayConfigurationValidating: Sendable"
        ]
    )
    try requireExcludes(
        appRuntimeModels,
        file: appRuntimeModelsPath,
        markers: ["nonisolated protocol XrayConfigurationValidating: Sendable"]
    )
    try requireContains(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "nonisolated protocol SharedRuntimeProfileStoring: Sendable",
            "nonisolated protocol XrayConfigurationBuilding: Sendable"
        ]
    )
    try requireContains(
        sharedInfrastructure,
        file: sharedInfrastructurePath,
        markers: [
            "protocol RuntimeCredentialResolving: Sendable",
            "actor KeychainRuntimeCredentialResolver: RuntimeCredentialResolving",
            "init(accessGroupResolver: @escaping @Sendable () throws -> String"
        ]
    )
    try requireContains(
        sharedInterfaces,
        file: sharedInterfacesPath,
        markers: [
            "protocol RuntimeConfigurationValidationLoading: Sendable",
            "protocol XrayConfigurationValidating: Sendable",
            "protocol XrayLifecycleSmokeTesting: Sendable",
            "protocol XrayRemoteEgressProbing: Sendable",
            "protocol PacketTunnelUDPControlProbing: Sendable",
            "protocol LibXrayPingProbing: Sendable"
        ]
    )
    try requireExcludes(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "protocol RuntimeCredentialResolving: Sendable",
            "protocol RuntimeConfigurationValidationLoading: Sendable",
            "protocol XrayConfigurationValidating: Sendable",
            "protocol XrayLifecycleSmokeTesting: Sendable",
            "protocol XrayRemoteEgressProbing: Sendable",
            "protocol PacketTunnelUDPControlProbing: Sendable",
            "protocol LibXrayPingProbing: Sendable",
            "actor KeychainRuntimeCredentialResolver: RuntimeCredentialResolving"
        ]
    )

    // Release must compile the same production Xray/Tun2Socks controller used
    // by Debug. Diagnostic entry points remain DEBUG-only and Release routes
    // their stable IPC cases to the typed unsupported response.
    try requireConditionalVisibility(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "import LibXray",
            "import Network",
            "import Tun2SocksKit",
            "nonisolated struct SystemLibXrayRawInvoker: LibXrayRawInvoking",
            "nonisolated enum XrayRuntimeLifecycleState:",
            "protocol XrayRuntimeSessionControlling: Sendable",
            "actor XrayRuntimeLifecycleController:"
        ],
        visibleInRelease: true
    )
    try requireConditionalVisibility(
        sharedInterfaces,
        file: sharedInterfacesPath,
        markers: [
            "protocol PacketTunnelUDPControlProbing: Sendable",
            "protocol LibXrayPingProbing: Sendable",
            "protocol XrayLifecycleSmokeTesting: Sendable",
            "protocol XrayRemoteEgressProbing: Sendable"
        ],
        visibleInRelease: true
    )
    try requireConditionalVisibility(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "final class PacketTunnelXrayConfigurationValidationService:",
            "final class PacketTunnelXrayLifecycleSmokeTestService:",
            "final class PacketTunnelXrayRemoteEgressProbeService:",
            "final class PacketTunnelUDPControlProbeService:",
            "final class PacketTunnelLibXrayPingProbeService:"
        ],
        visibleInRelease: false
    )
    try requireConditionalVisibility(
        provider,
        file: providerPath,
        markers: [
            "private lazy var xrayRuntimeController: XrayRuntimeLifecycleController?",
            "let dataPlaneOptions = DataPlanePacketTunnelStartOptions(options)",
            "xrayRuntimeController.startPacketTunnelDataPlane(",
            "xrayRuntimeController.stopActivePacketTunnelSession(",
            "private struct DataPlanePacketTunnelStartOptions"
        ],
        visibleInRelease: true
    )
    try requireConditionalVisibility(
        provider,
        file: providerPath,
        markers: [
            "private lazy var xrayLifecycleSmokeTester:",
            "private lazy var xrayRemoteEgressProbe:",
            "private lazy var udpControlProbe:",
            "private lazy var libXrayPingProbe:",
            "private struct RuntimeOnlyPacketTunnelStartOptions",
            "private struct LibXrayPingOnlyPacketTunnelStartOptions"
        ],
        visibleInRelease: false
    )
    try requireConditionalVisibility(
        extensionHandler,
        file: extensionHandlerPath,
        markers: [
            "private let xrayLifecycleSmokeTester:",
            "private let xrayRemoteEgressProbe:",
            "private let udpControlProbe:",
            "private let libXrayPingProbe:"
        ],
        visibleInRelease: true
    )
    try requireContains(
        provider,
        file: "\(providerPath):Release Xray composition",
        markers: [
            "return XrayRuntimeLifecycleController(",
            "runtimeConfigurationLoader: runtimeValidationLoader",
            "networkSettingsApplier: PacketTunnelNetworkSettingsApplier(provider: self)",
            "tunnelCancellationHandler: { [weak self] error in",
            "self?.cancelTunnelWithError(error)",
            "telemetryStore: telemetryStore"
        ]
    )
    try requireExcludes(
        provider,
        file: "\(providerPath):Release Xray composition",
        markers: [
            "NoOpXray",
            "NoopXray",
            "StubXrayRuntime",
            "FakeXrayRuntime",
            "fatalError(\"Xray runtime"
        ]
    )
    try requireConditionalVisibility(
        appMessaging,
        file: appMessagingPath,
        markers: [
            "nonisolated protocol TunnelRuntimeConfigurationValidationMessaging:",
            "nonisolated final class NetworkExtensionRuntimeConfigurationValidationMessenger:"
        ],
        visibleInRelease: true
    )
    try requireConditionalVisibility(
        appRuntimeModels,
        file: appRuntimeModelsPath,
        markers: [
            "actor RuntimeConfigurationValidationService",
            "actor XrayConfigurationValidationService",
            "actor XrayLifecycleSmokeTestService",
            "actor DataPlanePacketTunnelService"
        ],
        visibleInRelease: true
    )
    try requireConditionalVisibility(
        appMessaging,
        file: appMessagingPath,
        markers: [
            "nonisolated enum DataPlanePacketTunnelStartOptions",
            "nonisolated protocol DataPlanePacketTunnelSessionConnection:"
        ],
        visibleInRelease: true
    )
    try requireConditionalVisibility(
        appMessaging,
        file: appMessagingPath,
        markers: [
            "nonisolated enum RuntimeOnlyPacketTunnelStartOptions",
            "nonisolated enum LibXrayPingOnlyPacketTunnelStartOptions"
        ],
        visibleInRelease: false
    )
    try requireExcludes(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "nonisolated protocol RuntimeConfigurationValidationLoading: Sendable",
            "nonisolated protocol XrayConfigurationValidating: Sendable"
        ]
    )

    // The fork places api-apple.go and api-xray.go in the same Go package.
    // Stage 0 must keep the WG archive on the audited single-file build path
    // and reject any accidental LibXray runtime content before linking.
    try requireContains(
        wireGuardBridgeMakefile,
        file: wireGuardBridgeMakefilePath,
        markers: [
            "$(BUILDDIR)/libwg-go-$(1).a: $(GOROOT)/.prepared go.mod api-apple.go",
            #"-buildmode c-archive api-apple.go"#
        ]
    )
    try requireExcludes(
        wireGuardBridgeMakefile,
        file: wireGuardBridgeMakefilePath,
        markers: [
            "go.mod api-apple.go api-xray.go",
            "-buildmode c-archive api-xray.go",
            "-buildmode c-archive ."
        ]
    )
    try requireContains(
        wireGuardBuildScript,
        file: wireGuardBuildScriptPath,
        markers: [
            "scripts/patches/amneziawg-apple/WireGuardKitGo.Makefile",
            "bridgeMakefile=$audited_bridge_makefile_sha256",
            "if grep -Fq 'LibXray' \"$archive_symbol_audit\"; then",
            "if grep -Fq 'create_os_log' \"$archive_symbol_audit\"; then"
        ]
    )

    // The app-side values and Codable round trips are compiled in VPNTests. These
    // host checks prove that the extension still declares and routes the same cases.
    let sharedWireMarkers = [
        #""runXrayLifecycleSmokeTest""#,
        #""runLibXrayPingProbe""#,
        #""runXrayRemoteEgressProbe""#,
        #""probeActiveXrayEgress""#,
        #""runUDPControlProbe""#,
        #""getDiagnosticProviderMode""#,
        "xrayLifecycleSmokeTest",
        "libXrayPingProbe",
        "xrayRemoteEgressProbe",
        "udpControlProbe",
        "diagnosticProviderMode"
    ]
    try requireContains(appModels, file: appModelsPath, markers: sharedWireMarkers)
    try requireContains(extensionModels, file: extensionModelsPath, markers: sharedWireMarkers)
    try requireExcludes(
        appModels,
        file: appModelsPath,
        markers: ["nativeErrorMessage", "rawLibXrayError"]
    )
    try requireExcludes(
        extensionModels,
        file: extensionModelsPath,
        markers: ["nativeErrorMessage", "rawLibXrayError"]
    )

    try requireContains(
        extensionHandler,
        file: extensionHandlerPath,
        markers: [
            "case .runXrayLifecycleSmokeTest:",
            "guard case .xrayLifecycleSmokeTest(let payload)? = request.payload",
            "return .success(request: request, payload: .xrayLifecycleSmokeTest(validation))",
            "case .runLibXrayPingProbe:",
            "guard case .libXrayPingProbe(let payload)? = request.payload",
            "return .success(request: request, payload: .libXrayPingProbe(validation))",
            "case .runXrayRemoteEgressProbe:",
            "case .probeActiveXrayEgress:",
            "guard case .xrayRemoteEgressProbe(let payload)? = request.payload",
            "return .success(request: request, payload: .xrayRemoteEgressProbe(validation))",
            "case .runUDPControlProbe:",
            "guard case .udpControlProbe(let payload)? = request.payload",
            "return .success(request: request, payload: .udpControlProbe(validation))",
            "case .getDiagnosticProviderMode:",
            "diagnosticProviderModeProvider?.diagnosticProviderMode() ?? .unknown"
        ]
    )
    try requireExcludes(
        extensionHandler,
        file: extensionHandlerPath,
        markers: [
            "payload: .runXrayLifecycleSmokeTest",
            "payload: .runLibXrayPingProbe",
            "payload: .runXrayRemoteEgressProbe"
        ]
    )

    // Extension Xray capability and field-emission parity.
    try requireContains(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "[.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(configuration.transport.kind)",
            "normalizedALPN(configuration.trojan?.alpn)",
            "security.tlsSettings?.alpn = alpn",
            "normalizedOptional(configuration.vless.encryption)",
            "vmess.alterID.map({ $0 >= 0 })"
        ]
    )

    // LibXray ping classifier, redaction, and provider integration.
    try requireContains(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "protocol LibXrayPingBatchInvoking",
            "LibXrayPingBatchItemResponsePayload",
            "LibXrayPingErrorClassifier.category(for: item.error)",
            #"normalized.contains("quic") || normalized.contains("hysteria")"#,
            #"normalized.contains("tls") || normalized.contains("handshake failure")"#,
            #"normalized.contains("x509") || normalized.contains("certificate")"#,
            #"normalized.contains("auth") || normalized.contains("unauthorized")"#,
            #"normalized.contains("timeout") || normalized.contains("deadline exceeded")"#,
            "return .unknown",
            "nativeErrorPresent: item.error?.isEmpty == false",
            "LibXrayPingBatchPayload",
            #"encodedRuntimeRequest(method: "pingBatch""#,
            #"outboundTag: "proxy""#,
            #"url: "https://cp.cloudflare.com/""#
        ]
    )
    try requireContains(
        provider,
        file: providerPath,
        markers: [
            "LibXrayPingOnlyPacketTunnelStartOptions",
            "xrayRuntimeController.startPacketTunnelLibXrayPingOnly",
            "PacketTunnelLibXrayPingProbeService(controller: xrayRuntimeController)"
        ]
    )

    // Remote egress is a loopback SOCKS/HTTP probe and active probes must not
    // mutate native runtime, Tun2Socks, or network-settings lifecycle state.
    try requireContains(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            #"remoteEgressProbe.probe(host: "127.0.0.1", port: port)"#,
            #"remoteEgressProbe.probe(host: "127.0.0.1", port: session.port)"#,
            "XraySOCKS5RemoteConnect.requestBytes",
            "XrayRemoteEgressHTTPProbe.requestBytes"
        ]
    )
    try requireExcludes(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [#"remoteEgressProbe.probe(host: XraySOCKS5RemoteConnect.targetHost"#]
    )

    let controller = try sourceSlice(
        runtimeModels,
        file: runtimeModelsPath,
        from: "actor XrayRuntimeLifecycleController:",
        to: "final class PacketTunnelXrayLifecycleSmokeTestService"
    )
    let actorDeclaration = try sourceSlice(
        controller,
        file: runtimeModelsPath,
        from: "actor XrayRuntimeLifecycleController:",
        to: "private let runtimeConfigurationLoader"
    )
    try requireContains(
        actorDeclaration,
        file: "\(runtimeModelsPath):XrayRuntimeLifecycleController declaration",
        markers: [
            "actor XrayRuntimeLifecycleController:",
            "XrayConfigurationValidating",
            "XrayRemoteEgressProbing",
            "PacketTunnelUDPControlProbing",
            "LibXrayPingProbing",
            "DiagnosticProviderModeProviding",
            "XrayRuntimeSessionControlling"
        ]
    )
    try requireContains(
        controller,
        file: "\(runtimeModelsPath):XrayRuntimeLifecycleController",
        markers: [
            "private static func remoteProbeContext(for mode: XrayRuntimeLifecycleMode)",
            "case .packetTunnelRuntimeOnly:",
            "return .runtimeOnly",
            "case .packetTunnelDataPlane:",
            "return .dataPlane",
            "case .oneShotSmoke, .libXrayPingOnly:",
            "return nil",
            "func runLibXrayPingProbe(",
            "func diagnosticProviderMode() async -> TunnelDiagnosticProviderMode",
            "func startPacketTunnelLibXrayPingOnly(",
            "mode: .libXrayPingOnly"
        ]
    )
    try requireContains(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "[.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(resolved.transport.kind)",
            "mode: .packetTunnelRuntimeOnly",
            "return .runtimeOnlyStarted(",
            "category: .runtimeAlreadyRunning"
        ]
    )
    try requireExcludes(
        runtimeModels,
        file: runtimeModelsPath,
        markers: ["resolved.transport.kind == .tcp,"]
    )

    let activeProbe = try sourceFunction(
        controller,
        file: runtimeModelsPath,
        from: "func probeActiveXrayEgress("
    )
    try requireContains(
        activeProbe,
        file: "\(runtimeModelsPath):probeActiveXrayEgress",
        markers: [
            #"remoteEgressProbe.probe(host: "127.0.0.1", port: session.port)"#,
            "let probeContext = Self.remoteProbeContext(for: session.mode)",
            "probeContext: probeContext"
        ]
    )
    try requireExcludes(
        activeProbe,
        file: "\(runtimeModelsPath):probeActiveXrayEgress",
        markers: [
            "testXray(",
            "runXray(",
            "stopXray(",
            "tun2Socks",
            "networkSettingsApplier",
            "setTunnelNetworkSettings",
            "Socks5Tunnel.run",
            "Socks5Tunnel.quit"
        ]
    )

    // UDP control probes are runtime-only and cannot mutate either data plane.
    try requireContains(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "protocol UDPControlPathSnapshotProviding",
            "protocol UDPControlDatagramTransporting",
            "NetworkFrameworkUDPControlPathProvider",
            "NetworkFrameworkUDPControlDatagramTransport",
            "UDPControlDNSProbe.requestBytes",
            "UDPControlDNSProbe.maximumResponseBytes"
        ]
    )
    let udpProbe = try sourceFunction(
        controller,
        file: runtimeModelsPath,
        from: "func runUDPControlProbe("
    )
    try requireContains(
        udpProbe,
        file: "\(runtimeModelsPath):runUDPControlProbe",
        markers: [
            "session.mode == .packetTunnelRuntimeOnly",
            "category: .notRuntimeOnly"
        ]
    )
    try requireExcludes(
        udpProbe,
        file: "\(runtimeModelsPath):runUDPControlProbe",
        markers: [
            "LibXrayInvoke",
            "testXray(",
            "runXray(",
            "stopXray(",
            "remoteEgressProbe.probe",
            "readinessProbe.waitForReadiness",
            "Socks5Tunnel.run",
            "Socks5Tunnel.quit",
            "tun2Socks.run",
            "tun2Socks.quit",
            "networkSettingsApplier",
            "setTunnelNetworkSettings",
            "packetFlow"
        ]
    )

    let libXrayPingProbe = try sourceFunction(
        controller,
        file: runtimeModelsPath,
        from: "func runLibXrayPingProbe("
    )
    try requireContains(
        libXrayPingProbe,
        file: "\(runtimeModelsPath):runLibXrayPingProbe",
        markers: [
            "session.mode == .libXrayPingOnly",
            "libXrayPingBatch.pingBatch(",
            "builder.build("
        ]
    )
    try requireExcludes(
        libXrayPingProbe,
        file: "\(runtimeModelsPath):runLibXrayPingProbe",
        markers: [
            "testXray(",
            "runXray(",
            "stopXray(",
            "readinessProbe.waitForReadiness",
            "remoteEgressProbe.probe",
            "tun2Socks",
            "networkSettingsApplier",
            "setTunnelNetworkSettings",
            "packetFlow"
        ]
    )

    let pingOnlyStart = try sourceFunction(
        controller,
        file: runtimeModelsPath,
        from: "func startPacketTunnelLibXrayPingOnly("
    )
    try requireContains(
        pingOnlyStart,
        file: "\(runtimeModelsPath):startPacketTunnelLibXrayPingOnly",
        markers: [
            "mode: .libXrayPingOnly",
            "tun2SocksStarted: false",
            "networkSettingsApplied: false",
            "runXrayInvoked: false",
            "socksListenerReady: false"
        ]
    )
    try requireExcludes(
        pingOnlyStart,
        file: "\(runtimeModelsPath):startPacketTunnelLibXrayPingOnly",
        markers: [
            "testXray(",
            "runXray(",
            "stopXray(",
            "readinessProbe",
            "Socks5Tunnel.run",
            "Socks5Tunnel.quit",
            "tun2Socks.run",
            "tun2Socks.quit",
            "networkSettingsApplier",
            "setTunnelNetworkSettings",
            "packetFlow"
        ]
    )

    // PacketTunnelProvider owns lifecycle dispatch while the runtime actor owns
    // native/Tun2Socks/network settings implementation.
    try requireContains(
        provider,
        file: providerPath,
        markers: [
            "private lazy var xrayConfigurationValidator: (any XrayConfigurationValidating)? = {",
            "xrayRuntimeController",
            "PacketTunnelUDPControlProbeService(controller: xrayRuntimeController)",
            "PacketTunnelLibXrayPingProbeService(controller: xrayRuntimeController)",
            "diagnosticProviderModeProvider: xrayRuntimeController",
            "RuntimeOnlyPacketTunnelStartOptions",
            "DataPlanePacketTunnelStartOptions",
            "LibXrayPingOnlyPacketTunnelStartOptions",
            "xrayRuntimeController.startPacketTunnelRuntimeOnly",
            "xrayRuntimeController.startPacketTunnelDataPlane",
            "xrayRuntimeController.startPacketTunnelLibXrayPingOnly",
            "xrayRuntimeController.stopActivePacketTunnelSession"
        ]
    )
    try requireExcludes(
        provider,
        file: providerPath,
        markers: [
            "return PacketTunnelXrayConfigurationValidationService(runtimeConfigurationLoader: runtimeValidationLoader)",
            "localPort",
            "20_480",
            "packetFlow.readPackets",
            "packetFlow.writePackets",
            "Socks5Tunnel.run",
            "Socks5Tunnel.quit"
        ]
    )
    try requireContains(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "Socks5Tunnel.run(withConfig: .string(content: content))",
            "Socks5Tunnel.quit()",
            "Socks5Tunnel.stats",
            "provider.setTunnelNetworkSettings(settings)",
            "provider.setTunnelNetworkSettings(nil)",
            "ipv4.includedRoutes = [NEIPv4Route.default()]",
            "dns.matchDomains = plan.dnsMatchDomains",
            "localSocksUDPEnabled: mode == .packetTunnelDataPlane",
            "udpEnabled: true"
        ]
    )
    try requireExcludes(
        runtimeModels,
        file: runtimeModelsPath,
        markers: ["packetFlow.readPackets", "packetFlow.writePackets"]
    )

    // Debug UI and app adapter remain identity-only: no diagnostic SOCKS port.
    try requireContains(
        settings,
        file: settingsPath,
        markers: [
            "diagnostics.active_xray_egress.context",
            "diagnostics.udp_control.run",
            "diagnostics.libxray_ping.run",
            "diagnostics.libxray_ping_only.start",
            "diagnostics.provider_mode.label",
            "diagnostics.provider_mode.recover",
            "tunnelTelemetry.reconcileDiagnosticProviderState()",
            "tunnelTelemetry.recoverDiagnosticProvider()",
            "tunnelTelemetry.runUDPControlProbe()",
            "tunnelTelemetry.runLibXrayPingProbe(",
            "profile: viewModel?.selectedProfile",
            "tunnelTelemetry.persistentDiagnosticStartIsEligible",
            "tunnelTelemetry.runtimeOnlyDiagnosticModeIsRunning",
            "tunnelTelemetry.dataPlaneDiagnosticModeIsRunning",
            "tunnelTelemetry.libXrayPingOnlyDiagnosticModeIsRunning"
        ]
    )
    try requireExcludes(
        settings,
        file: settingsPath,
        markers: [
            "20_480",
            "selectedPort",
            "socksPort",
            "runtimeOnlyTunnelResult?.success != true",
            "dataPlaneTunnelResult?.success != true",
            "libXrayPingOnlyTunnelResult?.success == true",
            "libXrayPingOnlyTunnelResult?.success != true"
        ]
    )
    try requireContains(
        diagnostics,
        file: diagnosticsPath,
        markers: [
            "var diagnosticProviderMode: TunnelDiagnosticProviderMode = .idle",
            "func reconcileDiagnosticProviderState()",
            "func recoverDiagnosticProvider()",
            "var persistentDiagnosticStartIsEligible: Bool",
            "var diagnosticProviderIsOccupied: Bool",
            "let persistentXrayModeIsRunning = runtimeOnlyDiagnosticModeIsRunning",
            "|| dataPlaneDiagnosticModeIsRunning",
            "probeActiveXrayEgress(profile: profile)",
            "func runUDPControlProbe()",
            "func runLibXrayPingProbe(profile: VPNProfile?)",
            "func startLibXrayPingOnlyTunnel(profile: VPNProfile?)",
            "guard runtimeOnlyDiagnosticModeIsRunning else",
            "guard libXrayPingOnlyDiagnosticModeIsRunning else"
        ]
    )
    try requireExcludes(
        diagnostics,
        file: diagnosticsPath,
        markers: [
            "20_480",
            "selectedPort",
            "socksPort",
            "runtimeOnlyTunnelResult?.success == true",
            "dataPlaneTunnelResult?.success == true",
            "libXrayPingOnlyTunnelResult?.success == true"
        ]
    )

    // Stage 0 now has two hard runtime boundaries. The original provider owns
    // only native WireGuard/AmneziaWG, while the new provider owns only
    // Xray/Tun2Socks. Both processes validate their compile-time identity and
    // launch-option family before touching a runtime.
    try requireContains(
        wireGuardProvider,
        file: wireGuardProviderPath,
        markers: [
            "class PacketTunnelProvider: NEPacketTunnelProvider",
            "NativeWireGuardControllerReference",
            "NativePacketTunnelStartOptions",
            "PacketTunnelProviderIdentity.validatesLaunch(provider: self, options: options)",
            "providerProcess: .wireGuard"
        ]
    )
    try requireExcludes(
        wireGuardProvider,
        file: wireGuardProviderPath,
        markers: [
            "XrayRuntimeLifecycleController",
            "DataPlanePacketTunnelStartOptions",
            "RuntimeOnlyPacketTunnelStartOptions",
            "LibXrayPingOnlyPacketTunnelStartOptions",
            "Tun2Socks",
            "LibXray",
            "wgTurnOn",
            "wgTurnOff"
        ]
    )
    try requireContains(
        provider,
        file: providerPath,
        markers: [
            "class PacketTunnelProvider: NEPacketTunnelProvider",
            "XrayRuntimeLifecycleController",
            "DataPlanePacketTunnelStartOptions",
            "PacketTunnelProviderIdentity.validatesLaunch(provider: self, options: options)",
            "providerProcess: .xray"
        ]
    )
    try requireExcludes(
        provider,
        file: providerPath,
        markers: [
            "NativeWireGuardControllerReference",
            "NativePacketTunnelStartOptions",
            "NativeWireGuardRuntime",
            "wgTurnOn",
            "wgTurnOff",
            "wgSetLogger",
            "wgSetConfig",
            "wgGetConfig",
            "wgBumpSockets"
        ]
    )
    try requireContains(
        nativeRuntime,
        file: nativeRuntimePath,
        markers: [
            "NativeWireGuardRuntime",
            "WireGuardAdapter"
        ]
    )
    try requireExcludes(
        nativeRuntime,
        file: nativeRuntimePath,
        markers: ["LibXray", "Tun2SocksKit", "Socks5Tunnel"]
    )
    try requireExcludes(
        runtimeModels,
        file: runtimeModelsPath,
        markers: [
            "WireGuardKit",
            "NativeWireGuardRuntime",
            "wgTurnOn",
            "wgTurnOff",
            "wgSetLogger",
            "wgSetConfig",
            "wgGetConfig",
            "wgBumpSockets"
        ]
    )
    try requireExcludes(
        sharedInfrastructure + sharedInterfaces + extensionModels + extensionHandler,
        file: "PacketTunnelShared",
        markers: [
            "import LibXray",
            "import Tun2SocksKit",
            "import WireGuardKit",
            "wgTurnOn",
            "wgTurnOff",
            "wgSetLogger"
        ]
    )
    try requireContains(
        providerIdentity,
        file: providerIdentityPath,
        markers: [
            "#if KVN_WIREGUARD_PROVIDER",
            "#elseif KVN_XRAY_PROVIDER",
            "#error(\"Packet-tunnel targets must declare exactly one provider identity.\")",
            "executingBundleIdentifier == currentBundleIdentifier",
            "configuredProviderBundleIdentifier == currentBundleIdentifier",
            "containsNativeOptions && containsXrayOptions == false",
            "containsXrayOptions && containsNativeOptions == false",
            "su.24kvn.packet-tunnel.provider-routing"
        ]
    )

    // The application owns the one exhaustive protocol-to-provider decision.
    try requireContains(
        routing,
        file: routingPath,
        markers: [
            "static let wireGuardBundleIdentifier = \"su.24kvn.kvn-app.PacketTunnelExtension\"",
            "static let xrayBundleIdentifier = \"su.24kvn.kvn-app.PacketTunnelXrayExtension\"",
            "case .wireGuard, .amneziaWG:",
            "case .vless, .hysteria2, .trojan, .shadowsocks, .vmess:",
            "case .ikev2, .tuic:",
            "savedConfiguration == desiredConfiguration",
            "status == .disconnected || status == .invalid"
        ]
    )
    try requireExcludes(
        routing,
        file: routingPath,
        markers: ["default:"]
    )
}

do {
    try validate()
    print("Stage 0 source-contract validation passed (\(assertionCount) assertions).")
} catch {
    fputs("Stage 0 source-contract validation failed: \(error)\n", stderr)
    exit(EXIT_FAILURE)
}
