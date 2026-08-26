//
//  RuntimeConfigurationModels.swift
//  PacketTunnelExtension
//
//  Runtime configuration validation and Xray/Tun2Socks lifecycle.
//  Sensitive generated runtime configuration remains in memory.
//

import Foundation
import Darwin
import LibXray
import Network
import Tun2SocksKit
import NetworkExtension


nonisolated enum SharedRuntimeProtocolKind: String, Codable, Equatable, Sendable {
    case vless
    case vmess
    case trojan
    case shadowsocks
    case hysteria2
}

nonisolated enum SharedRuntimeBackendKind: String, Codable, Equatable, Sendable {
    case xray
}

nonisolated enum SharedRuntimeTransportKind: String, Codable, Equatable, Sendable {
    case tcp
    case websocket
    case grpc
    case httpUpgrade
    case xhttp
    case hysteria
}

nonisolated enum SharedRuntimeSecurityKind: String, Codable, Equatable, Sendable {
    case none
    case tls
    case reality
}

nonisolated enum SharedRuntimeCompleteness: String, Codable, Equatable, Sendable {
    case complete
    case incomplete
}

nonisolated struct SharedRuntimeEndpoint: Codable, Equatable, Sendable {
    var host: String
    var port: Int
}

nonisolated struct SharedRuntimeTransport: Codable, Equatable, Sendable {
    var kind: SharedRuntimeTransportKind
    var path: String?
    var host: String?
    var serviceName: String?
    var mode: String?
    var xhttp: SharedRuntimeXHTTPParameters?
}

nonisolated enum SharedRuntimeXHTTPMode: String, Codable, Equatable, Sendable {
    case auto
    case packetUp = "packet-up"
    case streamUp = "stream-up"
    case streamOne = "stream-one"
}

nonisolated struct SharedRuntimeXHTTPParameters: Codable, Equatable, Sendable, CustomDebugStringConvertible {
    var path: String?
    var host: String?
    var mode: SharedRuntimeXHTTPMode?

    var debugDescription: String {
        "SharedRuntimeXHTTPParameters(path: <redacted>, host: <redacted>, mode: \(mode?.rawValue ?? "<none>"))"
    }
}

nonisolated struct SharedRuntimeRealityPublicParameters: Codable, Equatable, Sendable, CustomDebugStringConvertible {
    var serverName: String
    var publicKey: String
    var shortID: String
    var fingerprint: String?
    var spiderX: String?

    var debugDescription: String {
        "SharedRuntimeRealityPublicParameters(serverName: <redacted>, publicKey: <redacted>, shortID: <redacted>, fingerprint: \(fingerprint ?? "<none>"), spiderX: <redacted>)"
    }
}

nonisolated struct SharedRuntimeSecurity: Codable, Equatable, Sendable {
    var kind: SharedRuntimeSecurityKind
    var serverName: String?
    var allowInsecure: Bool
    var fingerprint: String?
    var alpn: [String]?
    var shortID: String?
    var reality: SharedRuntimeRealityPublicParameters?

    init(
        kind: SharedRuntimeSecurityKind,
        serverName: String? = nil,
        allowInsecure: Bool = false,
        fingerprint: String? = nil,
        alpn: [String]? = nil,
        shortID: String? = nil,
        reality: SharedRuntimeRealityPublicParameters? = nil
    ) {
        self.kind = kind
        self.serverName = serverName
        self.allowInsecure = allowInsecure
        self.fingerprint = fingerprint
        self.alpn = alpn
        self.shortID = shortID
        self.reality = reality
    }
}

nonisolated struct SharedRuntimeVLESSParameters: Codable, Equatable, Sendable {
    var flow: String?
    var encryption: String?
}

nonisolated struct SharedRuntimeVMessParameters: Codable, Equatable, Sendable {
    var alterID: Int?
    var security: String?
}

nonisolated struct SharedRuntimeTrojanParameters: Codable, Equatable, Sendable {
    var alpn: [String]
}

nonisolated struct SharedRuntimeShadowsocksParameters: Codable, Equatable, Sendable {
    var method: String?
    var plugin: String?
    var isOutlineStaticKey: Bool
}

nonisolated struct SharedRuntimeHysteria2Parameters: Codable, Equatable, Sendable {
    var obfs: String?
    var bandwidthHint: String?
    var obfsPasswordReference: String?
}

nonisolated struct SharedRuntimeProfileRecord: Codable, Equatable, Sendable, CustomDebugStringConvertible {
    var schemaVersion: UInt32
    var profileID: UUID
    var recordRevision: String
    var updatedAt: Date
    var enabled: Bool
    var completeness: SharedRuntimeCompleteness
    var credentialReference: String
    var protocolKind: SharedRuntimeProtocolKind
    var backendKind: SharedRuntimeBackendKind
    var endpoint: SharedRuntimeEndpoint
    var transport: SharedRuntimeTransport
    var security: SharedRuntimeSecurity
    var vless: SharedRuntimeVLESSParameters
    var vmess: SharedRuntimeVMessParameters?
    var trojan: SharedRuntimeTrojanParameters?
    var shadowsocks: SharedRuntimeShadowsocksParameters?
    var hysteria2: SharedRuntimeHysteria2Parameters?

    var debugDescription: String {
        "SharedRuntimeProfileRecord(profileID: \(profileID.uuidString), recordRevision: \(recordRevision), protocol: \(protocolKind.rawValue), endpoint: <redacted>, credentialReference: <redacted>)"
    }
}

nonisolated struct SharedRuntimeProfileCollection: Codable, Equatable, Sendable, CustomDebugStringConvertible {
    var schemaVersion: UInt32
    var records: [SharedRuntimeProfileRecord]

    var debugDescription: String {
        "SharedRuntimeProfileCollection(schemaVersion: \(schemaVersion), records: \(records.count), payload: <redacted>)"
    }
}


nonisolated protocol SharedRuntimeProfileStoring: Sendable {
    func read(profileID: UUID) async throws -> SharedRuntimeProfileRecord
}

actor FileSharedRuntimeProfileStore: SharedRuntimeProfileStoring {
    private let rootDirectory: URL
    private let fileManager: FileManager
    private let decoder = JSONDecoder()
    private let maximumRecordBytes: Int
    private let maximumCollectionBytes: Int
    private let maximumRecordCount: Int

    init(
        rootDirectory: URL,
        fileManager: FileManager = .default,
        maximumRecordBytes: Int = RuntimeConfigurationProtocol.maximumRecordBytes,
        maximumCollectionBytes: Int = RuntimeConfigurationProtocol.maximumCollectionBytes,
        maximumRecordCount: Int = RuntimeConfigurationProtocol.maximumProfileRecordCount
    ) {
        self.rootDirectory = rootDirectory
        self.fileManager = fileManager
        self.maximumRecordBytes = maximumRecordBytes
        self.maximumCollectionBytes = maximumCollectionBytes
        self.maximumRecordCount = maximumRecordCount
        decoder.dateDecodingStrategy = .iso8601
    }

    static func appGroupStore(fileManager: FileManager = .default) -> FileSharedRuntimeProfileStore? {
        guard let containerURL = fileManager.containerURL(forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier) else {
            return nil
        }
        return FileSharedRuntimeProfileStore(
            rootDirectory: containerURL
                .appendingPathComponent("RuntimeProfiles", isDirectory: true),
            fileManager: fileManager
        )
    }

    func read(profileID: UUID) async throws -> SharedRuntimeProfileRecord {
        let collection = try loadCollection()
        guard let record = collection.records.first(where: { $0.profileID == profileID }) else {
            throw RuntimeConfigurationError.profileRecordNotFound
        }
        return record
    }

    private var collectionFileURL: URL {
        rootDirectory.appendingPathComponent("runtime-profiles-v1", isDirectory: false).appendingPathExtension("json")
    }

    private func loadCollection() throws -> SharedRuntimeProfileCollection {
        let fileURL = collectionFileURL
        guard fileManager.fileExists(atPath: fileURL.path) else {
            return SharedRuntimeProfileCollection(
                schemaVersion: RuntimeConfigurationProtocol.profileCollectionSchemaVersion,
                records: []
            )
        }
        do {
            let values = try fileURL.resourceValues(forKeys: [.fileSizeKey])
            if let size = values.fileSize, size > maximumCollectionBytes {
                throw RuntimeConfigurationError.profileRecordTooLarge
            }
            let data = try Data(contentsOf: fileURL, options: [.mappedIfSafe])
            guard data.count <= maximumCollectionBytes else {
                throw RuntimeConfigurationError.profileRecordTooLarge
            }
            let collection = try decoder.decode(SharedRuntimeProfileCollection.self, from: data)
            try validate(collection)
            return collection
        } catch let error as RuntimeConfigurationError {
            throw error
        } catch {
            throw RuntimeConfigurationError.profileRecordMalformed
        }
    }

    private func validate(_ collection: SharedRuntimeProfileCollection) throws {
        guard collection.schemaVersion == RuntimeConfigurationProtocol.profileCollectionSchemaVersion else {
            throw RuntimeConfigurationError.profileSchemaMismatch
        }
        guard collection.records.count <= maximumRecordCount else {
            throw RuntimeConfigurationError.profileRecordCountExceeded
        }
        let ids = collection.records.map(\.profileID)
        guard Set(ids).count == ids.count else {
            throw RuntimeConfigurationError.profileRecordMalformed
        }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        for record in collection.records {
            guard record.schemaVersion == RuntimeConfigurationProtocol.profileSchemaVersion else {
                throw RuntimeConfigurationError.profileSchemaMismatch
            }
            let data = try encoder.encode(record)
            guard data.count <= maximumRecordBytes else {
                throw RuntimeConfigurationError.profileRecordTooLarge
            }
        }
    }
}


nonisolated struct SensitiveRuntimeCredential: CustomStringConvertible, CustomDebugStringConvertible, Sendable {
    private let value: String

    init(_ value: String) {
        self.value = value
    }

    var description: String { "<redacted>" }
    var debugDescription: String { "<redacted>" }

    var isValidVLESSUserID: Bool {
        UUID(uuidString: value) != nil
    }

    var isValidUUID: Bool {
        UUID(uuidString: value) != nil
    }

    var isNonEmptySecret: Bool {
        value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
    }

    func withString<R>(_ body: (String) throws -> R) rethrows -> R {
        try body(value)
    }
}

nonisolated struct ResolvedRuntimeEndpoint: Equatable, Sendable {
    var host: String
    var port: Int
}

nonisolated struct ResolvedVLESSRuntimeConfiguration: CustomStringConvertible, CustomDebugStringConvertible, Sendable {
    var profileID: UUID
    var recordRevision: String
    var protocolKind: SharedRuntimeProtocolKind
    var endpoint: ResolvedRuntimeEndpoint
    var transport: SharedRuntimeTransport
    var security: SharedRuntimeSecurity
    var vless: SharedRuntimeVLESSParameters
    var vmess: SharedRuntimeVMessParameters?
    var trojan: SharedRuntimeTrojanParameters?
    var shadowsocks: SharedRuntimeShadowsocksParameters?
    var hysteria2: SharedRuntimeHysteria2Parameters?
    var credential: SensitiveRuntimeCredential
    var hysteria2ObfsPassword: SensitiveRuntimeCredential?

    var description: String {
        "ResolvedProxyRuntimeConfiguration(profileID: \(profileID.uuidString), recordRevision: \(recordRevision), protocol: \(protocolKind.rawValue), endpoint: <redacted>, credential: <redacted>)"
    }

    var debugDescription: String { description }
}

nonisolated enum XrayConfigurationBuilderError: String, Error, Equatable, Sendable {
    case unsupportedProtocol
    case unsupportedTransport
    case unsupportedSecurity
    case invalidEndpoint
    case invalidCredential
    case invalidTLSConfiguration
    case invalidRealityConfiguration
    case invalidXHTTPConfiguration
    case invalidXHTTPMode
    case invalidXHTTPPath
    case invalidXHTTPHost
    case encodingFailed
}

nonisolated struct XrayBuildOptions: Equatable, Sendable {
    var localSocksListenAddress: String
    var localSocksPort: Int
    var localSocksUDPEnabled: Bool

    init(
        localSocksListenAddress: String = "127.0.0.1",
        localSocksPort: Int = 10_808,
        localSocksUDPEnabled: Bool = false
    ) {
        self.localSocksListenAddress = localSocksListenAddress
        self.localSocksPort = localSocksPort
        self.localSocksUDPEnabled = localSocksUDPEnabled
    }
}

nonisolated struct SensitiveXrayConfiguration: CustomStringConvertible, CustomDebugStringConvertible, Sendable {
    private static let maximumBytes = 512 * 1_024
    private let jsonData: Data

    init(jsonData: Data) throws {
        guard jsonData.isEmpty == false, jsonData.count <= Self.maximumBytes else {
            throw XrayConfigurationBuilderError.encodingFailed
        }
        self.jsonData = jsonData
    }

    var description: String { "<redacted>" }
    var debugDescription: String { "<redacted>" }

    func withJSONString<R>(_ body: (String) throws -> R) throws -> R {
        guard let json = String(data: jsonData, encoding: .utf8) else {
            throw XrayConfigurationBuilderError.encodingFailed
        }
        return try body(json)
    }
}

nonisolated protocol XrayConfigurationBuilding: Sendable {
    nonisolated func build(
        from configuration: ResolvedVLESSRuntimeConfiguration,
        options: XrayBuildOptions
    ) throws -> SensitiveXrayConfiguration
}

nonisolated struct XrayConfigurationBuilder: XrayConfigurationBuilding {
    private static let supportedFingerprints: Set<String> = [
        "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn"
    ]

    nonisolated func build(
        from configuration: ResolvedVLESSRuntimeConfiguration,
        options: XrayBuildOptions = XrayBuildOptions()
    ) throws -> SensitiveXrayConfiguration {
        try validateEndpoint(configuration.endpoint)
        try validateInboundOptions(options)
        try validateProtocolMatrix(configuration)

        let credential = try configuration.credential.withString { value -> String in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.isEmpty == false else {
                throw XrayConfigurationBuilderError.invalidCredential
            }
            return trimmed
        }

        let transport = try streamTransport(for: configuration.transport)
        var security = try streamSecurity(for: configuration.security, protocolKind: configuration.protocolKind)
        if configuration.protocolKind == .trojan,
           security.security == "tls",
           let alpn = try normalizedALPN(configuration.trojan?.alpn) {
            security.tlsSettings?.alpn = alpn
        }
        let outbound = try outboundConfiguration(
            for: configuration,
            credential: credential,
            transport: transport,
            security: security
        )
        let document = XrayJSONDocument(
            log: XrayLogConfiguration(access: "none", error: "none", loglevel: "none"),
            inbounds: [
                XrayInboundConfiguration(
                    listen: options.localSocksListenAddress,
                    port: options.localSocksPort,
                    protocolName: "socks",
                    settings: XraySocksInboundSettings(auth: "noauth", udp: options.localSocksUDPEnabled)
                )
            ],
            outbounds: [outbound]
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        do {
            return try SensitiveXrayConfiguration(jsonData: encoder.encode(document))
        } catch {
            throw XrayConfigurationBuilderError.encodingFailed
        }
    }

    private func validateEndpoint(_ endpoint: ResolvedRuntimeEndpoint) throws {
        let host = endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard host.isEmpty == false,
              host.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              host.rangeOfCharacter(from: .controlCharacters) == nil,
              (1...65_535).contains(endpoint.port) else {
            throw XrayConfigurationBuilderError.invalidEndpoint
        }
    }

    private func validateInboundOptions(_ options: XrayBuildOptions) throws {
        guard options.localSocksListenAddress == "127.0.0.1",
              (1...65_535).contains(options.localSocksPort) else {
            throw XrayConfigurationBuilderError.invalidEndpoint
        }
    }

    private func normalizedALPN(_ values: [String]?) throws -> [String]? {
        guard let values else { return nil }
        let normalized = values.compactMap { value -> String? in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
        guard normalized.allSatisfy({ value in
            value.utf8.count <= 255
                && value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
                && value.rangeOfCharacter(from: .controlCharacters) == nil
        }) else {
            throw XrayConfigurationBuilderError.invalidTLSConfiguration
        }
        return normalized.isEmpty ? nil : normalized
    }

    private func validateProtocolMatrix(_ configuration: ResolvedVLESSRuntimeConfiguration) throws {
        switch configuration.protocolKind {
        case .vless:
            guard [.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(configuration.transport.kind) else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard [.tls, .reality].contains(configuration.security.kind) else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            let encryption = normalizedOptional(configuration.vless.encryption)?.lowercased()
            guard encryption == nil || encryption == "none" else {
                throw XrayConfigurationBuilderError.unsupportedProtocol
            }
            if let flow = normalizedOptional(configuration.vless.flow)?.lowercased() {
                guard flow == "xtls-rprx-vision",
                      [.tcp, .xhttp].contains(configuration.transport.kind) else {
                    throw XrayConfigurationBuilderError.unsupportedProtocol
                }
            }
        case .vmess:
            guard [.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(configuration.transport.kind) else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard [.none, .tls, .reality].contains(configuration.security.kind) else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            if let vmess = configuration.vmess {
                guard vmess.alterID.map({ $0 >= 0 }) ?? true else {
                    throw XrayConfigurationBuilderError.unsupportedProtocol
                }
                let cipher = normalizedOptional(vmess.security)?.lowercased()
                if let cipher, ["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"].contains(cipher) == false {
                    throw XrayConfigurationBuilderError.unsupportedProtocol
                }
            }
        case .trojan:
            guard [.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(configuration.transport.kind) else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard [.tls, .reality].contains(configuration.security.kind) else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
        case .shadowsocks:
            guard configuration.transport.kind == .tcp else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard configuration.security.kind == .none else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
        case .hysteria2:
            guard configuration.transport.kind == .hysteria else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard configuration.security.kind == .tls else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
        }
    }

    private func vlessUserParameters(_ parameters: SharedRuntimeVLESSParameters, credential: String) throws -> XrayVLESSUser {
        guard UUID(uuidString: credential) != nil else {
            throw XrayConfigurationBuilderError.invalidCredential
        }
        let encryption = normalizedOptional(parameters.encryption) ?? "none"
        guard encryption.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else {
            throw XrayConfigurationBuilderError.invalidCredential
        }
        let flow = normalizedOptional(parameters.flow)
        return XrayVLESSUser(id: credential, encryption: encryption, flow: flow)
    }

    private func outboundConfiguration(
        for configuration: ResolvedVLESSRuntimeConfiguration,
        credential: String,
        transport: XrayTransportMapping,
        security: XraySecurityMapping
    ) throws -> XrayOutboundConfiguration {
        let endpointHost = configuration.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines)
        let streamSettings = XrayStreamSettings(
            method: transport.method,
            network: transport.network,
            security: security.security,
            tlsSettings: security.tlsSettings,
            realitySettings: security.realitySettings,
            wsSettings: transport.wsSettings,
            grpcSettings: transport.grpcSettings,
            httpUpgradeSettings: transport.httpUpgradeSettings,
            xhttpSettings: transport.xhttpSettings,
            hysteriaSettings: transport.hysteriaSettings,
            finalmask: nil
        )

        switch configuration.protocolKind {
        case .vless:
            let vless = try vlessUserParameters(configuration.vless, credential: credential)
            return XrayOutboundConfiguration(
                protocolName: "vless",
                tag: "proxy",
                settings: .vless(XrayVLESSOutboundSettings(
                    vnext: [
                        XrayVLESSServer(
                            address: endpointHost,
                            port: configuration.endpoint.port,
                            users: [vless]
                        )
                    ]
                )),
                streamSettings: streamSettings
            )
        case .vmess:
            guard UUID(uuidString: credential) != nil else {
                throw XrayConfigurationBuilderError.invalidCredential
            }
            let vmess = configuration.vmess ?? SharedRuntimeVMessParameters(alterID: nil, security: nil)
            let user = XrayVMessUser(
                id: credential,
                alterId: max(0, vmess.alterID ?? 0),
                security: normalizedOptional(vmess.security) ?? "auto"
            )
            return XrayOutboundConfiguration(
                protocolName: "vmess",
                tag: "proxy",
                settings: .vmess(XrayVMessOutboundSettings(
                    vnext: [
                        XrayVMessServer(
                            address: endpointHost,
                            port: configuration.endpoint.port,
                            users: [user]
                        )
                    ]
                )),
                streamSettings: streamSettings
            )
        case .trojan:
            guard security.security != "none" else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            return XrayOutboundConfiguration(
                protocolName: "trojan",
                tag: "proxy",
                settings: .trojan(XrayTrojanOutboundSettings(
                    servers: [
                        XrayTrojanServer(
                            address: endpointHost,
                            port: configuration.endpoint.port,
                            password: credential
                        )
                    ]
                )),
                streamSettings: streamSettings
            )
        case .shadowsocks:
            guard configuration.security.kind == .none else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            guard configuration.transport.kind == .tcp else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            let shadowsocksMethod = try shadowsocksMethod(configuration.shadowsocks)
            return XrayOutboundConfiguration(
                protocolName: "shadowsocks",
                tag: "proxy",
                settings: .shadowsocks(XrayShadowsocksOutboundSettings(
                    servers: [
                        XrayShadowsocksServer(
                            address: endpointHost,
                            port: configuration.endpoint.port,
                            method: shadowsocksMethod,
                            password: credential
                        )
                    ]
                )),
                streamSettings: streamSettings
            )
        case .hysteria2:
            guard configuration.transport.kind == .hysteria else {
                throw XrayConfigurationBuilderError.unsupportedTransport
            }
            guard configuration.security.kind == .tls else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            let tlsSettings = try Hysteria2XrayTLSPolicy.tlsSettings(
                from: security.tlsSettings,
                endpointHost: endpointHost
            )
            let finalmask = try hysteria2FinalMaskSettings(for: configuration)
            let hysteriaStreamSettings = XrayStreamSettings(
                method: transport.method,
                network: transport.network,
                security: security.security,
                tlsSettings: tlsSettings,
                realitySettings: security.realitySettings,
                wsSettings: nil,
                grpcSettings: nil,
                httpUpgradeSettings: nil,
                xhttpSettings: nil,
                hysteriaSettings: XrayHysteriaStreamSettings(version: 2, auth: credential),
                finalmask: finalmask
            )
            return XrayOutboundConfiguration(
                protocolName: "hysteria",
                tag: "proxy",
                settings: .hysteria(XrayHysteriaOutboundSettings(
                    version: 2,
                    address: endpointHost,
                    port: configuration.endpoint.port
                )),
                streamSettings: hysteriaStreamSettings
            )
        }
    }

    private func shadowsocksMethod(_ parameters: SharedRuntimeShadowsocksParameters?) throws -> String {
        guard let method = normalizedOptional(parameters?.method)?.lowercased(),
              isSupportedShadowsocksMethod(method),
              normalizedOptional(parameters?.plugin) == nil else {
            throw XrayConfigurationBuilderError.unsupportedProtocol
        }
        return method
    }

    private func hysteria2FinalMaskSettings(for configuration: ResolvedVLESSRuntimeConfiguration) throws -> XrayFinalMaskSettings? {
        let parameters = configuration.hysteria2
        guard normalizedOptional(parameters?.bandwidthHint) == nil else {
            throw XrayConfigurationBuilderError.unsupportedProtocol
        }
        let obfs = normalizedOptional(parameters?.obfs)?.lowercased()
        guard let obfs else {
            return nil
        }
        guard obfs == "salamander", let obfsPassword = configuration.hysteria2ObfsPassword else {
            throw XrayConfigurationBuilderError.unsupportedProtocol
        }
        let password = try obfsPassword.withString { value -> String in
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.isEmpty == false else {
                throw XrayConfigurationBuilderError.invalidCredential
            }
            return trimmed
        }
        return XrayFinalMaskSettings(
            udp: [
                XrayFinalMaskLayer(
                    type: "salamander",
                    settings: XrayFinalMaskSalamanderSettings(password: password)
                )
            ]
        )
    }

    private func streamTransport(for transport: SharedRuntimeTransport) throws -> XrayTransportMapping {
        switch transport.kind {
        case .tcp:
            return XrayTransportMapping(network: "tcp")
        case .websocket:
            return XrayTransportMapping(
                network: "ws",
                wsSettings: XrayWebSocketSettings(
                    path: normalizedOptional(transport.path),
                    headers: XrayHeaderSettings(host: normalizedOptional(transport.host))
                )
            )
        case .grpc:
            return XrayTransportMapping(
                network: "grpc",
                grpcSettings: XrayGRPCSettings(serviceName: normalizedOptional(transport.serviceName))
            )
        case .httpUpgrade:
            return XrayTransportMapping(
                network: "httpupgrade",
                httpUpgradeSettings: XrayHTTPUpgradeSettings(
                    path: normalizedOptional(transport.path),
                    host: normalizedOptional(transport.host)
                )
            )
        case .xhttp:
            guard let xhttp = transport.xhttp else {
                throw XrayConfigurationBuilderError.invalidXHTTPConfiguration
            }
            do {
                try XHTTPParametersValidator.validate(transport: transport)
            } catch RuntimeConfigurationError.invalidXHTTPMode {
                throw XrayConfigurationBuilderError.invalidXHTTPMode
            } catch RuntimeConfigurationError.invalidXHTTPPath {
                throw XrayConfigurationBuilderError.invalidXHTTPPath
            } catch RuntimeConfigurationError.invalidXHTTPHost {
                throw XrayConfigurationBuilderError.invalidXHTTPHost
            } catch {
                throw XrayConfigurationBuilderError.invalidXHTTPConfiguration
            }
            return XrayTransportMapping(
                network: "xhttp",
                xhttpSettings: XrayXHTTPSettings(
                    host: normalizedOptional(xhttp.host),
                    path: normalizedOptional(xhttp.path),
                    mode: xhttp.mode?.rawValue
                )
            )
        case .hysteria:
            return XrayTransportMapping(
                network: "hysteria",
                method: "hysteria"
            )
        }
    }

    private func streamSecurity(
        for security: SharedRuntimeSecurity,
        protocolKind: SharedRuntimeProtocolKind
    ) throws -> XraySecurityMapping {
        switch security.kind {
        case .none:
            guard protocolKind == .shadowsocks || protocolKind == .vmess else {
                throw XrayConfigurationBuilderError.unsupportedSecurity
            }
            return XraySecurityMapping(security: "none", tlsSettings: nil, realitySettings: nil)
        case .tls:
            let serverName = normalizedOptional(security.serverName)
            guard serverName != nil || protocolKind == .hysteria2 else {
                throw XrayConfigurationBuilderError.invalidTLSConfiguration
            }
            let fingerprint = normalizedOptional(security.fingerprint)?.lowercased()
            guard isSupportedFingerprint(fingerprint) else {
                throw XrayConfigurationBuilderError.invalidTLSConfiguration
            }
            guard security.allowInsecure == false || protocolKind != .vless else {
                throw XrayConfigurationBuilderError.invalidTLSConfiguration
            }
            return XraySecurityMapping(
                security: "tls",
                tlsSettings: XrayTLSSettings(
                    serverName: serverName,
                    allowInsecure: security.allowInsecure,
                    fingerprint: fingerprint,
                    alpn: try normalizedALPN(security.alpn)
                ),
                realitySettings: nil
            )
        case .reality:
            guard let reality = security.reality else {
                throw XrayConfigurationBuilderError.invalidRealityConfiguration
            }
            do {
                try RealityPublicParametersValidator.validate(reality)
            } catch {
                throw XrayConfigurationBuilderError.invalidRealityConfiguration
            }
            return XraySecurityMapping(
                security: "reality",
                tlsSettings: nil,
                realitySettings: XrayRealitySettings(
                    serverName: reality.serverName.trimmingCharacters(in: .whitespacesAndNewlines),
                    fingerprint: normalizedOptional(reality.fingerprint)?.lowercased(),
                    publicKey: reality.publicKey.trimmingCharacters(in: .whitespacesAndNewlines),
                    shortId: reality.shortID.trimmingCharacters(in: .whitespacesAndNewlines),
                    spiderX: normalizedOptional(reality.spiderX)
                )
            )
        }
    }

    private func isSupportedFingerprint(_ value: String?) -> Bool {
        guard let value else {
            return true
        }
        return Self.supportedFingerprints.contains(value)
    }

    private func isSupportedShadowsocksMethod(_ value: String) -> Bool {
        [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "chacha20-ietf-poly1305",
            "xchacha20-poly1305",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305"
        ].contains(value)
    }

    private func normalizedOptional(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }
}

private nonisolated struct XrayTransportMapping {
    var network: String
    var method: String?
    var wsSettings: XrayWebSocketSettings?
    var grpcSettings: XrayGRPCSettings?
    var httpUpgradeSettings: XrayHTTPUpgradeSettings?
    var xhttpSettings: XrayXHTTPSettings?
    var hysteriaSettings: XrayHysteriaStreamSettings?
}

private nonisolated struct XraySecurityMapping {
    var security: String
    var tlsSettings: XrayTLSSettings?
    var realitySettings: XrayRealitySettings?
}

private nonisolated enum Hysteria2XrayTLSPolicy {
    static let requiredALPN = ["h3"]

    static func tlsSettings(
        from tlsSettings: XrayTLSSettings?,
        endpointHost: String
    ) throws -> XrayTLSSettings {
        guard let tlsSettings else {
            throw XrayConfigurationBuilderError.invalidTLSConfiguration
        }
        let serverName = try effectiveServerName(
            explicitServerName: tlsSettings.serverName,
            endpointHost: endpointHost
        )
        return XrayTLSSettings(
            serverName: serverName,
            allowInsecure: tlsSettings.allowInsecure,
            fingerprint: tlsSettings.fingerprint,
            alpn: requiredALPN
        )
    }

    static func h3ALPNConfigured(for configuration: ResolvedVLESSRuntimeConfiguration) -> Bool? {
        configuration.protocolKind == .hysteria2 ? true : nil
    }

    static func sniConfigured(for configuration: ResolvedVLESSRuntimeConfiguration) -> Bool? {
        guard configuration.protocolKind == .hysteria2 else {
            return nil
        }
        return (try? effectiveServerName(
            explicitServerName: configuration.security.serverName,
            endpointHost: configuration.endpoint.host
        )) != nil
    }

    static func allowInsecureConfigured(for configuration: ResolvedVLESSRuntimeConfiguration) -> Bool? {
        configuration.protocolKind == .hysteria2 ? configuration.security.allowInsecure : nil
    }

    private static func effectiveServerName(
        explicitServerName: String?,
        endpointHost: String
    ) throws -> String? {
        if let explicit = normalizedOptional(explicitServerName) {
            try validateServerName(explicit)
            return explicit
        }

        let host = endpointHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isHostnameCandidate(host) else {
            return nil
        }
        try validateServerName(host)
        return host
    }

    private static func validateServerName(_ serverName: String) throws {
        guard serverName.isEmpty == false,
              serverName.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              serverName.rangeOfCharacter(from: .controlCharacters) == nil,
              serverName.contains("/") == false,
              serverName.contains(":") == false else {
            throw XrayConfigurationBuilderError.invalidTLSConfiguration
        }
    }

    private static func isHostnameCandidate(_ host: String) -> Bool {
        guard host.isEmpty == false,
              host.hasPrefix("[") == false,
              host.hasSuffix("]") == false,
              host.contains(":") == false,
              isIPv4AddressLiteral(host) == false else {
            return false
        }
        return true
    }

    private static func isIPv4AddressLiteral(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else {
            return false
        }
        return parts.allSatisfy { part in
            guard part.isEmpty == false,
                  part.unicodeScalars.allSatisfy({ CharacterSet.decimalDigits.contains($0) }),
                  let value = Int(part),
                  (0...255).contains(value) else {
                return false
            }
            return true
        }
    }

    private static func normalizedOptional(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }
}

private nonisolated struct XrayJSONDocument: Encodable {
    var log: XrayLogConfiguration
    var inbounds: [XrayInboundConfiguration]
    var outbounds: [XrayOutboundConfiguration]
}

private nonisolated struct XrayLogConfiguration: Encodable {
    var access: String
    var error: String
    var loglevel: String
}

private nonisolated struct XrayInboundConfiguration: Encodable {
    var listen: String
    var port: Int
    var protocolName: String
    var settings: XraySocksInboundSettings

    enum CodingKeys: String, CodingKey {
        case listen, port, settings
        case protocolName = "protocol"
    }
}

private nonisolated struct XraySocksInboundSettings: Encodable {
    var auth: String
    var udp: Bool
}

private nonisolated struct XrayOutboundConfiguration: Encodable {
    var protocolName: String
    var tag: String
    var settings: XrayOutboundSettings
    var streamSettings: XrayStreamSettings

    enum CodingKeys: String, CodingKey {
        case tag, settings, streamSettings
        case protocolName = "protocol"
    }
}

private nonisolated enum XrayOutboundSettings: Encodable {
    case vless(XrayVLESSOutboundSettings)
    case vmess(XrayVMessOutboundSettings)
    case trojan(XrayTrojanOutboundSettings)
    case shadowsocks(XrayShadowsocksOutboundSettings)
    case hysteria(XrayHysteriaOutboundSettings)

    func encode(to encoder: Encoder) throws {
        switch self {
        case .vless(let settings):
            try settings.encode(to: encoder)
        case .vmess(let settings):
            try settings.encode(to: encoder)
        case .trojan(let settings):
            try settings.encode(to: encoder)
        case .shadowsocks(let settings):
            try settings.encode(to: encoder)
        case .hysteria(let settings):
            try settings.encode(to: encoder)
        }
    }
}

private nonisolated struct XrayVLESSOutboundSettings: Encodable {
    var vnext: [XrayVLESSServer]
}

private nonisolated struct XrayVLESSServer: Encodable {
    var address: String
    var port: Int
    var users: [XrayVLESSUser]
}

private nonisolated struct XrayVLESSUser: Encodable {
    var id: String
    var encryption: String
    var flow: String?
}

private nonisolated struct XrayVMessOutboundSettings: Encodable {
    var vnext: [XrayVMessServer]
}

private nonisolated struct XrayVMessServer: Encodable {
    var address: String
    var port: Int
    var users: [XrayVMessUser]
}

private nonisolated struct XrayVMessUser: Encodable {
    var id: String
    var alterId: Int
    var security: String
}

private nonisolated struct XrayTrojanOutboundSettings: Encodable {
    var servers: [XrayTrojanServer]
}

private nonisolated struct XrayTrojanServer: Encodable {
    var address: String
    var port: Int
    var password: String
}

private nonisolated struct XrayShadowsocksOutboundSettings: Encodable {
    var servers: [XrayShadowsocksServer]
}

private nonisolated struct XrayShadowsocksServer: Encodable {
    var address: String
    var port: Int
    var method: String
    var password: String
}

private nonisolated struct XrayHysteriaOutboundSettings: Encodable {
    var version: Int
    var address: String
    var port: Int
}

private nonisolated struct XrayStreamSettings: Encodable {
    var method: String?
    var network: String
    var security: String
    var tlsSettings: XrayTLSSettings?
    var realitySettings: XrayRealitySettings?
    var wsSettings: XrayWebSocketSettings?
    var grpcSettings: XrayGRPCSettings?
    var httpUpgradeSettings: XrayHTTPUpgradeSettings?
    var xhttpSettings: XrayXHTTPSettings?
    var hysteriaSettings: XrayHysteriaStreamSettings?
    var finalmask: XrayFinalMaskSettings?
}

private nonisolated struct XrayTLSSettings: Encodable {
    var serverName: String?
    var allowInsecure: Bool
    var fingerprint: String?
    var alpn: [String]?
}

private nonisolated struct XrayRealitySettings: Encodable {
    var serverName: String
    var fingerprint: String?
    var publicKey: String
    var shortId: String
    var spiderX: String?
}

private nonisolated struct XrayXHTTPSettings: Encodable {
    var host: String?
    var path: String?
    var mode: String?
}

private nonisolated struct XrayWebSocketSettings: Encodable {
    var path: String?
    var headers: XrayHeaderSettings?
}

private nonisolated struct XrayHeaderSettings: Encodable {
    var host: String?

    enum CodingKeys: String, CodingKey {
        case host = "Host"
    }
}

private nonisolated struct XrayGRPCSettings: Encodable {
    var serviceName: String?
}

private nonisolated struct XrayHTTPUpgradeSettings: Encodable {
    var path: String?
    var host: String?
}

private nonisolated struct XrayHysteriaStreamSettings: Encodable {
    var version: Int
    var auth: String
}

private nonisolated struct XrayFinalMaskSettings: Encodable {
    var udp: [XrayFinalMaskLayer]
}

private nonisolated struct XrayFinalMaskLayer: Encodable {
    var type: String
    var settings: XrayFinalMaskSalamanderSettings
}

private nonisolated struct XrayFinalMaskSalamanderSettings: Encodable {
    var password: String
}

nonisolated struct LibXrayTestInvocationResult: Equatable, Sendable {
    var success: Bool
    var apiVersionSupported: Bool
    var invoked: Bool
    var category: TunnelXrayConfigurationValidationCategory
}

nonisolated protocol LibXrayTestInvoking: Sendable {
    func test(_ configuration: SensitiveXrayConfiguration) async -> LibXrayTestInvocationResult
}

nonisolated protocol LibXrayRawInvoking: Sendable {
    var apiVersion: Int64 { get }
    func invoke(requestJSON: String) -> String?
}

nonisolated final class LibXrayInvocationSerialExecutor: @unchecked Sendable {
    static let shared = LibXrayInvocationSerialExecutor()

    private let queue = DispatchQueue(label: "su.24kvn.libxray.lifecycle")

    private init() {}

    func perform<R: Sendable>(_ operation: @escaping @Sendable () -> R) async -> R {
        await withCheckedContinuation { continuation in
            queue.async {
                continuation.resume(returning: operation())
            }
        }
    }
}

nonisolated final class LibXrayTestAdapterCore: LibXrayTestInvoking, @unchecked Sendable {
    static let supportedAPIVersion: Int64 = 2

    private let invoker: any LibXrayRawInvoking
    private let executor: LibXrayInvocationSerialExecutor

    init(invoker: any LibXrayRawInvoking, executor: LibXrayInvocationSerialExecutor = .shared) {
        self.invoker = invoker
        self.executor = executor
    }

    func test(_ configuration: SensitiveXrayConfiguration) async -> LibXrayTestInvocationResult {
        await executor.perform { [invoker] in
            Self.performTest(configuration, invoker: invoker)
        }
    }

    private static func performTest(
        _ configuration: SensitiveXrayConfiguration,
        invoker: any LibXrayRawInvoking
    ) -> LibXrayTestInvocationResult {
        guard invoker.apiVersion == Self.supportedAPIVersion else {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: false,
                invoked: false,
                category: .unsupportedLibXrayAPIVersion
            )
        }

        let requestString: String
        do {
            requestString = try configuration.withJSONString { xrayJSON in
                let envelope = LibXrayInvokeEnvelope(
                    apiVersion: Self.supportedAPIVersion,
                    method: "testXray",
                    payload: LibXrayTestPayload(xrayJson: xrayJSON)
                )
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys]
                let requestData = try encoder.encode(envelope)
                return String(decoding: requestData, as: UTF8.self)
            }
        } catch {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: true,
                invoked: false,
                category: .requestEncodingFailed
            )
        }

        guard let responseString = invoker.invoke(requestJSON: requestString) else {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: true,
                invoked: true,
                category: .invocationFailed
            )
        }
        guard responseString.isEmpty == false else {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: true,
                invoked: true,
                category: .emptyResponse
            )
        }
        guard let responseData = responseString.data(using: .utf8) else {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: true,
                invoked: true,
                category: .malformedResponse
            )
        }

        do {
            let decoder = JSONDecoder()
            let response = try decoder.decode(LibXrayInvokeResponse.self, from: responseData)
            guard response.success else {
                return LibXrayTestInvocationResult(
                    success: false,
                    apiVersionSupported: true,
                    invoked: true,
                    category: .configurationRejected
                )
            }
            return LibXrayTestInvocationResult(
                success: true,
                apiVersionSupported: true,
                invoked: true,
                category: .none
            )
        } catch {
            return LibXrayTestInvocationResult(
                success: false,
                apiVersionSupported: true,
                invoked: true,
                category: .malformedResponse
            )
        }
    }
}

private nonisolated struct LibXrayInvokeEnvelope: Encodable {
    var apiVersion: Int64
    var method: String
    var payload: LibXrayTestPayload
}

private nonisolated struct LibXrayTestPayload: Encodable {
    var xrayJson: String
}

private nonisolated struct LibXrayInvokeResponse: Decodable {
    var success: Bool
}

nonisolated struct LibXrayRuntimeInvocationResult: Equatable, Sendable {
    var success: Bool
    var apiVersionSupported: Bool
    var invoked: Bool
    var running: Bool?
    var category: TunnelXrayLifecycleSmokeTestCategory
}

nonisolated protocol LibXrayRuntimeInvoking: Sendable {
    func test(_ configuration: SensitiveXrayConfiguration) async -> LibXrayRuntimeInvocationResult
    func run(_ configuration: SensitiveXrayConfiguration) async -> LibXrayRuntimeInvocationResult
    func getState() async -> LibXrayRuntimeInvocationResult
    func stop() async -> LibXrayRuntimeInvocationResult
}

nonisolated struct LibXrayPingBatchInvocationResult: Equatable, Sendable {
    var success: Bool
    var apiVersionSupported: Bool
    var invoked: Bool
    var pingAccepted: Bool
    var pingCompleted: Bool
    var delayMs: Int64?
    var timedOut: Bool
    var nativeErrorPresent: Bool
    var category: TunnelLibXrayPingProbeCategory
}

nonisolated protocol LibXrayPingBatchInvoking: Sendable {
    func pingBatch(
        _ configuration: SensitiveXrayConfiguration,
        outboundTag: String,
        timeoutSeconds: Int,
        url: String
    ) async -> LibXrayPingBatchInvocationResult
}

nonisolated enum LibXrayPingErrorClassifier {
    static func category(for rawError: String?) -> TunnelLibXrayPingProbeCategory {
        guard let rawError, rawError.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false else {
            return .unknown
        }
        let normalized = rawError.lowercased()
        if normalized.contains("timeout") || normalized.contains("deadline exceeded") {
            return .timeout
        }
        if normalized.contains("x509") || normalized.contains("certificate") || normalized.contains("cert verify") {
            return .certificateFailure
        }
        if normalized.contains("tls") || normalized.contains("handshake failure") {
            return .tlsFailure
        }
        if normalized.contains("auth") || normalized.contains("unauthorized") || normalized.contains("password") {
            return .authenticationFailure
        }
        if normalized.contains("dns") || normalized.contains("lookup") || normalized.contains("no such host") {
            return .dnsFailure
        }
        if normalized.contains("network is unreachable") || normalized.contains("network unreachable") || normalized.contains("no route to host") {
            return .networkUnreachable
        }
        if normalized.contains("connection refused") {
            return .connectionRefused
        }
        if normalized.contains("connection reset") || normalized.contains("reset by peer") {
            return .connectionReset
        }
        if normalized.contains("eof") || normalized.contains("closed pipe") || normalized.contains("broken pipe") {
            return .eof
        }
        if normalized.contains("protocol error") || normalized.contains("malformed") {
            return .protocolFailure
        }
        if normalized.contains("quic") || normalized.contains("hysteria") {
            return .quicFailure
        }
        return .unknown
    }
}

nonisolated final class LibXrayRuntimeAdapterCore: LibXrayRuntimeInvoking, LibXrayPingBatchInvoking, @unchecked Sendable {
    static let supportedAPIVersion: Int64 = LibXrayTestAdapterCore.supportedAPIVersion

    private let invoker: any LibXrayRawInvoking
    private let executor: LibXrayInvocationSerialExecutor

    init(invoker: any LibXrayRawInvoking, executor: LibXrayInvocationSerialExecutor = .shared) {
        self.invoker = invoker
        self.executor = executor
    }

    func test(_ configuration: SensitiveXrayConfiguration) async -> LibXrayRuntimeInvocationResult {
        await invokeSensitive(method: "testXray", configuration: configuration, failureCategory: .testXrayRejected)
    }

    func run(_ configuration: SensitiveXrayConfiguration) async -> LibXrayRuntimeInvocationResult {
        await invokeSensitive(method: "runXray", configuration: configuration, failureCategory: .runXrayRejected)
    }

    func getState() async -> LibXrayRuntimeInvocationResult {
        await invokeEmpty(method: "getXrayState", failureCategory: .malformedLibXrayResponse, parseState: true)
    }

    func stop() async -> LibXrayRuntimeInvocationResult {
        await invokeEmpty(method: "stopXray", failureCategory: .stopXrayRejected, parseState: false)
    }

    func pingBatch(
        _ configuration: SensitiveXrayConfiguration,
        outboundTag: String = "proxy",
        timeoutSeconds: Int = 5,
        url: String = "https://cp.cloudflare.com/"
    ) async -> LibXrayPingBatchInvocationResult {
        await executor.perform { [invoker] in
            Self.performPingBatch(
                configuration,
                outboundTag: outboundTag,
                timeoutSeconds: timeoutSeconds,
                url: url,
                invoker: invoker
            )
        }
    }

    private func invokeSensitive(
        method: String,
        configuration: SensitiveXrayConfiguration,
        failureCategory: TunnelXrayLifecycleSmokeTestCategory
    ) async -> LibXrayRuntimeInvocationResult {
        await executor.perform { [invoker] in
            Self.performSensitiveInvoke(
                method: method,
                configuration: configuration,
                invoker: invoker,
                failureCategory: failureCategory
            )
        }
    }

    private func invokeEmpty(
        method: String,
        failureCategory: TunnelXrayLifecycleSmokeTestCategory,
        parseState: Bool
    ) async -> LibXrayRuntimeInvocationResult {
        await executor.perform { [invoker] in
            Self.performEmptyInvoke(
                method: method,
                invoker: invoker,
                failureCategory: failureCategory,
                parseState: parseState
            )
        }
    }

    private static func performSensitiveInvoke(
        method: String,
        configuration: SensitiveXrayConfiguration,
        invoker: any LibXrayRawInvoking,
        failureCategory: TunnelXrayLifecycleSmokeTestCategory
    ) -> LibXrayRuntimeInvocationResult {
        guard invoker.apiVersion == supportedAPIVersion else {
            return result(success: false, apiVersionSupported: false, invoked: false, category: .unsupportedLibXrayAPIVersion)
        }

        let requestString: String
        do {
            requestString = try configuration.withJSONString { xrayJSON in
                try encodedRuntimeRequest(method: method, payload: LibXrayRuntimePayload(xrayJson: xrayJSON))
            }
        } catch {
            return result(success: false, category: .requestEncodingFailed)
        }

        let failureMapper: ((String?) -> TunnelXrayLifecycleSmokeTestCategory)? = method == "runXray" ? { error in
            mapRunFailure(error)
        } : nil
        return invokeAndParseNoData(
            requestString: requestString,
            invoker: invoker,
            failureCategory: failureCategory,
            mapFailure: failureMapper
        )
    }

    private static func performEmptyInvoke(
        method: String,
        invoker: any LibXrayRawInvoking,
        failureCategory: TunnelXrayLifecycleSmokeTestCategory,
        parseState: Bool
    ) -> LibXrayRuntimeInvocationResult {
        guard invoker.apiVersion == supportedAPIVersion else {
            return result(success: false, apiVersionSupported: false, invoked: false, category: .unsupportedLibXrayAPIVersion)
        }

        let requestString: String
        do {
            requestString = try encodedRuntimeRequest(method: method, payload: LibXrayEmptyPayload())
        } catch {
            return result(success: false, category: .requestEncodingFailed)
        }

        if parseState {
            return invokeAndParseState(requestString: requestString, invoker: invoker)
        }
        return invokeAndParseNoData(requestString: requestString, invoker: invoker, failureCategory: failureCategory)
    }

    private static func performPingBatch(
        _ configuration: SensitiveXrayConfiguration,
        outboundTag: String,
        timeoutSeconds: Int,
        url: String,
        invoker: any LibXrayRawInvoking
    ) -> LibXrayPingBatchInvocationResult {
        guard invoker.apiVersion == supportedAPIVersion else {
            return pingResult(success: false, apiVersionSupported: false, invoked: false, category: .unsupportedLibXrayAPIVersion)
        }

        let requestString: String
        do {
            requestString = try configuration.withJSONString { xrayJSON in
                let payload = LibXrayPingBatchPayload(
                    configs: [LibXrayPingBatchItemPayload(xrayJson: xrayJSON, outboundTag: outboundTag)],
                    timeout: timeoutSeconds,
                    url: url
                )
                return try encodedRuntimeRequest(method: "pingBatch", payload: payload)
            }
        } catch {
            return pingResult(success: false, category: .requestEncodingFailed)
        }

        guard let responseString = invoker.invoke(requestJSON: requestString) else {
            return pingResult(success: false, invoked: true, category: .invocationFailed)
        }
        guard responseString.isEmpty == false else {
            return pingResult(success: false, invoked: true, category: .emptyResponse)
        }
        guard let responseData = responseString.data(using: .utf8) else {
            return pingResult(success: false, invoked: true, category: .malformedResponse)
        }

        do {
            let response = try JSONDecoder().decode(LibXrayRuntimeResponse<LibXrayPingBatchResponseData>.self, from: responseData)
            guard response.success else {
                return pingResult(success: false, invoked: true, category: .configurationRejected)
            }
            guard let item = response.data?.results.first else {
                return pingResult(success: false, invoked: true, pingAccepted: true, category: .malformedResponse)
            }
            let timedOut = item.delay == 11_000 || LibXrayPingErrorClassifier.category(for: item.error) == .timeout
            if item.success {
                return pingResult(
                    success: true,
                    invoked: true,
                    pingAccepted: true,
                    pingCompleted: true,
                    delayMs: item.delay,
                    nativeErrorPresent: false,
                    category: .success
                )
            }
            return pingResult(
                success: false,
                invoked: true,
                pingAccepted: true,
                pingCompleted: true,
                delayMs: item.delay,
                timedOut: timedOut,
                nativeErrorPresent: item.error?.isEmpty == false,
                category: timedOut ? .timeout : LibXrayPingErrorClassifier.category(for: item.error)
            )
        } catch {
            return pingResult(success: false, invoked: true, category: .malformedResponse)
        }
    }

    private static func invokeAndParseNoData(
        requestString: String,
        invoker: any LibXrayRawInvoking,
        failureCategory: TunnelXrayLifecycleSmokeTestCategory,
        mapFailure: ((String?) -> TunnelXrayLifecycleSmokeTestCategory)? = nil
    ) -> LibXrayRuntimeInvocationResult {
        guard let responseString = invoker.invoke(requestJSON: requestString) else {
            return result(success: false, invoked: true, category: .invocationFailed)
        }
        guard responseString.isEmpty == false else {
            return result(success: false, invoked: true, category: .emptyResponse)
        }
        guard let responseData = responseString.data(using: .utf8) else {
            return result(success: false, invoked: true, category: .malformedLibXrayResponse)
        }

        do {
            let response = try JSONDecoder().decode(LibXrayRuntimeResponse<LibXrayEmptyResponseData>.self, from: responseData)
            guard response.success else {
                return result(success: false, invoked: true, category: mapFailure?(response.error) ?? failureCategory)
            }
            return result(success: true, invoked: true, category: .none)
        } catch {
            return result(success: false, invoked: true, category: .malformedLibXrayResponse)
        }
    }

    private static func invokeAndParseState(
        requestString: String,
        invoker: any LibXrayRawInvoking
    ) -> LibXrayRuntimeInvocationResult {
        guard let responseString = invoker.invoke(requestJSON: requestString) else {
            return result(success: false, invoked: true, category: .invocationFailed)
        }
        guard responseString.isEmpty == false else {
            return result(success: false, invoked: true, category: .emptyResponse)
        }
        guard let responseData = responseString.data(using: .utf8) else {
            return result(success: false, invoked: true, category: .malformedLibXrayResponse)
        }

        do {
            let response = try JSONDecoder().decode(LibXrayRuntimeResponse<LibXrayStatePayload>.self, from: responseData)
            guard response.success, let running = response.data?.running else {
                return result(success: false, invoked: true, category: .malformedLibXrayResponse)
            }
            return result(success: true, invoked: true, running: running, category: .none)
        } catch {
            return result(success: false, invoked: true, category: .malformedLibXrayResponse)
        }
    }

    private static func encodedRuntimeRequest<Payload: Encodable>(method: String, payload: Payload) throws -> String {
        let envelope = LibXrayRuntimeEnvelope(apiVersion: supportedAPIVersion, method: method, payload: payload)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return String(decoding: try encoder.encode(envelope), as: UTF8.self)
    }

    private static func mapRunFailure(_ error: String?) -> TunnelXrayLifecycleSmokeTestCategory {
        let normalized = error?.lowercased() ?? ""
        if normalized.contains("address already in use") || normalized.contains("bind") {
            return .localPortUnavailable
        }
        return .runXrayRejected
    }

    private static func result(
        success: Bool,
        apiVersionSupported: Bool = true,
        invoked: Bool = false,
        running: Bool? = nil,
        category: TunnelXrayLifecycleSmokeTestCategory
    ) -> LibXrayRuntimeInvocationResult {
        LibXrayRuntimeInvocationResult(
            success: success,
            apiVersionSupported: apiVersionSupported,
            invoked: invoked,
            running: running,
            category: category
        )
    }

    private static func pingResult(
        success: Bool,
        apiVersionSupported: Bool = true,
        invoked: Bool = false,
        pingAccepted: Bool = false,
        pingCompleted: Bool = false,
        delayMs: Int64? = nil,
        timedOut: Bool = false,
        nativeErrorPresent: Bool = false,
        category: TunnelLibXrayPingProbeCategory
    ) -> LibXrayPingBatchInvocationResult {
        LibXrayPingBatchInvocationResult(
            success: success,
            apiVersionSupported: apiVersionSupported,
            invoked: invoked,
            pingAccepted: pingAccepted,
            pingCompleted: pingCompleted,
            delayMs: delayMs,
            timedOut: timedOut,
            nativeErrorPresent: nativeErrorPresent,
            category: category
        )
    }
}

private nonisolated struct LibXrayRuntimeEnvelope<Payload: Encodable>: Encodable {
    var apiVersion: Int64
    var method: String
    var payload: Payload
}

private nonisolated struct LibXrayRuntimePayload: Encodable {
    var xrayJson: String
}

private nonisolated struct LibXrayPingBatchPayload: Encodable {
    var configs: [LibXrayPingBatchItemPayload]
    var timeout: Int
    var url: String
}

private nonisolated struct LibXrayPingBatchItemPayload: Encodable {
    var xrayJson: String
    var outboundTag: String
}

private nonisolated struct LibXrayEmptyPayload: Encodable {}

private nonisolated struct LibXrayEmptyResponseData: Decodable {}

private nonisolated struct LibXrayStatePayload: Decodable {
    var running: Bool
}

private nonisolated struct LibXrayPingBatchResponseData: Decodable {
    var results: [LibXrayPingBatchItemResponsePayload]
}

private nonisolated struct LibXrayPingBatchItemResponsePayload: Decodable {
    var success: Bool
    var delay: Int64
    var error: String?
}

private nonisolated struct LibXrayRuntimeResponse<DataPayload: Decodable>: Decodable {
    var success: Bool
    var data: DataPayload?
    var error: String?
}

nonisolated struct SystemLibXrayRawInvoker: LibXrayRawInvoking {
    var apiVersion: Int64 { LibXrayLibXrayAPIVersion }

    func invoke(requestJSON: String) -> String? {
        LibXrayInvoke(requestJSON)
    }
}

nonisolated enum RealityPublicParametersValidator {
    private static let supportedFingerprints: Set<String> = [
        "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"
    ]

    static func validate(_ parameters: SharedRuntimeRealityPublicParameters) throws {
        let serverName = parameters.serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard serverName.isEmpty == false, serverName.contains(" ") == false else {
            throw RuntimeConfigurationError.invalidSecurityConfiguration
        }
        guard isValidRealityPublicKey(parameters.publicKey) else {
            throw RuntimeConfigurationError.invalidSecurityConfiguration
        }
        guard isValidRealityShortID(parameters.shortID) else {
            throw RuntimeConfigurationError.invalidSecurityConfiguration
        }
        if let fingerprint = parameters.fingerprint?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
           fingerprint.isEmpty == false,
           supportedFingerprints.contains(fingerprint) == false {
            throw RuntimeConfigurationError.invalidSecurityConfiguration
        }
        if let spiderX = parameters.spiderX {
            guard spiderX.contains("\n") == false, spiderX.contains("\r") == false, spiderX.utf8.count <= 512 else {
                throw RuntimeConfigurationError.invalidSecurityConfiguration
            }
        }
    }

    static func isValidRealityPublicKey(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count == 43 else {
            return false
        }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        return trimmed.unicodeScalars.allSatisfy { scalar in
            allowed.contains(scalar)
        }
    }

    static func isValidRealityShortID(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (2...16).contains(trimmed.count), trimmed.count.isMultiple(of: 2) else {
            return false
        }
        let allowed = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
        return trimmed.unicodeScalars.allSatisfy { scalar in
            allowed.contains(scalar)
        }
    }
}

nonisolated enum XHTTPParametersValidator {
    static func validate(_ parameters: SharedRuntimeXHTTPParameters) throws {
        if let path = parameters.path {
            try validatePath(path)
        }
        if let host = parameters.host {
            try validateHost(host)
        }
        if let mode = parameters.mode {
            guard SharedRuntimeXHTTPMode(rawValue: mode.rawValue) != nil else {
                throw RuntimeConfigurationError.invalidXHTTPMode
            }
        }
    }

    static func validate(transport: SharedRuntimeTransport) throws {
        guard transport.kind == .xhttp else {
            return
        }
        guard let parameters = transport.xhttp else {
            throw RuntimeConfigurationError.invalidXHTTPConfiguration
        }
        try validate(parameters)
        if let legacyMode = normalizedOptional(transport.mode),
           SharedRuntimeXHTTPMode(rawValue: legacyMode) == nil {
            throw RuntimeConfigurationError.invalidXHTTPMode
        }
        if let legacyPath = normalizedOptional(transport.path) {
            try validatePath(legacyPath)
        }
        if let legacyHost = normalizedOptional(transport.host) {
            try validateHost(legacyHost)
        }
    }

    private static func validatePath(_ value: String) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false,
              trimmed.hasPrefix("/"),
              trimmed.contains("\n") == false,
              trimmed.contains("\r") == false,
              trimmed.utf8.count <= 512 else {
            throw RuntimeConfigurationError.invalidXHTTPPath
        }
    }

    private static func validateHost(_ value: String) throws {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false,
              trimmed.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              trimmed.rangeOfCharacter(from: CharacterSet.controlCharacters) == nil,
              trimmed.utf8.count <= 255 else {
            throw RuntimeConfigurationError.invalidXHTTPHost
        }
    }

    private static func normalizedOptional(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }
}


actor RuntimeConfigurationLoader {
    private let store: any SharedRuntimeProfileStoring
    private let credentialResolver: any RuntimeCredentialResolving

    init(store: any SharedRuntimeProfileStoring, credentialResolver: any RuntimeCredentialResolving) {
        self.store = store
        self.credentialResolver = credentialResolver
    }

    func load(providerConfiguration propertyList: [String: Any]?) async throws -> ResolvedVLESSRuntimeConfiguration {
        let providerConfiguration = try RuntimeProviderConfiguration.parse(propertyList)
        let record = try await store.read(profileID: providerConfiguration.profileID)
        try validate(record: record, providerConfiguration: providerConfiguration)

        guard CredentialReferenceValidator.isValid(record.credentialReference) else {
            throw RuntimeConfigurationError.malformedCredentialReference
        }
        guard let credential = try await credentialResolver.credential(for: record.credentialReference) else {
            throw RuntimeConfigurationError.credentialUnavailable
        }
        guard credential.isEmpty == false else {
            throw RuntimeConfigurationError.credentialMalformed
        }
        let sensitiveCredential = SensitiveRuntimeCredential(credential)
        try validateCredential(sensitiveCredential, for: record.protocolKind)
        let sensitiveObfsPassword = try await resolveHysteria2ObfsPasswordIfNeeded(from: record)

        return ResolvedVLESSRuntimeConfiguration(
            profileID: record.profileID,
            recordRevision: record.recordRevision,
            protocolKind: record.protocolKind,
            endpoint: ResolvedRuntimeEndpoint(host: record.endpoint.host, port: record.endpoint.port),
            transport: record.transport,
            security: record.security,
            vless: record.vless,
            vmess: record.vmess,
            trojan: record.trojan,
            shadowsocks: record.shadowsocks,
            hysteria2: record.hysteria2,
            credential: sensitiveCredential,
            hysteria2ObfsPassword: sensitiveObfsPassword
        )
    }

    func validateRuntimeConfiguration(
        providerConfiguration propertyList: [String: Any]?,
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64? = nil
    ) async -> TunnelRuntimeConfigurationValidationResponse {
        let providerConfiguration: RuntimeProviderConfiguration
        do {
            providerConfiguration = try RuntimeProviderConfiguration.parse(propertyList)
        } catch {
            let category = Self.category(for: error)
            return .failure(
                correlationID: correlationID,
                stage: .providerConfiguration,
                category: category,
                providerConfigurationDiagnostic: RuntimeProviderConfiguration.diagnostic(for: propertyList, category: category)
            )
        }

        if let expectedProfileID, expectedProfileID != providerConfiguration.profileID {
            return .failure(correlationID: correlationID, stage: .providerConfiguration, category: .profileIdentityMismatch, providerConfigurationValid: true)
        }
        if let expectedRevisionToken, expectedRevisionToken != providerConfiguration.recordRevision {
            return .failure(correlationID: correlationID, stage: .providerConfiguration, category: .profileRevisionMismatch, providerConfigurationValid: true)
        }

        do {
            let resolved = try await load(providerConfiguration: propertyList)
            return .success(
                correlationID: correlationID,
                protocolName: resolved.protocolKind.rawValue,
                transportName: resolved.transport.kind.rawValue,
                securityName: resolved.security.kind.rawValue
            )
        } catch {
            return .failure(correlationID: correlationID, stage: Self.stage(for: error), category: Self.category(for: error), providerConfigurationValid: true)
        }
    }

    private func validate(record: SharedRuntimeProfileRecord, providerConfiguration: RuntimeProviderConfiguration) throws {
        guard record.schemaVersion == RuntimeConfigurationProtocol.profileSchemaVersion else {
            throw RuntimeConfigurationError.profileSchemaMismatch
        }
        guard record.profileID == providerConfiguration.profileID else {
            throw RuntimeConfigurationError.profileIdentityMismatch
        }
        let recordRevisionToken = try RuntimeProviderConfiguration.revisionToken(for: record.recordRevision)
        guard recordRevisionToken == providerConfiguration.recordRevision else {
            throw RuntimeConfigurationError.profileRevisionMismatch
        }
        guard record.enabled else {
            throw RuntimeConfigurationError.profileDisabled
        }
        guard record.completeness == .complete else {
            throw RuntimeConfigurationError.profileIncomplete
        }
        guard [.vless, .vmess, .trojan, .shadowsocks, .hysteria2].contains(record.protocolKind) else {
            throw RuntimeConfigurationError.unsupportedProtocol
        }
        try validateProtocolPayload(record)
        guard record.backendKind == .xray else {
            throw RuntimeConfigurationError.unsupportedProtocol
        }
        guard record.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false,
              record.endpoint.host.contains(" ") == false,
              (1...65_535).contains(record.endpoint.port) else {
            throw RuntimeConfigurationError.invalidEndpoint
        }
        try validate(transport: record.transport)
        try validate(security: record.security)
    }

    private func validate(transport: SharedRuntimeTransport) throws {
        switch transport.kind {
        case .tcp, .websocket, .grpc, .httpUpgrade:
            return
        case .xhttp:
            try XHTTPParametersValidator.validate(transport: transport)
        case .hysteria:
            return
        }
    }

    private func validateProtocolPayload(_ record: SharedRuntimeProfileRecord) throws {
        switch record.protocolKind {
        case .vless:
            return
        case .vmess:
            guard record.vmess != nil else { throw RuntimeConfigurationError.profileRecordMalformed }
        case .trojan:
            guard record.trojan != nil else { throw RuntimeConfigurationError.profileRecordMalformed }
        case .shadowsocks:
            guard record.shadowsocks != nil else { throw RuntimeConfigurationError.profileRecordMalformed }
        case .hysteria2:
            guard record.hysteria2 != nil else { throw RuntimeConfigurationError.profileRecordMalformed }
        }
    }

    private func validateCredential(_ credential: SensitiveRuntimeCredential, for protocolKind: SharedRuntimeProtocolKind) throws {
        switch protocolKind {
        case .vless, .vmess:
            guard credential.isValidUUID else {
                throw RuntimeConfigurationError.credentialMalformed
            }
        case .trojan, .shadowsocks, .hysteria2:
            guard credential.isNonEmptySecret else {
                throw RuntimeConfigurationError.credentialMalformed
            }
        }
    }

    private func resolveHysteria2ObfsPasswordIfNeeded(from record: SharedRuntimeProfileRecord) async throws -> SensitiveRuntimeCredential? {
        guard record.protocolKind == .hysteria2,
              let reference = record.hysteria2?.obfsPasswordReference else {
            return nil
        }
        guard CredentialReferenceValidator.isValid(reference) else {
            throw RuntimeConfigurationError.malformedCredentialReference
        }
        guard let secret = try await credentialResolver.credential(for: reference) else {
            throw RuntimeConfigurationError.credentialUnavailable
        }
        let sensitive = SensitiveRuntimeCredential(secret)
        guard sensitive.isNonEmptySecret else {
            throw RuntimeConfigurationError.credentialMalformed
        }
        return sensitive
    }

    private func validate(security: SharedRuntimeSecurity) throws {
        switch security.kind {
        case .none, .tls:
            return
        case .reality:
            guard let reality = security.reality else {
                throw RuntimeConfigurationError.invalidSecurityConfiguration
            }
            try RealityPublicParametersValidator.validate(reality)
        }
    }

    private static func stage(for error: any Error) -> TunnelRuntimeConfigurationValidationStage {
        guard let error = error as? RuntimeConfigurationError else {
            return .unknown
        }
        switch error {
        case .missingProviderConfiguration, .malformedProviderConfiguration,
             .providerConfigurationUnknownKey, .providerConfigurationMissingSchemaVersion,
             .providerConfigurationWrongSchemaVersionType, .providerConfigurationUnsupportedSchemaVersion,
             .providerConfigurationMissingProfileID, .providerConfigurationWrongProfileIDType,
             .providerConfigurationMalformedProfileID, .providerConfigurationMissingRecordRevision,
             .providerConfigurationWrongRecordRevisionType, .providerConfigurationInvalidRecordRevision,
             .providerConfigurationPersistedMismatch, .providerConfigurationContractMismatch,
             .providerConfigurationStaleSession, .unsupportedProviderSchema, .missingProfileID,
             .invalidProfileID, .missingRevision, .invalidRevision:
            return .providerConfiguration
        case .profileRecordNotFound, .profileRecordTooLarge, .profileRecordMalformed, .profileRecordCountExceeded,
             .profileSchemaMismatch, .profileIdentityMismatch, .profileRevisionMismatch,
             .profileDisabled, .profileIncomplete, .unsupportedProtocol, .invalidEndpoint,
             .unsupportedTransport, .invalidTransportConfiguration, .invalidXHTTPConfiguration,
             .invalidXHTTPMode, .invalidXHTTPPath, .invalidXHTTPHost, .invalidSecurityConfiguration,
             .sharedContainerUnavailable, .writeFailed, .deleteFailed:
            return .sharedRecord
        case .missingCredentialReference, .malformedCredentialReference:
            return .credentialReference
        case .credentialUnavailable, .credentialMalformed, .sharedKeychainConfigurationInvalid:
            return .credential
        }
    }

    private static func category(for error: any Error) -> TunnelRuntimeConfigurationValidationCategory {
        guard let error = error as? RuntimeConfigurationError else {
            return .unknown
        }
        return TunnelRuntimeConfigurationValidationCategory(rawValue: error.rawValue) ?? .unknown
    }
}

struct TunnelProtocolConfigurationSnapshot: @unchecked Sendable {
    var observationGeneration: UInt64
    var providerConfiguration: [String: Any]?
}

protocol TunnelProtocolConfigurationTracking: Sendable {
    func currentSnapshot() async -> TunnelProtocolConfigurationSnapshot
    func waitForExpectedConfiguration(
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        timeout: Duration
    ) async -> TunnelProtocolConfigurationSnapshot?
}

final class TunnelProtocolConfigurationTracker: TunnelProtocolConfigurationTracking, @unchecked Sendable {
    private struct Waiter {
        var expectedProfileID: UUID?
        var expectedRevisionToken: Int64?
        var continuation: CheckedContinuation<TunnelProtocolConfigurationSnapshot?, Never>
    }

    private let lock = NSLock()
    private var observation: NSKeyValueObservation?
    private var snapshot: TunnelProtocolConfigurationSnapshot
    private var nextGeneration: UInt64
    private var waiters: [UUID: Waiter] = [:]

    init(provider: NETunnelProvider) {
        self.snapshot = TunnelProtocolConfigurationTracker.snapshot(
            from: provider.protocolConfiguration,
            generation: 0
        )
        self.nextGeneration = 0
        self.observation = provider.observe(\.protocolConfiguration, options: [.new]) { [weak self] provider, _ in
            self?.record(protocolConfiguration: provider.protocolConfiguration)
        }
    }

    func currentSnapshot() async -> TunnelProtocolConfigurationSnapshot {
        lock.withLock { snapshot }
    }

    func waitForExpectedConfiguration(
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        timeout: Duration
    ) async -> TunnelProtocolConfigurationSnapshot? {
        let id = UUID()
        let timeoutTask = Task { [weak self] in
            do {
                try await Task.sleep(for: timeout)
                self?.completeWaiter(id, snapshot: nil)
            } catch {
                // Cancellation means the expected configuration or caller already completed the wait.
            }
        }

        let result = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let immediate: TunnelProtocolConfigurationSnapshot? = lock.withLock {
                    if Self.snapshotMatches(
                        snapshot,
                        expectedProfileID: expectedProfileID,
                        expectedRevisionToken: expectedRevisionToken
                    ) {
                        return snapshot
                    }
                    waiters[id] = Waiter(
                        expectedProfileID: expectedProfileID,
                        expectedRevisionToken: expectedRevisionToken,
                        continuation: continuation
                    )
                    return nil
                }
                if let immediate {
                    continuation.resume(returning: immediate)
                }
            }
        } onCancel: { [weak self] in
            self?.completeWaiter(id, snapshot: nil)
        }

        timeoutTask.cancel()
        return result
    }

    private func record(protocolConfiguration: NEVPNProtocol) {
        let completion = lock.withLock {
            nextGeneration &+= 1
            snapshot = Self.snapshot(from: protocolConfiguration, generation: nextGeneration)
            let currentSnapshot = snapshot
            let matchedIDs = waiters.compactMap { id, waiter in
                Self.snapshotMatches(
                    currentSnapshot,
                    expectedProfileID: waiter.expectedProfileID,
                    expectedRevisionToken: waiter.expectedRevisionToken
                ) ? id : nil
            }
            let continuations = matchedIDs.compactMap { id -> CheckedContinuation<TunnelProtocolConfigurationSnapshot?, Never>? in
                waiters.removeValue(forKey: id)?.continuation
            }
            return (continuations, currentSnapshot)
        }

        for continuation in completion.0 {
            continuation.resume(returning: completion.1)
        }
    }

    private func completeWaiter(_ id: UUID, snapshot: TunnelProtocolConfigurationSnapshot?) {
        let continuation = lock.withLock {
            waiters.removeValue(forKey: id)?.continuation
        }
        continuation?.resume(returning: snapshot)
    }

    private static func snapshot(
        from protocolConfiguration: NEVPNProtocol,
        generation: UInt64
    ) -> TunnelProtocolConfigurationSnapshot {
        TunnelProtocolConfigurationSnapshot(
            observationGeneration: generation,
            providerConfiguration: (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        )
    }

    private static func snapshotMatches(
        _ snapshot: TunnelProtocolConfigurationSnapshot,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?
    ) -> Bool {
        guard let parsed = try? RuntimeProviderConfiguration.parse(snapshot.providerConfiguration) else {
            return false
        }
        return parsed.matches(
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken
        )
    }
}

protocol XrayRuntimeConfigurationLoading: Sendable {
    func loadResolvedRuntimeConfigurationForXrayValidation(
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async throws -> ResolvedVLESSRuntimeConfiguration
}

final class PacketTunnelRuntimeConfigurationValidationLoader: RuntimeConfigurationValidationLoading, XrayRuntimeConfigurationLoading, @unchecked Sendable {
    private let configurationTracker: any TunnelProtocolConfigurationTracking
    private let loader: RuntimeConfigurationLoader
    private let propagationTimeout: Duration

    init(
        provider: NETunnelProvider,
        store: any SharedRuntimeProfileStoring,
        credentialResolver: any RuntimeCredentialResolving = KeychainRuntimeCredentialResolver(),
        propagationTimeout: Duration = .milliseconds(750)
    ) {
        self.configurationTracker = TunnelProtocolConfigurationTracker(provider: provider)
        self.loader = RuntimeConfigurationLoader(store: store, credentialResolver: credentialResolver)
        self.propagationTimeout = propagationTimeout
    }

    init(
        configurationTracker: any TunnelProtocolConfigurationTracking,
        store: any SharedRuntimeProfileStoring,
        credentialResolver: any RuntimeCredentialResolving = KeychainRuntimeCredentialResolver(),
        propagationTimeout: Duration = .milliseconds(750)
    ) {
        self.configurationTracker = configurationTracker
        self.loader = RuntimeConfigurationLoader(store: store, credentialResolver: credentialResolver)
        self.propagationTimeout = propagationTimeout
    }

    static func appGroupLoader(provider: NETunnelProvider) -> PacketTunnelRuntimeConfigurationValidationLoader? {
        guard let store = FileSharedRuntimeProfileStore.appGroupStore() else {
            return nil
        }
        return PacketTunnelRuntimeConfigurationValidationLoader(provider: provider, store: store)
    }

    func validateRuntimeConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelRuntimeConfigurationValidationResponse {
        let snapshot = await currentOrPropagatedSnapshot(
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken
        )
        guard snapshot.configurationPropagationTimedOut == false else {
            var diagnostic = RuntimeProviderConfiguration.diagnostic(
                for: snapshot.snapshot.providerConfiguration,
                category: .providerConfigurationStaleSession
            )
            diagnostic.extensionMatchesRequest = false
            diagnostic.extensionMatchesPersisted = false
            diagnostic.staleK1ConfigurationObserved = snapshot.staleK1ConfigurationObserved
            diagnostic.staleProfileConfigurationObserved = snapshot.staleProfileConfigurationObserved
            diagnostic.configurationPropagationTimedOut = true
            return .failure(
                correlationID: correlationID,
                stage: .providerConfiguration,
                category: .providerConfigurationStaleSession,
                providerConfigurationDiagnostic: diagnostic
            )
        }

        return await loader.validateRuntimeConfiguration(
            providerConfiguration: snapshot.snapshot.providerConfiguration,
            correlationID: correlationID,
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken
        )
    }

    func loadResolvedRuntimeConfigurationForXrayValidation(
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async throws -> ResolvedVLESSRuntimeConfiguration {
        let snapshot = await currentOrPropagatedSnapshot(
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken
        )
        guard snapshot.configurationPropagationTimedOut == false else {
            throw RuntimeConfigurationError.providerConfigurationStaleSession
        }
        return try await loader.load(providerConfiguration: snapshot.snapshot.providerConfiguration)
    }

    private func currentOrPropagatedSnapshot(
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?
    ) async -> RuntimeConfigurationPropagationSnapshot {
        let current = await configurationTracker.currentSnapshot()
        let currentState = Self.expectedState(
            snapshot: current,
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken
        )
        guard currentState.shouldWait else {
            return RuntimeConfigurationPropagationSnapshot(
                snapshot: current,
                configurationPropagationTimedOut: false,
                staleK1ConfigurationObserved: currentState.staleK1,
                staleProfileConfigurationObserved: currentState.staleProfile
            )
        }

        if let propagated = await configurationTracker.waitForExpectedConfiguration(
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken,
            timeout: propagationTimeout
        ) {
            return RuntimeConfigurationPropagationSnapshot(
                snapshot: propagated,
                configurationPropagationTimedOut: false,
                staleK1ConfigurationObserved: currentState.staleK1,
                staleProfileConfigurationObserved: currentState.staleProfile
            )
        }

        let latest = await configurationTracker.currentSnapshot()
        let latestState = Self.expectedState(
            snapshot: latest,
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken
        )
        return RuntimeConfigurationPropagationSnapshot(
            snapshot: latest,
            configurationPropagationTimedOut: true,
            staleK1ConfigurationObserved: currentState.staleK1 || latestState.staleK1,
            staleProfileConfigurationObserved: currentState.staleProfile || latestState.staleProfile
        )
    }

    private static func expectedState(
        snapshot: TunnelProtocolConfigurationSnapshot,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?
    ) -> RuntimeConfigurationExpectedState {
        do {
            let parsed = try RuntimeProviderConfiguration.parse(snapshot.providerConfiguration)
            let matches = parsed.matches(expectedProfileID: expectedProfileID, expectedRevisionToken: expectedRevisionToken)
            let staleProfile = matches == false && (expectedProfileID != nil || expectedRevisionToken != nil)
            return RuntimeConfigurationExpectedState(
                matches: matches,
                shouldWait: staleProfile,
                staleK1: false,
                staleProfile: staleProfile
            )
        } catch {
            let staleK1 = RuntimeProviderConfiguration.isRecognizedSentinelBootstrap(snapshot.providerConfiguration)
            return RuntimeConfigurationExpectedState(
                matches: false,
                shouldWait: staleK1,
                staleK1: staleK1,
                staleProfile: false
            )
        }
    }
}

#if DEBUG
final class PacketTunnelXrayConfigurationValidationService: XrayConfigurationValidating, @unchecked Sendable {
    private let runtimeConfigurationLoader: any XrayRuntimeConfigurationLoading
    private let builder: any XrayConfigurationBuilding
    private let libXray: any LibXrayTestInvoking
    private let buildOptions: XrayBuildOptions

    init(
        runtimeConfigurationLoader: any XrayRuntimeConfigurationLoading,
        builder: any XrayConfigurationBuilding = XrayConfigurationBuilder(),
        libXray: any LibXrayTestInvoking = LibXrayTestAdapterCore(invoker: SystemLibXrayRawInvoker()),
        buildOptions: XrayBuildOptions = XrayBuildOptions()
    ) {
        self.runtimeConfigurationLoader = runtimeConfigurationLoader
        self.builder = builder
        self.libXray = libXray
        self.buildOptions = buildOptions
    }

    func validateXrayConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayConfigurationValidationResponse {
        let startedAt = Date()

        let resolved: ResolvedVLESSRuntimeConfiguration
        do {
            resolved = try await runtimeConfigurationLoader.loadResolvedRuntimeConfigurationForXrayValidation(
                expectedProfileID: expectedProfileID,
                expectedRevisionToken: expectedRevisionToken,
                requestGeneration: requestGeneration
            )
        } catch {
            return .failure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: Self.category(forRuntimeError: error),
                durationMs: Self.durationMilliseconds(since: startedAt)
            )
        }
        let h3ALPNConfigured = Hysteria2XrayTLSPolicy.h3ALPNConfigured(for: resolved)
        let sniConfigured = Hysteria2XrayTLSPolicy.sniConfigured(for: resolved)

        let sensitiveConfiguration: SensitiveXrayConfiguration
        do {
            sensitiveConfiguration = try builder.build(from: resolved, options: buildOptions)
        } catch {
            return .failure(
                correlationID: correlationID,
                stage: .builder,
                category: Self.category(forBuilderError: error),
                runtimeConfigurationValid: true,
                protocolName: resolved.protocolKind.rawValue,
                transportName: resolved.transport.kind.rawValue,
                securityName: resolved.security.kind.rawValue,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                durationMs: Self.durationMilliseconds(since: startedAt)
            )
        }

        let invocation = await libXray.test(sensitiveConfiguration)
        if invocation.success {
            return .success(
                correlationID: correlationID,
                protocolName: resolved.protocolKind.rawValue,
                transportName: resolved.transport.kind.rawValue,
                securityName: resolved.security.kind.rawValue,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                durationMs: Self.durationMilliseconds(since: startedAt)
            )
        }

        return .failure(
            correlationID: correlationID,
            stage: invocation.apiVersionSupported ? .libXrayInvocation : .libXrayAPI,
            category: invocation.category,
            runtimeConfigurationValid: true,
            builderSucceeded: true,
            libXrayAvailable: true,
            libXrayAPIVersionSupported: invocation.apiVersionSupported,
            testXrayInvoked: invocation.invoked,
            protocolName: resolved.protocolKind.rawValue,
            transportName: resolved.transport.kind.rawValue,
            securityName: resolved.security.kind.rawValue,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            durationMs: Self.durationMilliseconds(since: startedAt)
        )
    }

    private static func category(forRuntimeError error: any Error) -> TunnelXrayConfigurationValidationCategory {
        guard let error = error as? RuntimeConfigurationError else {
            return .runtimeConfigurationInvalid
        }
        switch error {
        case .providerConfigurationStaleSession:
            return .providerConfigurationStaleSession
        case .profileIdentityMismatch:
            return .profileIdentityMismatch
        case .profileRevisionMismatch:
            return .profileRevisionMismatch
        case .unsupportedProtocol:
            return .unsupportedProtocol
        case .unsupportedTransport:
            return .unsupportedTransport
        case .invalidEndpoint:
            return .invalidEndpoint
        case .invalidXHTTPConfiguration:
            return .invalidXHTTPConfiguration
        case .invalidXHTTPMode:
            return .invalidXHTTPMode
        case .invalidXHTTPPath:
            return .invalidXHTTPPath
        case .invalidXHTTPHost:
            return .invalidXHTTPHost
        case .invalidSecurityConfiguration:
            return .invalidRealityConfiguration
        case .credentialMalformed:
            return .invalidCredential
        default:
            return .runtimeConfigurationInvalid
        }
    }

    private static func category(forBuilderError error: any Error) -> TunnelXrayConfigurationValidationCategory {
        guard let error = error as? XrayConfigurationBuilderError else {
            return .unknown
        }
        return TunnelXrayConfigurationValidationCategory(rawValue: error.rawValue) ?? .unknown
    }

    private static func durationMilliseconds(since startedAt: Date) -> Double {
        max(0, Date().timeIntervalSince(startedAt) * 1_000)
    }
}
#endif

nonisolated enum XrayRuntimeLifecycleState: String, Codable, Equatable, Sendable {
    case idle
    case validating
    case starting
    case waitingForReadiness
    case running
    case stopping
    case stopped
    case failed
    case rollbackFailed
}

nonisolated enum XrayRuntimeLifecycleMode: String, Sendable {
    case oneShotSmoke
    case packetTunnelRuntimeOnly
    case packetTunnelDataPlane
    case libXrayPingOnly
}

private struct XrayRuntimeSession: Sendable {
    var port: Int
    var protocolName: String
    var transportName: String
    var securityName: String
    var h3ALPNConfigured: Bool?
    var sniConfigured: Bool?
    var mode: XrayRuntimeLifecycleMode
    var tun2SocksStarted: Bool
    var networkSettingsApplied: Bool
    var startDurationMs: Double?
    var readinessDurationMs: Double?
    var startedAt: Date
}

nonisolated enum XrayRuntimeLifecycleStateMachineError: Error, Equatable, Sendable {
    case invalidTransition(from: XrayRuntimeLifecycleState, to: XrayRuntimeLifecycleState)
}

nonisolated struct XrayRuntimeLifecycleStateMachine: Sendable {
    private(set) var state: XrayRuntimeLifecycleState = .idle

    mutating func transition(to next: XrayRuntimeLifecycleState) throws {
        guard Self.allowedTransitions[state, default: []].contains(next) else {
            throw XrayRuntimeLifecycleStateMachineError.invalidTransition(from: state, to: next)
        }
        state = next
    }

    private static let allowedTransitions: [XrayRuntimeLifecycleState: Set<XrayRuntimeLifecycleState>] = [
        .idle: [.validating],
        .validating: [.starting, .failed],
        .starting: [.waitingForReadiness, .stopping, .failed],
        .waitingForReadiness: [.running, .stopping, .failed],
        .running: [.stopping, .failed],
        .stopping: [.stopped, .rollbackFailed, .failed],
        .stopped: [.idle],
        .failed: [.stopping, .idle],
        .rollbackFailed: [.idle]
    ]
}

nonisolated protocol XrayLocalPortSelecting: Sendable {
    func candidatePorts() async -> [Int]
}

nonisolated struct LoopbackXrayLocalPortSelector: XrayLocalPortSelecting {
    private let range: ClosedRange<Int>
    private let maximumCount: Int

    init(range: ClosedRange<Int> = 20_480...20_520, maximumCount: Int = 4) {
        self.range = range
        self.maximumCount = max(1, maximumCount)
    }

    func candidatePorts() async -> [Int] {
        var selected: [Int] = []
        for port in range {
            guard selected.count < maximumCount else { break }
            if Self.isLoopbackPortAvailable(port) {
                selected.append(port)
            }
        }
        return selected
    }

    private static func isLoopbackPortAvailable(_ port: Int) -> Bool {
        guard (1...65_535).contains(port) else {
            return false
        }
        let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            return false
        }
        defer { Darwin.close(descriptor) }

        var reuse: Int32 = 1
        _ = withUnsafePointer(to: &reuse) { pointer in
            Darwin.setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_REUSEADDR,
                pointer,
                socklen_t(MemoryLayout<Int32>.size)
            )
        }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(port).bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        return withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                Darwin.bind(descriptor, socketAddress, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
    }
}

nonisolated struct XraySOCKSReadinessProbeResult: Equatable, Sendable {
    var success: Bool
    var category: TunnelXrayLifecycleSmokeTestCategory
}

nonisolated protocol XraySOCKSReadinessProbing: Sendable {
    func waitForReadiness(host: String, port: Int) async -> XraySOCKSReadinessProbeResult
    func verifyClosed(host: String, port: Int) async -> XraySOCKSReadinessProbeResult
}

nonisolated enum XraySOCKS5Greeting {
    static let requestBytes = Data([0x05, 0x01, 0x00])

    static func validateResponse(_ data: Data) -> TunnelXrayLifecycleSmokeTestCategory {
        guard data.count >= 2 else {
            return .socksReadinessTimeout
        }
        let bytes = [UInt8](data.prefix(2))
        guard bytes[0] == 0x05 else {
            return .socksGreetingRejected
        }
        guard bytes[1] == 0x00 else {
            return .socksGreetingRejected
        }
        return .none
    }
}

nonisolated enum XraySOCKS5RemoteConnect {
    static let targetHost = "1.1.1.1"
    static let targetPort = 80
    static let requestBytes = Data([0x05, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x50])

    static func parseReply(_ data: Data) -> TunnelXrayRemoteEgressProbeCategory {
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else {
            return .timeout
        }
        guard bytes[0] == 0x05 else {
            return .unknown
        }
        guard let expectedLength = expectedReplyLength(bytes), bytes.count >= expectedLength else {
            return .timeout
        }
        switch bytes[1] {
        case 0x00:
            return .success
        default:
            return .socksConnectRejected
        }
    }

    static func expectedReplyLength(_ bytes: [UInt8]) -> Int? {
        guard bytes.count >= 4 else {
            return nil
        }
        switch bytes[3] {
        case 0x01:
            return 10
        case 0x03:
            guard bytes.count >= 5 else {
                return nil
            }
            return 5 + Int(bytes[4]) + 2
        case 0x04:
            return 22
        default:
            return nil
        }
    }
}

nonisolated struct XrayRemoteEgressProbeResult: Equatable, Sendable {
    var success: Bool
    var category: TunnelXrayRemoteEgressProbeCategory
    var socksConnectRequested: Bool
    var socksConnectAccepted: Bool
    var payloadWriteSucceeded: Bool
    var remoteFirstByteReceived: Bool
    var remoteResponseValidated: Bool

    init(
        success: Bool,
        category: TunnelXrayRemoteEgressProbeCategory,
        socksConnectRequested: Bool = false,
        socksConnectAccepted: Bool = false,
        payloadWriteSucceeded: Bool = false,
        remoteFirstByteReceived: Bool = false,
        remoteResponseValidated: Bool = false
    ) {
        self.success = success
        self.category = category
        self.socksConnectRequested = socksConnectRequested
        self.socksConnectAccepted = socksConnectAccepted
        self.payloadWriteSucceeded = payloadWriteSucceeded
        self.remoteFirstByteReceived = remoteFirstByteReceived
        self.remoteResponseValidated = remoteResponseValidated
    }
}

nonisolated enum XrayRemoteEgressHTTPProbe {
    static let maximumResponseBytes = 16 * 1_024
    static let requestBytes = Data("GET / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n".utf8)

    static func evaluate(
        socksConnectRequested: Bool,
        socksConnectCategory: TunnelXrayRemoteEgressProbeCategory,
        payloadWriteSucceeded: Bool,
        responseData: Data?,
        responseReadFailed: Bool = false
    ) -> XrayRemoteEgressProbeResult {
        guard socksConnectRequested else {
            return XrayRemoteEgressProbeResult(success: false, category: .socksConnectRejected)
        }
        guard socksConnectCategory == .success else {
            return XrayRemoteEgressProbeResult(
                success: false,
                category: socksConnectCategory,
                socksConnectRequested: true
            )
        }
        guard payloadWriteSucceeded else {
            return XrayRemoteEgressProbeResult(
                success: false,
                category: .payloadWriteFailed,
                socksConnectRequested: true,
                socksConnectAccepted: true
            )
        }
        guard let responseData else {
            return XrayRemoteEgressProbeResult(
                success: false,
                category: responseReadFailed ? .remoteReadFailed : .remoteFirstByteTimeout,
                socksConnectRequested: true,
                socksConnectAccepted: true,
                payloadWriteSucceeded: true
            )
        }
        guard responseData.isEmpty == false else {
            return XrayRemoteEgressProbeResult(
                success: false,
                category: .remoteFirstByteTimeout,
                socksConnectRequested: true,
                socksConnectAccepted: true,
                payloadWriteSucceeded: true
            )
        }
        guard isValidHTTPResponsePrefix(responseData) else {
            return XrayRemoteEgressProbeResult(
                success: false,
                category: .remoteResponseInvalid,
                socksConnectRequested: true,
                socksConnectAccepted: true,
                payloadWriteSucceeded: true,
                remoteFirstByteReceived: true
            )
        }
        return XrayRemoteEgressProbeResult(
            success: true,
            category: .success,
            socksConnectRequested: true,
            socksConnectAccepted: true,
            payloadWriteSucceeded: true,
            remoteFirstByteReceived: true,
            remoteResponseValidated: true
        )
    }

    static func isValidHTTPResponsePrefix(_ data: Data) -> Bool {
        let prefix = [UInt8](data.prefix(5))
        return prefix == [0x48, 0x54, 0x54, 0x50, 0x2F]
    }
}

nonisolated struct UDPControlProbeResult: Equatable, Sendable {
    var success: Bool
    var category: TunnelUDPControlProbeCategory
    var udpConnectionReady: Bool
    var udpWriteSucceeded: Bool
    var udpResponseReceived: Bool
    var udpResponseValidated: Bool

    init(
        success: Bool,
        category: TunnelUDPControlProbeCategory,
        udpConnectionReady: Bool = false,
        udpWriteSucceeded: Bool = false,
        udpResponseReceived: Bool = false,
        udpResponseValidated: Bool = false
    ) {
        self.success = success
        self.category = category
        self.udpConnectionReady = udpConnectionReady
        self.udpWriteSucceeded = udpWriteSucceeded
        self.udpResponseReceived = udpResponseReceived
        self.udpResponseValidated = udpResponseValidated
    }
}

nonisolated enum UDPControlDNSProbe {
    static let transactionID: UInt16 = 0x4B4E
    static let targetHost = "1.1.1.1"
    static let targetPort = 53
    static let maximumResponseBytes = 512
    static let requestBytes = requestBytes(transactionID: transactionID)

    static func requestBytes(transactionID: UInt16) -> Data {
        var bytes: [UInt8] = [
            UInt8((transactionID >> 8) & 0xFF),
            UInt8(transactionID & 0xFF),
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00
        ]
        for label in ["one", "one", "one", "one"] {
            let labelBytes = [UInt8](label.utf8)
            bytes.append(UInt8(labelBytes.count))
            bytes.append(contentsOf: labelBytes)
        }
        bytes.append(0x00)
        bytes.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        return Data(bytes)
    }

    static func evaluate(
        connectionReady: Bool,
        writeSucceeded: Bool,
        responseData: Data?,
        responseReadFailed: Bool = false,
        pathUnsatisfied: Bool = false,
        cancelled: Bool = false,
        transactionID: UInt16 = transactionID
    ) -> UDPControlProbeResult {
        if cancelled {
            return UDPControlProbeResult(success: false, category: .cancelled)
        }
        if pathUnsatisfied {
            return UDPControlProbeResult(success: false, category: .pathUnsatisfied)
        }
        guard connectionReady else {
            return UDPControlProbeResult(success: false, category: .connectionFailed)
        }
        guard writeSucceeded else {
            return UDPControlProbeResult(success: false, category: .writeFailed, udpConnectionReady: true)
        }
        guard let responseData else {
            return UDPControlProbeResult(
                success: false,
                category: responseReadFailed ? .readFailed : .readTimeout,
                udpConnectionReady: true,
                udpWriteSucceeded: true
            )
        }
        guard responseData.isEmpty == false else {
            return UDPControlProbeResult(
                success: false,
                category: .readTimeout,
                udpConnectionReady: true,
                udpWriteSucceeded: true
            )
        }
        guard responseMatches(responseData, transactionID: transactionID) else {
            return UDPControlProbeResult(
                success: false,
                category: .invalidResponse,
                udpConnectionReady: true,
                udpWriteSucceeded: true,
                udpResponseReceived: true
            )
        }
        return UDPControlProbeResult(
            success: true,
            category: .success,
            udpConnectionReady: true,
            udpWriteSucceeded: true,
            udpResponseReceived: true,
            udpResponseValidated: true
        )
    }

    static func responseMatches(_ data: Data, transactionID: UInt16) -> Bool {
        let bytes = [UInt8](data.prefix(12))
        guard bytes.count >= 12 else {
            return false
        }
        let responseTransactionID = (UInt16(bytes[0]) << 8) | UInt16(bytes[1])
        guard responseTransactionID == transactionID else {
            return false
        }
        let flags = (UInt16(bytes[2]) << 8) | UInt16(bytes[3])
        return (flags & 0x8000) != 0
    }
}

nonisolated protocol XrayRemoteEgressConnectivityProbing: Sendable {
    func probe(host: String, port: Int) async -> XrayRemoteEgressProbeResult
}

nonisolated protocol UDPControlPathSnapshotProviding: Sendable {
    func snapshot() async -> TunnelUDPControlProbePathSnapshot
}

nonisolated protocol UDPControlDatagramTransporting: Sendable {
    func exchange(request: Data, maximumResponseBytes: Int) async -> UDPControlDatagramExchangeResult
}

nonisolated struct UDPControlDatagramExchangeResult: Sendable {
    var category: TunnelUDPControlProbeCategory
    var connectionReady: Bool
    var writeSucceeded: Bool
    var responseData: Data?
    var pathSnapshot: TunnelUDPControlProbePathSnapshot?

    init(
        category: TunnelUDPControlProbeCategory,
        connectionReady: Bool = false,
        writeSucceeded: Bool = false,
        responseData: Data? = nil,
        pathSnapshot: TunnelUDPControlProbePathSnapshot? = nil
    ) {
        self.category = category
        self.connectionReady = connectionReady
        self.writeSucceeded = writeSucceeded
        self.responseData = responseData
        self.pathSnapshot = pathSnapshot
    }
}

nonisolated struct PacketTunnelUDPControlProbe: PacketTunnelUDPControlProbing {
    private let pathProvider: any UDPControlPathSnapshotProviding
    private let datagramTransport: any UDPControlDatagramTransporting

    init(
        pathProvider: any UDPControlPathSnapshotProviding = NetworkFrameworkUDPControlPathProvider(),
        datagramTransport: any UDPControlDatagramTransporting = NetworkFrameworkUDPControlDatagramTransport()
    ) {
        self.pathProvider = pathProvider
        self.datagramTransport = datagramTransport
    }

    func runUDPControlProbe(
        correlationID: UUID,
        requestGeneration: UInt64?
    ) async -> TunnelUDPControlProbeResponse {
        let startedAt = Date()
        let initialPath = await pathProvider.snapshot()
        guard initialPath.pathStatus != .unsatisfied else {
            return .failure(
                correlationID: correlationID,
                category: .pathUnsatisfied,
                pathSnapshot: initialPath,
                durationMs: Self.durationMilliseconds(since: startedAt)
            )
        }

        let exchange = await datagramTransport.exchange(
            request: UDPControlDNSProbe.requestBytes,
            maximumResponseBytes: UDPControlDNSProbe.maximumResponseBytes
        )
        let pathSnapshot = exchange.pathSnapshot ?? initialPath
        let result = UDPControlDNSProbe.evaluate(
            connectionReady: exchange.connectionReady,
            writeSucceeded: exchange.writeSucceeded,
            responseData: exchange.responseData,
            responseReadFailed: exchange.category == .readFailed,
            pathUnsatisfied: exchange.category == .pathUnsatisfied,
            cancelled: exchange.category == .cancelled
        )
        let duration = Self.durationMilliseconds(since: startedAt)
        if result.success {
            return .success(correlationID: correlationID, pathSnapshot: pathSnapshot, durationMs: duration)
        }
        return .failure(
            correlationID: correlationID,
            category: result.category,
            udpConnectionReady: result.udpConnectionReady,
            udpWriteSucceeded: result.udpWriteSucceeded,
            udpResponseReceived: result.udpResponseReceived,
            udpResponseValidated: result.udpResponseValidated,
            pathSnapshot: pathSnapshot,
            durationMs: duration
        )
    }

    private static func durationMilliseconds(since startedAt: Date) -> Double {
        max(0, Date().timeIntervalSince(startedAt) * 1_000)
    }
}

nonisolated struct NetworkFrameworkUDPControlPathProvider: UDPControlPathSnapshotProviding {
    private let timeoutMilliseconds: Int

    init(timeoutMilliseconds: Int = 1_000) {
        self.timeoutMilliseconds = timeoutMilliseconds
    }

    func snapshot() async -> TunnelUDPControlProbePathSnapshot {
        let monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "su.24kvn.kvn.udp-control.path")
        let gate = UDPControlOneShotGate<TunnelUDPControlProbePathSnapshot>()
        return await withCheckedContinuation { continuation in
            gate.install(continuation)
            monitor.pathUpdateHandler = { path in
                gate.complete(Self.sanitizedSnapshot(from: path))
                monitor.cancel()
            }
            monitor.start(queue: queue)
            queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMilliseconds)) {
                gate.complete(Self.unknownSnapshot)
                monitor.cancel()
            }
        }
    }

    static let unknownSnapshot = TunnelUDPControlProbePathSnapshot(
        pathStatus: .unknown,
        usesWiFi: false,
        usesCellular: false,
        usesWiredEthernet: false,
        supportsIPv4: false,
        supportsIPv6: false,
        supportsDNS: false
    )

    static func sanitizedSnapshot(from path: Network.NWPath) -> TunnelUDPControlProbePathSnapshot {
        TunnelUDPControlProbePathSnapshot(
            pathStatus: TunnelUDPControlProbePathStatus(path.status),
            usesWiFi: path.usesInterfaceType(Network.NWInterface.InterfaceType.wifi),
            usesCellular: path.usesInterfaceType(Network.NWInterface.InterfaceType.cellular),
            usesWiredEthernet: path.usesInterfaceType(Network.NWInterface.InterfaceType.wiredEthernet),
            supportsIPv4: path.supportsIPv4,
            supportsIPv6: path.supportsIPv6,
            supportsDNS: path.supportsDNS
        )
    }
}

nonisolated struct NetworkFrameworkUDPControlDatagramTransport: UDPControlDatagramTransporting {
    private let timeoutMilliseconds: Int

    init(timeoutMilliseconds: Int = 2_000) {
        self.timeoutMilliseconds = timeoutMilliseconds
    }

    func exchange(request: Data, maximumResponseBytes: Int) async -> UDPControlDatagramExchangeResult {
        guard let address = IPv4Address(UDPControlDNSProbe.targetHost),
              let port = NWEndpoint.Port(rawValue: UInt16(UDPControlDNSProbe.targetPort)) else {
            return UDPControlDatagramExchangeResult(category: .connectionFailed)
        }
        let exchange = NetworkFrameworkUDPDatagramExchange(
            host: Network.NWEndpoint.Host.ipv4(address),
            port: port,
            timeoutMilliseconds: timeoutMilliseconds
        )
        return await withTaskCancellationHandler {
            await exchange.run(request: request, maximumResponseBytes: maximumResponseBytes)
        } onCancel: {
            exchange.cancel()
        }
    }
}

private final class NetworkFrameworkUDPDatagramExchange: @unchecked Sendable {
    private let connection: NWConnection
    private let timeoutMilliseconds: Int
    private let queue = DispatchQueue(label: "su.24kvn.kvn.udp-control.exchange")
    private let gate = UDPControlOneShotGate<UDPControlDatagramExchangeResult>()
    private let lock = NSLock()
    private var connectionReady = false
    private var writeSucceeded = false
    private var pathSnapshot: TunnelUDPControlProbePathSnapshot?

    init(host: Network.NWEndpoint.Host, port: Network.NWEndpoint.Port, timeoutMilliseconds: Int) {
        self.connection = NWConnection(host: host, port: port, using: .udp)
        self.timeoutMilliseconds = timeoutMilliseconds
    }

    func run(request: Data, maximumResponseBytes: Int) async -> UDPControlDatagramExchangeResult {
        await withCheckedContinuation { continuation in
            gate.install(continuation)
            connection.stateUpdateHandler = { [weak self] state in
                self?.handleState(state, request: request, maximumResponseBytes: maximumResponseBytes)
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMilliseconds)) { [weak self] in
                self?.finish(category: .readTimeout, responseData: nil)
            }
        }
    }

    func cancel() {
        finish(category: .cancelled, responseData: nil)
    }

    private func handleState(
        _ state: NWConnection.State,
        request: Data,
        maximumResponseBytes: Int
    ) {
        switch state {
        case .ready:
            markConnectionReady()
            connection.send(content: request, completion: .contentProcessed { [weak self] error in
                guard let self else {
                    return
                }
                guard error == nil else {
                    finish(category: .writeFailed, responseData: nil)
                    return
                }
                markWriteSucceeded()
                connection.receiveMessage { [weak self] data, _, _, error in
                    guard let self else {
                        return
                    }
                    if error != nil {
                        finish(category: .readFailed, responseData: nil)
                        return
                    }
                    if let data, data.count > maximumResponseBytes {
                        finish(category: .invalidResponse, responseData: nil)
                        return
                    }
                    finish(category: data == nil ? .readFailed : .success, responseData: data)
                }
            })
        case .waiting:
            markPathSnapshot()
            if pathSnapshot?.pathStatus == .unsatisfied {
                finish(category: .pathUnsatisfied, responseData: nil)
            }
        case .failed:
            markPathSnapshot()
            finish(category: pathSnapshot?.pathStatus == .unsatisfied ? .pathUnsatisfied : .connectionFailed, responseData: nil)
        case .cancelled:
            finish(category: .cancelled, responseData: nil)
        case .setup, .preparing:
            break
        @unknown default:
            finish(category: .unknown, responseData: nil)
        }
    }

    private func markConnectionReady() {
        lock.withLock {
            connectionReady = true
            if let path = connection.currentPath {
                pathSnapshot = NetworkFrameworkUDPControlPathProvider.sanitizedSnapshot(from: path)
            }
        }
    }

    private func markWriteSucceeded() {
        lock.withLock {
            writeSucceeded = true
        }
    }

    private func markPathSnapshot() {
        lock.withLock {
            if let path = connection.currentPath {
                pathSnapshot = NetworkFrameworkUDPControlPathProvider.sanitizedSnapshot(from: path)
            }
        }
    }

    private func finish(category: TunnelUDPControlProbeCategory, responseData: Data?) {
        let result = lock.withLock {
            UDPControlDatagramExchangeResult(
                category: category,
                connectionReady: connectionReady,
                writeSucceeded: writeSucceeded,
                responseData: responseData,
                pathSnapshot: pathSnapshot
            )
        }
        connection.cancel()
        gate.complete(result)
    }
}

private final class UDPControlOneShotGate<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Never>?
    private var completedValue: Value?

    func install(_ continuation: CheckedContinuation<Value, Never>) {
        let value: Value? = lock.withLock {
            if let completedValue {
                return completedValue
            }
            self.continuation = continuation
            return nil
        }
        if let value {
            continuation.resume(returning: value)
        }
    }

    func complete(_ value: Value) {
        let continuation = lock.withLock {
            guard completedValue == nil else {
                return nil as CheckedContinuation<Value, Never>?
            }
            completedValue = value
            let continuation = self.continuation
            self.continuation = nil
            return continuation
        }
        continuation?.resume(returning: value)
    }
}

private extension TunnelUDPControlProbePathStatus {
    init(_ status: Network.NWPath.Status) {
        switch status {
        case .satisfied:
            self = .satisfied
        case .unsatisfied:
            self = .unsatisfied
        case .requiresConnection:
            self = .requiresConnection
        @unknown default:
            self = .unknown
        }
    }
}

nonisolated struct LoopbackXraySOCKSReadinessProbe: XraySOCKSReadinessProbing {
    private let timeout: Duration
    private let retryDelay: Duration
    private let socketTimeoutUsec: Int

    init(
        timeout: Duration = .milliseconds(750),
        retryDelay: Duration = .milliseconds(50),
        socketTimeoutUsec: Int = 250_000
    ) {
        self.timeout = timeout
        self.retryDelay = retryDelay
        self.socketTimeoutUsec = socketTimeoutUsec
    }

    func waitForReadiness(host: String, port: Int) async -> XraySOCKSReadinessProbeResult {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        var lastCategory: TunnelXrayLifecycleSmokeTestCategory = .socksConnectionFailed
        while ContinuousClock.now < deadline {
            let category = await Self.probeOnce(host: host, port: port, socketTimeoutUsec: socketTimeoutUsec)
            if category == .none {
                return XraySOCKSReadinessProbeResult(success: true, category: .none)
            }
            lastCategory = category
            if category == .socksGreetingRejected {
                return XraySOCKSReadinessProbeResult(success: false, category: category)
            }
            try? await Task.sleep(for: retryDelay)
        }
        return XraySOCKSReadinessProbeResult(
            success: false,
            category: lastCategory == .socksConnectionFailed ? .socksReadinessTimeout : lastCategory
        )
    }

    func verifyClosed(host: String, port: Int) async -> XraySOCKSReadinessProbeResult {
        let connectResult = await Self.tcpConnect(host: host, port: port, socketTimeoutUsec: socketTimeoutUsec)
        return XraySOCKSReadinessProbeResult(
            success: connectResult == false,
            category: connectResult ? .localPortStillOpen : .none
        )
    }

    private static func probeOnce(
        host: String,
        port: Int,
        socketTimeoutUsec: Int
    ) async -> TunnelXrayLifecycleSmokeTestCategory {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                continuation.resume(returning: Self.performProbeOnce(host: host, port: port, socketTimeoutUsec: socketTimeoutUsec))
            }
        }
    }

    private static func tcpConnect(host: String, port: Int, socketTimeoutUsec: Int) async -> Bool {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let descriptor = Self.connectedSocket(host: host, port: port, socketTimeoutUsec: socketTimeoutUsec)
                if descriptor >= 0 {
                    Darwin.close(descriptor)
                    continuation.resume(returning: true)
                } else {
                    continuation.resume(returning: false)
                }
            }
        }
    }

    private static func performProbeOnce(
        host: String,
        port: Int,
        socketTimeoutUsec: Int
    ) -> TunnelXrayLifecycleSmokeTestCategory {
        let descriptor = connectedSocket(host: host, port: port, socketTimeoutUsec: socketTimeoutUsec)
        guard descriptor >= 0 else {
            return .socksConnectionFailed
        }
        defer { Darwin.close(descriptor) }

        let requestBytes = [UInt8](XraySOCKS5Greeting.requestBytes)
        let sent = requestBytes.withUnsafeBytes { rawBuffer in
            Darwin.send(descriptor, rawBuffer.baseAddress, requestBytes.count, 0)
        }
        guard sent == requestBytes.count else {
            return .socksConnectionFailed
        }

        let responseLength = 2
        var response = [UInt8](repeating: 0, count: responseLength)
        let received = response.withUnsafeMutableBytes { rawBuffer in
            Darwin.recv(descriptor, rawBuffer.baseAddress, responseLength, 0)
        }
        guard received > 0 else {
            return .socksReadinessTimeout
        }
        return XraySOCKS5Greeting.validateResponse(Data(response.prefix(received)))
    }

    private static func connectedSocket(host: String, port: Int, socketTimeoutUsec: Int) -> Int32 {
        guard host == "127.0.0.1", (1...65_535).contains(port) else {
            return -1
        }
        let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            return -1
        }

        var timeout = timeval(tv_sec: 0, tv_usec: Int32(socketTimeoutUsec))
        _ = withUnsafePointer(to: &timeout) { pointer in
            Darwin.setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
        }
        _ = withUnsafePointer(to: &timeout) { pointer in
            Darwin.setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
        }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(port).bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr(host))

        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                Darwin.connect(descriptor, socketAddress, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        if connected {
            return descriptor
        }
        Darwin.close(descriptor)
        return -1
    }
}

nonisolated struct LoopbackXrayRemoteEgressProbe: XrayRemoteEgressConnectivityProbing {
    private let socketTimeoutUsec: Int

    init(socketTimeoutUsec: Int = 500_000) {
        self.socketTimeoutUsec = socketTimeoutUsec
    }

    func probe(host: String, port: Int) async -> XrayRemoteEgressProbeResult {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                continuation.resume(returning: Self.performProbe(host: host, port: port, socketTimeoutUsec: socketTimeoutUsec))
            }
        }
    }

    private static func performProbe(host: String, port: Int, socketTimeoutUsec: Int) -> XrayRemoteEgressProbeResult {
        let descriptor = connectedSocket(host: host, port: port, socketTimeoutUsec: socketTimeoutUsec)
        guard descriptor >= 0 else {
            return XrayRemoteEgressProbeResult(success: false, category: .networkUnavailable)
        }
        defer { Darwin.close(descriptor) }

        guard sendAll(descriptor: descriptor, data: XraySOCKS5Greeting.requestBytes) else {
            return XrayRemoteEgressProbeResult(success: false, category: .networkUnavailable)
        }
        guard let greeting = readExactly(descriptor: descriptor, byteCount: 2) else {
            return XrayRemoteEgressProbeResult(success: false, category: .timeout)
        }
        guard XraySOCKS5Greeting.validateResponse(greeting) == .none else {
            return XrayRemoteEgressProbeResult(success: false, category: .socksHandshakeRejected)
        }

        guard sendAll(descriptor: descriptor, data: XraySOCKS5RemoteConnect.requestBytes) else {
            return XrayRemoteEgressHTTPProbe.evaluate(
                socksConnectRequested: true,
                socksConnectCategory: .networkUnavailable,
                payloadWriteSucceeded: false,
                responseData: nil
            )
        }
        let reply = readSOCKSConnectReply(descriptor: descriptor)
        let category = XraySOCKS5RemoteConnect.parseReply(reply ?? Data())
        guard category == .success else {
            return XrayRemoteEgressHTTPProbe.evaluate(
                socksConnectRequested: true,
                socksConnectCategory: category,
                payloadWriteSucceeded: false,
                responseData: nil
            )
        }

        let payloadWritten = sendAll(descriptor: descriptor, data: XrayRemoteEgressHTTPProbe.requestBytes)
        guard payloadWritten else {
            return XrayRemoteEgressHTTPProbe.evaluate(
                socksConnectRequested: true,
                socksConnectCategory: .success,
                payloadWriteSucceeded: false,
                responseData: nil
            )
        }

        let response = readInitialRemoteResponse(
            descriptor: descriptor,
            maximumBytes: XrayRemoteEgressHTTPProbe.maximumResponseBytes
        )
        return XrayRemoteEgressHTTPProbe.evaluate(
            socksConnectRequested: true,
            socksConnectCategory: .success,
            payloadWriteSucceeded: true,
            responseData: response.data,
            responseReadFailed: response.readFailed
        )
    }

    private static func connectedSocket(host: String, port: Int, socketTimeoutUsec: Int) -> Int32 {
        guard host == "127.0.0.1", (1...65_535).contains(port) else {
            return -1
        }
        let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            return -1
        }

        var timeout = timeval(tv_sec: 0, tv_usec: Int32(socketTimeoutUsec))
        _ = withUnsafePointer(to: &timeout) { pointer in
            Darwin.setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
        }
        _ = withUnsafePointer(to: &timeout) { pointer in
            Darwin.setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
        }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = in_port_t(port).bigEndian
        address.sin_addr = in_addr(s_addr: inet_addr(host))

        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                Darwin.connect(descriptor, socketAddress, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
        if connected {
            return descriptor
        }
        Darwin.close(descriptor)
        return -1
    }

    private static func sendAll(descriptor: Int32, data: Data) -> Bool {
        let bytes = [UInt8](data)
        var sentTotal = 0
        while sentTotal < bytes.count {
            let sent = bytes.withUnsafeBytes { rawBuffer in
                Darwin.send(
                    descriptor,
                    rawBuffer.baseAddress?.advanced(by: sentTotal),
                    bytes.count - sentTotal,
                    0
                )
            }
            guard sent > 0 else {
                return false
            }
            sentTotal += sent
        }
        return true
    }

    private static func readExactly(descriptor: Int32, byteCount: Int) -> Data? {
        var bytes = [UInt8]()
        bytes.reserveCapacity(byteCount)
        while bytes.count < byteCount {
            let remaining = byteCount - bytes.count
            var buffer = [UInt8](repeating: 0, count: remaining)
            let received = buffer.withUnsafeMutableBytes { rawBuffer in
                Darwin.recv(descriptor, rawBuffer.baseAddress, remaining, 0)
            }
            guard received > 0 else {
                return nil
            }
            bytes.append(contentsOf: buffer.prefix(received))
        }
        return Data(bytes)
    }

    private static func readSOCKSConnectReply(descriptor: Int32) -> Data? {
        guard var reply = readExactly(descriptor: descriptor, byteCount: 4) else {
            return nil
        }
        let prefix = [UInt8](reply)
        guard let expectedLength = XraySOCKS5RemoteConnect.expectedReplyLength(prefix) else {
            return reply
        }
        if expectedLength > reply.count,
           let remainder = readExactly(descriptor: descriptor, byteCount: expectedLength - reply.count) {
            reply.append(remainder)
        }
        return reply
    }

    private static func readInitialRemoteResponse(
        descriptor: Int32,
        maximumBytes: Int
    ) -> (data: Data?, readFailed: Bool) {
        guard maximumBytes > 0 else {
            return (nil, true)
        }
        let capacity = min(maximumBytes, 1_024)
        var buffer = [UInt8](repeating: 0, count: capacity)
        let received = buffer.withUnsafeMutableBytes { rawBuffer in
            Darwin.recv(descriptor, rawBuffer.baseAddress, capacity, 0)
        }
        if received > 0 {
            return (Data(buffer.prefix(received)), false)
        }
        if received == 0 {
            return (Data(), false)
        }
        return (nil, errno != EAGAIN && errno != EWOULDBLOCK)
    }
}

nonisolated struct Tun2SocksRuntimeConfiguration: CustomStringConvertible, CustomDebugStringConvertible, Sendable {
    private let content: String

    init(content: String) {
        self.content = content
    }

    var description: String { "<redacted tun2socks configuration>" }
    var debugDescription: String { description }

    func withString<R>(_ body: (String) throws -> R) rethrows -> R {
        try body(content)
    }
}

nonisolated enum Tun2SocksConfigurationBuilderError: String, Error, Equatable, Sendable {
    case invalidLoopbackSocksEndpoint
    case invalidMTU
}

nonisolated struct Tun2SocksConfigurationBuilder: Sendable {
    var mtu: Int
    var taskStackSize: Int
    var tcpBufferSize: Int
    var maximumSessionCount: Int

    init(
        mtu: Int = 9_000,
        taskStackSize: Int = 24_576,
        tcpBufferSize: Int = 4_096,
        maximumSessionCount: Int = 768
    ) {
        self.mtu = mtu
        self.taskStackSize = taskStackSize
        self.tcpBufferSize = tcpBufferSize
        self.maximumSessionCount = maximumSessionCount
    }

    func build(localSocksHost: String, localSocksPort: Int, udpEnabled: Bool = false) throws -> Tun2SocksRuntimeConfiguration {
        guard localSocksHost == "127.0.0.1", (1...65_535).contains(localSocksPort) else {
            throw Tun2SocksConfigurationBuilderError.invalidLoopbackSocksEndpoint
        }
        guard (1_280...16_000).contains(mtu) else {
            throw Tun2SocksConfigurationBuilderError.invalidMTU
        }

        var lines = [
            "tunnel:",
            "  mtu: \(mtu)",
            "",
            "socks5:",
            "  port: \(localSocksPort)",
            "  address: \(localSocksHost)"
        ]
        if udpEnabled {
            lines.append("  udp: 'udp'")
        }
        lines.append(contentsOf: [
            "",
            "misc:",
            "  task-stack-size: \(taskStackSize)",
            "  tcp-buffer-size: \(tcpBufferSize)",
            "  max-session-count: \(maximumSessionCount)",
            "  connect-timeout: 5000",
            "  read-write-timeout: 60000",
            "  log-file: stderr",
            "  log-level: error",
            "  limit-nofile: 65535"
        ])
        return Tun2SocksRuntimeConfiguration(content: lines.joined(separator: "\n") + "\n")
    }
}

nonisolated struct Tun2SocksStartResult: Equatable, Sendable {
    var success: Bool
    var category: TunnelXrayLifecycleSmokeTestCategory
}

nonisolated struct Tun2SocksExitResult: Equatable, Sendable {
    var exited: Bool
    var exitCode: Int32?
}

protocol Tun2SocksRuntimeManaging: Sendable {
    func start(configuration: Tun2SocksRuntimeConfiguration) async -> Tun2SocksStartResult
    func quit() async
    func waitForExit(timeout: Duration) async -> Tun2SocksExitResult
    func counters() async -> TunnelTrafficCounters
}

final class Tun2SocksRunHandle: @unchecked Sendable {
    private let lock = NSLock()
    private var storedExitCode: Int32?
    private var task: Task<Void, Never>?

    var exitCode: Int32? {
        lock.withLock { storedExitCode }
    }

    func start(configuration: Tun2SocksRuntimeConfiguration) {
        task = Task.detached(priority: .utility) { [weak self] in
            let code = configuration.withString { content in
                Socks5Tunnel.run(withConfig: .string(content: content))
            }
            self?.record(exitCode: code)
        }
    }

    func waitUntilExit() async -> Int32 {
        while true {
            if let exitCode {
                return exitCode
            }
            try? await Task.sleep(for: .milliseconds(50))
        }
    }

    private func record(exitCode: Int32) {
        lock.withLock {
            storedExitCode = exitCode
        }
    }
}

actor SystemTun2SocksRuntimeAdapter: Tun2SocksRuntimeManaging {
    private var runHandle: Tun2SocksRunHandle?

    func start(configuration: Tun2SocksRuntimeConfiguration) async -> Tun2SocksStartResult {
        guard runHandle == nil else {
            return Tun2SocksStartResult(success: false, category: .runtimeAlreadyRunning)
        }

        let handle = Tun2SocksRunHandle()
        runHandle = handle
        handle.start(configuration: configuration)
        try? await Task.sleep(for: .milliseconds(150))

        if let exitCode = handle.exitCode {
            runHandle = nil
            return Tun2SocksStartResult(
                success: false,
                category: exitCode == 0 ? .tun2SocksUnexpectedExit : .tun2SocksStartupFailed
            )
        }

        return Tun2SocksStartResult(success: true, category: .none)
    }

    func quit() async {
        Socks5Tunnel.quit()
    }

    func waitForExit(timeout: Duration) async -> Tun2SocksExitResult {
        guard let runHandle else {
            return Tun2SocksExitResult(exited: true, exitCode: nil)
        }
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while ContinuousClock.now < deadline {
            if let exitCode = runHandle.exitCode {
                self.runHandle = nil
                return Tun2SocksExitResult(exited: true, exitCode: exitCode)
            }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return Tun2SocksExitResult(exited: false, exitCode: nil)
    }

    func counters() async -> TunnelTrafficCounters {
        let stats = Socks5Tunnel.stats
        return TunnelTrafficCounters(
            bytesUploaded: UInt64(max(0, stats.up.bytes)),
            bytesDownloaded: UInt64(max(0, stats.down.bytes)),
            packetsUploaded: UInt64(max(0, stats.up.packets)),
            packetsDownloaded: UInt64(max(0, stats.down.packets))
        )
    }
}

nonisolated struct PacketTunnelNetworkSettingsPlan: Equatable, Sendable {
    var tunnelRemoteAddress: String
    var ipv4Address: String
    var ipv4SubnetMask: String
    var mtu: Int
    var dnsServers: [String]
    var dnsMatchDomains: [String]
    var ipv6Policy: String
    var udpPolicy: String

    static let k3b3aIPv4FullTunnel = PacketTunnelNetworkSettingsPlan(
        tunnelRemoteAddress: "127.0.0.1",
        ipv4Address: "10.24.0.2",
        ipv4SubnetMask: "255.255.255.0",
        mtu: 9_000,
        dnsServers: ["1.1.1.1", "8.8.8.8"],
        dnsMatchDomains: [""],
        ipv6Policy: "ipv4OnlyNoIPv6Settings",
        udpPolicy: "enabledForDataPlaneDNSForwarding"
    )
}

nonisolated struct PacketTunnelNetworkSettingsBuilder: Sendable {
    var plan: PacketTunnelNetworkSettingsPlan

    init(plan: PacketTunnelNetworkSettingsPlan = .k3b3aIPv4FullTunnel) {
        self.plan = plan
    }

    func build() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: plan.tunnelRemoteAddress)
        let ipv4 = NEIPv4Settings(addresses: [plan.ipv4Address], subnetMasks: [plan.ipv4SubnetMask])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        settings.mtu = NSNumber(value: plan.mtu)

        let dns = NEDNSSettings(servers: plan.dnsServers)
        dns.matchDomains = plan.dnsMatchDomains
        settings.dnsSettings = dns
        return settings
    }
}

protocol PacketTunnelNetworkSettingsApplying: Sendable {
    func apply(_ settings: NEPacketTunnelNetworkSettings) async throws
    func clear() async -> Bool
}

final class PacketTunnelNetworkSettingsApplier: PacketTunnelNetworkSettingsApplying, @unchecked Sendable {
    private weak var provider: NEPacketTunnelProvider?

    init(provider: NEPacketTunnelProvider) {
        self.provider = provider
    }

    func apply(_ settings: NEPacketTunnelNetworkSettings) async throws {
        guard let provider else {
            throw NSError(
                domain: "su.24kvn.packet-tunnel.data-plane",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Data-plane network settings provider unavailable"]
            )
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            provider.setTunnelNetworkSettings(settings) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    func clear() async -> Bool {
        guard let provider else {
            return false
        }
        return await withCheckedContinuation { continuation in
            provider.setTunnelNetworkSettings(nil) { error in
                continuation.resume(returning: error == nil)
            }
        }
    }
}

protocol XrayRuntimeSessionControlling: Sendable {
    func startPacketTunnelRuntimeOnly(correlationID: UUID) async -> TunnelXrayLifecycleSmokeTestResponse
    func startPacketTunnelDataPlane(correlationID: UUID) async -> TunnelXrayLifecycleSmokeTestResponse
    func startPacketTunnelLibXrayPingOnly(correlationID: UUID) async -> TunnelXrayLifecycleSmokeTestResponse
    func stopPacketTunnelRuntimeOnly(correlationID: UUID) async -> TunnelXrayLifecycleSmokeTestResponse
    func stopActivePacketTunnelSession(correlationID: UUID) async -> TunnelXrayLifecycleSmokeTestResponse
}

actor XrayRuntimeLifecycleController: XrayConfigurationValidating, XrayRemoteEgressProbing, PacketTunnelUDPControlProbing, LibXrayPingProbing, DiagnosticProviderModeProviding, XrayRuntimeSessionControlling {
    private let runtimeConfigurationLoader: any XrayRuntimeConfigurationLoading
    private let builder: any XrayConfigurationBuilding
    private let libXray: any LibXrayRuntimeInvoking
    private let libXrayPingBatch: any LibXrayPingBatchInvoking
    private let portSelector: any XrayLocalPortSelecting
    private let readinessProbe: any XraySOCKSReadinessProbing
    private let remoteEgressProbe: any XrayRemoteEgressConnectivityProbing
    private let udpControlProbe: any PacketTunnelUDPControlProbing
    private let tun2SocksConfigurationBuilder: Tun2SocksConfigurationBuilder
    private let tun2Socks: (any Tun2SocksRuntimeManaging)?
    private let networkSettingsBuilder: PacketTunnelNetworkSettingsBuilder
    private let networkSettingsApplier: (any PacketTunnelNetworkSettingsApplying)?
    private let tunnelCancellationHandler: (@Sendable (NSError) -> Void)?
    private let telemetryStore: TunnelTelemetryStore?
    private var stateMachine = XrayRuntimeLifecycleStateMachine()
    private var activeSession: XrayRuntimeSession?
    private var tun2SocksExitMonitorTask: Task<Void, Never>?

    init(
        runtimeConfigurationLoader: any XrayRuntimeConfigurationLoading,
        builder: any XrayConfigurationBuilding = XrayConfigurationBuilder(),
        libXray: any LibXrayRuntimeInvoking = LibXrayRuntimeAdapterCore(invoker: SystemLibXrayRawInvoker()),
        libXrayPingBatch: (any LibXrayPingBatchInvoking)? = nil,
        portSelector: any XrayLocalPortSelecting = LoopbackXrayLocalPortSelector(),
        readinessProbe: any XraySOCKSReadinessProbing = LoopbackXraySOCKSReadinessProbe(),
        remoteEgressProbe: any XrayRemoteEgressConnectivityProbing = LoopbackXrayRemoteEgressProbe(),
        udpControlProbe: any PacketTunnelUDPControlProbing = PacketTunnelUDPControlProbe(),
        tun2SocksConfigurationBuilder: Tun2SocksConfigurationBuilder = Tun2SocksConfigurationBuilder(),
        tun2Socks: (any Tun2SocksRuntimeManaging)? = SystemTun2SocksRuntimeAdapter(),
        networkSettingsBuilder: PacketTunnelNetworkSettingsBuilder = PacketTunnelNetworkSettingsBuilder(),
        networkSettingsApplier: (any PacketTunnelNetworkSettingsApplying)? = nil,
        tunnelCancellationHandler: (@Sendable (NSError) -> Void)? = nil,
        telemetryStore: TunnelTelemetryStore? = nil
    ) {
        self.runtimeConfigurationLoader = runtimeConfigurationLoader
        self.builder = builder
        self.libXray = libXray
        if let libXrayPingBatch {
            self.libXrayPingBatch = libXrayPingBatch
        } else if let pingBatch = libXray as? any LibXrayPingBatchInvoking {
            self.libXrayPingBatch = pingBatch
        } else {
            self.libXrayPingBatch = LibXrayRuntimeAdapterCore(invoker: SystemLibXrayRawInvoker())
        }
        self.portSelector = portSelector
        self.readinessProbe = readinessProbe
        self.remoteEgressProbe = remoteEgressProbe
        self.udpControlProbe = udpControlProbe
        self.tun2SocksConfigurationBuilder = tun2SocksConfigurationBuilder
        self.tun2Socks = tun2Socks
        self.networkSettingsBuilder = networkSettingsBuilder
        self.networkSettingsApplier = networkSettingsApplier
        self.tunnelCancellationHandler = tunnelCancellationHandler
        self.telemetryStore = telemetryStore
    }

    func diagnosticProviderMode() async -> TunnelDiagnosticProviderMode {
        if let activeSession {
            switch activeSession.mode {
            case .packetTunnelRuntimeOnly:
                return .runtimeOnly
            case .packetTunnelDataPlane:
                return .dataPlane
            case .libXrayPingOnly:
                return .libXrayPingOnly
            case .oneShotSmoke:
                return .lifecycleSmoke
            }
        }

        return stateMachine.state == .idle ? .idle : .lifecycleSmoke
    }

    func validateXrayConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayConfigurationValidationResponse {
        let startedAt = Date()
        guard stateMachine.state == .idle, activeSession == nil else {
            return .failure(
                correlationID: correlationID,
                stage: .libXrayInvocation,
                category: .runtimeAlreadyRunning,
                durationMs: Self.durationMilliseconds(since: startedAt)
            )
        }

        let resolved: ResolvedVLESSRuntimeConfiguration
        do {
            resolved = try await runtimeConfigurationLoader.loadResolvedRuntimeConfigurationForXrayValidation(
                expectedProfileID: expectedProfileID,
                expectedRevisionToken: expectedRevisionToken,
                requestGeneration: requestGeneration
            )
        } catch {
            return .failure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: Self.xrayValidationCategory(forRuntimeError: error),
                durationMs: Self.durationMilliseconds(since: startedAt)
            )
        }
        let h3ALPNConfigured = Hysteria2XrayTLSPolicy.h3ALPNConfigured(for: resolved)
        let sniConfigured = Hysteria2XrayTLSPolicy.sniConfigured(for: resolved)

        let sensitiveConfiguration: SensitiveXrayConfiguration
        do {
            sensitiveConfiguration = try builder.build(from: resolved, options: XrayBuildOptions())
        } catch {
            return .failure(
                correlationID: correlationID,
                stage: .builder,
                category: Self.xrayValidationCategory(forBuilderError: error),
                runtimeConfigurationValid: true,
                protocolName: resolved.protocolKind.rawValue,
                transportName: resolved.transport.kind.rawValue,
                securityName: resolved.security.kind.rawValue,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                durationMs: Self.durationMilliseconds(since: startedAt)
            )
        }

        let invocation = await libXray.test(sensitiveConfiguration)
        if invocation.success {
            return .success(
                correlationID: correlationID,
                protocolName: resolved.protocolKind.rawValue,
                transportName: resolved.transport.kind.rawValue,
                securityName: resolved.security.kind.rawValue,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                durationMs: Self.durationMilliseconds(since: startedAt)
            )
        }

        return .failure(
            correlationID: correlationID,
            stage: invocation.apiVersionSupported ? .libXrayInvocation : .libXrayAPI,
            category: Self.xrayValidationCategory(forLifecycleCategory: invocation.category),
            runtimeConfigurationValid: true,
            builderSucceeded: true,
            libXrayAvailable: true,
            libXrayAPIVersionSupported: invocation.apiVersionSupported,
            testXrayInvoked: invocation.invoked,
            protocolName: resolved.protocolKind.rawValue,
            transportName: resolved.transport.kind.rawValue,
            securityName: resolved.security.kind.rawValue,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            durationMs: Self.durationMilliseconds(since: startedAt)
        )
    }

    func run(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayLifecycleSmokeTestResponse {
        guard stateMachine.state == .idle, activeSession == nil else {
            return failure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .runtimeAlreadyRunning,
                totalStartedAt: Date()
            )
        }
        let totalStartedAt = Date()
        try? stateMachine.transition(to: .validating)
        await telemetryStore?.markXrayLifecycleEvent(category: "xrayValidationStarted", state: .starting)

        let resolved: ResolvedVLESSRuntimeConfiguration
        do {
            resolved = try await runtimeConfigurationLoader.loadResolvedRuntimeConfigurationForXrayValidation(
                expectedProfileID: expectedProfileID,
                expectedRevisionToken: expectedRevisionToken,
                requestGeneration: requestGeneration
            )
        } catch {
            try? stateMachine.transition(to: .failed)
            let response = failure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: Self.category(forRuntimeError: error),
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        let protocolName = resolved.protocolKind.rawValue
        let transportName = resolved.transport.kind.rawValue
        let securityName = resolved.security.kind.rawValue
        let h3ALPNConfigured = Hysteria2XrayTLSPolicy.h3ALPNConfigured(for: resolved)
        let sniConfigured = Hysteria2XrayTLSPolicy.sniConfigured(for: resolved)
        guard Self.isSupportedRuntimeProfile(resolved) else {
            try? stateMachine.transition(to: .failed)
            let response = failure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: .unsupportedProfileForRuntimeSmoke,
                runtimeConfigurationLoaded: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        let candidatePorts = await portSelector.candidatePorts()
        guard candidatePorts.isEmpty == false else {
            try? stateMachine.transition(to: .failed)
            let response = failure(
                correlationID: correlationID,
                stage: .xrayBuild,
                category: .localPortUnavailable,
                runtimeConfigurationLoaded: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        var lastRunFailure: TunnelXrayLifecycleSmokeTestResponse?
        for port in candidatePorts {
            let response = await attempt(
                correlationID: correlationID,
                resolved: resolved,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                port: port,
                totalStartedAt: totalStartedAt,
                mode: .oneShotSmoke
            )
            if response.success || response.failureCategory != .localPortUnavailable {
                resetForNextOperation()
                return response
            }
            lastRunFailure = response
        }

        resetForNextOperation()
        return lastRunFailure ?? failure(
            correlationID: correlationID,
            stage: .runXray,
            category: .localPortUnavailable,
            runtimeConfigurationLoaded: true,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            totalStartedAt: totalStartedAt
        )
    }

    func runXrayRemoteEgressProbe(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayRemoteEgressProbeResponse {
        let totalStartedAt = Date()
        guard stateMachine.state == .idle, activeSession == nil else {
            return remoteFailure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .runtimeBusy,
                totalStartedAt: totalStartedAt
            )
        }
        try? stateMachine.transition(to: .validating)
        await telemetryStore?.markXrayLifecycleEvent(category: "xrayRemoteEgressProbeStarted", state: .starting)

        let resolved: ResolvedVLESSRuntimeConfiguration
        do {
            resolved = try await runtimeConfigurationLoader.loadResolvedRuntimeConfigurationForXrayValidation(
                expectedProfileID: expectedProfileID,
                expectedRevisionToken: expectedRevisionToken,
                requestGeneration: requestGeneration
            )
        } catch {
            try? stateMachine.transition(to: .failed)
            let response = remoteFailure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: .configurationRejected,
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        let protocolName = resolved.protocolKind.rawValue
        let transportName = resolved.transport.kind.rawValue
        let securityName = resolved.security.kind.rawValue
        let h3ALPNConfigured = Hysteria2XrayTLSPolicy.h3ALPNConfigured(for: resolved)
        let sniConfigured = Hysteria2XrayTLSPolicy.sniConfigured(for: resolved)
        let allowInsecureConfigured = Hysteria2XrayTLSPolicy.allowInsecureConfigured(for: resolved)
        guard Self.isSupportedRuntimeProfile(resolved) else {
            try? stateMachine.transition(to: .failed)
            let response = remoteFailure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: .configurationRejected,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        let candidatePorts = await portSelector.candidatePorts()
        guard let port = candidatePorts.first else {
            try? stateMachine.transition(to: .failed)
            let response = remoteFailure(
                correlationID: correlationID,
                stage: .xrayBuild,
                category: .networkUnavailable,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        let response = await remoteEgressAttempt(
            correlationID: correlationID,
            resolved: resolved,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            allowInsecureConfigured: allowInsecureConfigured,
            port: port,
            totalStartedAt: totalStartedAt
        )
        resetForNextOperation()
        return response
    }

    func probeActiveXrayEgress(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayRemoteEgressProbeResponse {
        let totalStartedAt = Date()
        guard let session = activeSession,
              stateMachine.state == .running,
              let probeContext = Self.remoteProbeContext(for: session.mode) else {
            return remoteFailure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .runtimeBusy,
                totalStartedAt: totalStartedAt
            )
        }

        let remoteStartedAt = Date()
        let remote = await remoteEgressProbe.probe(host: "127.0.0.1", port: session.port)
        let remoteDuration = Self.durationMilliseconds(since: remoteStartedAt)
        guard remote.success else {
            return remoteFailure(
                correlationID: correlationID,
                stage: Self.remoteStage(forRemoteCategory: remote.category),
                category: remote.category,
                xrayBuildPassed: true,
                testXrayPassed: true,
                xrayRunning: true,
                localSocksReady: true,
                remoteConnectAttempted: remote.socksConnectRequested,
                remoteConnectSucceeded: false,
                remoteConnectCategory: remote.category,
                socksConnectRequested: remote.socksConnectRequested,
                socksConnectAccepted: remote.socksConnectAccepted,
                payloadWriteSucceeded: remote.payloadWriteSucceeded,
                remoteFirstByteReceived: remote.remoteFirstByteReceived,
                remoteResponseValidated: remote.remoteResponseValidated,
                protocolName: session.protocolName,
                transportName: session.transportName,
                securityName: session.securityName,
                h3ALPNConfigured: session.h3ALPNConfigured,
                sniConfigured: session.sniConfigured,
                probeContext: probeContext,
                startDurationMs: session.startDurationMs,
                readinessDurationMs: session.readinessDurationMs,
                remoteConnectDurationMs: remoteDuration,
                totalStartedAt: totalStartedAt
            )
        }

        return .success(
            correlationID: correlationID,
            protocolName: session.protocolName,
            transportName: session.transportName,
            securityName: session.securityName,
            h3ALPNConfigured: session.h3ALPNConfigured,
            sniConfigured: session.sniConfigured,
            probeContext: probeContext,
            cleanupSucceeded: false,
            startDurationMs: session.startDurationMs,
            readinessDurationMs: session.readinessDurationMs,
            remoteConnectDurationMs: remoteDuration,
            stopDurationMs: nil,
            totalDurationMs: Self.durationMilliseconds(since: totalStartedAt)
        )
    }

    func runUDPControlProbe(
        correlationID: UUID,
        requestGeneration: UInt64?
    ) async -> TunnelUDPControlProbeResponse {
        guard let session = activeSession,
              stateMachine.state == .running,
              session.mode == .packetTunnelRuntimeOnly else {
            return .failure(
                correlationID: correlationID,
                category: .notRuntimeOnly
            )
        }
        return await udpControlProbe.runUDPControlProbe(
            correlationID: correlationID,
            requestGeneration: requestGeneration
        )
    }

    func runLibXrayPingProbe(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelLibXrayPingProbeResponse {
        let startedAt = Date()
        guard let session = activeSession,
              stateMachine.state == .running,
              session.mode == .libXrayPingOnly else {
            return libXrayPingFailure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .runtimeBusy,
                startedAt: startedAt
            )
        }

        let resolved: ResolvedVLESSRuntimeConfiguration
        do {
            resolved = try await runtimeConfigurationLoader.loadResolvedRuntimeConfigurationForXrayValidation(
                expectedProfileID: expectedProfileID,
                expectedRevisionToken: expectedRevisionToken,
                requestGeneration: requestGeneration
            )
        } catch {
            return libXrayPingFailure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: .configurationRejected,
                startedAt: startedAt
            )
        }

        let protocolName = resolved.protocolKind.rawValue
        let transportName = resolved.transport.kind.rawValue
        let securityName = resolved.security.kind.rawValue
        let h3ALPNConfigured = Hysteria2XrayTLSPolicy.h3ALPNConfigured(for: resolved)
        let sniConfigured = Hysteria2XrayTLSPolicy.sniConfigured(for: resolved)
        let allowInsecureConfigured = Hysteria2XrayTLSPolicy.allowInsecureConfigured(for: resolved)
        guard Self.isSupportedRuntimeProfile(resolved) else {
            return libXrayPingFailure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: .configurationRejected,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                startedAt: startedAt
            )
        }

        let sensitiveConfiguration: SensitiveXrayConfiguration
        do {
            sensitiveConfiguration = try builder.build(
                from: resolved,
                options: XrayBuildOptions(
                    localSocksListenAddress: "127.0.0.1",
                    localSocksPort: 20_480,
                    localSocksUDPEnabled: false
                )
            )
        } catch {
            return libXrayPingFailure(
                correlationID: correlationID,
                stage: .xrayBuild,
                category: .configurationRejected,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                startedAt: startedAt
            )
        }

        let ping = await libXrayPingBatch.pingBatch(
            sensitiveConfiguration,
            outboundTag: "proxy",
            timeoutSeconds: 5,
            url: "https://cp.cloudflare.com/"
        )
        if ping.success {
            return .success(
                correlationID: correlationID,
                delayMs: ping.delayMs,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                durationMs: Self.durationMilliseconds(since: startedAt)
            )
        }

        return libXrayPingFailure(
            correlationID: correlationID,
            stage: ping.invoked ? .libXrayPing : .responseValidation,
            category: ping.apiVersionSupported ? ping.category : .unsupportedLibXrayAPIVersion,
            xrayConfigurationBuilt: true,
            pingAccepted: ping.pingAccepted,
            pingCompleted: ping.pingCompleted,
            delayMs: ping.delayMs,
            timedOut: ping.timedOut,
            nativeErrorPresent: ping.nativeErrorPresent,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            allowInsecureConfigured: allowInsecureConfigured,
            startedAt: startedAt
        )
    }

    private static func remoteProbeContext(for mode: XrayRuntimeLifecycleMode) -> TunnelXrayRemoteEgressProbeContext? {
        switch mode {
        case .packetTunnelRuntimeOnly:
            return .runtimeOnly
        case .packetTunnelDataPlane:
            return .dataPlane
        case .oneShotSmoke, .libXrayPingOnly:
            return nil
        }
    }

    func startPacketTunnelRuntimeOnly(correlationID: UUID) async -> TunnelXrayLifecycleSmokeTestResponse {
        guard stateMachine.state == .idle, activeSession == nil else {
            return failure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .runtimeAlreadyRunning,
                totalStartedAt: Date()
            )
        }
        let totalStartedAt = Date()
        try? stateMachine.transition(to: .validating)
        await telemetryStore?.markXrayLifecycleEvent(category: "xrayValidationStarted", state: .starting)

        let resolved: ResolvedVLESSRuntimeConfiguration
        do {
            resolved = try await runtimeConfigurationLoader.loadResolvedRuntimeConfigurationForXrayValidation(
                expectedProfileID: nil,
                expectedRevisionToken: nil,
                requestGeneration: nil
            )
        } catch {
            try? stateMachine.transition(to: .failed)
            let response = failure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: Self.category(forRuntimeError: error),
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        let protocolName = resolved.protocolKind.rawValue
        let transportName = resolved.transport.kind.rawValue
        let securityName = resolved.security.kind.rawValue
        let h3ALPNConfigured = Hysteria2XrayTLSPolicy.h3ALPNConfigured(for: resolved)
        let sniConfigured = Hysteria2XrayTLSPolicy.sniConfigured(for: resolved)
        guard Self.isSupportedRuntimeProfile(resolved) else {
            try? stateMachine.transition(to: .failed)
            let response = failure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: .unsupportedProfileForRuntimeSmoke,
                runtimeConfigurationLoaded: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        let candidatePorts = await portSelector.candidatePorts()
        guard candidatePorts.isEmpty == false else {
            try? stateMachine.transition(to: .failed)
            let response = failure(
                correlationID: correlationID,
                stage: .xrayBuild,
                category: .localPortUnavailable,
                runtimeConfigurationLoaded: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        var lastRunFailure: TunnelXrayLifecycleSmokeTestResponse?
        for port in candidatePorts {
            let response = await attempt(
                correlationID: correlationID,
                resolved: resolved,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                port: port,
                totalStartedAt: totalStartedAt,
                mode: .packetTunnelRuntimeOnly
            )
            if response.success || response.failureCategory != .localPortUnavailable {
                if response.success == false {
                    resetForNextOperation()
                }
                return response
            }
            lastRunFailure = response
        }

        resetForNextOperation()
        return lastRunFailure ?? failure(
            correlationID: correlationID,
            stage: .runXray,
            category: .localPortUnavailable,
            runtimeConfigurationLoaded: true,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            totalStartedAt: totalStartedAt
        )
    }

    func startPacketTunnelDataPlane(correlationID: UUID) async -> TunnelXrayLifecycleSmokeTestResponse {
        guard stateMachine.state == .idle, activeSession == nil else {
            return failure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .runtimeAlreadyRunning,
                totalStartedAt: Date()
            )
        }
        let totalStartedAt = Date()
        try? stateMachine.transition(to: .validating)
        await telemetryStore?.markXrayLifecycleEvent(category: "dataPlaneValidationStarted", state: .starting)

        let resolved: ResolvedVLESSRuntimeConfiguration
        do {
            resolved = try await runtimeConfigurationLoader.loadResolvedRuntimeConfigurationForXrayValidation(
                expectedProfileID: nil,
                expectedRevisionToken: nil,
                requestGeneration: nil
            )
        } catch {
            try? stateMachine.transition(to: .failed)
            let response = failure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: Self.category(forRuntimeError: error),
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        let protocolName = resolved.protocolKind.rawValue
        let transportName = resolved.transport.kind.rawValue
        let securityName = resolved.security.kind.rawValue
        let h3ALPNConfigured = Hysteria2XrayTLSPolicy.h3ALPNConfigured(for: resolved)
        let sniConfigured = Hysteria2XrayTLSPolicy.sniConfigured(for: resolved)
        guard Self.isSupportedRuntimeProfile(resolved) else {
            try? stateMachine.transition(to: .failed)
            let response = failure(
                correlationID: correlationID,
                stage: .runtimeConfiguration,
                category: .unsupportedProfileForRuntimeSmoke,
                runtimeConfigurationLoaded: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        await telemetryStore?.markDataPlaneStarting(
            profileID: resolved.profileID,
            protocolName: protocolName,
            transportName: transportName
        )

        let candidatePorts = await portSelector.candidatePorts()
        guard candidatePorts.isEmpty == false else {
            try? stateMachine.transition(to: .failed)
            let response = failure(
                correlationID: correlationID,
                stage: .xrayBuild,
                category: .localPortUnavailable,
                runtimeConfigurationLoaded: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }

        var lastRunFailure: TunnelXrayLifecycleSmokeTestResponse?
        for port in candidatePorts {
            let response = await attempt(
                correlationID: correlationID,
                resolved: resolved,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                port: port,
                totalStartedAt: totalStartedAt,
                mode: .packetTunnelDataPlane
            )
            if response.success || response.failureCategory != .localPortUnavailable {
                if response.success == false {
                    resetForNextOperation()
                }
                return response
            }
            lastRunFailure = response
        }

        resetForNextOperation()
        return lastRunFailure ?? failure(
            correlationID: correlationID,
            stage: .runXray,
            category: .localPortUnavailable,
            runtimeConfigurationLoaded: true,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            totalStartedAt: totalStartedAt
        )
    }

    func startPacketTunnelLibXrayPingOnly(correlationID: UUID) async -> TunnelXrayLifecycleSmokeTestResponse {
        guard stateMachine.state == .idle, activeSession == nil else {
            return failure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .runtimeAlreadyRunning,
                totalStartedAt: Date()
            )
        }

        let totalStartedAt = Date()
        try? stateMachine.transition(to: .validating)
        try? stateMachine.transition(to: .starting)
        try? stateMachine.transition(to: .waitingForReadiness)
        try? stateMachine.transition(to: .running)
        activeSession = XrayRuntimeSession(
            port: 0,
            protocolName: "libXrayPingOnly",
            transportName: "none",
            securityName: "none",
            h3ALPNConfigured: nil,
            sniConfigured: nil,
            mode: .libXrayPingOnly,
            tun2SocksStarted: false,
            networkSettingsApplied: false,
            startDurationMs: Self.durationMilliseconds(since: totalStartedAt),
            readinessDurationMs: nil,
            startedAt: totalStartedAt
        )

        return TunnelXrayLifecycleSmokeTestResponse(
            correlationID: correlationID,
            success: true,
            runtimeConfigurationLoaded: false,
            xrayConfigurationBuilt: false,
            testXrayPassed: false,
            runXrayInvoked: false,
            runningStateObserved: false,
            socksListenerReady: false,
            socksGreetingAccepted: false,
            stopXrayInvoked: false,
            stoppedStateObserved: false,
            localPortClosed: false,
            rollbackAttempted: false,
            rollbackSucceeded: true,
            protocolName: "libXrayPingOnly",
            transportName: "none",
            securityName: "none",
            h3ALPNConfigured: nil,
            sniConfigured: nil,
            failureStage: nil,
            failureCategory: nil,
            startDurationMs: Self.durationMilliseconds(since: totalStartedAt),
            readinessDurationMs: nil,
            stopDurationMs: nil,
            totalDurationMs: Self.durationMilliseconds(since: totalStartedAt),
            diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                stage: .preStartState,
                category: .none,
                extensionRequestReached: true,
                correlationIDPrefix: String(correlationID.uuidString.prefix(8))
            )
        )
    }

    func stopPacketTunnelRuntimeOnly(correlationID: UUID) async -> TunnelXrayLifecycleSmokeTestResponse {
        let totalStartedAt = Date()
        guard let session = activeSession else {
            let response = failure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .runtimeAlreadyRunning,
                totalStartedAt: totalStartedAt
            )
            resetForNextOperation()
            return response
        }
        if session.mode == .packetTunnelDataPlane {
            return await stopDataPlaneSession(session, correlationID: correlationID)
        }
        if session.mode == .libXrayPingOnly {
            activeSession = nil
            try? stateMachine.transition(to: .stopping)
            try? stateMachine.transition(to: .stopped)
            try? stateMachine.transition(to: .idle)
            return TunnelXrayLifecycleSmokeTestResponse(
                correlationID: correlationID,
                success: true,
                runtimeConfigurationLoaded: false,
                xrayConfigurationBuilt: false,
                testXrayPassed: false,
                runXrayInvoked: false,
                runningStateObserved: false,
                socksListenerReady: false,
                socksGreetingAccepted: false,
                stopXrayInvoked: false,
                stoppedStateObserved: false,
                localPortClosed: false,
                rollbackAttempted: false,
                rollbackSucceeded: true,
                protocolName: session.protocolName,
                transportName: session.transportName,
                securityName: session.securityName,
                h3ALPNConfigured: nil,
                sniConfigured: nil,
                failureStage: nil,
                failureCategory: nil,
                startDurationMs: session.startDurationMs,
                readinessDurationMs: nil,
                stopDurationMs: Self.durationMilliseconds(since: totalStartedAt),
                totalDurationMs: Self.durationMilliseconds(since: totalStartedAt),
                diagnostic: TunnelXrayLifecycleSmokeTestDiagnostic(
                    stage: .stoppedState,
                    category: .none,
                    extensionRequestReached: true,
                    correlationIDPrefix: String(correlationID.uuidString.prefix(8))
                )
            )
        }

        let cleanup = await stopAndVerify(port: session.port)
        activeSession = nil
        let response: TunnelXrayLifecycleSmokeTestResponse
        if cleanup.success {
            response = .success(
                correlationID: correlationID,
                protocolName: session.protocolName,
                transportName: session.transportName,
                securityName: session.securityName,
                h3ALPNConfigured: session.h3ALPNConfigured,
                sniConfigured: session.sniConfigured,
                startDurationMs: session.startDurationMs,
                readinessDurationMs: session.readinessDurationMs,
                stopDurationMs: cleanup.stopDurationMs,
                totalDurationMs: Self.durationMilliseconds(since: totalStartedAt)
            )
        } else {
            response = failure(
                correlationID: correlationID,
                stage: cleanup.stage,
                category: .rollbackFailed,
                runtimeConfigurationLoaded: true,
                xrayConfigurationBuilt: true,
                testXrayPassed: true,
                runXrayInvoked: true,
                runningStateObserved: true,
                socksListenerReady: true,
                socksGreetingAccepted: true,
                stopXrayInvoked: cleanup.stopInvoked,
                stoppedStateObserved: cleanup.stoppedStateObserved,
                localPortClosed: cleanup.portClosed,
                rollbackAttempted: true,
                rollbackSucceeded: false,
                protocolName: session.protocolName,
                transportName: session.transportName,
                securityName: session.securityName,
                h3ALPNConfigured: session.h3ALPNConfigured,
                sniConfigured: session.sniConfigured,
                stopDurationMs: cleanup.stopDurationMs,
                totalStartedAt: totalStartedAt
            )
        }
        resetForNextOperation()
        return response
    }

    func stopActivePacketTunnelSession(correlationID: UUID) async -> TunnelXrayLifecycleSmokeTestResponse {
        guard let session = activeSession else {
            return await stopPacketTunnelRuntimeOnly(correlationID: correlationID)
        }
        switch session.mode {
        case .packetTunnelDataPlane:
            return await stopDataPlaneSession(session, correlationID: correlationID)
        case .packetTunnelRuntimeOnly, .oneShotSmoke, .libXrayPingOnly:
            return await stopPacketTunnelRuntimeOnly(correlationID: correlationID)
        }
    }

    private static func isSupportedRuntimeProfile(_ resolved: ResolvedVLESSRuntimeConfiguration) -> Bool {
        switch resolved.protocolKind {
        case .vless:
            return [.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(resolved.transport.kind)
                && [.tls, .reality].contains(resolved.security.kind)
        case .vmess:
            return [.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(resolved.transport.kind)
                && [.none, .tls, .reality].contains(resolved.security.kind)
        case .trojan:
            return [.tcp, .websocket, .grpc, .httpUpgrade, .xhttp].contains(resolved.transport.kind)
                && [.tls, .reality].contains(resolved.security.kind)
        case .shadowsocks:
            return resolved.transport.kind == .tcp && resolved.security.kind == .none
        case .hysteria2:
            return resolved.transport.kind == .hysteria && resolved.security.kind == .tls
        }
    }

    private func attempt(
        correlationID: UUID,
        resolved: ResolvedVLESSRuntimeConfiguration,
        protocolName: String,
        transportName: String,
        securityName: String,
        h3ALPNConfigured: Bool?,
        sniConfigured: Bool?,
        port: Int,
        totalStartedAt: Date,
        mode: XrayRuntimeLifecycleMode
    ) async -> TunnelXrayLifecycleSmokeTestResponse {
        let options = XrayBuildOptions(
            localSocksListenAddress: "127.0.0.1",
            localSocksPort: port,
            localSocksUDPEnabled: mode == .packetTunnelDataPlane
        )
        let sensitiveConfiguration: SensitiveXrayConfiguration
        do {
            sensitiveConfiguration = try builder.build(from: resolved, options: options)
        } catch {
            try? stateMachine.transition(to: .failed)
            return failure(
                correlationID: correlationID,
                stage: .xrayBuild,
                category: Self.category(forBuilderError: error),
                runtimeConfigurationLoaded: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                totalStartedAt: totalStartedAt
            )
        }

        let preflight = await libXray.test(sensitiveConfiguration)
        guard preflight.success else {
            try? stateMachine.transition(to: .failed)
            return failure(
                correlationID: correlationID,
                stage: preflight.apiVersionSupported ? .testXray : .testXray,
                category: preflight.category,
                runtimeConfigurationLoaded: true,
                xrayConfigurationBuilt: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                totalStartedAt: totalStartedAt
            )
        }

        let preStartState = await libXray.getState()
        guard preStartState.success else {
            try? stateMachine.transition(to: .failed)
            return failure(
                correlationID: correlationID,
                stage: .preStartState,
                category: preStartState.category,
                runtimeConfigurationLoaded: true,
                xrayConfigurationBuilt: true,
                testXrayPassed: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                totalStartedAt: totalStartedAt
            )
        }
        guard preStartState.running != true else {
            try? stateMachine.transition(to: .failed)
            return failure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .runtimeAlreadyRunning,
                runtimeConfigurationLoaded: true,
                xrayConfigurationBuilt: true,
                testXrayPassed: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                totalStartedAt: totalStartedAt
            )
        }

        try? stateMachine.transition(to: .starting)
        await telemetryStore?.markXrayLifecycleEvent(category: "xrayStartRequested", state: .starting)
        let startStartedAt = Date()
        let run = await libXray.run(sensitiveConfiguration)
        let startDuration = Self.durationMilliseconds(since: startStartedAt)
        guard run.success else {
            try? stateMachine.transition(to: .failed)
            return failure(
                correlationID: correlationID,
                stage: .runXray,
                category: run.category,
                runtimeConfigurationLoaded: true,
                xrayConfigurationBuilt: true,
                testXrayPassed: true,
                runXrayInvoked: run.invoked,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                startDurationMs: startDuration,
                totalStartedAt: totalStartedAt
            )
        }

        try? stateMachine.transition(to: .waitingForReadiness)
        guard await waitForRunningState() else {
            return await rollbackFailure(
                correlationID: correlationID,
                stage: .runningState,
                category: .xrayDidNotReachRunningState,
                runtimeConfigurationLoaded: true,
                xrayConfigurationBuilt: true,
                testXrayPassed: true,
                runXrayInvoked: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                startDurationMs: startDuration,
                totalStartedAt: totalStartedAt,
                port: port
            )
        }

        await telemetryStore?.markXrayLifecycleEvent(category: "xrayRunningObserved", state: .running)
        let readinessStartedAt = Date()
        let readiness = await readinessProbe.waitForReadiness(host: "127.0.0.1", port: port)
        let readinessDuration = Self.durationMilliseconds(since: readinessStartedAt)
        guard readiness.success else {
            let stage: TunnelXrayLifecycleSmokeTestStage = readiness.category == .socksGreetingRejected ? .socksGreeting : .socksReadiness
            return await rollbackFailure(
                correlationID: correlationID,
                stage: stage,
                category: readiness.category,
                runtimeConfigurationLoaded: true,
                xrayConfigurationBuilt: true,
                testXrayPassed: true,
                runXrayInvoked: true,
                runningStateObserved: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                startDurationMs: startDuration,
                readinessDurationMs: readinessDuration,
                totalStartedAt: totalStartedAt,
                port: port
            )
        }

        try? stateMachine.transition(to: .running)
        await telemetryStore?.markXrayLifecycleEvent(category: "xraySOCKSReady", state: .running)
        if mode == .packetTunnelRuntimeOnly {
            activeSession = XrayRuntimeSession(
                port: port,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                mode: .packetTunnelRuntimeOnly,
                tun2SocksStarted: false,
                networkSettingsApplied: false,
                startDurationMs: startDuration,
                readinessDurationMs: readinessDuration,
                startedAt: totalStartedAt
            )
            return .runtimeOnlyStarted(
                correlationID: correlationID,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                startDurationMs: startDuration,
                readinessDurationMs: readinessDuration,
                totalDurationMs: Self.durationMilliseconds(since: totalStartedAt)
            )
        }
        if mode == .packetTunnelDataPlane {
            return await completeDataPlaneStart(
                correlationID: correlationID,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                port: port,
                startDurationMs: startDuration,
                readinessDurationMs: readinessDuration,
                totalStartedAt: totalStartedAt
            )
        }
        return await stopAfterSuccess(
            correlationID: correlationID,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            startDurationMs: startDuration,
            readinessDurationMs: readinessDuration,
            totalStartedAt: totalStartedAt,
            port: port
        )
    }

    private func remoteEgressAttempt(
        correlationID: UUID,
        resolved: ResolvedVLESSRuntimeConfiguration,
        protocolName: String,
        transportName: String,
        securityName: String,
        h3ALPNConfigured: Bool?,
        sniConfigured: Bool?,
        allowInsecureConfigured: Bool?,
        port: Int,
        totalStartedAt: Date
    ) async -> TunnelXrayRemoteEgressProbeResponse {
        let options = XrayBuildOptions(
            localSocksListenAddress: "127.0.0.1",
            localSocksPort: port,
            localSocksUDPEnabled: false
        )
        let sensitiveConfiguration: SensitiveXrayConfiguration
        do {
            sensitiveConfiguration = try builder.build(from: resolved, options: options)
        } catch {
            try? stateMachine.transition(to: .failed)
            return remoteFailure(
                correlationID: correlationID,
                stage: .xrayBuild,
                category: .configurationRejected,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                totalStartedAt: totalStartedAt
            )
        }

        let preflight = await libXray.test(sensitiveConfiguration)
        guard preflight.success else {
            try? stateMachine.transition(to: .failed)
            return remoteFailure(
                correlationID: correlationID,
                stage: .testXray,
                category: .configurationRejected,
                xrayBuildPassed: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                totalStartedAt: totalStartedAt
            )
        }

        let preStartState = await libXray.getState()
        guard preStartState.success else {
            try? stateMachine.transition(to: .failed)
            return remoteFailure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .unknown,
                xrayBuildPassed: true,
                testXrayPassed: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                totalStartedAt: totalStartedAt
            )
        }
        guard preStartState.running != true else {
            try? stateMachine.transition(to: .failed)
            return remoteFailure(
                correlationID: correlationID,
                stage: .preStartState,
                category: .runtimeBusy,
                xrayBuildPassed: true,
                testXrayPassed: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                totalStartedAt: totalStartedAt
            )
        }

        try? stateMachine.transition(to: .starting)
        await telemetryStore?.markXrayLifecycleEvent(category: "xrayStartRequested", state: .starting)
        let startStartedAt = Date()
        let run = await libXray.run(sensitiveConfiguration)
        let startDuration = Self.durationMilliseconds(since: startStartedAt)
        guard run.success else {
            try? stateMachine.transition(to: .failed)
            return remoteFailure(
                correlationID: correlationID,
                stage: .runXray,
                category: .configurationRejected,
                xrayBuildPassed: true,
                testXrayPassed: true,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                startDurationMs: startDuration,
                totalStartedAt: totalStartedAt
            )
        }

        try? stateMachine.transition(to: .waitingForReadiness)
        guard await waitForRunningState() else {
            return await remoteRollbackFailure(
                correlationID: correlationID,
                stage: .runningState,
                category: .xrayExited,
                xrayBuildPassed: true,
                testXrayPassed: true,
                xrayRunning: false,
                localSocksReady: false,
                remoteConnectAttempted: false,
                remoteConnectSucceeded: false,
                remoteConnectCategory: .xrayExited,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                startDurationMs: startDuration,
                totalStartedAt: totalStartedAt,
                port: port
            )
        }

        await telemetryStore?.markXrayLifecycleEvent(category: "xrayRunningObserved", state: .running)
        let readinessStartedAt = Date()
        let readiness = await readinessProbe.waitForReadiness(host: "127.0.0.1", port: port)
        let readinessDuration = Self.durationMilliseconds(since: readinessStartedAt)
        guard readiness.success else {
            let stage: TunnelXrayRemoteEgressProbeStage = readiness.category == .socksGreetingRejected ? .socksGreeting : .socksReadiness
            return await remoteRollbackFailure(
                correlationID: correlationID,
                stage: stage,
                category: Self.remoteCategory(forLifecycleCategory: readiness.category),
                xrayBuildPassed: true,
                testXrayPassed: true,
                xrayRunning: true,
                localSocksReady: false,
                remoteConnectAttempted: false,
                remoteConnectSucceeded: false,
                remoteConnectCategory: Self.remoteCategory(forLifecycleCategory: readiness.category),
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                startDurationMs: startDuration,
                readinessDurationMs: readinessDuration,
                totalStartedAt: totalStartedAt,
                port: port
            )
        }

        try? stateMachine.transition(to: .running)
        await telemetryStore?.markXrayLifecycleEvent(category: "xraySOCKSReady", state: .running)
        let remoteStartedAt = Date()
        let remote = await remoteEgressProbe.probe(host: "127.0.0.1", port: port)
        let remoteDuration = Self.durationMilliseconds(since: remoteStartedAt)
        guard remote.success else {
            return await remoteRollbackFailure(
                correlationID: correlationID,
                stage: Self.remoteStage(forRemoteCategory: remote.category),
                category: remote.category,
                xrayBuildPassed: true,
                testXrayPassed: true,
                xrayRunning: true,
                localSocksReady: true,
                remoteConnectAttempted: remote.socksConnectRequested,
                remoteConnectSucceeded: false,
                remoteConnectCategory: remote.category,
                socksConnectRequested: remote.socksConnectRequested,
                socksConnectAccepted: remote.socksConnectAccepted,
                payloadWriteSucceeded: remote.payloadWriteSucceeded,
                remoteFirstByteReceived: remote.remoteFirstByteReceived,
                remoteResponseValidated: remote.remoteResponseValidated,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                startDurationMs: startDuration,
                readinessDurationMs: readinessDuration,
                remoteConnectDurationMs: remoteDuration,
                totalStartedAt: totalStartedAt,
                port: port
            )
        }

        let cleanup = await stopAndVerify(port: port)
        if cleanup.success {
            return .success(
                correlationID: correlationID,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                allowInsecureConfigured: allowInsecureConfigured,
                startDurationMs: startDuration,
                readinessDurationMs: readinessDuration,
                remoteConnectDurationMs: remoteDuration,
                stopDurationMs: cleanup.stopDurationMs,
                totalDurationMs: Self.durationMilliseconds(since: totalStartedAt)
            )
        }

        return remoteFailure(
            correlationID: correlationID,
            stage: Self.remoteStage(forCleanupStage: cleanup.stage),
            category: .cleanupFailed,
            xrayBuildPassed: true,
            testXrayPassed: true,
            xrayRunning: true,
            localSocksReady: true,
            remoteConnectAttempted: true,
            remoteConnectSucceeded: true,
            remoteConnectCategory: .success,
            socksConnectRequested: true,
            socksConnectAccepted: true,
            payloadWriteSucceeded: true,
            remoteFirstByteReceived: true,
            remoteResponseValidated: true,
            remoteEgressSucceeded: true,
            cleanupSucceeded: false,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            allowInsecureConfigured: allowInsecureConfigured,
            startDurationMs: startDuration,
            readinessDurationMs: readinessDuration,
            remoteConnectDurationMs: remoteDuration,
            stopDurationMs: cleanup.stopDurationMs,
            totalStartedAt: totalStartedAt
        )
    }

    private func completeDataPlaneStart(
        correlationID: UUID,
        protocolName: String,
        transportName: String,
        securityName: String,
        h3ALPNConfigured: Bool?,
        sniConfigured: Bool?,
        port: Int,
        startDurationMs: Double?,
        readinessDurationMs: Double?,
        totalStartedAt: Date
    ) async -> TunnelXrayLifecycleSmokeTestResponse {
        guard let tun2Socks, let networkSettingsApplier else {
            return await rollbackDataPlaneFailure(
                correlationID: correlationID,
                stage: .dataPlane,
                category: .providerUnavailable,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                startDurationMs: startDurationMs,
                readinessDurationMs: readinessDurationMs,
                totalStartedAt: totalStartedAt,
                port: port,
                tun2SocksStarted: false,
                networkSettingsApplied: false
            )
        }

        let tun2SocksConfiguration: Tun2SocksRuntimeConfiguration
        do {
            tun2SocksConfiguration = try tun2SocksConfigurationBuilder.build(
                localSocksHost: "127.0.0.1",
                localSocksPort: port,
                udpEnabled: true
            )
        } catch {
            return await rollbackDataPlaneFailure(
                correlationID: correlationID,
                stage: .tun2SocksStart,
                category: .tun2SocksConfigurationInvalid,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                startDurationMs: startDurationMs,
                readinessDurationMs: readinessDurationMs,
                totalStartedAt: totalStartedAt,
                port: port,
                tun2SocksStarted: false,
                networkSettingsApplied: false
            )
        }

        await telemetryStore?.markXrayLifecycleEvent(category: "tun2SocksStartRequested", state: .starting)
        let tun2SocksStart = await tun2Socks.start(configuration: tun2SocksConfiguration)
        guard tun2SocksStart.success else {
            return await rollbackDataPlaneFailure(
                correlationID: correlationID,
                stage: .tun2SocksStart,
                category: tun2SocksStart.category,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                startDurationMs: startDurationMs,
                readinessDurationMs: readinessDurationMs,
                totalStartedAt: totalStartedAt,
                port: port,
                tun2SocksStarted: false,
                networkSettingsApplied: false
            )
        }
        await telemetryStore?.markTun2SocksStarted()

        do {
            try await networkSettingsApplier.apply(networkSettingsBuilder.build())
        } catch {
            return await rollbackDataPlaneFailure(
                correlationID: correlationID,
                stage: .networkSettings,
                category: .networkSettingsFailed,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                startDurationMs: startDurationMs,
                readinessDurationMs: readinessDurationMs,
                totalStartedAt: totalStartedAt,
                port: port,
                tun2SocksStarted: true,
                networkSettingsApplied: true
            )
        }

        activeSession = XrayRuntimeSession(
            port: port,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            mode: .packetTunnelDataPlane,
            tun2SocksStarted: true,
            networkSettingsApplied: true,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            startedAt: totalStartedAt
        )
        await telemetryStore?.markNetworkSettingsApplied()
        await telemetryStore?.markDataPlaneRunning(counters: await tun2Socks.counters())
        startTun2SocksExitMonitor(correlationID: correlationID)

        return .runtimeOnlyStarted(
            correlationID: correlationID,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            totalDurationMs: Self.durationMilliseconds(since: totalStartedAt)
        )
    }

    private func startTun2SocksExitMonitor(correlationID: UUID) {
        tun2SocksExitMonitorTask?.cancel()
        guard let tun2Socks else {
            return
        }
        tun2SocksExitMonitorTask = Task { [weak self] in
            while Task.isCancelled == false {
                let exit = await tun2Socks.waitForExit(timeout: .milliseconds(250))
                if Task.isCancelled {
                    return
                }
                if exit.exited {
                    await self?.handleUnexpectedTun2SocksExit(correlationID: correlationID)
                    return
                }
            }
        }
    }

    private func handleUnexpectedTun2SocksExit(correlationID: UUID) async {
        guard let session = activeSession, session.mode == .packetTunnelDataPlane else {
            return
        }
        await telemetryStore?.markDataPlaneFailure(category: .runtimeExited)
        _ = await cleanupDataPlaneDependencies(
            tun2SocksStarted: false,
            networkSettingsApplied: session.networkSettingsApplied
        )
        _ = await stopAndVerify(port: session.port)
        activeSession = nil
        resetForNextOperation()
        tunnelCancellationHandler?(NSError(
            domain: "su.24kvn.packet-tunnel.data-plane",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "Data-plane forwarder exited unexpectedly"]
        ))
    }

    private func waitForRunningState() async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: .milliseconds(750))
        while ContinuousClock.now < deadline {
            let state = await libXray.getState()
            if state.success, state.running == true {
                return true
            }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return false
    }

    private func waitForStoppedState() async -> Bool {
        let deadline = ContinuousClock.now.advanced(by: .milliseconds(750))
        while ContinuousClock.now < deadline {
            let state = await libXray.getState()
            if state.success, state.running == false {
                return true
            }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return false
    }

    private func stopAfterSuccess(
        correlationID: UUID,
        protocolName: String,
        transportName: String,
        securityName: String,
        h3ALPNConfigured: Bool?,
        sniConfigured: Bool?,
        startDurationMs: Double?,
        readinessDurationMs: Double?,
        totalStartedAt: Date,
        port: Int
    ) async -> TunnelXrayLifecycleSmokeTestResponse {
        let cleanup = await stopAndVerify(port: port)
        if cleanup.success {
            return .success(
                correlationID: correlationID,
                protocolName: protocolName,
                transportName: transportName,
                securityName: securityName,
                h3ALPNConfigured: h3ALPNConfigured,
                sniConfigured: sniConfigured,
                startDurationMs: startDurationMs,
                readinessDurationMs: readinessDurationMs,
                stopDurationMs: cleanup.stopDurationMs,
                totalDurationMs: Self.durationMilliseconds(since: totalStartedAt)
            )
        }

        return failure(
            correlationID: correlationID,
            stage: cleanup.stage,
            category: .rollbackFailed,
            runtimeConfigurationLoaded: true,
            xrayConfigurationBuilt: true,
            testXrayPassed: true,
            runXrayInvoked: true,
            runningStateObserved: true,
            socksListenerReady: true,
            socksGreetingAccepted: true,
            stopXrayInvoked: cleanup.stopInvoked,
            stoppedStateObserved: cleanup.stoppedStateObserved,
            localPortClosed: cleanup.portClosed,
            rollbackAttempted: true,
            rollbackSucceeded: false,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            stopDurationMs: cleanup.stopDurationMs,
            totalStartedAt: totalStartedAt
        )
    }

    private func stopDataPlaneSession(
        _ session: XrayRuntimeSession,
        correlationID: UUID
    ) async -> TunnelXrayLifecycleSmokeTestResponse {
        let totalStartedAt = Date()
        tun2SocksExitMonitorTask?.cancel()
        tun2SocksExitMonitorTask = nil
        await telemetryStore?.markXrayLifecycleEvent(category: "dataPlaneStopRequested", state: .stopping)
        let dataPlaneCleanup = await cleanupDataPlaneDependencies(
            tun2SocksStarted: session.tun2SocksStarted,
            networkSettingsApplied: session.networkSettingsApplied
        )
        let xrayCleanup = await stopAndVerify(port: session.port)
        activeSession = nil

        if dataPlaneCleanup.success, xrayCleanup.success {
            let response = TunnelXrayLifecycleSmokeTestResponse.success(
                correlationID: correlationID,
                protocolName: session.protocolName,
                transportName: session.transportName,
                securityName: session.securityName,
                h3ALPNConfigured: session.h3ALPNConfigured,
                sniConfigured: session.sniConfigured,
                startDurationMs: session.startDurationMs,
                readinessDurationMs: session.readinessDurationMs,
                stopDurationMs: xrayCleanup.stopDurationMs,
                totalDurationMs: Self.durationMilliseconds(since: totalStartedAt)
            )
            await telemetryStore?.markStopped()
            resetForNextOperation()
            return response
        }

        let failedStage = dataPlaneCleanup.success ? xrayCleanup.stage : dataPlaneCleanup.stage
        let failedCategory = dataPlaneCleanup.success ? TunnelXrayLifecycleSmokeTestCategory.rollbackFailed : dataPlaneCleanup.category
        let response = failure(
            correlationID: correlationID,
            stage: failedStage,
            category: failedCategory,
            runtimeConfigurationLoaded: true,
            xrayConfigurationBuilt: true,
            testXrayPassed: true,
            runXrayInvoked: true,
            runningStateObserved: true,
            socksListenerReady: true,
            socksGreetingAccepted: true,
            stopXrayInvoked: xrayCleanup.stopInvoked,
            stoppedStateObserved: xrayCleanup.stoppedStateObserved,
            localPortClosed: xrayCleanup.portClosed,
            rollbackAttempted: true,
            rollbackSucceeded: false,
            protocolName: session.protocolName,
            transportName: session.transportName,
            securityName: session.securityName,
            h3ALPNConfigured: session.h3ALPNConfigured,
            sniConfigured: session.sniConfigured,
            stopDurationMs: xrayCleanup.stopDurationMs,
            totalStartedAt: totalStartedAt
        )
        await telemetryStore?.markDataPlaneFailure(category: .runtimeExited)
        resetForNextOperation()
        return response
    }

    private func rollbackDataPlaneFailure(
        correlationID: UUID,
        stage: TunnelXrayLifecycleSmokeTestStage,
        category: TunnelXrayLifecycleSmokeTestCategory,
        protocolName: String?,
        transportName: String?,
        securityName: String?,
        h3ALPNConfigured: Bool?,
        sniConfigured: Bool?,
        startDurationMs: Double?,
        readinessDurationMs: Double?,
        totalStartedAt: Date,
        port: Int,
        tun2SocksStarted: Bool,
        networkSettingsApplied: Bool
    ) async -> TunnelXrayLifecycleSmokeTestResponse {
        await telemetryStore?.markXrayLifecycleEvent(category: "dataPlaneRollbackStarted", state: .stopping, failure: .tun2SocksStartupFailed)
        let dataPlaneCleanup = await cleanupDataPlaneDependencies(
            tun2SocksStarted: tun2SocksStarted,
            networkSettingsApplied: networkSettingsApplied
        )
        let xrayCleanup = await stopAndVerify(port: port)
        let rollbackSucceeded = dataPlaneCleanup.success && xrayCleanup.success
        await telemetryStore?.markXrayLifecycleEvent(
            category: rollbackSucceeded ? "dataPlaneRollbackSucceeded" : "dataPlaneRollbackFailed",
            state: rollbackSucceeded ? .stopped : .failed,
            failure: rollbackSucceeded ? nil : .tun2SocksStartupFailed
        )

        return failure(
            correlationID: correlationID,
            stage: rollbackSucceeded ? stage : .rollback,
            category: rollbackSucceeded ? category : .rollbackFailed,
            runtimeConfigurationLoaded: true,
            xrayConfigurationBuilt: true,
            testXrayPassed: true,
            runXrayInvoked: true,
            runningStateObserved: true,
            socksListenerReady: true,
            socksGreetingAccepted: true,
            stopXrayInvoked: xrayCleanup.stopInvoked,
            stoppedStateObserved: xrayCleanup.stoppedStateObserved,
            localPortClosed: xrayCleanup.portClosed,
            rollbackAttempted: true,
            rollbackSucceeded: rollbackSucceeded,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            stopDurationMs: xrayCleanup.stopDurationMs,
            totalStartedAt: totalStartedAt
        )
    }

    private func cleanupDataPlaneDependencies(
        tun2SocksStarted: Bool,
        networkSettingsApplied: Bool
    ) async -> (success: Bool, stage: TunnelXrayLifecycleSmokeTestStage, category: TunnelXrayLifecycleSmokeTestCategory) {
        var success = true
        var failedStage = TunnelXrayLifecycleSmokeTestStage.dataPlane
        var failedCategory = TunnelXrayLifecycleSmokeTestCategory.none

        if tun2SocksStarted, let tun2Socks {
            await telemetryStore?.markXrayLifecycleEvent(category: "tun2SocksStopRequested", state: .stopping)
            await tun2Socks.quit()
            let exit = await tun2Socks.waitForExit(timeout: .seconds(2))
            if exit.exited == false {
                success = false
                failedStage = .tun2SocksStop
                failedCategory = .tun2SocksDidNotStop
            } else {
                await telemetryStore?.markTun2SocksStopped()
            }
        }

        if networkSettingsApplied, let networkSettingsApplier {
            let cleared = await networkSettingsApplier.clear()
            if cleared == false {
                success = false
                failedStage = .networkSettings
                failedCategory = .networkSettingsFailed
            }
        }

        return (success, failedStage, failedCategory)
    }

    private func rollbackFailure(
        correlationID: UUID,
        stage: TunnelXrayLifecycleSmokeTestStage,
        category: TunnelXrayLifecycleSmokeTestCategory,
        runtimeConfigurationLoaded: Bool,
        xrayConfigurationBuilt: Bool,
        testXrayPassed: Bool,
        runXrayInvoked: Bool,
        runningStateObserved: Bool = false,
        protocolName: String?,
        transportName: String?,
        securityName: String?,
        h3ALPNConfigured: Bool?,
        sniConfigured: Bool?,
        startDurationMs: Double?,
        readinessDurationMs: Double? = nil,
        totalStartedAt: Date,
        port: Int
    ) async -> TunnelXrayLifecycleSmokeTestResponse {
        await telemetryStore?.markXrayLifecycleEvent(category: "xrayRollbackStarted", state: .stopping, failure: .xrayStartupFailed)
        let cleanup = await stopAndVerify(port: port)
        let rollbackSucceeded = cleanup.success
        await telemetryStore?.markXrayLifecycleEvent(
            category: rollbackSucceeded ? "xrayRollbackSucceeded" : "xrayRollbackFailed",
            state: rollbackSucceeded ? .stopped : .failed,
            failure: rollbackSucceeded ? nil : .xrayStartupFailed
        )
        return failure(
            correlationID: correlationID,
            stage: rollbackSucceeded ? stage : .rollback,
            category: rollbackSucceeded ? category : .rollbackFailed,
            runtimeConfigurationLoaded: runtimeConfigurationLoaded,
            xrayConfigurationBuilt: xrayConfigurationBuilt,
            testXrayPassed: testXrayPassed,
            runXrayInvoked: runXrayInvoked,
            runningStateObserved: runningStateObserved,
            socksListenerReady: false,
            socksGreetingAccepted: false,
            stopXrayInvoked: cleanup.stopInvoked,
            stoppedStateObserved: cleanup.stoppedStateObserved,
            localPortClosed: cleanup.portClosed,
            rollbackAttempted: true,
            rollbackSucceeded: rollbackSucceeded,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            stopDurationMs: cleanup.stopDurationMs,
            totalStartedAt: totalStartedAt
        )
    }

    private func remoteRollbackFailure(
        correlationID: UUID,
        stage: TunnelXrayRemoteEgressProbeStage,
        category: TunnelXrayRemoteEgressProbeCategory,
        xrayBuildPassed: Bool,
        testXrayPassed: Bool,
        xrayRunning: Bool,
        localSocksReady: Bool,
        remoteConnectAttempted: Bool,
        remoteConnectSucceeded: Bool,
        remoteConnectCategory: TunnelXrayRemoteEgressProbeCategory,
        socksConnectRequested: Bool = false,
        socksConnectAccepted: Bool = false,
        payloadWriteSucceeded: Bool = false,
        remoteFirstByteReceived: Bool = false,
        remoteResponseValidated: Bool = false,
        protocolName: String?,
        transportName: String?,
        securityName: String?,
        h3ALPNConfigured: Bool?,
        sniConfigured: Bool?,
        allowInsecureConfigured: Bool?,
        probeContext: TunnelXrayRemoteEgressProbeContext? = nil,
        startDurationMs: Double?,
        readinessDurationMs: Double? = nil,
        remoteConnectDurationMs: Double? = nil,
        totalStartedAt: Date,
        port: Int
    ) async -> TunnelXrayRemoteEgressProbeResponse {
        await telemetryStore?.markXrayLifecycleEvent(category: "xrayRemoteEgressRollbackStarted", state: .stopping, failure: .xrayStartupFailed)
        let cleanup = await stopAndVerify(port: port)
        let cleanupSucceeded = cleanup.success
        await telemetryStore?.markXrayLifecycleEvent(
            category: cleanupSucceeded ? "xrayRemoteEgressRollbackSucceeded" : "xrayRemoteEgressRollbackFailed",
            state: cleanupSucceeded ? .stopped : .failed,
            failure: cleanupSucceeded ? nil : .xrayStartupFailed
        )

        return remoteFailure(
            correlationID: correlationID,
            stage: cleanupSucceeded ? stage : .rollback,
            category: cleanupSucceeded ? category : .cleanupFailed,
            xrayBuildPassed: xrayBuildPassed,
            testXrayPassed: testXrayPassed,
            xrayRunning: xrayRunning,
            localSocksReady: localSocksReady,
            remoteConnectAttempted: remoteConnectAttempted,
            remoteConnectSucceeded: remoteConnectSucceeded,
            remoteConnectCategory: remoteConnectCategory,
            socksConnectRequested: socksConnectRequested,
            socksConnectAccepted: socksConnectAccepted,
            payloadWriteSucceeded: payloadWriteSucceeded,
            remoteFirstByteReceived: remoteFirstByteReceived,
            remoteResponseValidated: remoteResponseValidated,
            remoteEgressSucceeded: remoteConnectSucceeded,
            cleanupSucceeded: cleanupSucceeded,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            allowInsecureConfigured: allowInsecureConfigured,
            probeContext: probeContext,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            remoteConnectDurationMs: remoteConnectDurationMs,
            stopDurationMs: cleanup.stopDurationMs,
            totalStartedAt: totalStartedAt
        )
    }

    private func stopAndVerify(port: Int) async -> XrayRuntimeCleanupResult {
        try? stateMachine.transition(to: .stopping)
        await telemetryStore?.markXrayLifecycleEvent(category: "xrayStopRequested", state: .stopping)
        let stopStartedAt = Date()
        let stop = await libXray.stop()
        let stopDuration = Self.durationMilliseconds(since: stopStartedAt)
        guard stop.success else {
            try? stateMachine.transition(to: .rollbackFailed)
            return XrayRuntimeCleanupResult(
                success: false,
                stage: .stopXray,
                stopInvoked: stop.invoked,
                stoppedStateObserved: false,
                portClosed: false,
                stopDurationMs: stopDuration
            )
        }

        let stopped = await waitForStoppedState()
        guard stopped else {
            try? stateMachine.transition(to: .rollbackFailed)
            return XrayRuntimeCleanupResult(
                success: false,
                stage: .stoppedState,
                stopInvoked: true,
                stoppedStateObserved: false,
                portClosed: false,
                stopDurationMs: stopDuration
            )
        }

        await telemetryStore?.markXrayLifecycleEvent(category: "xrayStoppedObserved", state: .stopped)
        let closure = await readinessProbe.verifyClosed(host: "127.0.0.1", port: port)
        guard closure.success else {
            try? stateMachine.transition(to: .rollbackFailed)
            return XrayRuntimeCleanupResult(
                success: false,
                stage: .portClosure,
                stopInvoked: true,
                stoppedStateObserved: true,
                portClosed: false,
                stopDurationMs: stopDuration
            )
        }

        try? stateMachine.transition(to: .stopped)
        return XrayRuntimeCleanupResult(
            success: true,
            stage: .portClosure,
            stopInvoked: true,
            stoppedStateObserved: true,
            portClosed: true,
            stopDurationMs: stopDuration
        )
    }

    private func resetForNextOperation() {
        if activeSession == nil {
            tun2SocksExitMonitorTask?.cancel()
            tun2SocksExitMonitorTask = nil
        }
        switch stateMachine.state {
        case .stopped, .failed, .rollbackFailed:
            try? stateMachine.transition(to: .idle)
        case .idle:
            break
        case .validating, .starting, .waitingForReadiness, .stopping:
            activeSession = nil
            stateMachine = XrayRuntimeLifecycleStateMachine()
        case .running:
            if activeSession == nil {
                stateMachine = XrayRuntimeLifecycleStateMachine()
            }
        }
    }

    private func failure(
        correlationID: UUID,
        stage: TunnelXrayLifecycleSmokeTestStage,
        category: TunnelXrayLifecycleSmokeTestCategory,
        runtimeConfigurationLoaded: Bool = false,
        xrayConfigurationBuilt: Bool = false,
        testXrayPassed: Bool = false,
        runXrayInvoked: Bool = false,
        runningStateObserved: Bool = false,
        socksListenerReady: Bool = false,
        socksGreetingAccepted: Bool = false,
        stopXrayInvoked: Bool = false,
        stoppedStateObserved: Bool = false,
        localPortClosed: Bool = false,
        rollbackAttempted: Bool = false,
        rollbackSucceeded: Bool = false,
        protocolName: String? = nil,
        transportName: String? = nil,
        securityName: String? = nil,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        startDurationMs: Double? = nil,
        readinessDurationMs: Double? = nil,
        stopDurationMs: Double? = nil,
        totalStartedAt: Date
    ) -> TunnelXrayLifecycleSmokeTestResponse {
        .failure(
            correlationID: correlationID,
            stage: stage,
            category: category,
            runtimeConfigurationLoaded: runtimeConfigurationLoaded,
            xrayConfigurationBuilt: xrayConfigurationBuilt,
            testXrayPassed: testXrayPassed,
            runXrayInvoked: runXrayInvoked,
            runningStateObserved: runningStateObserved,
            socksListenerReady: socksListenerReady,
            socksGreetingAccepted: socksGreetingAccepted,
            stopXrayInvoked: stopXrayInvoked,
            stoppedStateObserved: stoppedStateObserved,
            localPortClosed: localPortClosed,
            rollbackAttempted: rollbackAttempted,
            rollbackSucceeded: rollbackSucceeded,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            stopDurationMs: stopDurationMs,
            totalDurationMs: Self.durationMilliseconds(since: totalStartedAt)
        )
    }

    private func remoteFailure(
        correlationID: UUID,
        stage: TunnelXrayRemoteEgressProbeStage,
        category: TunnelXrayRemoteEgressProbeCategory,
        xrayBuildPassed: Bool = false,
        testXrayPassed: Bool = false,
        xrayRunning: Bool = false,
        localSocksReady: Bool = false,
        remoteConnectAttempted: Bool = false,
        remoteConnectSucceeded: Bool = false,
        remoteConnectCategory: TunnelXrayRemoteEgressProbeCategory? = nil,
        socksConnectRequested: Bool? = nil,
        socksConnectAccepted: Bool = false,
        payloadWriteSucceeded: Bool = false,
        remoteFirstByteReceived: Bool = false,
        remoteResponseValidated: Bool = false,
        remoteEgressSucceeded: Bool = false,
        cleanupSucceeded: Bool = false,
        protocolName: String? = nil,
        transportName: String? = nil,
        securityName: String? = nil,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        allowInsecureConfigured: Bool? = nil,
        probeContext: TunnelXrayRemoteEgressProbeContext? = nil,
        startDurationMs: Double? = nil,
        readinessDurationMs: Double? = nil,
        remoteConnectDurationMs: Double? = nil,
        stopDurationMs: Double? = nil,
        totalStartedAt: Date
    ) -> TunnelXrayRemoteEgressProbeResponse {
        .failure(
            correlationID: correlationID,
            stage: stage,
            category: category,
            xrayBuildPassed: xrayBuildPassed,
            testXrayPassed: testXrayPassed,
            xrayRunning: xrayRunning,
            localSocksReady: localSocksReady,
            remoteConnectAttempted: remoteConnectAttempted,
            remoteConnectSucceeded: remoteConnectSucceeded,
            remoteConnectCategory: remoteConnectCategory,
            socksConnectRequested: socksConnectRequested,
            socksConnectAccepted: socksConnectAccepted,
            payloadWriteSucceeded: payloadWriteSucceeded,
            remoteFirstByteReceived: remoteFirstByteReceived,
            remoteResponseValidated: remoteResponseValidated,
            remoteEgressSucceeded: remoteEgressSucceeded,
            cleanupSucceeded: cleanupSucceeded,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            allowInsecureConfigured: allowInsecureConfigured,
            probeContext: probeContext,
            startDurationMs: startDurationMs,
            readinessDurationMs: readinessDurationMs,
            remoteConnectDurationMs: remoteConnectDurationMs,
            stopDurationMs: stopDurationMs,
            totalDurationMs: Self.durationMilliseconds(since: totalStartedAt)
        )
    }

    private func libXrayPingFailure(
        correlationID: UUID,
        stage: TunnelLibXrayPingProbeStage,
        category: TunnelLibXrayPingProbeCategory,
        xrayConfigurationBuilt: Bool = false,
        pingAccepted: Bool = false,
        pingCompleted: Bool = false,
        delayMs: Int64? = nil,
        timedOut: Bool = false,
        nativeErrorPresent: Bool = false,
        protocolName: String? = nil,
        transportName: String? = nil,
        securityName: String? = nil,
        h3ALPNConfigured: Bool? = nil,
        sniConfigured: Bool? = nil,
        allowInsecureConfigured: Bool? = nil,
        startedAt: Date
    ) -> TunnelLibXrayPingProbeResponse {
        .failure(
            correlationID: correlationID,
            stage: stage,
            category: category,
            xrayConfigurationBuilt: xrayConfigurationBuilt,
            pingAccepted: pingAccepted,
            pingCompleted: pingCompleted,
            delayMs: delayMs,
            timedOut: timedOut,
            nativeErrorPresent: nativeErrorPresent,
            protocolName: protocolName,
            transportName: transportName,
            securityName: securityName,
            h3ALPNConfigured: h3ALPNConfigured,
            sniConfigured: sniConfigured,
            allowInsecureConfigured: allowInsecureConfigured,
            durationMs: Self.durationMilliseconds(since: startedAt)
        )
    }

    private static func category(forRuntimeError error: any Error) -> TunnelXrayLifecycleSmokeTestCategory {
        guard let error = error as? RuntimeConfigurationError else {
            return .runtimeConfigurationInvalid
        }
        switch error {
        case .providerConfigurationStaleSession:
            return .providerConfigurationStaleSession
        case .profileIdentityMismatch:
            return .profileIdentityMismatch
        case .profileRevisionMismatch:
            return .profileRevisionMismatch
        case .unsupportedProtocol, .unsupportedTransport:
            return .unsupportedProfileForRuntimeSmoke
        default:
            return .runtimeConfigurationInvalid
        }
    }

    private static func category(forBuilderError error: any Error) -> TunnelXrayLifecycleSmokeTestCategory {
        guard let error = error as? XrayConfigurationBuilderError else {
            return .xrayBuildFailed
        }
        switch error {
        case .encodingFailed:
            return .requestEncodingFailed
        default:
            return .xrayBuildFailed
        }
    }

    private static func remoteCategory(forLifecycleCategory category: TunnelXrayLifecycleSmokeTestCategory) -> TunnelXrayRemoteEgressProbeCategory {
        switch category {
        case .none:
            return .none
        case .socksReadinessTimeout:
            return .timeout
        case .socksConnectionFailed, .localPortUnavailable, .localPortStillOpen:
            return .networkUnavailable
        case .socksGreetingRejected:
            return .socksHandshakeRejected
        case .runtimeAlreadyRunning, .operationSuperseded:
            return .runtimeBusy
        case .testXrayRejected, .runXrayRejected, .xrayBuildFailed, .requestEncodingFailed, .unsupportedProfileForRuntimeSmoke:
            return .configurationRejected
        case .xrayDidNotReachRunningState, .xrayDidNotStop:
            return .xrayExited
        case .providerUnavailable:
            return .providerUnavailable
        case .providerTimeout:
            return .providerTimeout
        case .invalidResponse:
            return .invalidResponse
        case .requestIDMismatch:
            return .requestIDMismatch
        case .correlationMismatch:
            return .correlationMismatch
        case .rollbackFailed, .stopXrayRejected:
            return .cleanupFailed
        default:
            return .unknown
        }
    }

    private static func remoteStage(forCleanupStage stage: TunnelXrayLifecycleSmokeTestStage) -> TunnelXrayRemoteEgressProbeStage {
        switch stage {
        case .stopXray:
            return .stopXray
        case .stoppedState:
            return .stoppedState
        case .portClosure:
            return .portClosure
        case .rollback:
            return .rollback
        default:
            return .unknown
        }
    }

    private static func remoteStage(forRemoteCategory category: TunnelXrayRemoteEgressProbeCategory) -> TunnelXrayRemoteEgressProbeStage {
        switch category {
        case .socksHandshakeRejected:
            return .socksGreeting
        case .socksConnectRejected, .networkUnavailable:
            return .remoteConnect
        case .payloadWriteFailed:
            return .remotePayload
        case .remoteFirstByteTimeout:
            return .remoteFirstByte
        case .remoteReadFailed, .remoteResponseInvalid:
            return .remoteResponse
        case .xrayExited:
            return .runningState
        case .cleanupFailed:
            return .rollback
        default:
            return .remoteConnect
        }
    }

    private static func xrayValidationCategory(forRuntimeError error: any Error) -> TunnelXrayConfigurationValidationCategory {
        guard let error = error as? RuntimeConfigurationError else {
            return .runtimeConfigurationInvalid
        }
        switch error {
        case .providerConfigurationStaleSession:
            return .providerConfigurationStaleSession
        case .profileIdentityMismatch:
            return .profileIdentityMismatch
        case .profileRevisionMismatch:
            return .profileRevisionMismatch
        case .unsupportedProtocol:
            return .unsupportedProtocol
        case .unsupportedTransport:
            return .unsupportedTransport
        case .invalidEndpoint:
            return .invalidEndpoint
        case .invalidXHTTPConfiguration:
            return .invalidXHTTPConfiguration
        case .invalidXHTTPMode:
            return .invalidXHTTPMode
        case .invalidXHTTPPath:
            return .invalidXHTTPPath
        case .invalidXHTTPHost:
            return .invalidXHTTPHost
        case .invalidSecurityConfiguration:
            return .invalidRealityConfiguration
        case .credentialMalformed:
            return .invalidCredential
        default:
            return .runtimeConfigurationInvalid
        }
    }

    private static func xrayValidationCategory(forBuilderError error: any Error) -> TunnelXrayConfigurationValidationCategory {
        guard let error = error as? XrayConfigurationBuilderError else {
            return .unknown
        }
        return TunnelXrayConfigurationValidationCategory(rawValue: error.rawValue) ?? .unknown
    }

    private static func xrayValidationCategory(
        forLifecycleCategory category: TunnelXrayLifecycleSmokeTestCategory
    ) -> TunnelXrayConfigurationValidationCategory {
        switch category {
        case .none:
            return .none
        case .runtimeConfigurationInvalid:
            return .runtimeConfigurationInvalid
        case .providerConfigurationStaleSession:
            return .providerConfigurationStaleSession
        case .profileIdentityMismatch:
            return .profileIdentityMismatch
        case .profileRevisionMismatch:
            return .profileRevisionMismatch
        case .unsupportedLibXrayAPIVersion:
            return .unsupportedLibXrayAPIVersion
        case .requestEncodingFailed:
            return .requestEncodingFailed
        case .invocationFailed:
            return .invocationFailed
        case .emptyResponse:
            return .emptyResponse
        case .malformedLibXrayResponse:
            return .malformedResponse
        case .testXrayRejected:
            return .configurationRejected
        case .runtimeAlreadyRunning:
            return .runtimeAlreadyRunning
        case .providerUnavailable:
            return .providerUnavailable
        case .providerTimeout:
            return .providerTimeout
        case .invalidResponse:
            return .invalidResponse
        case .requestIDMismatch:
            return .requestIDMismatch
        case .correlationMismatch:
            return .correlationMismatch
        case .internalRuntimeError:
            return .internalLibXrayError
        case .unknown:
            return .unknown
        default:
            return .unknownLibXrayError
        }
    }

    private static func durationMilliseconds(since startedAt: Date) -> Double {
        max(0, Date().timeIntervalSince(startedAt) * 1_000)
    }
}

private struct XrayRuntimeCleanupResult: Sendable {
    var success: Bool
    var stage: TunnelXrayLifecycleSmokeTestStage
    var stopInvoked: Bool
    var stoppedStateObserved: Bool
    var portClosed: Bool
    var stopDurationMs: Double?
}

#if DEBUG
final class PacketTunnelXrayLifecycleSmokeTestService: XrayLifecycleSmokeTesting, @unchecked Sendable {
    private let controller: XrayRuntimeLifecycleController

    init(controller: XrayRuntimeLifecycleController) {
        self.controller = controller
    }

    init(
        runtimeConfigurationLoader: any XrayRuntimeConfigurationLoading,
        builder: any XrayConfigurationBuilding = XrayConfigurationBuilder(),
        libXray: any LibXrayRuntimeInvoking = LibXrayRuntimeAdapterCore(invoker: SystemLibXrayRawInvoker()),
        portSelector: any XrayLocalPortSelecting = LoopbackXrayLocalPortSelector(),
        readinessProbe: any XraySOCKSReadinessProbing = LoopbackXraySOCKSReadinessProbe(),
        telemetryStore: TunnelTelemetryStore? = nil
    ) {
        self.controller = XrayRuntimeLifecycleController(
            runtimeConfigurationLoader: runtimeConfigurationLoader,
            builder: builder,
            libXray: libXray,
            portSelector: portSelector,
            readinessProbe: readinessProbe,
            telemetryStore: telemetryStore
        )
    }

    func runXrayLifecycleSmokeTest(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayLifecycleSmokeTestResponse {
        await controller.run(
            correlationID: correlationID,
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken,
            requestGeneration: requestGeneration
        )
    }
}

final class PacketTunnelXrayRemoteEgressProbeService: XrayRemoteEgressProbing, @unchecked Sendable {
    private let controller: XrayRuntimeLifecycleController

    init(controller: XrayRuntimeLifecycleController) {
        self.controller = controller
    }

    init(
        runtimeConfigurationLoader: any XrayRuntimeConfigurationLoading,
        builder: any XrayConfigurationBuilding = XrayConfigurationBuilder(),
        libXray: any LibXrayRuntimeInvoking = LibXrayRuntimeAdapterCore(invoker: SystemLibXrayRawInvoker()),
        portSelector: any XrayLocalPortSelecting = LoopbackXrayLocalPortSelector(),
        readinessProbe: any XraySOCKSReadinessProbing = LoopbackXraySOCKSReadinessProbe(),
        remoteEgressProbe: any XrayRemoteEgressConnectivityProbing = LoopbackXrayRemoteEgressProbe(),
        telemetryStore: TunnelTelemetryStore? = nil
    ) {
        self.controller = XrayRuntimeLifecycleController(
            runtimeConfigurationLoader: runtimeConfigurationLoader,
            builder: builder,
            libXray: libXray,
            portSelector: portSelector,
            readinessProbe: readinessProbe,
            remoteEgressProbe: remoteEgressProbe,
            telemetryStore: telemetryStore
        )
    }

    func runXrayRemoteEgressProbe(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayRemoteEgressProbeResponse {
        await controller.runXrayRemoteEgressProbe(
            correlationID: correlationID,
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken,
            requestGeneration: requestGeneration
        )
    }

    func probeActiveXrayEgress(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayRemoteEgressProbeResponse {
        await controller.probeActiveXrayEgress(
            correlationID: correlationID,
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken,
            requestGeneration: requestGeneration
        )
    }
}

final class PacketTunnelUDPControlProbeService: PacketTunnelUDPControlProbing, @unchecked Sendable {
    private let controller: XrayRuntimeLifecycleController

    init(controller: XrayRuntimeLifecycleController) {
        self.controller = controller
    }

    init(
        runtimeConfigurationLoader: any XrayRuntimeConfigurationLoading,
        builder: any XrayConfigurationBuilding = XrayConfigurationBuilder(),
        libXray: any LibXrayRuntimeInvoking = LibXrayRuntimeAdapterCore(invoker: SystemLibXrayRawInvoker()),
        portSelector: any XrayLocalPortSelecting = LoopbackXrayLocalPortSelector(),
        readinessProbe: any XraySOCKSReadinessProbing = LoopbackXraySOCKSReadinessProbe(),
        udpControlProbe: any PacketTunnelUDPControlProbing = PacketTunnelUDPControlProbe(),
        telemetryStore: TunnelTelemetryStore? = nil
    ) {
        self.controller = XrayRuntimeLifecycleController(
            runtimeConfigurationLoader: runtimeConfigurationLoader,
            builder: builder,
            libXray: libXray,
            portSelector: portSelector,
            readinessProbe: readinessProbe,
            udpControlProbe: udpControlProbe,
            telemetryStore: telemetryStore
        )
    }

    func runUDPControlProbe(
        correlationID: UUID,
        requestGeneration: UInt64?
    ) async -> TunnelUDPControlProbeResponse {
        await controller.runUDPControlProbe(
            correlationID: correlationID,
            requestGeneration: requestGeneration
        )
    }
}

final class PacketTunnelLibXrayPingProbeService: LibXrayPingProbing, @unchecked Sendable {
    private let controller: XrayRuntimeLifecycleController

    init(controller: XrayRuntimeLifecycleController) {
        self.controller = controller
    }

    init(
        runtimeConfigurationLoader: any XrayRuntimeConfigurationLoading,
        builder: any XrayConfigurationBuilding = XrayConfigurationBuilder(),
        libXray: any LibXrayRuntimeInvoking = LibXrayRuntimeAdapterCore(invoker: SystemLibXrayRawInvoker()),
        libXrayPingBatch: (any LibXrayPingBatchInvoking)? = nil,
        telemetryStore: TunnelTelemetryStore? = nil
    ) {
        self.controller = XrayRuntimeLifecycleController(
            runtimeConfigurationLoader: runtimeConfigurationLoader,
            builder: builder,
            libXray: libXray,
            libXrayPingBatch: libXrayPingBatch,
            telemetryStore: telemetryStore
        )
    }

    func runLibXrayPingProbe(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelLibXrayPingProbeResponse {
        await controller.runLibXrayPingProbe(
            correlationID: correlationID,
            expectedProfileID: expectedProfileID,
            expectedRevisionToken: expectedRevisionToken,
            requestGeneration: requestGeneration
        )
    }
}
#endif

private struct RuntimeConfigurationExpectedState {
    var matches: Bool
    var shouldWait: Bool
    var staleK1: Bool
    var staleProfile: Bool
}

private struct RuntimeConfigurationPropagationSnapshot {
    var snapshot: TunnelProtocolConfigurationSnapshot
    var configurationPropagationTimedOut: Bool
    var staleK1ConfigurationObserved: Bool
    var staleProfileConfigurationObserved: Bool
}
