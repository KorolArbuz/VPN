//
//  NativeWireGuardConfigParser.swift
//  VPN
//
//  Strict, secret-safe wg-quick configuration import for WireGuard and
//  AmneziaWG. Private material is moved into the shared keychain before a
//  profile is returned; the durable profile contains references only.
//

import Foundation

nonisolated struct NativeWireGuardConfigParser: Sendable {
    private enum Section {
        case none
        case interface
        case peer
    }

    private struct ParsedPeer: Sendable {
        var publicKey: String
        var presharedKey: String?
        var allowedIPs: [String]
        var excludedIPs: [String]
        var endpoint: WireGuardEndpointProfileConfiguration?
        var persistentKeepAlive: String?
    }

    private struct ParsedDocument: Sendable {
        var privateKey: String
        var interfaceAddresses: [String]
        var dnsServers: [String]
        var dnsSearchDomains: [String]
        var listenPort: UInt16?
        var mtu: UInt16?
        var peers: [ParsedPeer]
        var headerProtectionKey: String?
        var amnezia: AmneziaWGProfileParameters?
    }

    private static let interfaceKeys: Set<String> = [
        "privatekey", "listenport", "address", "dns", "mtu",
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
        "headerprotectionkey", "contentpaddingaddition", "rekeyaftertime",
        "rekeytimeout", "rejectaftertime", "keepalivetimeout",
        "maxhandshakeattempts", "randomtrailers", "disablecookies"
    ]
    private static let amneziaKeys: Set<String> = [
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
        "headerprotectionkey", "contentpaddingaddition", "rekeyaftertime",
        "rekeytimeout", "rejectaftertime", "keepalivetimeout",
        "maxhandshakeattempts", "randomtrailers", "disablecookies"
    ]
    private static let peerKeys: Set<String> = [
        "publickey", "presharedkey", "allowedips", "excludedips", "endpoint", "persistentkeepalive"
    ]
    private static let repeatableKeys: Set<String> = ["address", "dns", "allowedips", "excludedips"]

    private let credentialStore: any CredentialStoring

    init(credentialStore: any CredentialStoring = KeychainCredentialStore()) {
        self.credentialStore = credentialStore
    }

    static func looksLikeConfiguration(_ text: String) -> Bool {
        let normalized = text.lowercased()
        return normalized.contains("[interface]")
            && normalized.contains("privatekey")
            && normalized.contains("[peer]")
            && normalized.contains("publickey")
    }

    func parse(_ text: String) async throws -> VPNImportResult {
        let document = try parseDocument(text)
        var storedReferences: [String] = []

        do {
            try Task.checkCancellation()
            let privateKeyReference = try await credentialStore.store(
                document.privateKey,
                label: "Native tunnel interface private key"
            )
            storedReferences.append(privateKeyReference)

            var peers: [WireGuardPeerProfileConfiguration] = []
            peers.reserveCapacity(document.peers.count)
            for (index, parsedPeer) in document.peers.enumerated() {
                try Task.checkCancellation()
                let presharedKeyReference: String?
                if let presharedKey = parsedPeer.presharedKey {
                    let reference = try await credentialStore.store(
                        presharedKey,
                        label: "Native tunnel peer \(index + 1) preshared key"
                    )
                    storedReferences.append(reference)
                    presharedKeyReference = reference
                } else {
                    presharedKeyReference = nil
                }
                peers.append(WireGuardPeerProfileConfiguration(
                    publicKey: parsedPeer.publicKey,
                    presharedKeyReference: presharedKeyReference,
                    allowedIPs: parsedPeer.allowedIPs,
                    excludedIPs: parsedPeer.excludedIPs,
                    endpoint: parsedPeer.endpoint,
                    persistentKeepAlive: parsedPeer.persistentKeepAlive
                ))
            }

            let headerProtectionKeyReference: String?
            if let headerProtectionKey = document.headerProtectionKey {
                try Task.checkCancellation()
                let reference = try await credentialStore.store(
                    headerProtectionKey,
                    label: "AmneziaWG header protection key"
                )
                storedReferences.append(reference)
                headerProtectionKeyReference = reference
            } else {
                headerProtectionKeyReference = nil
            }

            let configuration = WireGuardProfileConfiguration(
                presharedKeyReference: peers.first?.presharedKeyReference,
                allowedIPs: peers.first?.allowedIPs ?? [],
                interfaceAddresses: document.interfaceAddresses,
                dnsServers: document.dnsServers,
                dnsSearchDomains: document.dnsSearchDomains,
                listenPort: document.listenPort,
                mtu: document.mtu,
                peers: peers,
                headerProtectionKeyReference: headerProtectionKeyReference,
                amnezia: document.amnezia
            )
            let protocolType: VPNProtocol = document.amnezia == nil && headerProtectionKeyReference == nil
                ? .wireGuard
                : .amneziaWG
            let protocolConfiguration: VPNProtocolConfiguration = protocolType == .wireGuard
                ? .wireGuard(configuration)
                : .amneziaWG(configuration)
            guard let primaryEndpoint = peers.compactMap(\.endpoint).first else {
                throw VPNImportError.missingRequiredComponent("peer endpoint")
            }

            let profile = VPNProfile.draft(
                name: "Imported \(protocolType.displayName)",
                protocolType: protocolType,
                serverAddress: primaryEndpoint.host,
                port: Int(primaryEndpoint.port),
                credentialReference: privateKeyReference,
                transportSettings: VPNTransportSettings(network: "native"),
                routingSettings: VPNRoutingSettings(
                    routeAllTraffic: peers.contains { peer in
                        peer.allowedIPs.contains("0.0.0.0/0") || peer.allowedIPs.contains("::/0")
                    },
                    dnsServers: document.dnsServers,
                    excludedRoutes: peers.flatMap(\.excludedIPs)
                ),
                protocolConfiguration: protocolConfiguration,
                source: .importedURL,
                metadata: [
                    "nativeConfigFormat": "wg-quick",
                    "nativePeerCount": String(peers.count)
                ]
            )
            let capability = NativeWireGuardProfileValidator.capability(for: profile)
            guard capability.isReady else {
                throw VPNImportError.unsupportedCapability(capability.statusText)
            }

            return VPNImportResult(
                kind: .profile(profile),
                detectedScheme: protocolType.rawValue,
                displayName: profile.name,
                sanitizedSummary: [
                    "format": "wg-quick",
                    "protocol": protocolType.displayName,
                    "host": primaryEndpoint.host,
                    "port": String(primaryEndpoint.port),
                    "peers": String(peers.count),
                    "privateKey": "Stored securely",
                    "presharedKeys": "\(peers.compactMap(\.presharedKeyReference).count) stored securely",
                    "headerProtectionKey": headerProtectionKeyReference == nil ? "Not present" : "Stored securely"
                ]
            )
        } catch {
            for reference in storedReferences.reversed() {
                try? await credentialStore.delete(reference: reference)
            }
            throw error
        }
    }

    private func parseDocument(_ text: String) throws -> ParsedDocument {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.isEmpty == false else {
            throw VPNImportError.emptyInput
        }

        var section = Section.none
        var interfaceAttributes: [String: String]?
        var peerAttributes: [[String: String]] = []
        var currentAttributes: [String: String] = [:]

        func flushCurrentSection() throws {
            switch section {
            case .none:
                guard currentAttributes.isEmpty else {
                    throw VPNImportError.invalidPayload("A native configuration value appears outside a section.")
                }
            case .interface:
                guard interfaceAttributes == nil else {
                    throw VPNImportError.invalidPayload("A native configuration may contain only one Interface section.")
                }
                interfaceAttributes = currentAttributes
            case .peer:
                peerAttributes.append(currentAttributes)
            }
            currentAttributes.removeAll(keepingCapacity: true)
        }

        for rawLine in trimmed.split(whereSeparator: \.isNewline) {
            let commentFree = rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? rawLine
            let line = commentFree.trimmingCharacters(in: .whitespacesAndNewlines)
            guard line.isEmpty == false else { continue }
            let lowercased = line.lowercased()

            if lowercased == "[interface]" || lowercased == "[peer]" {
                try flushCurrentSection()
                section = lowercased == "[interface]" ? .interface : .peer
                continue
            }

            guard section != .none, let equalsIndex = line.firstIndex(of: "=") else {
                throw VPNImportError.invalidPayload("The native configuration contains a malformed line.")
            }
            let key = line[..<equalsIndex].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = line[line.index(after: equalsIndex)...].trimmingCharacters(in: .whitespacesAndNewlines)
            guard key.isEmpty == false, value.isEmpty == false else {
                throw VPNImportError.invalidPayload("The native configuration contains an empty key or value.")
            }
            let allowedKeys = section == .interface ? Self.interfaceKeys : Self.peerKeys
            guard allowedKeys.contains(key) else {
                throw VPNImportError.invalidPayload("The native configuration contains an unsupported \(section == .interface ? "interface" : "peer") option.")
            }
            if let existing = currentAttributes[key] {
                guard Self.repeatableKeys.contains(key) else {
                    throw VPNImportError.invalidPayload("The native configuration contains a duplicate option.")
                }
                currentAttributes[key] = existing + "," + value
            } else {
                currentAttributes[key] = value
            }
        }
        try flushCurrentSection()

        guard let interfaceAttributes else {
            throw VPNImportError.missingRequiredComponent("Interface section")
        }
        guard peerAttributes.isEmpty == false else {
            throw VPNImportError.missingRequiredComponent("Peer section")
        }
        guard peerAttributes.count <= NativeWireGuardRuntimeProtocol.maximumPeerCount else {
            throw VPNImportError.invalidPayload("The native configuration contains too many peers.")
        }
        guard let privateKey = interfaceAttributes["privatekey"], Self.isValidKey(privateKey) else {
            throw VPNImportError.invalidPayload("The interface private key is missing or invalid.")
        }

        let addresses = Self.list(interfaceAttributes["address"])
        guard addresses.isEmpty == false else {
            throw VPNImportError.missingRequiredComponent("interface address")
        }
        for address in addresses where NativeWireGuardProfileValidator.isValidIPRange(address) == false {
            throw VPNImportError.invalidPayload("An interface address is invalid.")
        }

        var dnsServers: [String] = []
        var dnsSearchDomains: [String] = []
        for value in Self.list(interfaceAttributes["dns"]) {
            if NativeWireGuardProfileValidator.isValidIPAddress(value) {
                dnsServers.append(value)
            } else {
                guard Self.isValidSearchDomain(value) else {
                    throw VPNImportError.invalidPayload("A DNS value is invalid.")
                }
                dnsSearchDomains.append(value)
            }
        }

        let listenPort = try Self.optionalUInt16(interfaceAttributes["listenport"], field: "listen port", allowZero: false)
        let mtu = try Self.optionalUInt16(interfaceAttributes["mtu"], field: "MTU", allowZero: false)
        let headerProtectionKey = interfaceAttributes["headerprotectionkey"]
        if let headerProtectionKey, Self.isValidKey(headerProtectionKey) == false {
            throw VPNImportError.invalidPayload("The header protection key is invalid.")
        }

        let parsedPeers = try peerAttributes.map { attributes -> ParsedPeer in
            guard let publicKey = attributes["publickey"], Self.isValidKey(publicKey) else {
                throw VPNImportError.invalidPayload("A peer public key is missing or invalid.")
            }
            if let presharedKey = attributes["presharedkey"], Self.isValidKey(presharedKey) == false {
                throw VPNImportError.invalidPayload("A peer preshared key is invalid.")
            }
            let allowedIPs = Self.list(attributes["allowedips"])
            guard allowedIPs.isEmpty == false else {
                throw VPNImportError.missingRequiredComponent("peer allowed IPs")
            }
            for range in allowedIPs where NativeWireGuardProfileValidator.isValidIPRange(range) == false {
                throw VPNImportError.invalidPayload("A peer allowed IP range is invalid.")
            }
            let excludedIPs = Self.list(attributes["excludedips"])
            for range in excludedIPs where NativeWireGuardProfileValidator.isValidIPRange(range) == false {
                throw VPNImportError.invalidPayload("A peer excluded IP range is invalid.")
            }
            let endpoint = try attributes["endpoint"].map(Self.parseEndpoint)
            let keepAlive = attributes["persistentkeepalive"]
            return ParsedPeer(
                publicKey: publicKey,
                presharedKey: attributes["presharedkey"],
                allowedIPs: allowedIPs,
                excludedIPs: excludedIPs,
                endpoint: endpoint,
                persistentKeepAlive: keepAlive
            )
        }
        guard Set(parsedPeers.map(\.publicKey)).count == parsedPeers.count else {
            throw VPNImportError.invalidPayload("Peer public keys must be unique.")
        }
        guard parsedPeers.contains(where: { $0.endpoint != nil }) else {
            throw VPNImportError.missingRequiredComponent("peer endpoint")
        }

        let hasAmneziaOptions = interfaceAttributes.keys.contains(where: Self.amneziaKeys.contains)
        let amnezia = hasAmneziaOptions ? try Self.amneziaParameters(interfaceAttributes) : nil
        return ParsedDocument(
            privateKey: privateKey,
            interfaceAddresses: addresses,
            dnsServers: dnsServers,
            dnsSearchDomains: dnsSearchDomains,
            listenPort: listenPort,
            mtu: mtu,
            peers: parsedPeers,
            headerProtectionKey: headerProtectionKey,
            amnezia: amnezia
        )
    }

    private static func amneziaParameters(_ values: [String: String]) throws -> AmneziaWGProfileParameters {
        AmneziaWGProfileParameters(
            junkPacketCount: try optionalUInt16(values["jc"], field: "Jc"),
            junkPacketMinSize: try optionalUInt16(values["jmin"], field: "Jmin"),
            junkPacketMaxSize: try optionalUInt16(values["jmax"], field: "Jmax"),
            initPacketJunkSize: try optionalUInt16(values["s1"], field: "S1"),
            responsePacketJunkSize: try optionalUInt16(values["s2"], field: "S2"),
            cookieReplyPacketJunkSize: try optionalUInt16(values["s3"], field: "S3"),
            transportPacketJunkSize: try optionalUInt16(values["s4"], field: "S4"),
            initPacketMagicHeader: values["h1"],
            responsePacketMagicHeader: values["h2"],
            underloadPacketMagicHeader: values["h3"],
            transportPacketMagicHeader: values["h4"],
            specialJunk1: values["i1"],
            specialJunk2: values["i2"],
            specialJunk3: values["i3"],
            specialJunk4: values["i4"],
            specialJunk5: values["i5"],
            contentPaddingAddition: values["contentpaddingaddition"],
            rekeyAfterTime: values["rekeyaftertime"],
            rekeyTimeout: values["rekeytimeout"],
            rejectAfterTime: values["rejectaftertime"],
            keepaliveTimeout: values["keepalivetimeout"],
            maxHandshakeAttempts: values["maxhandshakeattempts"],
            randomTrailers: values["randomtrailers"],
            disableCookies: values["disablecookies"]
        )
    }

    private static func parseEndpoint(_ value: String) throws -> WireGuardEndpointProfileConfiguration {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let host: String
        let portText: Substring
        if trimmed.hasPrefix("[") {
            guard let closingBracket = trimmed.firstIndex(of: "]") else {
                throw VPNImportError.invalidPayload("A peer endpoint is invalid.")
            }
            host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<closingBracket])
            let suffix = trimmed[trimmed.index(after: closingBracket)...]
            guard suffix.hasPrefix(":"), suffix.count > 1 else {
                throw VPNImportError.invalidPayload("A peer endpoint is invalid.")
            }
            portText = suffix.dropFirst()
        } else {
            guard let colon = trimmed.lastIndex(of: ":"), trimmed[..<colon].contains(":") == false else {
                throw VPNImportError.invalidPayload("A peer endpoint is invalid.")
            }
            host = String(trimmed[..<colon])
            portText = trimmed[trimmed.index(after: colon)...]
        }
        guard host.isEmpty == false,
              host.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              let port = UInt16(portText), port > 0 else {
            throw VPNImportError.invalidPayload("A peer endpoint is invalid.")
        }
        return WireGuardEndpointProfileConfiguration(host: host, port: port)
    }

    private static func optionalUInt16(
        _ value: String?,
        field: String,
        allowZero: Bool = true
    ) throws -> UInt16? {
        guard let value else { return nil }
        guard let parsed = UInt16(value), allowZero || parsed > 0 else {
            throw VPNImportError.invalidPayload("The \(field) value is invalid.")
        }
        return parsed
    }

    private static func list(_ value: String?) -> [String] {
        value?.split(separator: ",", omittingEmptySubsequences: true)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { $0.isEmpty == false } ?? []
    }

    private static func isValidKey(_ value: String) -> Bool {
        Data(base64Encoded: value.trimmingCharacters(in: .whitespacesAndNewlines))?.count == 32
    }

    private static func isValidSearchDomain(_ value: String) -> Bool {
        let domain = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return domain.isEmpty == false
            && domain.utf8.count <= 253
            && domain.rangeOfCharacter(from: .whitespacesAndNewlines) == nil
            && domain.rangeOfCharacter(from: .controlCharacters) == nil
    }
}
