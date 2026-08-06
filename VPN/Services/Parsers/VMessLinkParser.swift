//
//  VMessLinkParser.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated struct VMessLinkParser {
    let credentialStore: CredentialStoring

    func parse(_ text: String) async throws -> VPNImportResult {
        let payload = String(text.dropFirst("vmess://".count))
        guard let data = ParserSupport.decodedBase64(payload) else {
            throw VPNImportError.invalidBase64Payload
        }

        let decoder = JSONDecoder()
        let decoded: VMessPayload
        do {
            decoded = try decoder.decode(VMessPayload.self, from: data)
        } catch {
            throw VPNImportError.invalidPayload("The VMess JSON payload is invalid.")
        }

        guard decoded.add.isEmpty == false else {
            throw VPNImportError.missingRequiredComponent("server address")
        }

        guard let port = Int(decoded.port) else {
            throw VPNImportError.invalidPort
        }

        guard decoded.id.isEmpty == false else {
            throw VPNImportError.missingRequiredComponent("user id")
        }

        let credentialReference = try await credentialStore.store(decoded.id, label: "VMess user id")
        let name = decoded.ps.isEmpty ? decoded.add : decoded.ps
        let profile = VPNProfile.draft(
            name: name,
            protocolType: .vmess,
            serverAddress: decoded.add,
            port: port,
            credentialReference: credentialReference,
            transportSettings: VPNTransportSettings(network: decoded.net, security: decoded.tls, path: decoded.path, host: decoded.host),
            tlsSettings: VPNTLSSettings(isEnabled: decoded.tls.isEmpty == false, serverName: decoded.sni.isEmpty ? decoded.host : decoded.sni),
            protocolConfiguration: .vmess(VMessProfileConfiguration(alterID: Int(decoded.aid), security: decoded.scy)),
            source: .importedURL
        )

        return VPNImportResult(
            kind: .profile(profile),
            detectedScheme: "vmess",
            displayName: name,
            sanitizedSummary: ["credential": SecretMasker.masked(decoded.id), "host": decoded.add, "port": "\(port)"]
        )
    }
}

private struct VMessPayload: Decodable {
    var ps: String
    var add: String
    var port: String
    var id: String
    var aid: String
    var scy: String
    var net: String
    var type: String
    var host: String
    var path: String
    var tls: String
    var sni: String

    private enum CodingKeys: String, CodingKey {
        case ps, add, port, id, aid, scy, net, type, host, path, tls, sni
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ps = try container.decodeIfPresent(String.self, forKey: .ps) ?? ""
        add = try container.decodeIfPresent(String.self, forKey: .add) ?? ""
        port = try container.decodeIfPresent(String.self, forKey: .port) ?? ""
        id = try container.decodeIfPresent(String.self, forKey: .id) ?? ""
        aid = try container.decodeIfPresent(String.self, forKey: .aid) ?? "0"
        scy = try container.decodeIfPresent(String.self, forKey: .scy) ?? ""
        net = try container.decodeIfPresent(String.self, forKey: .net) ?? ""
        type = try container.decodeIfPresent(String.self, forKey: .type) ?? ""
        host = try container.decodeIfPresent(String.self, forKey: .host) ?? ""
        path = try container.decodeIfPresent(String.self, forKey: .path) ?? ""
        tls = try container.decodeIfPresent(String.self, forKey: .tls) ?? ""
        sni = try container.decodeIfPresent(String.self, forKey: .sni) ?? ""
    }
}
