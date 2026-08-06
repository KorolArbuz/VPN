//
//  ParserSupport.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum ParserSupport {
    static func components(from text: String) throws -> URLComponents {
        guard let components = URLComponents(string: text), let scheme = components.scheme, scheme.isEmpty == false else {
            throw VPNImportError.malformedURL
        }

        if hasMalformedPort(in: text) {
            throw VPNImportError.invalidPort
        }

        return components
    }

    static func requiredHost(from components: URLComponents) throws -> String {
        guard let host = components.host, host.isEmpty == false else {
            throw VPNImportError.missingRequiredComponent("host")
        }

        return host
    }

    static func requiredPort(from components: URLComponents, defaultPort: Int? = nil) throws -> Int {
        if let port = components.port {
            return port
        }

        if hasExplicitInvalidPort(components) {
            throw VPNImportError.invalidPort
        }

        if let defaultPort {
            return defaultPort
        }

        throw VPNImportError.missingRequiredComponent("port")
    }

    static func queryDictionary(from components: URLComponents) -> [String: String] {
        var values: [String: String] = [:]

        for item in components.queryItems ?? [] {
            values[item.name] = item.value ?? ""
        }

        return values
    }

    static func displayName(from components: URLComponents, fallback: String) -> String {
        if let fragment = components.percentEncodedFragment?.removingPercentEncoding, fragment.isEmpty == false {
            return fragment
        }

        return fallback
    }

    static func decodedUser(from components: URLComponents) -> String? {
        components.percentEncodedUser?.removingPercentEncoding ?? components.user
    }

    static func decodedBase64(_ input: String) -> Data? {
        var normalized = input
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let padding = normalized.count % 4
        if padding > 0 {
            normalized += String(repeating: "=", count: 4 - padding)
        }

        return Data(base64Encoded: normalized)
    }

    private static func hasExplicitInvalidPort(_ components: URLComponents) -> Bool {
        guard let host = components.host else {
            return false
        }

        let marker = "\(host):"
        guard let range = components.string?.range(of: marker) else {
            return false
        }

        let suffix = components.string?[range.upperBound...] ?? ""
        let portText = suffix.prefix { character in
            character != "/" && character != "?" && character != "#"
        }

        return portText.isEmpty == false && Int(portText) == nil
    }

    private static func hasMalformedPort(in text: String) -> Bool {
        guard let schemeRange = text.range(of: "://") else {
            return false
        }

        let afterScheme = text[schemeRange.upperBound...]
        let authority = afterScheme.prefix { character in
            character != "/" && character != "?" && character != "#"
        }
        let hostPort = authority.split(separator: "@", omittingEmptySubsequences: false).last.map(String.init) ?? String(authority)

        guard hostPort.contains("]") == false, let colonIndex = hostPort.lastIndex(of: ":") else {
            return false
        }

        let portText = hostPort[hostPort.index(after: colonIndex)...]
        return portText.isEmpty == false && portText.allSatisfy(\.isNumber) == false
    }
}
