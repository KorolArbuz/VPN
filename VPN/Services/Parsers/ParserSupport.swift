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
}
