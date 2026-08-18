//
//  ParserSupport.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum ParserSupport {
    static func components(from text: String) throws -> URLComponents {
        // Detect a non-numeric port before constructing URLComponents: modern
        // Foundation's URLComponents(string:) returns nil for an invalid port
        // (e.g. "host:bad"), which would otherwise surface as the less-specific
        // `.malformedURL` and make the `.invalidPort` path dead code.
        if hasMalformedPort(in: text) {
            throw VPNImportError.invalidPort
        }

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
        if hasExplicitInvalidPort(components) {
            throw VPNImportError.invalidPort
        }

        if let port = components.port {
            guard isValidPortValue(port) else {
                throw VPNImportError.invalidPort
            }
            return port
        }

        if let defaultPort {
            guard isValidPortValue(defaultPort) else {
                throw VPNImportError.invalidPort
            }
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
        let user: String
        if let percentEncodedUser = components.percentEncodedUser {
            user = percentEncodedUser.removingPercentEncoding ?? percentEncodedUser
        } else if let decodedUser = components.user {
            user = decodedUser
        } else {
            return nil
        }

        if let percentEncodedPassword = components.percentEncodedPassword {
            let password = percentEncodedPassword.removingPercentEncoding ?? percentEncodedPassword
            return "\(user):\(password)"
        }
        if let decodedPassword = components.password {
            return "\(user):\(decodedPassword)"
        }

        return user
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
        guard let string = components.string else {
            return false
        }

        return hasMalformedPort(in: string)
    }

    /// True when the authority carries an explicit port that is not a valid
    /// network port (non-numeric, or outside `1...65535`). Correctly ignores
    /// IPv6 address colons and userinfo (`user:password@`) colons.
    static func hasMalformedPort(in text: String) -> Bool {
        guard let portText = explicitPortText(in: text), portText.isEmpty == false else {
            return false
        }

        return isValidPortText(portText) == false
    }

    /// Extracts the explicit port substring from a URL's authority, or `nil`
    /// when there is no explicit port. Deterministic single source of truth for
    /// port parsing.
    private static func explicitPortText(in text: String) -> String? {
        guard let schemeRange = text.range(of: "://") else {
            return nil
        }

        let afterScheme = text[schemeRange.upperBound...]
        let authority = afterScheme.prefix { character in
            character != "/" && character != "?" && character != "#"
        }
        // Strip userinfo (`user:password@`) by taking everything after the last
        // "@" so a colon inside credentials is never read as a port separator.
        let hostPort: Substring
        if let atIndex = authority.lastIndex(of: "@") {
            hostPort = authority[authority.index(after: atIndex)...]
        } else {
            hostPort = authority
        }

        // Bracketed IPv6 literal: the port (if any) follows the closing "]".
        if hostPort.hasPrefix("[") {
            guard let closeIndex = hostPort.firstIndex(of: "]") else {
                return nil
            }
            let afterBracket = hostPort[hostPort.index(after: closeIndex)...]
            guard afterBracket.hasPrefix(":") else {
                return nil
            }
            return String(afterBracket.dropFirst())
        }

        // Regular host: the host contains no colon, so the last colon (if any)
        // introduces the port.
        guard let colonIndex = hostPort.lastIndex(of: ":") else {
            return nil
        }
        return String(hostPort[hostPort.index(after: colonIndex)...])
    }

    private static func isValidPortText(_ text: String) -> Bool {
        guard let value = Int(text) else {
            return false
        }
        return isValidPortValue(value)
    }

    private static func isValidPortValue(_ value: Int) -> Bool {
        (1...65535).contains(value)
    }
}
