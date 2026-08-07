//
//  AppLanguage.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated enum AppLanguage: String, CaseIterable, Identifiable, Sendable {
    case system
    case english
    case russian

    static let storageKey = "app.language"

    var id: String {
        rawValue
    }

    var locale: Locale {
        switch self {
        case .system:
            .autoupdatingCurrent
        case .english:
            Locale(identifier: "en")
        case .russian:
            Locale(identifier: "ru")
        }
    }

    var localizedTitleKey: String {
        switch self {
        case .system:
            "settings.language.system"
        case .english:
            "settings.language.english"
        case .russian:
            "settings.language.russian"
        }
    }

    static func persistedValue(_ rawValue: String) -> AppLanguage {
        AppLanguage(rawValue: rawValue) ?? .system
    }
}
