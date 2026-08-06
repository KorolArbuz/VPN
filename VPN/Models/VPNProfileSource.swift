//
//  VPNProfileSource.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated enum VPNProfileSource: String, CaseIterable, Codable, Identifiable, Sendable {
    case manual
    case importedURL
    case subscription
    case qrCode
    case file
    case bundledMock

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .manual:
            "Manual"
        case .importedURL:
            "Imported URL"
        case .subscription:
            "Subscription"
        case .qrCode:
            "QR Code"
        case .file:
            "File"
        case .bundledMock:
            "Bundled Mock"
        }
    }
}
