//
//  ImportPayloadModels.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated enum AddProfileRoute: Hashable, Sendable {
    case scanQRCode
    case chooseQRImage
    case pasteLink
    case importFile
    case manualSetup

    var destinationKind: AddProfileDestinationKind {
        switch self {
        case .scanQRCode:
            .scanner
        case .chooseQRImage:
            .imagePicker
        case .pasteLink:
            .pasteLink
        case .importFile:
            .fileImporter
        case .manualSetup:
            .manualSetup
        }
    }
}

nonisolated enum AddProfileDestinationKind: Hashable, Sendable {
    case scanner
    case scannerFallback
    case imagePicker
    case pasteLink
    case fileImporter
    case manualSetup
}

nonisolated enum AddProfileNavigationPolicy {
    static func destinationKind(for route: AddProfileRoute, isLiveScannerAvailable: Bool) -> AddProfileDestinationKind {
        if route == .scanQRCode && isLiveScannerAvailable == false {
            return .scannerFallback
        }

        return route.destinationKind
    }
}

nonisolated enum ImportPayloadRoute: Identifiable, Hashable, Sendable {
    case single(VPNImportResult)
    case batch(BatchImportDraft)
    case qrPayloads(QRPayloadSelectionDraft)

    var id: UUID {
        switch self {
        case .single(let result):
            result.id
        case .batch(let draft):
            draft.id
        case .qrPayloads(let draft):
            draft.id
        }
    }
}

nonisolated struct QRPayloadSelectionDraft: Identifiable, Hashable, Sendable {
    var id: UUID
    var title: String
    var payloads: [String]

    init(id: UUID = UUID(), title: String, payloads: [String]) {
        self.id = id
        self.title = title
        self.payloads = payloads
    }
}

nonisolated struct BatchImportDraft: Identifiable, Hashable, Sendable {
    var id: UUID
    var title: String
    var detectedFormat: SubscriptionContentFormat
    var profiles: [BatchImportProfileDraft]
    var warnings: [String]

    init(
        id: UUID = UUID(),
        title: String,
        detectedFormat: SubscriptionContentFormat,
        profiles: [BatchImportProfileDraft],
        warnings: [String] = []
    ) {
        self.id = id
        self.title = title
        self.detectedFormat = detectedFormat
        self.profiles = profiles
        self.warnings = warnings
    }
}

nonisolated struct BatchImportProfileDraft: Identifiable, Hashable, Sendable {
    var id: UUID
    var profile: VPNProfile
    var isSelected: Bool

    init(id: UUID = UUID(), profile: VPNProfile, isSelected: Bool = true) {
        self.id = id
        self.profile = profile
        self.isSelected = isSelected
    }
}
