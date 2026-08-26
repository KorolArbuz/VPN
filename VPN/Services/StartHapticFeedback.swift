//
//  StartHapticFeedback.swift
//  VPN
//
//  User-initiated feedback for the main Start/Stop connection action.
//

import UIKit

nonisolated protocol ConnectionActionHapticFeedbackProviding: Sendable {
    @MainActor
    func playMediumImpact()
}

nonisolated struct SystemConnectionActionHapticFeedback: ConnectionActionHapticFeedbackProviding {
    @MainActor
    func playMediumImpact() {
        let generator = UIImpactFeedbackGenerator(style: .medium)
        generator.prepare()
        generator.impactOccurred()
    }
}

nonisolated struct DisabledConnectionActionHapticFeedback: ConnectionActionHapticFeedbackProviding {
    @MainActor
    func playMediumImpact() {}
}
