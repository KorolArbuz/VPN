//
//  StartHapticFeedback.swift
//  VPN
//
//  User-initiated feedback for the main Start button.
//

import UIKit

nonisolated protocol StartHapticFeedbackProviding: Sendable {
    @MainActor
    func playLightStartImpact()
}

nonisolated struct SystemStartHapticFeedback: StartHapticFeedbackProviding {
    @MainActor
    func playLightStartImpact() {
        let generator = UIImpactFeedbackGenerator(style: .light)
        generator.prepare()
        generator.impactOccurred()
    }
}

nonisolated struct DisabledStartHapticFeedback: StartHapticFeedbackProviding {
    @MainActor
    func playLightStartImpact() {}
}
