//
//  ConnectionButton.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ConnectionButton: View {
    let state: VPNConnectionState
    let isEnabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle()
                    .fill(backgroundStyle)
                    .frame(width: 152, height: 152)
                    .shadow(color: shadowColor, radius: 10, y: 5)

                if isInFlight {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .tint(.white)
                        .scaleEffect(1.2)
                } else {
                    Image(systemName: iconName)
                        .font(.system(size: 48, weight: .semibold))
                        .foregroundStyle(.white)
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(isEnabled == false)
        .opacity(isEnabled ? 1 : 0.7)
        .animation(.snappy(duration: 0.25), value: state)
        .accessibilityLabel(buttonTitle)
    }

    private var buttonTitle: String {
        switch state {
        case .connected:
            "Disconnect"
        case .testing:
            "Testing"
        case .connecting:
            "Connecting"
        case .disconnecting:
            "Disconnecting"
        case .disconnected, .failed:
            "Connect"
        }
    }

    private var iconName: String {
        state == .connected ? "power.circle" : "power"
    }

    private var isInFlight: Bool {
        switch state {
        case .testing, .connecting, .disconnecting:
            true
        case .disconnected, .connected, .failed:
            false
        }
    }

    private var backgroundStyle: some ShapeStyle {
        switch state {
        case .connected:
            AnyShapeStyle(.green)
        case .failed:
            AnyShapeStyle(.red)
        case .testing, .connecting, .disconnecting:
            AnyShapeStyle(.orange)
        case .disconnected:
            AnyShapeStyle(.tint)
        }
    }

    private var shadowColor: Color {
        switch state {
        case .connected:
            .green.opacity(0.28)
        case .failed:
            .red.opacity(0.24)
        case .testing, .connecting, .disconnecting:
            .orange.opacity(0.24)
        case .disconnected:
            .accentColor.opacity(0.22)
        }
    }
}

#Preview {
    VStack {
        ConnectionButton(state: .disconnected, isEnabled: true) {}
        ConnectionButton(state: .connected, isEnabled: true) {}
    }
}
