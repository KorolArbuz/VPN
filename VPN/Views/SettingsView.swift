//
//  SettingsView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct SettingsView: View {
    var body: some View {
        List {
            Section("App") {
                LabeledContent("Connection Engine", value: "Mock")
                LabeledContent("NetworkExtension", value: "Not configured")
                LabeledContent("Diagnostics", value: "Local only")
            }

            Section("Security") {
                Label("Credentials are stored by reference in this prototype.", systemImage: "lock.shield")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Settings")
    }
}

#Preview {
    NavigationStack {
        SettingsView()
    }
}
