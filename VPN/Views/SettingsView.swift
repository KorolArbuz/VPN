//
//  SettingsView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct SettingsView: View {
    @AppStorage(AppLanguage.storageKey) private var languageRawValue = AppLanguage.system.rawValue

    var body: some View {
        List {
            Section("settings.language") {
                Picker("settings.language", selection: $languageRawValue) {
                    ForEach(AppLanguage.allCases) { language in
                        Text(LocalizedStringKey(language.localizedTitleKey))
                            .tag(language.rawValue)
                    }
                }
                .pickerStyle(.inline)
            }

            Section("App") {
                LabeledContent("settings.connection_engine", value: "Mock")
                LabeledContent("Mode", value: "Demo")
                LabeledContent("NetworkExtension", value: "Not configured")
                LabeledContent("Diagnostics", value: "Local only")
            }

            Section("Security") {
                Label("Credentials are stored by reference in this prototype.", systemImage: "lock.shield")
                    .foregroundStyle(.secondary)
                Label("vpn.demo_mode", systemImage: "info.circle")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("settings.title")
    }
}

#Preview {
    NavigationStack {
        SettingsView()
    }
}
