//
//  VPNApp.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

@main
struct VPNApp: App {
    @State private var connectionManager = MockVPNConnectionManager()
    @AppStorage(AppLanguage.storageKey) private var languageRawValue = AppLanguage.system.rawValue

    var body: some Scene {
        WindowGroup {
            ContentView(connectionManager: connectionManager)
                .environment(\.locale, AppLanguage.persistedValue(languageRawValue).locale)
        }
    }
}
