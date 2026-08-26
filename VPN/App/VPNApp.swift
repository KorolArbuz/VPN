//
//  VPNApp.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI
import UIKit

@main
struct VPNApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var connectionManager = ProductionVPNConnectionComposition.makeConnectionManager()
    @AppStorage(AppLanguage.storageKey) private var languageRawValue = AppLanguage.system.rawValue

    var body: some Scene {
        WindowGroup {
            ContentView(connectionManager: connectionManager)
                .environment(\.locale, AppLanguage.persistedValue(languageRawValue).locale)
        }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, supportedInterfaceOrientationsFor window: UIWindow?) -> UIInterfaceOrientationMask {
        AppOrientationPolicy.supportedInterfaceOrientations(for: UIDevice.current.userInterfaceIdiom)
    }
}

enum AppOrientationPolicy {
    static func supportedInterfaceOrientations(for idiom: UIUserInterfaceIdiom) -> UIInterfaceOrientationMask {
        idiom == .phone ? .portrait : .all
    }
}
