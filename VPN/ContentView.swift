//
//  ContentView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ContentView: View {
    @State private var viewModel: VPNDashboardViewModel
    @State private var healthDiagnostics = PortableHealthDiagnosticsViewModel()
    @State private var selectedTab: AppTab = .home

    init(connectionManager: VPNConnectionManaging = MockVPNConnectionManager()) {
        let profileRepository = FileVPNProfileRepository()
        let credentialStore = KeychainCredentialStore()
        let runtimeProfileSynchronizer: any RuntimeProfileSynchronizing
        if let appGroupSynchronizer = RuntimeProfileSynchronizer.appGroupSynchronizer(
            profileRepository: profileRepository,
            credentialStore: credentialStore
        ) {
            runtimeProfileSynchronizer = appGroupSynchronizer
        } else {
            runtimeProfileSynchronizer = UnavailableRuntimeProfileSynchronizer()
        }
        _viewModel = State(initialValue: VPNDashboardViewModel(
            connectionManager: connectionManager,
            profileRepository: profileRepository,
            subscriptionUpdater: URLSessionSubscriptionUpdater(credentialStore: credentialStore),
            credentialStore: credentialStore,
            runtimeProfileSynchronizer: runtimeProfileSynchronizer
        ))
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            VPNDashboardView(viewModel: viewModel)
                .tabItem {
                    Label("tab.home", systemImage: "house")
                }
                .tag(AppTab.home)

            NavigationStack {
                ProfilesView(viewModel: viewModel) {
                    selectedTab = .home
                }
            }
            .tabItem {
                Label("profiles.title", systemImage: "list.bullet.rectangle")
            }
            .tag(AppTab.profiles)

            NavigationStack {
                SettingsView(viewModel: viewModel, healthDiagnostics: healthDiagnostics)
            }
            .tabItem {
                Label("settings.title", systemImage: "gearshape")
            }
            .tag(AppTab.settings)
        }
    }
}

private enum AppTab: Hashable {
    case home
    case profiles
    case settings
}

#Preview {
    ContentView()
}
