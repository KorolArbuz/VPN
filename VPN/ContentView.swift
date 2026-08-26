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

    init(connectionManager: VPNConnectionManaging) {
        let profileRepository = FileVPNProfileRepository()
        let credentialStore = KeychainCredentialStore()
        let runtimeProfileSynchronizer: any RuntimeProfileSynchronizing
        if let xraySynchronizer = RuntimeProfileSynchronizer.appGroupSynchronizer(
            profileRepository: profileRepository,
            credentialStore: credentialStore
        ), let nativePublisher = NativeWireGuardProfilePublisher.appGroupPublisher(
            credentialStore: credentialStore
        ) {
            runtimeProfileSynchronizer = CompositeRuntimeProfileSynchronizer(
                xray: xraySynchronizer,
                native: NativeWireGuardRuntimeProfileSynchronizer(publisher: nativePublisher)
            )
        } else {
            runtimeProfileSynchronizer = UnavailableRuntimeProfileSynchronizer()
        }
        _viewModel = State(initialValue: VPNDashboardViewModel(
            connectionManager: connectionManager,
            profileRepository: profileRepository,
            subscriptionUpdater: URLSessionSubscriptionUpdater(credentialStore: credentialStore),
            credentialStore: credentialStore,
            runtimeProfileSynchronizer: runtimeProfileSynchronizer,
            connectionTelemetryManager: DashboardConnectionTelemetryController()
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
        .modifier(
            AuthoritativeConnectionScenePhaseModifier(viewModel: viewModel)
        )
    }
}

private struct AuthoritativeConnectionScenePhaseModifier: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase

    let viewModel: VPNDashboardViewModel

    func body(content: Content) -> some View {
        content.onChange(of: scenePhase) { oldPhase, newPhase in
            guard oldPhase != .active, newPhase == .active else {
                return
            }
            Task { @MainActor in
                await viewModel.applicationDidBecomeActive()
            }
        }
    }
}

private enum AppTab: Hashable {
    case home
    case profiles
    case settings
}

#Preview {
    ContentView(connectionManager: MockVPNConnectionManager())
}
