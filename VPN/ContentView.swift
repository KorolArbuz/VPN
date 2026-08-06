//
//  ContentView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ContentView: View {
    @State private var viewModel = VPNDashboardViewModel()
    @State private var selectedTab: AppTab = .home

    var body: some View {
        TabView(selection: $selectedTab) {
            VPNDashboardView(viewModel: viewModel)
                .tabItem {
                    Label("Home", systemImage: "house")
                }
                .tag(AppTab.home)

            NavigationStack {
                ProfilesView(viewModel: viewModel) {
                    selectedTab = .home
                }
            }
            .tabItem {
                Label("Profiles", systemImage: "list.bullet.rectangle")
            }
            .tag(AppTab.profiles)

            NavigationStack {
                SettingsView()
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
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
