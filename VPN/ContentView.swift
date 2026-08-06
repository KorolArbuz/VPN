//
//  ContentView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ContentView: View {
    @State private var viewModel = VPNDashboardViewModel()

    var body: some View {
        TabView {
            VPNDashboardView(viewModel: viewModel)
                .tabItem {
                    Label("Home", systemImage: "house")
                }

            NavigationStack {
                ProfilesView(viewModel: viewModel)
            }
            .tabItem {
                Label("Profiles", systemImage: "list.bullet.rectangle")
            }

            NavigationStack {
                SettingsView()
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
            }
        }
    }
}

#Preview {
    ContentView()
}
