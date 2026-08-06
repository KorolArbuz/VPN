//
//  AddSubscriptionView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct AddSubscriptionView: View {
    @Bindable var viewModel: VPNDashboardViewModel
    @State private var name = ""
    @State private var urlText = ""

    var body: some View {
        Form {
            Section("Subscription") {
                TextField("Name", text: $name)
                TextField("URL", text: $urlText)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                HStack {
                    Button {
                        Task {
                            await viewModel.previewSubscription(urlText: urlText, name: name)
                        }
                    } label: {
                        Label("Preview", systemImage: "eye")
                    }

                    Spacer()

                    Button {
                        Task {
                            await viewModel.addSubscription(name: name, urlText: urlText)
                        }
                    } label: {
                        Label("Save", systemImage: "tray.and.arrow.down")
                    }
                }
            }

            if let importErrorMessage = viewModel.importErrorMessage {
                Section {
                    Label(importErrorMessage, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }

            Section("Mock Preview") {
                if viewModel.subscriptionPreviewProfiles.isEmpty {
                    Text("No preview loaded")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(viewModel.subscriptionPreviewProfiles) { profile in
                        ProfilePreviewLine(profile: profile)
                    }
                }
            }

            Section("Saved Subscriptions") {
                ForEach(viewModel.subscriptions) { subscription in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(subscription.name)
                        Text(subscription.lastUpdatedAt?.formatted(date: .abbreviated, time: .shortened) ?? "Never updated")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("Profiles: \(subscription.profileCount)")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        Button {
                            Task {
                                await viewModel.refreshSubscription(subscription)
                            }
                        } label: {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }
                    }
                }
            }
        }
        .navigationTitle("Subscription")
    }
}

private struct ProfilePreviewLine: View {
    let profile: VPNProfile

    var body: some View {
        HStack {
            Image(systemName: profile.protocolType.iconName)
            VStack(alignment: .leading) {
                Text(profile.name)
                Text("\(profile.serverAddress):\(profile.port.map(String.init) ?? "--")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
