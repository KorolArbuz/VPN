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

                Button {
                    Task {
                        await viewModel.addSubscription(name: name, urlText: urlText)
                    }
                } label: {
                    Label("Save Subscription", systemImage: "tray.and.arrow.down")
                }
                .disabled(urlText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            if let importErrorMessage = viewModel.importErrorMessage {
                Section {
                    Label(importErrorMessage, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }

            Section("Saved Subscriptions") {
                if viewModel.subscriptions.isEmpty {
                    Text("No subscriptions saved")
                        .foregroundStyle(.secondary)
                }

                ForEach(viewModel.subscriptions) { subscription in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(subscription.name)
                                    .font(.headline)
                                Text(SecretMasker.sanitizedURLDisplay(subscription.url))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                                Text(subscription.lastUpdatedAt?.formatted(date: .abbreviated, time: .shortened) ?? "Not updated yet")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }

                            Spacer()

                            Toggle("Enabled", isOn: Binding(
                                get: { subscription.isEnabled },
                                set: { isEnabled in
                                    Task {
                                        await viewModel.setSubscriptionEnabled(subscription, isEnabled: isEnabled)
                                    }
                                }
                            ))
                            .labelsHidden()
                        }

                        Button {
                            Task {
                                await viewModel.refreshSubscription(subscription)
                            }
                        } label: {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }

                        Button(role: .destructive) {
                            Task {
                                await viewModel.deleteSubscription(subscription)
                            }
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
            }
        }
        .navigationTitle("Subscription")
    }
}
