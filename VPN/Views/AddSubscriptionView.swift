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
    @State private var allowInsecureHTTP = false
    @State private var savedSubscription: VPNSubscription?

    var body: some View {
        Form {
            Section {
                Text("Add a provider link, preview the profiles it contains, then choose what to save.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 4)
            }

            Section("Provider") {
                TextField("Name", text: $name)
                TextField("HTTPS URL", text: $urlText)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                if usesHTTP {
                    Toggle("Allow HTTP for this subscription", isOn: $allowInsecureHTTP)
                    Text("HTTP provider links can expose subscription tokens on the network.")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                }

                Button {
                    Task {
                        await viewModel.previewSubscription(urlText: urlText, name: name, allowInsecureHTTP: allowInsecureHTTP)
                    }
                } label: {
                    actionLabel(title: "Preview", systemImage: "eye")
                }
                .disabled(canPreview == false || viewModel.subscriptionRefreshState == .downloading)
            }

            if let importErrorMessage = viewModel.importErrorMessage {
                Section {
                    Label(importErrorMessage, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }

            if let preview = viewModel.subscriptionPreview {
                previewSections(preview)
            }
        }
        .navigationTitle("Add Subscription")
        .navigationDestination(item: $savedSubscription) { subscription in
            SubscriptionDetailsView(subscription: subscription, viewModel: viewModel)
        }
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") {
                    Task {
                        await viewModel.cancelSubscriptionFlow()
                    }
                }
            }
        }
    }

    private var canPreview: Bool {
        let trimmed = urlText.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty == false && (usesHTTP == false || allowInsecureHTTP)
    }

    private var usesHTTP: Bool {
        urlText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("http://")
    }

    @ViewBuilder
    private func previewSections(_ preview: SubscriptionPreview) -> some View {
        Section("Preview") {
            LabeledContent("Provider", value: preview.subscription.name)
            LabeledContent("Host", value: preview.subscription.sanitizedHost)
            LabeledContent("Format", value: preview.detectedFormat.displayName)
            LabeledContent("Profiles", value: "\(preview.profiles.count)")
            LabeledContent("Valid", value: "\(preview.validCount)")
            LabeledContent("Incomplete", value: "\(preview.incompleteCount)")
            LabeledContent("Duplicates", value: "\(preview.duplicateCount)")
        }

        if preview.warnings.isEmpty == false {
            Section("Notes") {
                ForEach(preview.warnings, id: \.self) { warning in
                    Label(warning, systemImage: "info.circle")
                        .foregroundStyle(.secondary)
                }
            }
        }

        Section {
            HStack {
                Button("Select All") {
                    viewModel.setAllSubscriptionPreviewProfilesSelected(true)
                }
                Spacer()
                Button("Deselect All") {
                    viewModel.setAllSubscriptionPreviewProfilesSelected(false)
                }
            }
        }

        Section("Profiles") {
            ForEach(preview.profiles) { item in
                SubscriptionPreviewProfileRow(item: item) { isSelected in
                    viewModel.setSubscriptionPreviewSelection(id: item.id, isSelected: isSelected)
                }
            }
        }

        Section {
            Button {
                Task {
                    savedSubscription = await viewModel.saveSubscriptionPreview()
                }
            } label: {
                actionLabel(title: "Save Subscription", systemImage: "tray.and.arrow.down")
            }
            .buttonStyle(.borderedProminent)
            .disabled(preview.selectedProfiles.isEmpty || viewModel.subscriptionRefreshState == .saving)
        }
    }

    private func actionLabel(title: String, systemImage: String) -> some View {
        HStack {
            if [.downloading, .saving, .validating].contains(viewModel.subscriptionRefreshState) {
                ProgressView()
            } else {
                Image(systemName: systemImage)
            }
            Text(title)
        }
    }
}

private struct SubscriptionPreviewProfileRow: View {
    let item: SubscriptionProfilePreview
    let onSelectionChanged: (Bool) -> Void

    var body: some View {
        Toggle(isOn: Binding(
            get: { item.isSelected },
            set: onSelectionChanged
        )) {
            VStack(alignment: .leading, spacing: 4) {
                Text(item.profile.name)
                    .font(.headline)
                Text("\(item.profile.protocolType.displayName) • \(item.profile.serverAddress):\(item.profile.port.map(String.init) ?? "--")")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text(statusText)
                    .font(.caption)
                    .foregroundStyle(statusStyle)
            }
        }
        .disabled(item.state != .valid)
    }

    private var statusText: String {
        switch item.state {
        case .valid: "Ready"
        case .incomplete: "Incomplete: \(item.message ?? "")"
        case .invalid: item.message ?? "Invalid"
        case .duplicate: "Duplicate provider entry"
        }
    }

    private var statusStyle: Color {
        item.state == .valid ? .secondary : .orange
    }
}
