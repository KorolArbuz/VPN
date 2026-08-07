//
//  ProfilesView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ProfilesView: View {
    @Bindable var viewModel: VPNDashboardViewModel
    var onProfileSaved: () -> Void = {}
    @State private var isAddSheetPresented = false

    var body: some View {
        List {
            Section("Profiles") {
                if viewModel.profiles.isEmpty {
                    ContentUnavailableView("No VPN Profiles", systemImage: "list.bullet.rectangle")
                } else {
                    ForEach(viewModel.profiles) { profile in
                        NavigationLink {
                            ProfileDetailView(profile: profile, viewModel: viewModel)
                        } label: {
                            ProfileRow(profile: profile, isSelected: viewModel.selectedProfile?.id == profile.id)
                        }
                        .swipeActions {
                            Button(role: .destructive) {
                                Task {
                                    await viewModel.deleteProfile(profile)
                                }
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                    }
                }
            }

            Section("Subscriptions") {
                if viewModel.subscriptions.isEmpty {
                    Text("No subscriptions")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(viewModel.subscriptions) { subscription in
                        NavigationLink {
                            SubscriptionDetailsView(subscription: subscription, viewModel: viewModel)
                        } label: {
                            SubscriptionRow(subscription: subscription)
                        }
                            .swipeActions {
                                Button(role: .destructive) {
                                    Task {
                                        await viewModel.deleteSubscription(subscription, mode: .deleteProfiles)
                                    }
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }

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
        }
        .navigationTitle("Profiles")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    isAddSheetPresented = true
                } label: {
                    Label("Add Profile", systemImage: "plus")
                }
            }
        }
        .sheet(isPresented: $isAddSheetPresented) {
            AddVPNSheet(viewModel: viewModel) {
                isAddSheetPresented = false
                onProfileSaved()
            }
        }
    }
}

private struct ProfileRow: View {
    let profile: VPNProfile
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: profile.protocolType.iconName)
                .font(.title3)
                .foregroundStyle(profile.isEnabled ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 4) {
                Text(profile.name)
                    .font(.headline)

                Text("\(profile.serverAddress):\(profile.port.map(String.init) ?? "--")")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                Text("\(profile.protocolType.displayName) • \(profile.source.displayName)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 6) {
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.tint)
                }

                Text(profile.isComplete ? (profile.isEnabled ? "Enabled" : "Disabled") : "Incomplete")
                    .font(.caption)
                    .foregroundStyle(profile.isComplete && profile.isEnabled ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
            }
        }
        .padding(.vertical, 4)
    }
}

private struct SubscriptionRow: View {
    let subscription: VPNSubscription

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(subscription.name)
                    .font(.headline)
                Spacer()
                Text(subscription.isEnabled ? "Enabled" : "Disabled")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Text(subscription.sanitizedHost)
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Text("Profiles: \(subscription.profileCount)")
                .font(.caption)
                .foregroundStyle(.secondary)

            if let lastError = subscription.lastError {
                Text(lastError)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .padding(.vertical, 4)
    }
}

struct SubscriptionDetailsView: View {
    let subscription: VPNSubscription
    @Bindable var viewModel: VPNDashboardViewModel
    @State private var editedName: String
    @State private var missingPolicy: MissingSubscriptionProfilePolicy = .keep
    @State private var showsDeleteConfirmation = false

    init(subscription: VPNSubscription, viewModel: VPNDashboardViewModel) {
        self.subscription = subscription
        self.viewModel = viewModel
        _editedName = State(initialValue: subscription.name)
    }

    var body: some View {
        Form {
            Section("Provider") {
                TextField("Name", text: $editedName)
                LabeledContent("Host", value: currentSubscription.sanitizedHost)
                LabeledContent("URL", value: currentSubscription.sanitizedURLDisplay)
                Toggle("Enabled", isOn: Binding(
                    get: { currentSubscription.isEnabled },
                    set: { isEnabled in
                        Task { await viewModel.setSubscriptionEnabled(currentSubscription, isEnabled: isEnabled) }
                    }
                ))
            }

            Section("Status") {
                LabeledContent("Profiles", value: "\(linkedProfiles.count)")
                LabeledContent("Last Update", value: currentSubscription.lastSuccessfulRefreshAt?.formatted(date: .abbreviated, time: .shortened) ?? "Not updated yet")
                LabeledContent("State", value: currentSubscription.refreshState.rawValue.capitalized)
                if let lastError = currentSubscription.lastError {
                    Label(lastError, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }

            Section {
                Button {
                    Task {
                        await viewModel.refreshSubscription(currentSubscription)
                    }
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(viewModel.subscriptionRefreshState == .downloading || currentSubscription.isEnabled == false)
            } footer: {
                Text("Refresh only runs when you tap the button.")
            }

            if let plan = viewModel.subscriptionUpdatePlan, plan.subscription.id == currentSubscription.id {
                refreshPreviewSection(plan)
            }

            Section("Profiles") {
                if linkedProfiles.isEmpty {
                    Text("No profiles saved from this subscription")
                        .foregroundStyle(.secondary)
                }
                ForEach(linkedProfiles) { profile in
                    Button {
                        viewModel.selectProfile(profile)
                    } label: {
                        ProfileActionRow(
                            title: profile.name,
                            subtitle: "\(profile.protocolType.displayName) • \(profile.serverAddress):\(profile.port.map(String.init) ?? "--")",
                            systemImage: profile.protocolType.iconName
                        )
                    }
                    .disabled(profile.isComplete == false || profile.isEnabled == false)
                }
            }

            Section("Refresh Schedule") {
                Picker("Interval", selection: .constant("manual")) {
                    Text("Manual only").tag("manual")
                    Text("Daily unavailable").tag("daily")
                    Text("Weekly unavailable").tag("weekly")
                }
                .disabled(true)
            }

            Section {
                Button(role: .destructive) {
                    showsDeleteConfirmation = true
                } label: {
                    Label("Delete Subscription", systemImage: "trash")
                }
            }
        }
        .navigationTitle(currentSubscription.name)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Save") {
                    Task {
                        await viewModel.renameSubscription(currentSubscription, to: editedName)
                    }
                }
            }
        }
        .confirmationDialog("Delete Subscription", isPresented: $showsDeleteConfirmation, titleVisibility: .visible) {
            Button("Delete subscription and profiles", role: .destructive) {
                Task { await viewModel.deleteSubscription(currentSubscription, mode: .deleteProfiles) }
            }
            Button("Keep profiles as local profiles") {
                Task { await viewModel.deleteSubscription(currentSubscription, mode: .keepProfiles) }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    @ViewBuilder
    private func refreshPreviewSection(_ plan: SubscriptionUpdatePlan) -> some View {
        Section("Refresh Preview") {
            LabeledContent("Added", value: "\(plan.addedCount)")
            LabeledContent("Updated", value: "\(plan.updatedCount)")
            LabeledContent("Unchanged", value: "\(plan.unchangedCount)")
            LabeledContent("Missing", value: "\(plan.missingCount)")
            LabeledContent("Invalid", value: "\(plan.invalidCount)")
            LabeledContent("Duplicates", value: "\(plan.duplicateCount)")

            Button {
                Task {
                    await viewModel.applySubscriptionUpdate(missingPolicy: missingPolicy)
                }
            } label: {
                Label("Apply Update", systemImage: "checkmark.circle")
            }
        }

        if plan.missingCount > 0 {
            Section("Missing Profiles") {
                Picker("When applying", selection: $missingPolicy) {
                    Text("Keep Missing").tag(MissingSubscriptionProfilePolicy.keep)
                    Text("Disable Missing").tag(MissingSubscriptionProfilePolicy.disable)
                    Text("Remove Missing").tag(MissingSubscriptionProfilePolicy.remove)
                }
            }
        }
    }

    private var currentSubscription: VPNSubscription {
        viewModel.subscriptions.first(where: { $0.id == subscription.id }) ?? subscription
    }

    private var linkedProfiles: [VPNProfile] {
        viewModel.profiles.filter { $0.sourceSubscriptionID == currentSubscription.id }
    }
}

private struct ProfileDetailView: View {
    let profile: VPNProfile
    @Bindable var viewModel: VPNDashboardViewModel
    @State private var editedName: String

    init(profile: VPNProfile, viewModel: VPNDashboardViewModel) {
        self.profile = profile
        self.viewModel = viewModel
        _editedName = State(initialValue: profile.name)
    }

    var body: some View {
        Form {
            Section("Profile") {
                TextField("Name", text: $editedName)

                Button {
                    viewModel.selectProfile(profile)
                } label: {
                    Label("Use Profile", systemImage: "checkmark.circle")
                }

                Toggle("Enabled", isOn: Binding(
                    get: { currentProfile.isEnabled },
                    set: { newValue in
                        Task {
                            await viewModel.setProfileEnabled(currentProfile, isEnabled: newValue)
                        }
                    }
                ))
            }

            Section("Connection") {
                LabeledContent("Protocol", value: profile.protocolType.displayName)
                LabeledContent("Server", value: profile.serverAddress)
                LabeledContent("Port", value: profile.port.map(String.init) ?? "Missing")
                LabeledContent("Source", value: profile.source.displayName)
                LabeledContent("Credentials", value: profile.maskedCredentialText)
            }

            Section("Security") {
                LabeledContent("TLS", value: profile.tlsSettings.isEnabled ? "Enabled" : "Disabled")
                if let serverName = profile.tlsSettings.serverName {
                    LabeledContent("Server Name", value: serverName)
                }
                if profile.tlsSettings.allowInsecure {
                    Label("Allow Insecure is enabled", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
            }

            if profile.isComplete == false {
                Section("Missing") {
                    ForEach(profile.missingRequiredFields, id: \.self) { field in
                        Label(field, systemImage: "exclamationmark.circle")
                            .foregroundStyle(.orange)
                    }
                }
            }
        }
        .navigationTitle(profile.name)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Save") {
                    Task {
                        await viewModel.renameProfile(profile, to: editedName)
                    }
                }
            }
        }
    }

    private var currentProfile: VPNProfile {
        viewModel.profiles.first(where: { $0.id == profile.id }) ?? profile
    }
}

#Preview {
    NavigationStack {
        ProfilesView(viewModel: VPNDashboardViewModel())
    }
}
