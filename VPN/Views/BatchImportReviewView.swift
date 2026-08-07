//
//  BatchImportReviewView.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import SwiftUI

struct BatchImportReviewView: View {
    let draft: BatchImportDraft
    @Bindable var viewModel: VPNDashboardViewModel
    var onProfileSaved: () -> Void = {}
    @State private var profiles: [BatchImportProfileDraft]
    @State private var isSaving = false
    @State private var errorMessage: String?

    init(draft: BatchImportDraft, viewModel: VPNDashboardViewModel, onProfileSaved: @escaping () -> Void = {}) {
        self.draft = draft
        self.viewModel = viewModel
        self.onProfileSaved = onProfileSaved
        _profiles = State(initialValue: draft.profiles)
    }

    var body: some View {
        Form {
            Section("Import Summary") {
                LabeledContent("Format", value: draft.detectedFormat.displayName)
                LabeledContent("Profiles", value: "\(profiles.count)")
                LabeledContent("Selected", value: "\(selectedProfiles.count)")
            }

            if draft.warnings.isEmpty == false {
                Section("Notes") {
                    ForEach(draft.warnings, id: \.self) { warning in
                        Label(warning, systemImage: "info.circle")
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Section {
                HStack {
                    Button("Select All") {
                        setAll(true)
                    }
                    Spacer()
                    Button("Deselect All") {
                        setAll(false)
                    }
                }
            }

            Section("Profiles") {
                ForEach($profiles) { $item in
                    Toggle(isOn: Binding(
                        get: { item.isSelected },
                        set: { item.isSelected = $0 && item.profile.isComplete }
                    )) {
                        BatchImportProfileRowContent(profile: item.profile)
                    }
                    .disabled(item.profile.isComplete == false)
                }
            }

            Section {
                Button {
                    Task {
                        await saveSelectedProfiles()
                    }
                } label: {
                    HStack {
                        if isSaving {
                            ProgressView()
                        }
                        Text("Save Selected Profiles")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(selectedProfiles.isEmpty || isSaving)

                if let errorMessage {
                    Text(errorMessage)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Review Profiles")
    }

    private var selectedProfiles: [VPNProfile] {
        profiles.filter(\.isSelected).map(\.profile)
    }

    private func setAll(_ isSelected: Bool) {
        profiles = profiles.map { item in
            var updated = item
            updated.isSelected = isSelected && item.profile.isComplete
            return updated
        }
    }

    @MainActor
    private func saveSelectedProfiles() async {
        guard isSaving == false else { return }
        isSaving = true
        errorMessage = nil

        for profile in selectedProfiles {
            let didSave = await viewModel.saveProfileDraft(profile)
            if didSave == false {
                errorMessage = viewModel.profileSaveMessage ?? "Some profiles could not be imported."
                isSaving = false
                return
            }
        }

        isSaving = false
        onProfileSaved()
    }
}

private struct BatchImportProfileRowContent: View {
    let profile: VPNProfile

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(profile.name)
                .font(.headline)
            Text(connectionText)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Text(statusText)
                .font(.caption)
                .foregroundStyle(profile.isComplete ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
        }
    }

    private var connectionText: String {
        "\(profile.protocolType.displayName) • \(profile.serverAddress):\(profile.port.map(String.init) ?? "--")"
    }

    private var statusText: String {
        profile.isComplete ? "Ready" : "Incomplete: \(profile.missingRequiredFields.joined(separator: ", "))"
    }
}
