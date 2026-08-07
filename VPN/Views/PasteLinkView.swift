//
//  PasteLinkView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI
import UIKit

struct PasteLinkView: View {
    @Bindable var viewModel: VPNDashboardViewModel
    var onProfileSaved: () -> Void = {}
    @State private var linkText = ""
    @State private var reviewResult: VPNImportResult?

    var body: some View {
        Form {
            Section {
                Text("Paste a VLESS, Trojan, Hysteria, VMess, Shadowsocks or TUIC link to import a profile.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 4)
            }

            Section {
                TextEditor(text: $linkText)
                    .frame(minHeight: 120)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .accessibilityLabel(Text("profiles.profile_link"))

                Button {
                    linkText = UIPasteboard.general.string ?? ""
                } label: {
                    Label("profiles.paste_from_clipboard", systemImage: "doc.on.clipboard")
                }
                .buttonStyle(.borderless)
            } footer: {
                Text("Subscription URLs can be saved for later refresh. No network request is made here.")
            }

            if let importErrorMessage = viewModel.importErrorMessage {
                Section {
                    Label(importErrorMessage, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }

            Section {
                Button {
                    Task {
                        await viewModel.parseImportText(linkText)
                        reviewResult = viewModel.importResult
                    }
                } label: {
                    Text("common.continue")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(linkText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .accessibilityLabel(Text("profiles.continue_to_review"))
            }
        }
        .navigationTitle("profiles.paste_link")
        .navigationDestination(item: $reviewResult) { result in
            ReviewProfileView(importResult: result, viewModel: viewModel, onProfileSaved: onProfileSaved)
        }
    }
}

struct ReviewProfileView: View {
    let importResult: VPNImportResult
    @Bindable var viewModel: VPNDashboardViewModel
    var onProfileSaved: () -> Void = {}
    var manualCredentialValue: String?
    @State private var showAdvancedDetails = false

    var body: some View {
        Form {
            switch importResult.kind {
            case .profile(let profile):
                profileSections(profile)

                Section {
                    Button {
                        Task {
                            let didSave: Bool
                            if case .profile(let profile) = importResult.kind, let manualCredentialValue {
                                didSave = await viewModel.saveProfileDraft(profile, credentialValue: manualCredentialValue)
                            } else {
                                didSave = await viewModel.saveImportResultAndSelect()
                            }
                            if didSave {
                                onProfileSaved()
                            }
                        }
                    } label: {
                        HStack {
                            if viewModel.isSavingProfile {
                                ProgressView()
                                    .tint(.white)
                            }
                            Text(saveButtonTitle)
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(profile.isComplete == false || viewModel.isSavingProfile)

                    if let message = viewModel.profileSaveMessage {
                        Text(message)
                            .font(.footnote)
                            .foregroundStyle(saveMessageStyle)
                    }
                }
            case .subscription:
                Section {
                    ContentUnavailableView("Subscriptions are saved from the Add Subscription screen", systemImage: "calendar.badge.plus")
                }
            }
        }
        .navigationTitle("profiles.review_profile")
    }

    @ViewBuilder
    private func profileSections(_ profile: VPNProfile) -> some View {
        Section("Profile") {
            LabeledContent("Name", value: profile.name)
            LabeledContent("Protocol", value: profile.protocolType.displayName)
            LabeledContent("Validation", value: profile.isComplete ? "Ready" : "Incomplete")
        }

        Section("Server") {
            LabeledContent("Address", value: profile.serverAddress.isEmpty ? "Missing" : profile.serverAddress)
            LabeledContent("Port", value: profile.port.map(String.init) ?? "Missing")
        }

        Section("Transport") {
            LabeledContent("Transport", value: profile.transportSettings.network ?? "Default")
            if let path = profile.transportSettings.path {
                LabeledContent("Path", value: path)
            }
            if let host = profile.transportSettings.host {
                LabeledContent("Host Header", value: host)
            }
            if let mode = profile.metadata["mode"] {
                LabeledContent("Mode", value: mode)
            }
        }

        Section("Security") {
            LabeledContent("Security", value: securityText(for: profile))
            if let serverName = profile.tlsSettings.serverName {
                LabeledContent("SNI", value: serverName)
            }
            if let fingerprint = profile.tlsSettings.fingerprint {
                LabeledContent("Fingerprint", value: fingerprint)
            }
            if profile.tlsSettings.publicKeyReference != nil {
                LabeledContent("Public Key", value: "Stored securely")
            }
            if let shortID = profile.tlsSettings.shortID {
                LabeledContent("Short ID", value: SecretMasker.masked(shortID))
            }
        }

        Section("Credentials") {
            LabeledContent("Credential", value: profile.maskedCredentialText)
        }

        if profile.isComplete == false {
            Section("Missing") {
                ForEach(profile.missingRequiredFields, id: \.self) { field in
                    Label(field, systemImage: "exclamationmark.circle")
                        .foregroundStyle(.orange)
                }
            }
        }

        if importResult.sanitizedSummary.isEmpty == false {
            Section {
                DisclosureGroup("Advanced details", isExpanded: $showAdvancedDetails) {
                    ForEach(importResult.sanitizedSummary.keys.sorted(), id: \.self) { key in
                        LabeledContent(displayName(for: key), value: importResult.sanitizedSummary[key] ?? "")
                    }
                }
            }
        }
    }

    private var saveButtonTitle: String {
        viewModel.isSavingProfile ? "Saving" : "Save Profile"
    }

    private var saveMessageStyle: Color {
        switch viewModel.profileSaveState {
        case .saved:
            .green
        case .failed, .incomplete, .duplicate:
            .red
        case .idle, .saving:
            .secondary
        }
    }

    private func securityText(for profile: VPNProfile) -> String {
        if profile.tlsSettings.publicKeyReference != nil {
            return "Reality"
        }

        if profile.tlsSettings.isEnabled {
            return "TLS"
        }

        return "None"
    }

    private func displayName(for key: String) -> String {
        switch key {
        case "fp":
            "Fingerprint"
        case "pbk":
            "Public Key"
        case "sid":
            "Short ID"
        case "type":
            "Transport"
        case "sni":
            "SNI"
        default:
            key
        }
    }
}
