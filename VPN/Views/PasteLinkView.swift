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
    @State private var linkText = ""

    var body: some View {
        Form {
            Section("Link") {
                TextEditor(text: $linkText)
                    .frame(minHeight: 120)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                Button {
                    linkText = UIPasteboard.general.string ?? ""
                } label: {
                    Label("Paste from Clipboard", systemImage: "doc.on.clipboard")
                }

                Button {
                    Task {
                        await viewModel.parseImportText(linkText)
                    }
                } label: {
                    Label("Parse", systemImage: "doc.text.magnifyingglass")
                }
            }

            if let importErrorMessage = viewModel.importErrorMessage {
                Section {
                    Label(importErrorMessage, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }

            if let importResult = viewModel.importResult {
                ImportResultPreview(importResult: importResult)

                Section {
                    Button {
                        Task {
                            await viewModel.saveImportResult()
                        }
                    } label: {
                        Label(saveTitle(for: importResult), systemImage: "tray.and.arrow.down")
                    }
                }
            }
        }
        .navigationTitle("Paste Link")
    }

    private func saveTitle(for result: VPNImportResult) -> String {
        switch result.kind {
        case .profile:
            "Save Profile"
        case .subscription:
            "Save Subscription"
        }
    }
}

private struct ImportResultPreview: View {
    let importResult: VPNImportResult

    var body: some View {
        Section("Recognized") {
            LabeledContent("Scheme", value: importResult.detectedScheme)
            LabeledContent("Name", value: importResult.displayName)

            switch importResult.kind {
            case .profile(let profile):
                LabeledContent("Protocol", value: profile.protocolType.displayName)
                LabeledContent("Hostname", value: profile.serverAddress)
                LabeledContent("Port", value: profile.port.map(String.init) ?? "Missing")
                LabeledContent("Transport", value: profile.transportSettings.network ?? "Default")
                LabeledContent("TLS", value: profile.tlsSettings.isEnabled ? tlsText(for: profile) : "Disabled")
                LabeledContent("Credentials", value: profile.maskedCredentialText)

                if profile.isComplete == false {
                    Text("Incomplete: \(profile.missingRequiredFields.joined(separator: ", "))")
                        .foregroundStyle(.orange)
                }
            case .subscription(let subscription):
                LabeledContent("Type", value: "Subscription")
                LabeledContent("URL", value: subscription.url.host ?? "Unknown host")
            }

            ForEach(importResult.warnings, id: \.self) { warning in
                Label(warning, systemImage: "info.circle")
                    .foregroundStyle(.secondary)
            }
        }

        if importResult.sanitizedSummary.isEmpty == false {
            Section("Safe Summary") {
                ForEach(importResult.sanitizedSummary.keys.sorted(), id: \.self) { key in
                    LabeledContent(key, value: importResult.sanitizedSummary[key] ?? "")
                }
            }
        }
    }

    private func tlsText(for profile: VPNProfile) -> String {
        if profile.tlsSettings.publicKeyReference != nil {
            return "Reality"
        }

        return "Enabled"
    }
}
