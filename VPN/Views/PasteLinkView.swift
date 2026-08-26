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
    var onImportSucceeded: (ImportFlowSuccessKind) -> Void = { _ in }
    @State private var linkText = ""
    @State private var importRoute: ImportPayloadRoute?
    @State private var isDetectingInput = false
    @State private var importOperationID: UUID?

    var body: some View {
        Form {
            Section {
                Text("Paste a VPN link or subscription URL to import it.")
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
                        await continueImport()
                    }
                } label: {
                    HStack {
                        if isDetectingInput {
                            ProgressView()
                        }
                        Text("common.continue")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(linkText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isDetectingInput)
                .accessibilityLabel(Text("profiles.continue_to_review"))
            }
        }
        .navigationTitle("profiles.paste_link")
        .navigationDestination(item: $importRoute) { route in
            switch route {
            case .single(let result):
                ReviewProfileView(
                    importResult: result,
                    viewModel: viewModel,
                    onImportSucceeded: onImportSucceeded,
                    sourceText: linkText
                )
            case .batch(let draft):
                BatchImportReviewView(draft: draft, viewModel: viewModel, onImportSucceeded: onImportSucceeded)
            case .qrPayloads(let draft):
                QRPayloadSelectionView(draft: draft, viewModel: viewModel) { route in
                    importRoute = route
                }
            }
        }
        .onDisappear {
            importOperationID = nil
        }
    }

    @MainActor
    private func continueImport() async {
        guard isDetectingInput == false else { return }
        let operationID = UUID()
        importOperationID = operationID
        isDetectingInput = true
        viewModel.importErrorMessage = nil
        defer {
            if importOperationID == operationID {
                importOperationID = nil
            }
            isDetectingInput = false
        }

        do {
            let route = try await viewModel.routeImportPayload(text: linkText, title: String(localized: "profiles.paste_link"))
            guard importOperationID == operationID else {
                await viewModel.discardImportRoute(route)
                return
            }
            importOperationID = nil
            importRoute = route
        } catch {
            if importOperationID == operationID {
                viewModel.importErrorMessage = error.localizedDescription
            }
        }
    }
}

private struct SubscriptionReviewSections: View {
    let subscription: VPNSubscription

    var body: some View {
        Section("profiles.subscription") {
            LabeledContent("Name", value: subscription.name)
            LabeledContent("Provider", value: subscription.sanitizedHost)
            LabeledContent("URL", value: subscription.sanitizedURLDisplay)
        }
    }
}

private struct NativeWireGuardReviewSections: View {
    let configuration: WireGuardProfileConfiguration
    let mode: VPNProtocol

    var body: some View {
        Section("Native interface") {
            LabeledContent("Mode", value: mode.displayName)
            LabeledContent("Addresses", value: configuration.interfaceAddresses.joined(separator: ", "))
            if configuration.dnsServers.isEmpty == false {
                LabeledContent("DNS", value: configuration.dnsServers.joined(separator: ", "))
            }
            if configuration.dnsSearchDomains.isEmpty == false {
                LabeledContent("Search domains", value: configuration.dnsSearchDomains.joined(separator: ", "))
            }
            if let listenPort = configuration.listenPort {
                LabeledContent("Listen port", value: String(listenPort))
            }
            if let mtu = configuration.mtu {
                LabeledContent("MTU", value: String(mtu))
            }
            LabeledContent("Private key", value: "Stored securely")
            if configuration.headerProtectionKeyReference != nil {
                LabeledContent("Header protection key", value: "Stored securely")
            }
        }

        Section("Peers") {
            ForEach(configuration.peers, id: \.publicKey) { peer in
                VStack(alignment: .leading, spacing: 6) {
                    LabeledContent("Public key", value: abbreviatedKey(peer.publicKey))
                    LabeledContent("Allowed IPs", value: peer.allowedIPs.joined(separator: ", "))
                    if peer.excludedIPs.isEmpty == false {
                        LabeledContent("Excluded IPs", value: peer.excludedIPs.joined(separator: ", "))
                    }
                    if let endpoint = peer.endpoint {
                        LabeledContent("Endpoint", value: "\(endpoint.host):\(endpoint.port)")
                    }
                    if let keepAlive = peer.persistentKeepAlive {
                        LabeledContent("Persistent keepalive", value: keepAlive)
                    }
                    if peer.presharedKeyReference != nil {
                        LabeledContent("Preshared key", value: "Stored securely")
                    }
                }
            }
        }

        if mode == .amneziaWG {
            Section("AmneziaWG protection") {
                LabeledContent("Manifest mode", value: "AmneziaWG")
                LabeledContent("Obfuscation parameters", value: configuration.amnezia?.hasAnyValue == true ? "Configured" : "Header key only")
            }
        }
    }

    private func abbreviatedKey(_ value: String) -> String {
        guard value.count > 16 else { return value }
        return "\(value.prefix(8))…\(value.suffix(8))"
    }
}

struct ReviewProfileView: View {
    let importResult: VPNImportResult
    @Bindable var viewModel: VPNDashboardViewModel
    var onImportSucceeded: (ImportFlowSuccessKind) -> Void = { _ in }
    var manualCredentialValue: String?
    var sourceText: String?
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
                                didSave = await viewModel.saveImportResultAndSelect(importResult)
                            }
                            if didSave {
                                onImportSucceeded(.profile)
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
                    .disabled(profile.runtimeCapability.isReady == false || viewModel.isSavingProfile)

                    if let message = viewModel.profileSaveMessage {
                        Text(message)
                            .font(.footnote)
                            .foregroundStyle(saveMessageStyle)
                    }
                }
            case .subscription(let subscription):
                SubscriptionReviewSections(subscription: subscription)

                Section {
                    Button {
                        Task {
                            let didSave = await viewModel.saveSubscriptionImportResult(subscription, sourceText: sourceText)
                            if didSave {
                                onImportSucceeded(.subscription)
                            }
                        }
                    } label: {
                        HStack {
                            if viewModel.subscriptionRefreshState == .downloading || viewModel.subscriptionRefreshState == .saving {
                                ProgressView()
                            }
                            Text("Save Subscription")
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(viewModel.subscriptionRefreshState == .downloading || viewModel.subscriptionRefreshState == .saving)

                    if let importErrorMessage = viewModel.importErrorMessage {
                        Text(importErrorMessage)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }
        }
        .navigationTitle("profiles.review_profile")
        .onDisappear {
            Task {
                await viewModel.discardImportResult(importResult)
            }
        }
    }

    @ViewBuilder
    private func profileSections(_ profile: VPNProfile) -> some View {
        let capability = profile.runtimeCapability
        Section("Profile") {
            LabeledContent("Name", value: profile.name)
            LabeledContent("Protocol", value: profile.protocolType.displayName)
            LabeledContent("Validation", value: capability.statusText)
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

        if let configuration = nativeConfiguration(for: profile) {
            NativeWireGuardReviewSections(configuration: configuration, mode: profile.protocolType)
        }

        if profile.isComplete == false {
            Section("Missing") {
                ForEach(profile.missingRequiredFields, id: \.self) { field in
                    Label(field, systemImage: "exclamationmark.circle")
                        .foregroundStyle(.orange)
                }
            }
        }

        if let issue = capability.issue {
            Section("Unsupported configuration") {
                Label(issue.message, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
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

    private func nativeConfiguration(for profile: VPNProfile) -> WireGuardProfileConfiguration? {
        switch profile.protocolConfiguration {
        case .wireGuard(let configuration), .amneziaWG(let configuration):
            configuration
        default:
            nil
        }
    }

    private var saveButtonTitle: String {
        viewModel.isSavingProfile ? "Saving" : "Save Profile"
    }

    private var saveMessageStyle: Color {
        switch viewModel.profileSaveState {
        case .saved:
            .green
        case .failed, .incomplete, .duplicate, .unsupported:
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
