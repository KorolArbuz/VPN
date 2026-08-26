//
//  ManualSetupView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ManualSetupView: View {
    @Bindable var viewModel: VPNDashboardViewModel
    var onImportSucceeded: (ImportFlowSuccessKind) -> Void = { _ in }
    @State private var protocolType: VPNProtocol = .vless
    @State private var name = ""
    @State private var serverAddress = ""
    @State private var portText = ""
    @State private var transport = "tcp"
    @State private var tlsEnabled = true
    @State private var serverName = ""
    @State private var credential = ""
    @State private var nativeConfiguration = ""
    @State private var nativeConfigurationError: String?
    @State private var isReviewingNativeConfiguration = false
    @State private var reviewResult: VPNImportResult?

    var body: some View {
        Form {
            Section {
                Text(isNativeProtocol
                     ? "Paste a complete native configuration. Private keys and preshared keys are moved to secure storage before review."
                     : "Enter basic server details and review the profile before saving.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 4)
            }

            Section("Protocol") {
                Picker("Protocol", selection: $protocolType) {
                    ForEach(supportedProtocols) { vpnProtocol in
                        Text(vpnProtocol.displayName).tag(vpnProtocol)
                    }
                }
            }

            if isNativeProtocol {
                Section("Native configuration") {
                    TextField("Name (optional)", text: $name)
                    TextEditor(text: $nativeConfiguration)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 220)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .privacySensitive()

                    Text("Use the standard [Interface] and one or more [Peer] sections. The selected mode must match the configuration.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                if let nativeConfigurationError {
                    Section {
                        Label(nativeConfigurationError, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.red)
                    }
                }
            } else {
                Section("Server") {
                    TextField("Name", text: $name)
                    TextField("Server Address", text: $serverAddress)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Port", text: $portText)
                        .keyboardType(.numberPad)
                }

                Section("Credentials") {
                    SecureField(credentialPlaceholder, text: $credential)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                if showsTransport {
                    Section("Transport") {
                        TextField("Transport", text: $transport)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                }

                Section("TLS") {
                    Toggle("TLS", isOn: $tlsEnabled)

                    if tlsEnabled {
                        TextField("SNI / Server Name", text: $serverName)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                }
            }

            Section {
                Button {
                    if isNativeProtocol {
                        reviewNativeConfiguration()
                    } else {
                        reviewResult = makeImportResult()
                    }
                } label: {
                    HStack {
                        if isReviewingNativeConfiguration {
                            ProgressView()
                        }
                        Label("Review Profile", systemImage: "doc.text.magnifyingglass")
                    }
                }
                .disabled(canReview == false || isReviewingNativeConfiguration)
            }
        }
        .navigationTitle("Manual Setup")
        .navigationDestination(item: $reviewResult) { result in
            ReviewProfileView(
                importResult: result,
                viewModel: viewModel,
                onImportSucceeded: onImportSucceeded,
                manualCredentialValue: isNativeProtocol ? nil : credential
            )
        }
    }

    private var supportedProtocols: [VPNProtocol] {
        [.vless, .trojan, .hysteria2, .wireGuard, .amneziaWG]
    }

    private var showsTransport: Bool {
        isNativeProtocol == false
    }

    private var isNativeProtocol: Bool {
        protocolType == .wireGuard || protocolType == .amneziaWG
    }

    private var credentialPlaceholder: String {
        switch protocolType {
        case .vless:
            "UUID"
        case .trojan, .hysteria2:
            "Password"
        case .wireGuard, .amneziaWG:
            "Private Key"
        case .ikev2, .shadowsocks, .tuic, .vmess:
            "Credential"
        }
    }

    private var canReview: Bool {
        if isNativeProtocol {
            return nativeConfiguration.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
        }
        return serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
            && Int(portText) != nil
            && credential.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
    }

    private func makeImportResult() -> VPNImportResult {
        let profile = makeProfile()
        return VPNImportResult(
            kind: .profile(profile),
            detectedScheme: protocolType.rawValue,
            displayName: profile.name,
            sanitizedSummary: [
                "credential": SecretMasker.masked(credential),
                "host": profile.serverAddress,
                "port": profile.port.map(String.init) ?? ""
            ]
        )
    }

    private func makeProfile() -> VPNProfile {
        VPNProfile.draft(
            name: name.isEmpty ? "\(protocolType.displayName) Profile" : name,
            protocolType: protocolType,
            serverAddress: serverAddress,
            port: Int(portText),
            credentialReference: credential.isEmpty ? nil : "pending://manual-credential",
            transportSettings: VPNTransportSettings(network: showsTransport ? transport : nil),
            tlsSettings: VPNTLSSettings(isEnabled: tlsEnabled, serverName: serverName.isEmpty ? nil : serverName),
            protocolConfiguration: configuration,
            source: .manual
        )
    }

    private var configuration: VPNProtocolConfiguration {
        switch protocolType {
        case .vless:
            .vless(VLESSProfileConfiguration(flow: nil, encryption: "none"))
        case .hysteria2:
            .hysteria2(Hysteria2ProfileConfiguration(obfs: nil, bandwidthHint: nil))
        case .trojan:
            .trojan(TrojanProfileConfiguration(alpn: []))
        case .wireGuard:
            .wireGuard(WireGuardProfileConfiguration())
        case .amneziaWG:
            .amneziaWG(WireGuardProfileConfiguration())
        case .ikev2, .shadowsocks, .tuic, .vmess:
            .vless(VLESSProfileConfiguration(flow: nil, encryption: "none"))
        }
    }

    private func reviewNativeConfiguration() {
        nativeConfigurationError = nil
        isReviewingNativeConfiguration = true
        Task {
            defer { isReviewingNativeConfiguration = false }
            do {
                reviewResult = try await viewModel.reviewNativeConfiguration(
                    nativeConfiguration,
                    expectedProtocol: protocolType,
                    displayName: name
                )
            } catch {
                nativeConfigurationError = error.localizedDescription
            }
        }
    }
}
