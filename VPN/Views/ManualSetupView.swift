//
//  ManualSetupView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ManualSetupView: View {
    @Bindable var viewModel: VPNDashboardViewModel
    var onProfileSaved: () -> Void = {}
    @State private var protocolType: VPNProtocol = .vless
    @State private var name = ""
    @State private var serverAddress = ""
    @State private var portText = ""
    @State private var transport = "tcp"
    @State private var tlsEnabled = true
    @State private var serverName = ""
    @State private var credential = ""
    @State private var reviewResult: VPNImportResult?

    var body: some View {
        Form {
            Section {
                Text("Enter basic server details and review the profile before saving.")
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

            Section {
                Button {
                    reviewResult = makeImportResult()
                } label: {
                    Label("Review Profile", systemImage: "doc.text.magnifyingglass")
                }
                .disabled(canReview == false)
            }
        }
        .navigationTitle("Manual Setup")
        .navigationDestination(item: $reviewResult) { result in
            ReviewProfileView(
                importResult: result,
                viewModel: viewModel,
                onProfileSaved: onProfileSaved,
                manualCredentialValue: credential
            )
        }
    }

    private var supportedProtocols: [VPNProtocol] {
        [.vless, .trojan, .hysteria2]
    }

    private var showsTransport: Bool {
        true
    }

    private var credentialPlaceholder: String {
        switch protocolType {
        case .vless:
            "UUID"
        case .trojan, .hysteria2:
            "Password"
        case .wireGuard, .ikev2, .shadowsocks, .tuic, .vmess:
            "Credential"
        }
    }

    private var canReview: Bool {
        serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false
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
        case .wireGuard, .ikev2, .shadowsocks, .tuic, .vmess:
            .vless(VLESSProfileConfiguration(flow: nil, encryption: "none"))
        }
    }
}
