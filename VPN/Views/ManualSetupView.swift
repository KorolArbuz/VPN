//
//  ManualSetupView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ManualSetupView: View {
    @Bindable var viewModel: VPNDashboardViewModel
    @State private var protocolType: VPNProtocol = .wireGuard
    @State private var name = ""
    @State private var serverAddress = ""
    @State private var portText = ""
    @State private var username = ""
    @State private var transport = "tcp"
    @State private var tlsEnabled = true
    @State private var serverName = ""
    @State private var allowInsecure = false

    var body: some View {
        Form {
            Section("Protocol") {
                Picker("Protocol", selection: $protocolType) {
                    ForEach(VPNProtocol.allCases) { vpnProtocol in
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

            if showsUsername {
                Section("Identity") {
                    TextField("Username", text: $username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Text("Secrets are not stored in this prototype form. Add them later through secure storage.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
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

                    Toggle("Allow Insecure", isOn: $allowInsecure)

                    if allowInsecure {
                        Label("Use only for testing. Certificate validation would be weakened.", systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
            }

            Section {
                Button {
                    Task {
                        await viewModel.saveProfile(makeProfile())
                    }
                } label: {
                    Label("Save", systemImage: "tray.and.arrow.down")
                }
            }
        }
        .navigationTitle("Manual Setup")
    }

    private var showsUsername: Bool {
        [.ikev2].contains(protocolType)
    }

    private var showsTransport: Bool {
        [.vless, .hysteria2, .trojan, .shadowsocks, .tuic, .vmess].contains(protocolType)
    }

    private func makeProfile() -> VPNProfile {
        VPNProfile.draft(
            name: name.isEmpty ? "\(protocolType.displayName) Profile" : name,
            protocolType: protocolType,
            serverAddress: serverAddress,
            port: Int(portText),
            username: username.isEmpty ? nil : username,
            credentialReference: nil,
            transportSettings: VPNTransportSettings(network: showsTransport ? transport : nil),
            tlsSettings: VPNTLSSettings(isEnabled: tlsEnabled, serverName: serverName.isEmpty ? nil : serverName, allowInsecure: allowInsecure),
            protocolConfiguration: configuration,
            source: .manual
        )
    }

    private var configuration: VPNProtocolConfiguration {
        switch protocolType {
        case .wireGuard:
            .wireGuard(WireGuardProfileConfiguration(peerPublicKeyReference: nil, presharedKeyReference: nil, allowedIPs: []))
        case .ikev2:
            .ikev2(IKEv2ProfileConfiguration(remoteIdentifier: serverName.isEmpty ? nil : serverName, localIdentifier: nil, authenticationMethod: "usernamePassword"))
        case .vless:
            .vless(VLESSProfileConfiguration(flow: nil, encryption: "none"))
        case .hysteria2:
            .hysteria2(Hysteria2ProfileConfiguration(obfs: nil, bandwidthHint: nil))
        case .trojan:
            .trojan(TrojanProfileConfiguration(alpn: []))
        case .shadowsocks:
            .shadowsocks(ShadowsocksProfileConfiguration(method: nil, plugin: nil))
        case .tuic:
            .tuic(TUICProfileConfiguration(congestionControl: nil, udpRelayMode: nil))
        case .vmess:
            .vmess(VMessProfileConfiguration(alterID: nil, security: nil))
        }
    }
}
