//
//  VPNDashboardView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct VPNDashboardView: View {
    @Bindable var viewModel: VPNDashboardViewModel
    @State private var isConnectionSheetPresented = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    connectionStatus
                    currentConnectionCard
                    connectedMetrics
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity)
            }
            .background(Color(.systemBackground))
            .navigationTitle("Universal VPN")
            .navigationBarTitleDisplayMode(.inline)
            .sheet(isPresented: $isConnectionSheetPresented) {
                ConnectionSelectionView(viewModel: viewModel)
                    .presentationDetents([.medium, .large])
            }
            .task {
                await viewModel.loadInitialData()
            }
        }
    }

    private var connectionStatus: some View {
        VStack(spacing: 12) {
            ConnectionButton(
                state: viewModel.connectionState,
                isEnabled: viewModel.canToggleConnection && viewModel.canConnect
            ) {
                Task {
                    await viewModel.toggleConnection()
                }
            }

            VStack(spacing: 6) {
                HStack(spacing: 8) {
                    if isInFlight {
                        ProgressView()
                            .controlSize(.small)
                    }

                    Text(viewModel.connectionState.displayName)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(statusColor)
                }
                .animation(.snappy(duration: 0.25), value: viewModel.connectionState)

                if let errorMessage = viewModel.errorMessage {
                    VStack(spacing: 8) {
                        Text(errorMessage)
                            .font(.footnote)
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)

                        if viewModel.connectionState == .failed && viewModel.canConnect {
                            Button("Retry") {
                                Task {
                                    await viewModel.connect()
                                }
                            }
                            .font(.footnote.weight(.semibold))
                        }
                    }
                    .padding(.horizontal)
                }
            }
        }
        .padding(.top, 4)
    }

    private var currentConnectionCard: some View {
        Button {
            isConnectionSheetPresented = true
        } label: {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .top, spacing: 12) {
                    Text(flagText)
                        .font(.largeTitle)
                        .frame(width: 44, alignment: .leading)

                    VStack(alignment: .leading, spacing: 5) {
                        Text("Current Connection")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .textCase(.uppercase)

                        Text(primaryConnectionTitle)
                            .font(.headline)
                            .foregroundStyle(.primary)
                            .lineLimit(2)

                        Text(secondaryConnectionTitle)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)

                        if let selectedProfile = viewModel.selectedProfile {
                            Text(selectedProfile.name)
                                .font(.caption)
                                .foregroundStyle(selectedProfile.isComplete ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
                                .lineLimit(1)
                        } else if viewModel.selectedServer != nil {
                            Text("Using built-in server")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Spacer(minLength: 8)

                    Image(systemName: "chevron.right")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.tertiary)
                        .padding(.top, 4)
                }

                Divider()

                HStack(spacing: 16) {
                    compactStat("Ping", pingText, "speedometer")
                    compactStat("Load", loadText, "chart.bar")
                    compactStat("Mode", modeText, "slider.horizontal.3")
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Current connection. Tap to change server, protocol, or profile.")
    }

    @ViewBuilder
    private var connectedMetrics: some View {
        if viewModel.connectionState == .connected {
            HStack(spacing: 8) {
                Text(pingText)
                Text("·")
                    .foregroundStyle(.tertiary)
                Text(packetLossText)
                Text("·")
                    .foregroundStyle(.tertiary)
                Text(connectionTimeText)
            }
            .font(.footnote)
            .foregroundStyle(.secondary)
            .padding(.top, 2)
            .accessibilityLabel("Connection details. Ping \(pingText), packet loss \(packetLossText), session \(connectionTimeText).")
        }
    }

    private func compactStat(_ title: String, _ value: String, _ systemImage: String) -> some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
        } icon: {
            Image(systemName: systemImage)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var primaryConnectionTitle: String {
        if let profile = viewModel.selectedProfile {
            return profile.serverAddress.isEmpty ? "Incomplete Profile" : profile.serverAddress
        }

        return viewModel.selectedServer?.country ?? "No server selected"
    }

    private var secondaryConnectionTitle: String {
        if let profile = viewModel.selectedProfile {
            let port = profile.port.map { ":\($0)" } ?? ""
            if profile.isComplete == false {
                return "Missing \(profile.missingRequiredFields.joined(separator: ", "))"
            }
            return "\(profile.protocolType.displayName) \(port)"
        }

        guard let server = viewModel.selectedServer else {
            return "Choose a server or profile"
        }

        return "\(server.city) - \(server.name)"
    }

    private var modeText: String {
        if let profile = viewModel.selectedProfile {
            return profile.protocolType.displayName
        }

        return viewModel.selectedProtocol.displayName
    }

    private var pingText: String {
        guard let server = viewModel.selectedServer else {
            return "--"
        }

        return "\(viewModel.currentMetrics?.latency ?? server.latency) ms"
    }

    private var loadText: String {
        guard let server = viewModel.selectedServer else {
            return "--"
        }

        let load = viewModel.currentMetrics?.serverLoad ?? server.load
        return load.formatted(.percent.precision(.fractionLength(0)))
    }

    private var packetLossText: String {
        guard let packetLoss = viewModel.currentMetrics?.packetLoss else {
            return "Packet Loss --"
        }

        return "Packet Loss " + packetLoss.formatted(.percent.precision(.fractionLength(1)))
    }

    private var connectionTimeText: String {
        guard let connectionTime = viewModel.currentMetrics?.connectionTime else {
            return "Session --"
        }

        return "Session " + connectionTime.formatted(.number.precision(.fractionLength(2))) + " s"
    }

    private var flagText: String {
        if viewModel.selectedProfile != nil {
            return "VPN"
        }

        guard let countryCode = viewModel.selectedServer?.countryCode else {
            return "--"
        }

        return flagEmoji(for: countryCode)
    }

    private var isInFlight: Bool {
        switch viewModel.connectionState {
        case .testing, .connecting, .disconnecting:
            true
        case .disconnected, .connected, .failed:
            false
        }
    }

    private var statusColor: Color {
        switch viewModel.connectionState {
        case .connected:
            .green
        case .failed:
            .red
        case .testing, .connecting, .disconnecting:
            .orange
        case .disconnected:
            .secondary
        }
    }

    private func flagEmoji(for countryCode: String) -> String {
        let base: UInt32 = 127_397
        let scalars = countryCode.uppercased().unicodeScalars.compactMap { UnicodeScalar(base + $0.value) }
        return String(String.UnicodeScalarView(scalars))
    }
}

#Preview {
    VPNDashboardView(viewModel: VPNDashboardViewModel())
}
