//
//  ServerSelectionView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ServerSelectionView: View {
    @Bindable var viewModel: VPNDashboardViewModel

    var body: some View {
        List(viewModel.servers) { server in
            Button {
                viewModel.selectServer(server)
            } label: {
                ServerRow(
                    server: server,
                    isSelected: viewModel.selectedServer?.id == server.id
                )
            }
            .buttonStyle(.plain)
            .disabled(server.isAvailable == false)
        }
        .navigationTitle("Servers")
        .overlay {
            if viewModel.servers.isEmpty {
                ContentUnavailableView("No servers", systemImage: "server.rack")
            }
        }
    }
}

private struct ServerRow: View {
    let server: VPNServer
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Text(server.countryCode)
                        .font(.subheadline.monospaced().bold())
                        .frame(width: 34, alignment: .leading)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(server.country)
                            .font(.headline)

                        Text("\(server.city) - \(server.name)")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }

                HStack(spacing: 10) {
                    Label("\(server.latency) ms", systemImage: "speedometer")
                    Label(server.load.formatted(.percent.precision(.fractionLength(0))), systemImage: "chart.bar")
                }
                .font(.caption)
                .foregroundStyle(.secondary)

                Text(server.supportedProtocols.map(\.displayName).joined(separator: ", "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            Spacer()

            if server.isAvailable {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .font(.title3)
                    .foregroundStyle(isSelected ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
            } else {
                Label("Unavailable", systemImage: "wifi.slash")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .opacity(server.isAvailable ? 1 : 0.45)
        .padding(.vertical, 6)
    }
}

#Preview {
    NavigationStack {
        ServerSelectionView(viewModel: VPNDashboardViewModel())
    }
}
