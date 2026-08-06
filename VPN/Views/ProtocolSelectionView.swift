//
//  ProtocolSelectionView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ProtocolSelectionView: View {
    @Bindable var viewModel: VPNDashboardViewModel

    private var options: [VPNProtocolSelection] {
        [.automatic] + VPNProtocol.allCases.map { .manual($0) }
    }

    var body: some View {
        List(options) { option in
            Button {
                viewModel.selectProtocol(option)
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(option.displayName)
                            .font(.headline)

                        if option == .automatic {
                            Text("Best supported protocol for the selected server")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else if viewModel.isProtocolCompatible(option) == false {
                            Text("Not supported by selected server")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Spacer()

                    if viewModel.selectedProtocol == option {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.tint)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(viewModel.isProtocolCompatible(option) == false)
            .opacity(viewModel.isProtocolCompatible(option) ? 1 : 0.45)
        }
        .navigationTitle("Protocol")
    }
}

#Preview {
    NavigationStack {
        ProtocolSelectionView(viewModel: VPNDashboardViewModel())
    }
}
