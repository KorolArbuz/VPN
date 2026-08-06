//
//  ConnectionSelectionView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct ConnectionSelectionView: View {
    @Bindable var viewModel: VPNDashboardViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var selectionMode: SelectionMode = .automatic

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Mode", selection: $selectionMode) {
                        ForEach(SelectionMode.allCases) { mode in
                            Text(mode.title).tag(mode)
                        }
                    }
                    .pickerStyle(.segmented)

                    if selectionMode == .automatic {
                        Button {
                            Task {
                                await viewModel.selectBestServer()
                            }
                        } label: {
                            Label("Select Best Connection", systemImage: "wand.and.sparkles")
                        }
                    }
                }

                Section("Server") {
                    NavigationLink {
                        ServerSelectionView(viewModel: viewModel)
                    } label: {
                        LabeledContent("Server", value: serverValue)
                    }
                    .disabled(selectionMode == .automatic)
                }

                Section("Protocol") {
                    NavigationLink {
                        ProtocolSelectionView(viewModel: viewModel)
                    } label: {
                        LabeledContent("Protocol", value: protocolValue)
                    }
                    .disabled(selectionMode == .automatic)
                }

                Section("Profile") {
                    if viewModel.profiles.isEmpty {
                        Text("No saved profiles")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(viewModel.profiles) { profile in
                            Button {
                                viewModel.selectProfile(profile)
                            } label: {
                                HStack {
                                    Image(systemName: profile.protocolType.iconName)
                                    VStack(alignment: .leading) {
                                        Text(profile.name)
                                        Text("\(profile.serverAddress):\(profile.port.map(String.init) ?? "--")")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    if viewModel.selectedProfile?.id == profile.id {
                                        Image(systemName: "checkmark.circle.fill")
                                            .foregroundStyle(.tint)
                                    }
                                }
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
            }
            .navigationTitle("Connection")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
            .onChange(of: selectionMode) { _, newValue in
                if newValue == .automatic {
                    viewModel.selectProtocol(.automatic)
                }
            }
        }
    }

    private var serverValue: String {
        guard let server = viewModel.selectedServer else {
            return "Automatic"
        }

        return "\(server.city), \(server.country)"
    }

    private var protocolValue: String {
        viewModel.effectiveProtocol?.displayName ?? viewModel.selectedProtocol.displayName
    }
}

private enum SelectionMode: String, CaseIterable, Identifiable {
    case automatic
    case manual

    var id: String { rawValue }

    var title: String {
        switch self {
        case .automatic:
            "Automatic"
        case .manual:
            "Manual"
        }
    }
}

#Preview {
    ConnectionSelectionView(viewModel: VPNDashboardViewModel())
}
