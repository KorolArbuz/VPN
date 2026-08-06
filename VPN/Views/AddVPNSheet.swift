//
//  AddVPNSheet.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct AddVPNSheet: View {
    @Bindable var viewModel: VPNDashboardViewModel
    var onProfileSaved: () -> Void = {}
    @Environment(\.dismiss) private var dismiss
    @State private var path: [AddProfileRoute] = []

    var body: some View {
        NavigationStack(path: $path) {
            List {
                Section {
                    Text("Choose how you want to add a VPN profile.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 4)
                }

                Section {
                    NavigationLink(value: AddProfileRoute.pasteLink) {
                        ProfileActionRow(
                            title: "Paste Link",
                            subtitle: "Import a VPN link or save a subscription URL.",
                        systemImage: "link"
                    )
                    }

                    NavigationLink(value: AddProfileRoute.manualSetup) {
                        ProfileActionRow(
                            title: "Manual Setup",
                            subtitle: "Enter server details yourself and save a draft.",
                            systemImage: "slider.horizontal.3"
                        )
                    }
                }

                Section {
                    NavigationLink {
                        AddSubscriptionView(viewModel: viewModel)
                    } label: {
                        ProfileActionRow(
                            title: "Add Subscription",
                            subtitle: "Save a provider URL. Refresh stays mock-only for now.",
                            systemImage: "calendar.badge.plus"
                        )
                    }

                    ProfileActionRow(
                        title: "Import File",
                        subtitle: "Load a local configuration file.",
                        systemImage: "doc.badge.plus",
                        isEnabled: false
                    )

                    ProfileActionRow(
                        title: "Scan QR Code",
                        subtitle: "Use the camera to scan a profile code.",
                        systemImage: "qrcode.viewfinder",
                        isEnabled: false
                    )
                }
            }
            .navigationTitle("Add Profile")
            .navigationDestination(for: AddProfileRoute.self) { route in
                switch route {
                case .pasteLink:
                    PasteLinkView(viewModel: viewModel) {
                        finishFlow()
                    }
                case .manualSetup:
                    ManualSetupView(viewModel: viewModel) {
                        finishFlow()
                    }
                }
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }

    private func finishFlow() {
        path.removeAll()
        dismiss()
        onProfileSaved()
    }
}

private enum AddProfileRoute: Hashable {
    case pasteLink
    case manualSetup
}

#Preview {
    AddVPNSheet(viewModel: VPNDashboardViewModel())
}
