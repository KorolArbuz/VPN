//
//  AddVPNSheet.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct AddVPNSheet: View {
    @Bindable var viewModel: VPNDashboardViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                NavigationLink {
                    PasteLinkView(viewModel: viewModel)
                } label: {
                    Label("Paste Link", systemImage: "link")
                }

                NavigationLink {
                    AddSubscriptionView(viewModel: viewModel)
                } label: {
                    Label("Add Subscription", systemImage: "calendar.badge.plus")
                }

                NavigationLink {
                    PlaceholderImportView(title: "Scan QR Code", systemImage: "qrcode.viewfinder")
                } label: {
                    Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                }

                NavigationLink {
                    PlaceholderImportView(title: "Import File", systemImage: "doc.badge.plus")
                } label: {
                    Label("Import File", systemImage: "doc.badge.plus")
                }

                NavigationLink {
                    ManualSetupView(viewModel: viewModel)
                } label: {
                    Label("Manual Setup", systemImage: "slider.horizontal.3")
                }
            }
            .navigationTitle("Add VPN")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }
}

private struct PlaceholderImportView: View {
    let title: String
    let systemImage: String

    var body: some View {
        ContentUnavailableView(title, systemImage: systemImage, description: Text("This import path is prepared for a later stage."))
            .navigationTitle(title)
    }
}
