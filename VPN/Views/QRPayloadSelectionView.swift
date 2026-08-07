//
//  QRPayloadSelectionView.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import SwiftUI

struct QRPayloadSelectionView: View {
    let draft: QRPayloadSelectionDraft
    @Bindable var viewModel: VPNDashboardViewModel
    let onRoute: (ImportPayloadRoute) -> Void
    @State private var errorMessage: String?
    @State private var isProcessing = false

    var body: some View {
        List {
            Section {
                Text("Several QR codes were found. Choose the profile you want to review.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Section("QR Codes") {
                ForEach(Array(draft.payloads.enumerated()), id: \.offset) { index, payload in
                    Button {
                        Task {
                            await select(payload)
                        }
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("QR Code \(index + 1)")
                                .font(.headline)
                            Text(sanitizedSummary(for: payload))
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .disabled(isProcessing)
                }
            }

            if let errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Choose QR Code")
    }

    @MainActor
    private func select(_ payload: String) async {
        guard isProcessing == false else { return }
        isProcessing = true
        defer { isProcessing = false }

        do {
            let route = try await viewModel.routeImportPayload(text: payload, title: "QR Code")
            onRoute(route)
        } catch {
            errorMessage = "Unsupported QR content."
        }
    }

    private func sanitizedSummary(for payload: String) -> String {
        guard let scheme = payload.split(separator: ":", maxSplits: 1).first else {
            return "VPN profile"
        }
        return "\(scheme.uppercased()) profile"
    }
}
