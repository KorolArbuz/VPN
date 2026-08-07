//
//  QRImportView.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import PhotosUI
import SwiftUI
import UIKit
import Vision
import VisionKit

struct QRScannerView: View {
    @Bindable var viewModel: VPNDashboardViewModel
    let onProfileSaved: () -> Void
    let onRoute: (ImportPayloadRoute) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var selectedItem: PhotosPickerItem?
    @State private var processingMessage: String?
    @State private var errorMessage: String?
    @State private var didHandlePayload = false
    @State private var qrImageProcessingTask: Task<Void, Never>?
    @State private var qrImageOperationID: UUID?

    var body: some View {
        VStack(spacing: 20) {
            if isLiveScannerAvailable {
                LiveQRScannerView { payload in
                    handlePayloadOnce(payload)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .overlay(alignment: .bottom) {
                    if let processingMessage {
                        processingOverlay(processingMessage)
                    }
                }
            } else {
                fallbackContent
            }
        }
        .navigationTitle("Scan QR Code")
        .onChange(of: selectedItem) { _, newItem in
            guard let newItem else { return }
            Task {
                await processImageItem(newItem)
            }
        }
        .alert("QR Import Failed", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if $0 == false { errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private var fallbackContent: some View {
        ContentUnavailableView {
            Label("Live QR scanning is unavailable on this device.", systemImage: "qrcode.viewfinder")
        } description: {
            Text("Choose a QR image from Photos or paste a VPN link instead.")
        } actions: {
            VStack(spacing: 12) {
                PhotosPicker(selection: $selectedItem, matching: .images) {
                    Label("Choose QR Image", systemImage: "photo")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)

                NavigationLink {
                    PasteLinkView(viewModel: viewModel, onProfileSaved: onProfileSaved)
                } label: {
                    Label("Paste Link", systemImage: "link")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)

                Button("Cancel", role: .cancel) {
                    dismiss()
                }
                .buttonStyle(.borderless)
            }
            .frame(maxWidth: 280)
        }
        .padding()
    }

    private var isLiveScannerAvailable: Bool {
        #if targetEnvironment(simulator)
        false
        #else
        if #available(iOS 16.0, *) {
            return DataScannerViewController.isSupported && DataScannerViewController.isAvailable
        }
        return false
        #endif
    }

    private func processingOverlay(_ message: String) -> some View {
        Label(message, systemImage: "qrcode")
            .padding(12)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
            .padding()
    }

    private func handlePayloadOnce(_ payload: String) {
        guard didHandlePayload == false else { return }
        didHandlePayload = true
        Task {
            await processPayload(payload, scanningMessage: "Processing QR...")
        }
    }

    @MainActor
    private func processImageItem(_ item: PhotosPickerItem) async {
        qrImageProcessingTask?.cancel()
        let operationID = UUID()
        qrImageOperationID = operationID

        qrImageProcessingTask = Task {
            await processImageItem(item, operationID: operationID)
        }
    }

    @MainActor
    private func processImageItem(_ item: PhotosPickerItem, operationID: UUID) async {
        do {
            guard qrImageOperationID == operationID else { return }
            processingMessage = "Scanning..."
            guard let data = try await item.loadTransferable(type: Data.self) else {
                throw VPNImportError.invalidPayload("The image could not be read.")
            }
            try Task.checkCancellation()
            guard qrImageOperationID == operationID else { return }

            processingMessage = "Processing QR..."
            let payloads = try await viewModel.qrCodePayloads(in: data)
            try Task.checkCancellation()
            guard qrImageOperationID == operationID else { return }

            let route: ImportPayloadRoute
            if payloads.count == 1, let payload = payloads.first {
                route = try await viewModel.routeImportPayload(text: payload, title: "QR Image")
            } else {
                route = .qrPayloads(QRPayloadSelectionDraft(title: "QR Image", payloads: payloads))
            }
            try Task.checkCancellation()
            guard qrImageOperationID == operationID else { return }

            processingMessage = "Preparing profile..."
            onRoute(route)
            processingMessage = nil
            selectedItem = nil
            qrImageOperationID = nil
        } catch is CancellationError {
            if qrImageOperationID == operationID {
                processingMessage = nil
                qrImageOperationID = nil
            }
        } catch {
            guard qrImageOperationID == operationID else { return }
            processingMessage = nil
            errorMessage = normalizedQRImageError(error)
            selectedItem = nil
            qrImageOperationID = nil
        }
    }

    @MainActor
    private func processPayload(_ payload: String, scanningMessage: String) async {
        do {
            processingMessage = scanningMessage
            let route = try await viewModel.routeImportPayload(text: payload, title: "QR Code")
            processingMessage = "Preparing profile..."
            onRoute(route)
            processingMessage = nil
        } catch {
            processingMessage = nil
            errorMessage = "Unsupported QR content."
        }
    }

    private func normalizedQRImageError(_ error: Error) -> String {
        if let qrError = error as? QRCodeImageImportError {
            return qrError.localizedDescription
        }

        return error.localizedDescription
    }
}

private struct LiveQRScannerView: UIViewControllerRepresentable {
    let onPayload: (String) -> Void

    func makeUIViewController(context: Context) -> UIViewController {
        guard #available(iOS 16.0, *) else {
            return UIViewController()
        }

        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: true,
            isGuidanceEnabled: true,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onPayload: onPayload)
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onPayload: (String) -> Void
        private var didHandlePayload = false

        init(onPayload: @escaping (String) -> Void) {
            self.onPayload = onPayload
        }

        @available(iOS 16.0, *)
        func dataScanner(
            _ dataScanner: DataScannerViewController,
            didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            guard didHandlePayload == false else { return }
            for item in addedItems {
                if case .barcode(let barcode) = item, let payload = barcode.payloadStringValue {
                    didHandlePayload = true
                    dataScanner.stopScanning()
                    onPayload(payload)
                    return
                }
            }
        }
    }
}
