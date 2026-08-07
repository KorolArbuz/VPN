//
//  QRImportView.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import AVFoundation
import PhotosUI
import SwiftUI
import UIKit
import Vision
import VisionKit

enum QRScannerCameraAccessState: Equatable {
    case checking
    case authorized
    case permissionRequired
    case denied
    case restricted
    case unavailable

    var fallbackTitle: String {
        switch self {
        case .checking:
            "qr.checking_camera"
        case .permissionRequired, .denied, .restricted:
            "qr.camera_permission_required"
        case .unavailable:
            "qr.camera_unavailable"
        case .authorized:
            ""
        }
    }

    var fallbackDescription: String {
        switch self {
        case .checking:
            "qr.please_wait"
        case .permissionRequired:
            "qr.permission_not_configured"
        case .denied:
            "qr.permission_denied_description"
        case .restricted:
            "qr.permission_restricted_description"
        case .unavailable:
            "qr.camera_unavailable_description"
        case .authorized:
            ""
        }
    }

    var showsSettingsAction: Bool {
        self == .denied || self == .restricted
    }
}

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
    @State private var cameraAccessState: QRScannerCameraAccessState = .checking

    var body: some View {
        VStack(spacing: 20) {
            if cameraAccessState == .authorized {
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
        .navigationTitle("qr.title")
        .task {
            await updateCameraAccessState()
        }
        .onChange(of: selectedItem) { _, newItem in
            guard let newItem else { return }
            Task {
                await processImageItem(newItem)
            }
        }
        .alert("qr.import_failed", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if $0 == false { errorMessage = nil } }
        )) {
            Button("common.ok", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private var fallbackContent: some View {
        ContentUnavailableView {
            Label(LocalizedStringKey(cameraAccessState.fallbackTitle), systemImage: "qrcode.viewfinder")
        } description: {
            Text(LocalizedStringKey(cameraAccessState.fallbackDescription))
        } actions: {
            VStack(spacing: 12) {
                if cameraAccessState == .checking {
                    ProgressView()
                }

                PhotosPicker(selection: $selectedItem, matching: .images) {
                    Label("profiles.choose_qr_image", systemImage: "photo")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)

                NavigationLink {
                    PasteLinkView(viewModel: viewModel, onProfileSaved: onProfileSaved)
                } label: {
                    Label("profiles.paste_link", systemImage: "link")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)

                if cameraAccessState.showsSettingsAction,
                   let settingsURL = URL(string: UIApplication.openSettingsURLString) {
                    Link(destination: settingsURL) {
                        Label("qr.open_settings", systemImage: "gearshape")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }

                Button("common.cancel", role: .cancel) {
                    dismiss()
                }
                .buttonStyle(.borderless)
            }
            .frame(maxWidth: 280)
        }
        .padding()
    }

    @MainActor
    private func updateCameraAccessState() async {
        guard isLiveScannerSupported else {
            cameraAccessState = .unavailable
            return
        }

        guard hasCameraUsageDescription else {
            cameraAccessState = .permissionRequired
            return
        }

        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            cameraAccessState = .authorized
        case .notDetermined:
            let isGranted = await AVCaptureDevice.requestAccess(for: .video)
            cameraAccessState = isGranted ? .authorized : .denied
        case .denied:
            cameraAccessState = .denied
        case .restricted:
            cameraAccessState = .restricted
        @unknown default:
            cameraAccessState = .unavailable
        }
    }

    private var hasCameraUsageDescription: Bool {
        Bundle.main.object(forInfoDictionaryKey: "NSCameraUsageDescription") as? String != nil
    }

    private var isLiveScannerSupported: Bool {
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

    static func dismantleUIViewController(_ uiViewController: UIViewController, coordinator: Coordinator) {
        guard #available(iOS 16.0, *),
              let scanner = uiViewController as? DataScannerViewController else {
            return
        }

        scanner.stopScanning()
        scanner.delegate = nil
    }

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
                    DispatchQueue.main.async { [onPayload] in
                        onPayload(payload)
                    }
                    return
                }
            }
        }
    }
}
