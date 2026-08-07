//
//  AddVPNSheet.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI
import UniformTypeIdentifiers
import PhotosUI

struct AddVPNSheet: View {
    @Bindable var viewModel: VPNDashboardViewModel
    var onProfileSaved: () -> Void = {}
    @Environment(\.dismiss) private var dismiss
    @State private var path: [AddProfileRoute] = []
    @State private var isFileImporterPresented = false
    @State private var isQRImagePickerPresented = false
    @State private var selectedQRImageItem: PhotosPickerItem?
    @State private var importRoute: ImportPayloadRoute?
    @State private var importErrorMessage: String?
    @State private var processingMessage: String?
    @State private var qrImageProcessingTask: Task<Void, Never>?
    @State private var qrImageOperationID: UUID?

    var body: some View {
        NavigationStack(path: $path) {
            List {
                Section {
                    Text("Choose how you want to add a VPN profile.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 4)
                }

                Section("Quick Import") {
                    NavigationLink(value: AddProfileRoute.scanQRCode) {
                        ProfileActionRow(
                            title: "Scan QR Code",
                            subtitle: "Scan a QR code using the camera.",
                            systemImage: "qrcode.viewfinder"
                        )
                    }
                    .accessibilityLabel("Scan QR Code")

                    Button {
                        isQRImagePickerPresented = true
                    } label: {
                        ProfileActionRow(
                            title: "Choose QR Image",
                            subtitle: "Import a QR code from Photos.",
                            systemImage: "photo"
                        )
                    }
                    .accessibilityLabel("Choose QR Image")

                    NavigationLink(value: AddProfileRoute.pasteLink) {
                        ProfileActionRow(
                            title: "Paste Link",
                            subtitle: "Import a VPN link or save a subscription URL.",
                            systemImage: "link"
                        )
                    }

                    Button {
                        isFileImporterPresented = true
                    } label: {
                        ProfileActionRow(
                            title: "Import File",
                            subtitle: "Open a .txt, .conf, .json, .yaml or .yml file.",
                            systemImage: "doc.badge.plus"
                        )
                    }
                    .accessibilityLabel("Import File")
                }

                Section("Other Methods") {
                    NavigationLink(value: AddProfileRoute.manualSetup) {
                        ProfileActionRow(
                            title: "Manual Setup",
                            subtitle: "Enter server details yourself and save a draft.",
                            systemImage: "slider.horizontal.3"
                        )
                    }

                    NavigationLink {
                        AddSubscriptionView(viewModel: viewModel)
                    } label: {
                        ProfileActionRow(
                            title: "Add Subscription",
                            subtitle: "Preview a provider link and save selected profiles.",
                            systemImage: "calendar.badge.plus"
                        )
                    }
                }

                if let processingMessage {
                    Section {
                        HStack {
                            ProgressView()
                            Text(processingMessage)
                                .foregroundStyle(.secondary)
                        }
                    }
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
                case .scanQRCode:
                    QRScannerView(viewModel: viewModel, onProfileSaved: finishFlow) { route in
                        importRoute = route
                    }
                case .chooseQRImage, .importFile:
                    EmptyView()
                }
            }
            .navigationDestination(item: $importRoute) { route in
                switch route {
                case .single(let result):
                    ReviewProfileView(importResult: result, viewModel: viewModel) {
                        finishFlow()
                    }
                case .batch(let draft):
                    BatchImportReviewView(draft: draft, viewModel: viewModel) {
                        finishFlow()
                    }
                case .qrPayloads(let draft):
                    QRPayloadSelectionView(draft: draft, viewModel: viewModel) { route in
                        importRoute = route
                    }
                }
            }
            .fileImporter(isPresented: $isFileImporterPresented, allowedContentTypes: allowedFileTypes) { result in
                handleFileImport(result)
            }
            .photosPicker(isPresented: $isQRImagePickerPresented, selection: $selectedQRImageItem, matching: .images)
            .onChange(of: selectedQRImageItem) { _, newItem in
                guard let newItem else { return }
                handleQRImageSelection(newItem)
            }
            .alert("Import Failed", isPresented: Binding(
                get: { importErrorMessage != nil },
                set: { if $0 == false { importErrorMessage = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(importErrorMessage ?? "")
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

    private var allowedFileTypes: [UTType] {
        [
            .plainText,
            .json,
            UTType(filenameExtension: "conf"),
            UTType(filenameExtension: "yaml"),
            UTType(filenameExtension: "yml")
        ].compactMap { $0 }
    }

    private func handleFileImport(_ result: Result<URL, Error>) {
        Task {
            do {
                processingMessage = "Reading file..."
                let url = try result.get()
                let data = try readSecurityScopedFile(url)
                processingMessage = "Detecting format..."
                let route = try await viewModel.routeImportPayload(data: data, title: url.deletingPathExtension().lastPathComponent)
                processingMessage = "Preparing profile..."
                importRoute = route
                processingMessage = nil
            } catch {
                processingMessage = nil
                importErrorMessage = error.localizedDescription
            }
        }
    }

    private func handleQRImageSelection(_ item: PhotosPickerItem) {
        qrImageProcessingTask?.cancel()
        let operationID = UUID()
        qrImageOperationID = operationID

        qrImageProcessingTask = Task {
            do {
                guard qrImageOperationID == operationID else { return }
                processingMessage = "Processing QR..."
                guard let data = try await item.loadTransferable(type: Data.self) else {
                    throw VPNImportError.invalidPayload("The image could not be read.")
                }
                try Task.checkCancellation()
                guard qrImageOperationID == operationID else { return }

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
                importRoute = route
                processingMessage = nil
                selectedQRImageItem = nil
                qrImageOperationID = nil
            } catch is CancellationError {
                if qrImageOperationID == operationID {
                    processingMessage = nil
                    qrImageOperationID = nil
                }
            } catch {
                guard qrImageOperationID == operationID else { return }
                processingMessage = nil
                selectedQRImageItem = nil
                importErrorMessage = normalizedQRImageError(error)
                qrImageOperationID = nil
            }
        }
    }

    private func readSecurityScopedFile(_ url: URL) throws -> Data {
        let didStartAccess = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccess {
                url.stopAccessingSecurityScopedResource()
            }
        }

        let values = try url.resourceValues(forKeys: [.fileSizeKey])
        if let fileSize = values.fileSize, fileSize > 2 * 1024 * 1024 {
            throw VPNImportError.invalidPayload("The file is too large.")
        }

        let data = try Data(contentsOf: url)
        guard data.count <= 2 * 1024 * 1024 else {
            throw VPNImportError.invalidPayload("The file is too large.")
        }
        return data
    }

    private func finishFlow() {
        path.removeAll()
        importRoute = nil
        qrImageProcessingTask?.cancel()
        qrImageProcessingTask = nil
        qrImageOperationID = nil
        dismiss()
        onProfileSaved()
    }

    private func normalizedQRImageError(_ error: Error) -> String {
        if let qrError = error as? QRCodeImageImportError {
            return qrError.localizedDescription
        }

        return error.localizedDescription
    }
}

#Preview {
    AddVPNSheet(viewModel: VPNDashboardViewModel())
}
