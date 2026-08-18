//
//  QRCodeImageImporting.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation
import UIKit
import Vision

nonisolated protocol QRCodeImageDetecting: Sendable {
    func detectPayloads(in data: Data) async throws -> [String]
}

nonisolated struct QRCodeImageImportProcessor: Sendable {
    private let detector: QRCodeImageDetecting
    private let router: ImportPayloadRouter

    init(detector: QRCodeImageDetecting, router: ImportPayloadRouter) {
        self.detector = detector
        self.router = router
    }

    func process(data: Data, title: String) async throws -> ImportPayloadRoute {
        let payloads = try await detector.detectPayloads(in: data)
        guard let payload = payloads.first else {
            throw QRCodeImageImportError.noQRCodeFound
        }
        return try await router.route(text: payload, title: title)
    }

    func payloads(in data: Data) async throws -> [String] {
        try await detector.detectPayloads(in: data)
    }

    func processOptionalData(_ data: Data?, title: String) async throws -> ImportPayloadRoute? {
        guard let data else {
            return nil
        }

        return try await process(data: data, title: title)
    }
}

actor QRImageImportCoordinator {
    private let processor: QRCodeImageImportProcessor
    private var activeTask: Task<ImportPayloadRoute, Error>?
    private var generation = 0
    private(set) var isProcessing = false
    private(set) var errorMessage: String?

    init(processor: QRCodeImageImportProcessor) {
        self.processor = processor
    }

    func start(data: Data?, title: String) async -> ImportPayloadRoute? {
        generation += 1
        let currentGeneration = generation
        activeTask?.cancel()

        guard let data else {
            isProcessing = false
            errorMessage = nil
            activeTask = nil
            return nil
        }

        isProcessing = true
        errorMessage = nil

        let task = Task<ImportPayloadRoute, Error> {
            try await processor.process(data: data, title: title)
        }
        activeTask = task

        do {
            let route = try await task.value
            guard isCurrentGeneration(currentGeneration) else {
                return nil
            }
            clearCurrentOperation(currentGeneration)
            return route
        } catch is CancellationError {
            clearCurrentOperation(currentGeneration)
            return nil
        } catch {
            if isCurrentGeneration(currentGeneration) {
                errorMessage = error.localizedDescription
                clearCurrentOperation(currentGeneration)
            }
            return nil
        }
    }

    private func isCurrentGeneration(_ value: Int) -> Bool {
        generation == value
    }

    private func clearCurrentOperation(_ value: Int) {
        guard isCurrentGeneration(value) else {
            return
        }

        isProcessing = false
        activeTask = nil
    }
}

nonisolated enum QRCodeImageImportError: LocalizedError, Equatable, Sendable {
    case invalidImage
    case noQRCodeFound
    case recognitionUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidImage:
            "The image could not be read."
        case .noQRCodeFound:
            "No QR code was found in this image"
        case .recognitionUnavailable:
            "QR recognition is temporarily unavailable. Try another image or use Paste Link."
        }
    }
}

nonisolated struct VisionQRCodeImageDetector: QRCodeImageDetecting {
    func detectPayloads(in data: Data) async throws -> [String] {
        return try await Task.detached(priority: .userInitiated) {
            guard let image = UIImage(data: data), let cgImage = image.cgImage else {
                throw QRCodeImageImportError.invalidImage
            }

            let request = VNDetectBarcodesRequest()
            request.symbologies = [.qr]
            let handler = VNImageRequestHandler(cgImage: cgImage)

            do {
                try handler.perform([request])
            } catch {
                if (error as NSError).domain == VNErrorDomain && (error as NSError).code == 9 {
                    throw QRCodeImageImportError.recognitionUnavailable
                }
                throw error
            }

            let payloads = (request.results ?? [])
                .compactMap { observation -> String? in
                    guard observation.symbology == .qr,
                          let payload = observation.payloadStringValue?.trimmingCharacters(in: .whitespacesAndNewlines),
                          payload.isEmpty == false else {
                        return nil
                    }
                    return payload
                }

            guard payloads.isEmpty == false else {
                throw QRCodeImageImportError.noQRCodeFound
            }

            return payloads
        }.value
    }
}
