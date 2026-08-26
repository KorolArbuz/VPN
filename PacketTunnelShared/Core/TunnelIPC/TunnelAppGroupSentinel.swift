//
//  TunnelAppGroupSentinel.swift
//  PacketTunnelExtension
//

import Foundation
import OSLog

nonisolated protocol TunnelAppGroupSentinelReading: Sendable {
    func readAndRespond(correlationID: UUID) async -> TunnelAppGroupSentinelResponse?
}

nonisolated struct FileTunnelAppGroupSentinelReader: TunnelAppGroupSentinelReading, @unchecked Sendable {
    private struct SentinelFile: Codable {
        var correlationID: UUID
        var appNonce: String
        var providerNonce: String?
    }

    private let fileManager: FileManager

    init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    func readAndRespond(correlationID: UUID) async -> TunnelAppGroupSentinelResponse? {
        guard let fileURL = Self.fileURL(correlationID: correlationID, fileManager: fileManager),
              let data = try? Data(contentsOf: fileURL, options: [.mappedIfSafe]),
              data.count <= 16 * 1_024,
              var sentinel = try? JSONDecoder().decode(SentinelFile.self, from: data),
              sentinel.correlationID == correlationID,
              sentinel.appNonce.isEmpty == false,
              sentinel.appNonce.utf8.count <= 256 else {
            return nil
        }

        sentinel.providerNonce = UUID().uuidString
        let writeSucceeded: Bool
        do {
            let encoded = try JSONEncoder().encode(sentinel)
            try encoded.write(to: fileURL, options: [.atomic])
            try? fileManager.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: fileURL.path
            )
            writeSucceeded = true
        } catch {
            writeSucceeded = false
        }

        Logger(subsystem: "su.24kvn.kvn-app", category: "Tunnel.IPC").notice(
            "app-group sentinel attempt=\(correlationID.uuidString, privacy: .public) providerRead=true providerWrite=\(writeSucceeded, privacy: .public)"
        )
        return TunnelAppGroupSentinelResponse(
            correlationID: correlationID,
            providerReadSucceeded: true,
            providerWriteSucceeded: writeSucceeded
        )
    }

    private static func fileURL(correlationID: UUID, fileManager: FileManager) -> URL? {
        fileManager.containerURL(forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier)?
            .appendingPathComponent("TunnelDiagnostics", isDirectory: true)
            .appendingPathComponent("SelfTests", isDirectory: true)
            .appendingPathComponent("app-group-\(correlationID.uuidString.lowercased()).json")
    }
}
