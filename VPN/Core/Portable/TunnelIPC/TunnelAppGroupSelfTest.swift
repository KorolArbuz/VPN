//
//  TunnelAppGroupSelfTest.swift
//  VPN
//

import Foundation
import OSLog

nonisolated struct TunnelAppGroupSelfTestResult: Equatable, Sendable {
    var correlationID: UUID
    var appWriteSucceeded: Bool
    var providerReadSucceeded: Bool
    var providerWriteSucceeded: Bool
    var appReadSucceeded: Bool
    var cleanupSucceeded: Bool
    var failureCategory: String?

    var success: Bool {
        appWriteSucceeded
            && providerReadSucceeded
            && providerWriteSucceeded
            && appReadSucceeded
            && cleanupSucceeded
    }
}

nonisolated final class TunnelAppGroupSelfTester: @unchecked Sendable {
    private struct SentinelFile: Codable {
        var correlationID: UUID
        var appNonce: String
        var providerNonce: String?
    }

    private let messenger: any TunnelKeychainSentinelMessaging
    private let fileManager: FileManager
    private let containerURLOverride: URL?
    private let logger = Logger(subsystem: "su.24kvn.kvn-app", category: "Tunnel.IPC")

    init(
        messenger: any TunnelKeychainSentinelMessaging = NetworkExtensionKeychainSentinelMessenger(),
        fileManager: FileManager = .default,
        containerURLOverride: URL? = nil
    ) {
        self.messenger = messenger
        self.fileManager = fileManager
        self.containerURLOverride = containerURLOverride
    }

    func run() async -> TunnelAppGroupSelfTestResult {
        let correlationID = UUID()
        var result = TunnelAppGroupSelfTestResult(
            correlationID: correlationID,
            appWriteSucceeded: false,
            providerReadSucceeded: false,
            providerWriteSucceeded: false,
            appReadSucceeded: false,
            cleanupSucceeded: false,
            failureCategory: nil
        )
        guard let fileURL = Self.fileURL(
            correlationID: correlationID,
            fileManager: fileManager,
            containerURLOverride: containerURLOverride
        ) else {
            result.failureCategory = "sharedContainerUnavailable"
            return result
        }

        do {
            try fileManager.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            let sentinel = SentinelFile(
                correlationID: correlationID,
                appNonce: UUID().uuidString,
                providerNonce: nil
            )
            try JSONEncoder().encode(sentinel).write(to: fileURL, options: [.atomic])
            try? fileManager.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: fileURL.path
            )
            result.appWriteSucceeded = true
        } catch {
            result.failureCategory = "appGroupWriteFailed"
            result.cleanupSucceeded = cleanup(fileURL)
            return result
        }

        do {
            let request = TunnelMessageRequest(
                kind: .verifyKeychainSentinel,
                payload: .keychainSentinel(TunnelKeychainSentinelRequest(
                    correlationID: correlationID,
                    diagnosticPurpose: "sharedAppGroupSentinel"
                ))
            )
            let messageResult = try await messenger.sendKeychainSentinel(request)
            guard case .keychainSentinel(let response) = messageResult.response.payload,
                  response.correlationID == correlationID,
                  let appGroup = response.appGroupSentinel,
                  appGroup.correlationID == correlationID else {
                result.failureCategory = "providerResponseMalformed"
                result.cleanupSucceeded = cleanup(fileURL)
                return result
            }
            result.providerReadSucceeded = appGroup.providerReadSucceeded
            result.providerWriteSucceeded = appGroup.providerWriteSucceeded
        } catch let error as TunnelMessageErrorCode {
            result.failureCategory = error.rawValue
            result.cleanupSucceeded = cleanup(fileURL)
            return result
        } catch let failure as TunnelKeychainSentinelDiagnosticFailure {
            result.failureCategory = failure.diagnostic.category.rawValue
            result.cleanupSucceeded = cleanup(fileURL)
            return result
        } catch {
            result.failureCategory = "providerMessageSendFailed"
            result.cleanupSucceeded = cleanup(fileURL)
            return result
        }

        if let data = try? Data(contentsOf: fileURL, options: [.mappedIfSafe]),
           data.count <= 16 * 1_024,
           let sentinel = try? JSONDecoder().decode(SentinelFile.self, from: data),
           sentinel.correlationID == correlationID,
           sentinel.providerNonce?.isEmpty == false {
            result.appReadSucceeded = true
        } else {
            result.failureCategory = "appGroupReadBackFailed"
        }
        result.cleanupSucceeded = cleanup(fileURL)
        if result.success == false, result.failureCategory == nil {
            result.failureCategory = "appGroupRoundTripFailed"
        }
        logger.notice(
            "app-group self-test attempt=\(correlationID.uuidString, privacy: .public) appWrite=\(result.appWriteSucceeded, privacy: .public) providerRead=\(result.providerReadSucceeded, privacy: .public) providerWrite=\(result.providerWriteSucceeded, privacy: .public) appRead=\(result.appReadSucceeded, privacy: .public) cleanup=\(result.cleanupSucceeded, privacy: .public)"
        )
        return result
    }

    private func cleanup(_ fileURL: URL) -> Bool {
        do {
            if fileManager.fileExists(atPath: fileURL.path) {
                try fileManager.removeItem(at: fileURL)
            }
            return true
        } catch {
            return false
        }
    }

    private static func fileURL(
        correlationID: UUID,
        fileManager: FileManager,
        containerURLOverride: URL?
    ) -> URL? {
        (containerURLOverride
            ?? fileManager.containerURL(forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier))?
            .appendingPathComponent("TunnelDiagnostics", isDirectory: true)
            .appendingPathComponent("SelfTests", isDirectory: true)
            .appendingPathComponent("app-group-\(correlationID.uuidString.lowercased()).json")
    }
}
