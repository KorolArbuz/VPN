//
//  PacketTunnelProvider.swift
//  PacketTunnelExtension
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Dispatch
import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let telemetryStore = TunnelTelemetryStore()
    private let telemetrySnapshotStore = TunnelTelemetrySnapshotStore.appGroupStore()
    private let nativeWireGuardControllerReference = NativeWireGuardControllerReference()
    private lazy var appMessageHandler = TunnelAppMessageHandler(
        telemetryStore: telemetryStore,
        snapshotStore: telemetrySnapshotStore,
        keychainSentinelReader: KeychainTunnelKeychainSentinelReader(),
        appGroupSentinelReader: FileTunnelAppGroupSentinelReader(),
        providerProcess: .wireGuard
    )

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard PacketTunnelProviderIdentity.validatesLaunch(provider: self, options: options) else {
            completionHandler(PacketTunnelProviderIdentity.wrongProviderError)
            return
        }

        let containsNativeMarker = NativePacketTunnelStartOptions.containsNativeMarker(in: options)
        let optionAttemptID = NativePacketTunnelStartOptions.attemptID(in: options)
        let diagnosticAttemptID = optionAttemptID ?? RecentNativeActivationAttempt.latestAttemptID()
        if containsNativeMarker, let diagnosticAttemptID {
            NativeWireGuardTrace.event(
                .activationContextDecodeStarted,
                outcome: .started,
                attemptID: diagnosticAttemptID
            )
        }
        let nativeOptions = NativePacketTunnelStartOptions(options)
        let completionGate = TunnelStartCompletionGate(
            completion: completionHandler,
            duplicateHandler: {
                guard let diagnosticAttemptID else { return }
                NativeWireGuardTrace.event(
                    .completionDuplicateIgnored,
                    outcome: .informational,
                    attemptID: diagnosticAttemptID
                )
            }
        )
        if nativeOptions.containsNativeConfiguration {
            guard let mode = nativeOptions.mode, let attemptID = nativeOptions.attemptID else {
                if let diagnosticAttemptID {
                    Task {
                        guard let claim = completionGate.claimCompletion() else { return }
                        await NativeWireGuardTrace.event(
                            .activationContextDecoded,
                            outcome: .failed,
                            attemptID: diagnosticAttemptID,
                            error: NativeWireGuardExtensionError.providerConfigurationInvalid.nsError,
                            failureCategory: .activationContextInvalid
                        ).value
                        claim.finish(NativeWireGuardExtensionError.providerConfigurationInvalid.nsError)
                    }
                } else {
                    completionGate.complete(NativeWireGuardExtensionError.providerConfigurationInvalid.nsError)
                }
                return
            }
            NativeWireGuardTrace.event(
                .activationContextDecoded,
                attemptID: attemptID,
                mode: mode
            )
            NativeWireGuardTrace.event(
                .providerProcessEntered,
                attemptID: attemptID,
                mode: mode
            )
            NativeWireGuardTrace.event(
                .providerStartTunnelEntered,
                outcome: .started,
                attemptID: attemptID,
                mode: mode
            )
            NativeWireGuardTrace.event(
                .nativeBackendSelectionStarted,
                outcome: .started,
                attemptID: attemptID,
                mode: mode
            )
            NativeWireGuardTrace.event(
                .nativeBackendSelected,
                attemptID: attemptID,
                mode: mode
            )
            let startupTaskReference = NativeStartupTaskReference()
            let startupStartedAt = DispatchTime.now().uptimeNanoseconds
            NativeWireGuardTrace.event(
                .startupWatchdogStarted,
                outcome: .started,
                attemptID: attemptID,
                mode: mode,
                additionalDetails: ["watchdogIntervalSeconds": "25"]
            )
            let watchdog = Task { [completionGate, startupTaskReference] in
                do {
                    try await Task.sleep(for: .seconds(25))
                } catch {
                    return
                }
                guard let claim = completionGate.claimCompletion() else { return }
                startupTaskReference.cancel()
                let timeoutError = NativeWireGuardExtensionError.providerStartupStalled
                let now = DispatchTime.now().uptimeNanoseconds
                let elapsedMilliseconds = Double(now &- startupStartedAt) / 1_000_000
                await NativeWireGuardTrace.event(
                    .providerStartupWatchdogFired,
                    outcome: .failed,
                    attemptID: attemptID,
                    mode: mode,
                    error: timeoutError.nsError,
                    failureCategory: .providerStartupStalled,
                    additionalDetails: [
                        "lastProviderStage": NativeWireGuardTrace.lastRecordedStage(for: attemptID)?.rawValue ?? "unknown",
                        "elapsedMilliseconds": String(format: "%.0f", elapsedMilliseconds),
                        "startupTaskCancelled": "true",
                        "watchdogIntervalSeconds": "25"
                    ]
                ).value
                claim.finish(timeoutError.nsError)
            }
            completionGate.setWatchdog(watchdog)
            NativeWireGuardTrace.event(
                .startupTaskCreationStarted,
                outcome: .started,
                attemptID: attemptID,
                mode: mode
            )
            let startupEntryGate = NativeStartupEntryGate()
            let startupTask = Task { [weak self, completionGate, startupEntryGate] in
                await startupEntryGate.waitUntilOpened()
                await NativeWireGuardTrace.event(
                    .startupTaskEntered,
                    outcome: .started,
                    attemptID: attemptID,
                    mode: mode
                ).value
                guard let self else {
                    let error = NativeWireGuardExtensionError.nativeBackendControllerUnavailable
                    guard let claim = completionGate.claimCompletion() else { return }
                    await NativeWireGuardTrace.event(
                        .providerStartupFailed,
                        outcome: .failed,
                        attemptID: attemptID,
                        mode: mode,
                        error: error.nsError,
                        failureCategory: .nativeBackendControllerUnavailable
                    ).value
                    claim.finish(error.nsError)
                    return
                }
                await NativeWireGuardTrace.event(
                    .nativeBackendControllerResolutionStarted,
                    outcome: .started,
                    attemptID: attemptID,
                    mode: mode
                ).value
                NativeWireGuardTrace.controllerConstructionCheckpoint(
                    .nativeBackendControllerMakeArgumentsStarted,
                    outcome: .started,
                    attemptID: attemptID,
                    mode: mode
                )
                let controllerProvider = self
                let controllerTelemetryStore = self.telemetryStore
                let controllerAttemptID = attemptID
                let controllerMode = mode
                NativeWireGuardTrace.controllerConstructionCheckpoint(
                    .nativeBackendControllerMakeArgumentsPrepared,
                    attemptID: attemptID,
                    mode: mode
                )
                NativeWireGuardTrace.controllerConstructionCheckpoint(
                    .nativeBackendControllerMakeCallStarted,
                    outcome: .started,
                    attemptID: attemptID,
                    mode: mode
                )
                let controller = await NativeWireGuardTunnelController.make(
                    provider: controllerProvider,
                    telemetryStore: controllerTelemetryStore,
                    attemptID: controllerAttemptID,
                    mode: controllerMode
                )
                NativeWireGuardTrace.controllerConstructionCheckpoint(
                    .nativeBackendControllerMakeCallReturned,
                    attemptID: attemptID,
                    mode: mode
                )
                self.nativeWireGuardControllerReference.install(controller)
                await NativeWireGuardTrace.event(
                    .nativeBackendControllerResolved,
                    attemptID: attemptID,
                    mode: mode
                ).value
                do {
                    try await controller.start(expectedMode: mode, attemptID: attemptID)
                    await persistTelemetrySnapshot()
                    guard let claim = completionGate.claimCompletion() else { return }
                    await NativeWireGuardTrace.event(
                        .providerStartupCompleted,
                        attemptID: attemptID,
                        mode: mode
                    ).value
                    claim.finish(nil)
                } catch let error as NativeWireGuardStartupFailure {
                    guard let claim = completionGate.claimCompletion() else { return }
                    await NativeWireGuardTrace.event(
                        .providerStartupFailed,
                        outcome: .failed,
                        attemptID: attemptID,
                        mode: mode,
                        error: error.nsError,
                        failureCategory: NativeWireGuardTrace.category(for: error.category),
                        nativeStatus: error.nativeStatus,
                        systemErrorDomain: error.underlyingError?.domain,
                        systemErrorCode: error.underlyingError?.code
                    ).value
                    claim.finish(error.nsError)
                } catch let error as NativeWireGuardExtensionError {
                    guard let claim = completionGate.claimCompletion() else { return }
                    await NativeWireGuardTrace.event(
                        .providerStartupFailed,
                        outcome: .failed,
                        attemptID: attemptID,
                        mode: mode,
                        error: error.nsError,
                        failureCategory: NativeWireGuardTrace.category(for: error)
                    ).value
                    claim.finish(error.nsError)
                } catch {
                    let failure = NativeWireGuardStartupFailure(
                        category: .nativeBackendControllerUnavailable,
                        nativeStatus: nil,
                        underlyingError: error as NSError
                    )
                    guard let claim = completionGate.claimCompletion() else { return }
                    await NativeWireGuardTrace.event(
                        .providerStartupFailed,
                        outcome: .failed,
                        attemptID: attemptID,
                        mode: mode,
                        error: failure.nsError,
                        failureCategory: .unknownProviderStartupFailure
                    ).value
                    claim.finish(failure.nsError)
                }
            }
            startupTaskReference.install(startupTask)
            NativeWireGuardTrace.event(
                .startupTaskCreated,
                attemptID: attemptID,
                mode: mode
            )
            startupEntryGate.open()
            return
        }

        let invalidConfiguration = NativeWireGuardExtensionError.providerConfigurationInvalid
        if let diagnosticAttemptID {
            Task {
                await NativeWireGuardTrace.event(
                    .providerStartTunnelEntered,
                    outcome: .failed,
                    attemptID: diagnosticAttemptID,
                    error: invalidConfiguration.nsError,
                    failureCategory: .invalidProviderConfiguration
                ).value
                completionGate.complete(invalidConfiguration.nsError)
            }
        } else {
            completionGate.complete(invalidConfiguration.nsError)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        Task { [telemetryStore] in
            if let controller = nativeWireGuardControllerReference.current() {
                _ = await controller.stopIfActive()
            }
            await telemetryStore.markStopped()
            await persistTelemetrySnapshot()
            completionHandler()
        }
    }

    private func persistTelemetrySnapshot() async {
        guard let telemetrySnapshotStore else {
            return
        }
        let runtime = await telemetryStore.runtimeSnapshot()
        let events = await telemetryStore.recentEvents()
        try? await telemetrySnapshotStore.write(runtime: runtime, events: events)
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let completionHandler else {
            return
        }

        let handler = appMessageHandler
        Task {
            let response = await handler.handle(messageData)
            completionHandler(response)
        }
    }
    
    override func sleep(completionHandler: @escaping () -> Void) {
        // Add code here to get ready to sleep.
        completionHandler()
    }
    
    override func wake() {
        // Add code here to wake up.
    }
}

private final class NativeWireGuardControllerReference: @unchecked Sendable {
    private let lock = NSLock()
    private var value: NativeWireGuardTunnelController?

    func install(_ controller: NativeWireGuardTunnelController) {
        lock.withLock {
            value = controller
        }
    }

    func current() -> NativeWireGuardTunnelController? {
        lock.withLock { value }
    }
}

private final class NativeStartupTaskReference: @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<Void, Never>?
    private var cancellationRequested = false

    func install(_ task: Task<Void, Never>) {
        let shouldCancel = lock.withLock {
            self.task = task
            return cancellationRequested
        }
        if shouldCancel {
            task.cancel()
        }
    }

    func cancel() {
        let task = lock.withLock {
            cancellationRequested = true
            return self.task
        }
        task?.cancel()
    }
}

private final class NativeStartupEntryGate: @unchecked Sendable {
    private let lock = NSLock()
    private var isOpen = false
    private var waiter: CheckedContinuation<Void, Never>?

    func waitUntilOpened() async {
        await withCheckedContinuation { continuation in
            let shouldResumeImmediately = lock.withLock {
                if isOpen {
                    return true
                }
                waiter = continuation
                return false
            }
            if shouldResumeImmediately {
                continuation.resume()
            }
        }
    }

    func open() {
        let continuation = lock.withLock {
            isOpen = true
            defer { waiter = nil }
            return waiter
        }
        continuation?.resume()
    }
}

private enum RecentNativeActivationAttempt {
    private struct Metadata: Decodable {
        var attemptID: UUID
        var startedAt: Date
    }

    static func latestAttemptID(
        now: Date = Date(),
        fileManager: FileManager = .default
    ) -> UUID? {
        guard let containerURL = fileManager.containerURL(
            forSecurityApplicationGroupIdentifier: TunnelTelemetryAppGroup.identifier
        ) else {
            return nil
        }
        let fileURL = containerURL
            .appendingPathComponent("TunnelDiagnostics", isDirectory: true)
            .appendingPathComponent("latest-attempt.json")
        guard let data = try? Data(contentsOf: fileURL, options: [.mappedIfSafe]),
              data.count <= 64 * 1_024 else {
            return nil
        }
        let decoder = JSONDecoder()
        TunnelDiagnosticDateCodec.configure(decoder)
        guard let metadata = try? decoder.decode(Metadata.self, from: data) else {
            return nil
        }
        let age = now.timeIntervalSince(metadata.startedAt)
        guard age >= -5, age <= 120 else { return nil }
        return metadata.attemptID
    }
}

private struct NativePacketTunnelStartOptions {
    static let modeKey = "kvn.native.mode"
    static let attemptIDKey = "kvn.native.attemptID"
    static let allowedKeys: Set<String> = [modeKey, attemptIDKey]

    let containsNativeConfiguration: Bool
    let mode: NativeWireGuardMode?
    let attemptID: UUID?

    static func containsNativeMarker(in options: [String: NSObject]?) -> Bool {
        options?.keys.contains(where: { $0.hasPrefix("kvn.native.") }) == true
    }

    static func attemptID(in options: [String: NSObject]?) -> UUID? {
        guard let rawAttemptID = options?[attemptIDKey] as? String else { return nil }
        return UUID(uuidString: rawAttemptID)
    }

    init(_ options: [String: NSObject]?) {
        let options = options ?? [:]
        let nativeKeys = options.keys.filter { $0.hasPrefix("kvn.native.") }
        containsNativeConfiguration = nativeKeys.isEmpty == false
        if let rawAttemptID = options[Self.attemptIDKey] as? String {
            attemptID = UUID(uuidString: rawAttemptID)
        } else {
            attemptID = nil
        }
        guard containsNativeConfiguration,
              Set(nativeKeys).subtracting(Self.allowedKeys).isEmpty,
              Set(Self.allowedKeys).subtracting(nativeKeys).isEmpty,
              let rawMode = options[Self.modeKey] as? String,
              attemptID != nil else {
            mode = nil
            return
        }
        mode = NativeWireGuardMode(rawValue: rawMode)
    }
}
