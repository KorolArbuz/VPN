//
//  TunnelStartupDiagnosticsTests.swift
//  VPNTests
//

import Foundation
import Testing
@testable import VPN

@Suite(.serialized)
struct TunnelStartupDiagnosticsTests {
    @Test
    func startupEventRoundTripsWithStableOrderingAndIsolatedAttempts() async throws {
        let rootURL = temporaryDirectory(named: "round-trip")
        defer { try? FileManager.default.removeItem(at: rootURL) }
        let store = TunnelStartupDiagnosticsStore(
            rootDirectoryURL: rootURL,
            maximumAttemptCount: 4,
            maximumEventsPerSource: 8
        )
        let firstAttempt = UUID()
        let secondAttempt = UUID()
        let baseDate = Date(timeIntervalSince1970: 1_000)

        try await store.beginAttempt(
            attemptID: firstAttempt,
            profileID: UUID(),
            protocolName: "amneziaWG",
            startedAt: baseDate
        )
        try await store.record(TunnelDiagnosticEvent(
            timestamp: baseDate.addingTimeInterval(2),
            attemptID: firstAttempt,
            source: .provider,
            stage: .runtimeProfileLoaded,
            outcome: .succeeded
        ))
        try await store.record(TunnelDiagnosticEvent(
            timestamp: baseDate.addingTimeInterval(1),
            attemptID: firstAttempt,
            source: .app,
            stage: .sessionStartRequested,
            outcome: .started
        ))

        try await store.beginAttempt(
            attemptID: secondAttempt,
            profileID: UUID(),
            protocolName: "wireGuard",
            startedAt: baseDate.addingTimeInterval(10)
        )
        try await store.record(TunnelDiagnosticEvent(
            attemptID: secondAttempt,
            source: .app,
            stage: .appConnectRequested,
            outcome: .started
        ))

        let first = try #require(try await store.attempt(id: firstAttempt))
        let second = try #require(try await store.latestAttempt())
        #expect(first.events.map(\.stage) == [.sessionStartRequested, .runtimeProfileLoaded])
        #expect(first.events.allSatisfy { $0.attemptID == firstAttempt })
        #expect(second.metadata.attemptID == secondAttempt)
        #expect(second.events.allSatisfy { $0.attemptID == secondAttempt })
    }

    @Test
    func storageBoundsAttemptsAndEvents() async throws {
        let rootURL = temporaryDirectory(named: "bounds")
        defer { try? FileManager.default.removeItem(at: rootURL) }
        let store = TunnelStartupDiagnosticsStore(
            rootDirectoryURL: rootURL,
            maximumAttemptCount: 2,
            maximumEventsPerSource: 2
        )
        let attempts = [UUID(), UUID(), UUID()]
        for (index, attemptID) in attempts.enumerated() {
            try await store.beginAttempt(
                attemptID: attemptID,
                profileID: nil,
                protocolName: "amneziaWG",
                startedAt: Date(timeIntervalSince1970: TimeInterval(index + 1))
            )
        }
        #expect(try await store.attempt(id: attempts[0]) == nil)
        #expect(try await store.attempt(id: attempts[1]) != nil)
        #expect(try await store.attempt(id: attempts[2]) != nil)

        for index in 0..<4 {
            try await store.record(TunnelDiagnosticEvent(
                timestamp: Date(timeIntervalSince1970: TimeInterval(100 + index)),
                attemptID: attempts[2],
                source: .app,
                stage: .networkExtensionStatusChanged,
                outcome: .informational,
                details: ["neStatus": "status-\(index)"]
            ))
        }
        let latest = try #require(try await store.latestAttempt())
        #expect(latest.events.count == 2)
        #expect(latest.events.map { $0.details["neStatus"] } == ["status-2", "status-3"])
    }

    @Test
    func diagnosticErrorCapturesNSErrorChainWithMaximumDepth() {
        var error = NSError(domain: "leaf.domain", code: 99, userInfo: [
            NSLocalizedDescriptionKey: "leaf"
        ])
        for depth in 0..<12 {
            error = NSError(domain: "level.\(depth)", code: depth, userInfo: [
                NSLocalizedDescriptionKey: "level \(depth)",
                NSUnderlyingErrorKey: error
            ])
        }

        let diagnostic = TunnelDiagnosticError(error: error, maximumUnderlyingDepth: 8)
        #expect(diagnostic.domain == "level.11")
        #expect(diagnostic.code == 11)
        #expect(chainDepth(diagnostic) == 9)
    }

    @Test
    func diagnosticReportNeverExportsFixtureSecrets() {
        let privateKey = Data(repeating: 0xA1, count: 32).base64EncodedString()
        let presharedKey = Data(repeating: 0xB2, count: 32).base64EncodedString()
        let rawCredential = "fixture-credential-value-0123456789abcdef"
        let attemptID = UUID()
        let error = NSError(domain: "fixture", code: -3, userInfo: [
            NSLocalizedDescriptionKey: "backend failed \(privateKey) \(presharedKey) \(rawCredential)"
        ])
        let metadata = TunnelDiagnosticAttemptMetadata(
            schemaVersion: 1,
            attemptID: attemptID,
            startedAt: Date(timeIntervalSince1970: 100),
            profileID: UUID(),
            protocolName: "amneziaWG",
            appBuild: TunnelBuildIdentity(version: "1.0", build: "148", bundleIdentifier: "app")
        )
        let snapshot = TunnelDiagnosticAttemptSnapshot(
            metadata: metadata,
            appBuild: metadata.appBuild,
            extensionBuild: TunnelBuildIdentity(version: "1.0", build: "148", bundleIdentifier: "extension"),
            events: [TunnelDiagnosticEvent(
                attemptID: attemptID,
                source: .provider,
                stage: .tunnelStartFailed,
                outcome: .failed,
                details: [
                    "nativeCode": "-3",
                    "credentialValue": rawCredential,
                    "privateKey": privateKey
                ],
                failureCategory: .nativeBackendStartupFailed,
                error: TunnelDiagnosticError(error: error)
            )]
        )

        let report = TunnelDiagnosticReportExporter.report(for: snapshot)
        #expect(report.contains(privateKey) == false)
        #expect(report.contains(presharedKey) == false)
        #expect(report.contains(rawCredential) == false)
        #expect(report.contains("nativeCode=-3"))
        #expect(report.contains(attemptID.uuidString))
    }

    @Test
    func completionGateCallsSuccessExactlyOnce() {
        let counter = LockedCompletionCounter()
        let gate = TunnelStartCompletionGate { error in
            counter.record(error)
        }

        #expect(gate.complete(nil))
        #expect(counter.count == 1)
        #expect(counter.firstError == nil)
    }

    @Test
    func completionGateCallsFailureExactlyOnce() {
        let counter = LockedCompletionCounter()
        let gate = TunnelStartCompletionGate { error in
            counter.record(error)
        }
        let error = NSError(domain: "test.provider", code: 41)

        #expect(gate.complete(error))
        #expect(counter.count == 1)
        #expect(counter.firstError?.domain == "test.provider")
        #expect(counter.firstError?.code == 41)
    }

    @Test
    func completionGateIgnoresAndReportsSecondCompletion() {
        let counter = LockedCompletionCounter()
        let duplicates = LockedCompletionCounter()
        let gate = TunnelStartCompletionGate(
            completion: { error in
                counter.record(error)
            },
            duplicateHandler: {
                duplicates.record(nil)
            }
        )

        #expect(gate.complete(nil))
        #expect(gate.complete(NSError(domain: "late", code: 1)) == false)
        #expect(counter.count == 1)
        #expect(duplicates.count == 1)
    }

    @Test
    func concurrentCompetingCompletionsProduceExactlyOneResult() async {
        let counter = LockedCompletionCounter()
        let gate = TunnelStartCompletionGate { error in
            counter.record(error)
        }

        await withTaskGroup(of: Void.self) { group in
            for index in 0..<32 {
                group.addTask {
                    if index.isMultiple(of: 2) {
                        gate.complete(nil)
                    } else {
                        gate.complete(NSError(domain: "competing", code: index))
                    }
                }
            }
        }

        #expect(counter.count == 1)
        #expect(gate.hasCompleted)
        #expect(gate.complete(nil) == false)
        #expect(counter.count == 1)
    }

    @Test
    func fractionalTimestampsRoundTripAndExportMilliseconds() async throws {
        let rootURL = temporaryDirectory(named: "fractional-time")
        defer { try? FileManager.default.removeItem(at: rootURL) }
        let store = TunnelStartupDiagnosticsStore(rootDirectoryURL: rootURL)
        let attemptID = UUID()
        let timestamp = Date(timeIntervalSince1970: 1_000.143)
        try await store.beginAttempt(
            attemptID: attemptID,
            profileID: nil,
            protocolName: "amneziaWG",
            startedAt: timestamp
        )
        try await store.record(TunnelDiagnosticEvent(
            timestamp: timestamp,
            monotonicNanoseconds: 10,
            sourceSequence: 1,
            attemptID: attemptID,
            source: .provider,
            stage: .providerStartTunnelEntered,
            outcome: .started
        ))

        let snapshot = try #require(try await store.attempt(id: attemptID))
        let event = try #require(snapshot.events.first)
        #expect(abs(event.timestamp.timeIntervalSince1970 - timestamp.timeIntervalSince1970) < 0.000_5)
        #expect(TunnelDiagnosticReportExporter.report(for: snapshot).contains(".143Z"))
    }

    @Test
    func equalWallClockTimestampsUseMonotonicAndSequenceTieBreakers() async throws {
        let rootURL = temporaryDirectory(named: "equal-time")
        defer { try? FileManager.default.removeItem(at: rootURL) }
        let store = TunnelStartupDiagnosticsStore(rootDirectoryURL: rootURL)
        let attemptID = UUID()
        let timestamp = Date(timeIntervalSince1970: 2_000.500)
        try await store.beginAttempt(
            attemptID: attemptID,
            profileID: nil,
            protocolName: "amneziaWG",
            startedAt: timestamp
        )
        let events: [TunnelDiagnosticEvent] = [
            TunnelDiagnosticEvent(
                timestamp: timestamp,
                monotonicNanoseconds: 30,
                sourceSequence: 3,
                attemptID: attemptID,
                source: .provider,
                stage: .startupTaskEntered,
                outcome: .started
            ),
            TunnelDiagnosticEvent(
                timestamp: timestamp,
                monotonicNanoseconds: 10,
                sourceSequence: 1,
                attemptID: attemptID,
                source: .provider,
                stage: .nativeBackendSelectionStarted,
                outcome: .started
            ),
            TunnelDiagnosticEvent(
                timestamp: timestamp,
                monotonicNanoseconds: 20,
                sourceSequence: 2,
                attemptID: attemptID,
                source: .provider,
                stage: .startupTaskCreated,
                outcome: .succeeded
            )
        ]
        for event in events {
            try await store.record(event)
        }

        let snapshot = try #require(try await store.attempt(id: attemptID))
        #expect(snapshot.events.map(\.stage) == [
            .nativeBackendSelectionStarted,
            .startupTaskCreated,
            .startupTaskEntered
        ])
        #expect(snapshot.events.map(\.sourceSequence) == [1, 2, 3])
    }

    @Test
    func terminalOutcomeIsPersistedOnlyOnceUnderRacingProducers() async throws {
        let rootURL = temporaryDirectory(named: "terminal-dedupe")
        defer { try? FileManager.default.removeItem(at: rootURL) }
        let store = TunnelStartupDiagnosticsStore(rootDirectoryURL: rootURL)
        let attemptID = UUID()
        try await store.beginAttempt(
            attemptID: attemptID,
            profileID: nil,
            protocolName: "amneziaWG"
        )

        await withTaskGroup(of: Void.self) { group in
            for index in 0..<24 {
                group.addTask {
                    let stage: TunnelStartupStage = index.isMultiple(of: 3)
                        ? .tunnelStartCompleted
                        : .tunnelStartFailed
                    try? await store.record(TunnelDiagnosticEvent(
                        attemptID: attemptID,
                        source: .app,
                        stage: stage,
                        outcome: stage == .tunnelStartCompleted ? .succeeded : .failed
                    ))
                }
            }
        }

        let snapshot = try #require(try await store.attempt(id: attemptID))
        let terminals = snapshot.events.filter {
            $0.stage == .tunnelStartCompleted
                || $0.stage == .tunnelStartFailed
                || $0.stage == .tunnelStartCancelled
        }
        #expect(terminals.count == 1)
    }

    @Test
    func providerStartTunnelEvidencePreventsActivationFailureClassification() {
        let attemptID = UUID()
        let events = [
            diagnosticEvent(.providerProcessEntered, attemptID: attemptID),
            diagnosticEvent(.providerStartTunnelEntered, attemptID: attemptID),
            diagnosticEvent(.nativeBackendSelected, attemptID: attemptID)
        ]

        let category = NativeTunnelStartupFailureClassifier.category(
            for: NativeTunnelConnectionError.connectionFailed,
            events: events
        )

        #expect(category == .providerStartupAbortedBeforeRuntimeLoad)
        #expect(category != .providerActivationFailure)
    }

    @Test
    func controllerBlindSpotClassifiesFromLastProviderEvidence() {
        let attemptID = UUID()
        let events = [
            diagnosticEvent(.providerProcessEntered, attemptID: attemptID),
            diagnosticEvent(.providerStartTunnelEntered, attemptID: attemptID),
            diagnosticEvent(.startupTaskEntered, attemptID: attemptID),
            diagnosticEvent(.nativeBackendControllerResolutionStarted, attemptID: attemptID)
        ]

        #expect(NativeTunnelStartupFailureClassifier.category(
            for: NativeTunnelConnectionError.connectionFailed,
            events: events
        ) == .providerStartupAbortedBeforeRuntimeLoad)
    }

    @Test
    func runtimeLoaderEvidenceTakesPriorityOverOuterControllerBoundary() {
        let attemptID = UUID()
        let events = [
            diagnosticEvent(.providerProcessEntered, attemptID: attemptID),
            diagnosticEvent(.providerStartTunnelEntered, attemptID: attemptID),
            diagnosticEvent(.nativeBackendControllerResolutionStarted, attemptID: attemptID),
            diagnosticEvent(.nativeBackendControllerMakeCallStarted, attemptID: attemptID),
            diagnosticEvent(.nativeBackendControllerMakeEntered, attemptID: attemptID),
            diagnosticEvent(.runtimeLoaderResolutionStarted, attemptID: attemptID)
        ]

        #expect(NativeTunnelStartupFailureClassifier.category(
            for: NativeTunnelConnectionError.connectionFailed,
            events: events
        ) == .runtimeLoaderUnavailable)
    }

    @Test
    func appObservationTimeoutRemainsDistinctAfterProviderStartTunnelEntered() {
        let attemptID = UUID()
        let events = [
            diagnosticEvent(.providerProcessEntered, attemptID: attemptID),
            diagnosticEvent(.providerStartTunnelEntered, attemptID: attemptID),
            diagnosticEvent(.runtimeProfileLoadStarted, attemptID: attemptID)
        ]

        #expect(NativeTunnelStartupFailureClassifier.category(
            for: NativeTunnelConnectionError.connectionTimedOut,
            events: events
        ) == .appConnectionObservationTimeout)
    }

    @Test
    func nativeConnectionErrorCodeEightIsAppConnectionFailedWrapper() {
        let error = NativeTunnelConnectionError.connectionFailed
        let nsError = error as NSError

        #expect(nsError.domain == "VPN.NativeTunnelConnectionError")
        #expect(nsError.code == 8)
        #expect(error.diagnosticCaseName == "connectionFailed")
        #expect(nsError.localizedDescription == "The native packet tunnel failed to connect.")
    }

    @Test
    func watchdogAndNormalCompletionRaceCanClaimGateOnlyOnce() async {
        let counter = LockedCompletionCounter()
        let gate = TunnelStartCompletionGate { error in
            counter.record(error)
        }

        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                if let claim = gate.claimCompletion() {
                    claim.finish(nil)
                }
            }
            group.addTask {
                if let claim = gate.claimCompletion() {
                    claim.finish(NSError(domain: "watchdog", code: 1))
                }
            }
        }

        #expect(counter.count == 1)
        #expect(gate.hasCompleted)
    }

    @Test
    func startupLocalizationKeysExistInEnglishAndRussian() throws {
        try Stage0TestResources.requireLocalizations(for: [
            "diagnostics.startup.ok",
            "diagnostics.startup.failed",
            "diagnostics.startup.not_reached",
            "diagnostics.startup.unknown",
            "diagnostics.startup.started"
        ])
    }

    @Test
    func appGroupSelfTestProvesFourWayRoundTripAndCleansUp() async {
        let containerURL = temporaryDirectory(named: "app-group")
        defer { try? FileManager.default.removeItem(at: containerURL) }
        let messenger = RecordingAppGroupSentinelMessenger(containerURL: containerURL)
        let tester = TunnelAppGroupSelfTester(
            messenger: messenger,
            containerURLOverride: containerURL
        )

        let result = await tester.run()

        #expect(result.success)
        #expect(result.appWriteSucceeded)
        #expect(result.providerReadSucceeded)
        #expect(result.providerWriteSucceeded)
        #expect(result.appReadSucceeded)
        #expect(result.cleanupSucceeded)
        #expect(await messenger.requestCount == 1)
        let sentinelURL = containerURL
            .appendingPathComponent("TunnelDiagnostics", isDirectory: true)
            .appendingPathComponent("SelfTests", isDirectory: true)
            .appendingPathComponent("app-group-\(result.correlationID.uuidString.lowercased()).json")
        #expect(FileManager.default.fileExists(atPath: sentinelURL.path) == false)
    }

    @Test
    func settingsRuntimeStatusDoesNotCallNativeProductionRouteDemo() {
        let production = SettingsConnectionRuntimeStatus(usesProductionCore: true)
        let fallback = SettingsConnectionRuntimeStatus(usesProductionCore: false)

        #expect(production.modeValueKey == "diagnostics.startup.mode.production")
        #expect(production.networkExtensionValueKey == "diagnostics.startup.network_extension.configured")
        #expect(fallback.modeValueKey == "diagnostics.startup.mode.demo")
    }

    @Test
    func nativeConstructionJournalPreservesInitializerCheckpointsAndMergesDuplicates() async throws {
        let rootURL = temporaryDirectory(named: "native-construction-journal")
        defer { try? FileManager.default.removeItem(at: rootURL) }
        let store = TunnelStartupDiagnosticsStore(rootDirectoryURL: rootURL)
        let attemptID = UUID()
        let build = TunnelBuildIdentity(
            version: "1.0",
            build: "2",
            bundleIdentifier: "su.24kvn.kvn-app.PacketTunnelExtension",
            sourceRevision: "7cce16b-dirty"
        )
        try await store.beginAttempt(
            attemptID: attemptID,
            profileID: UUID(),
            protocolName: "amneziaWG"
        )

        let stages: [TunnelStartupStage] = [
            .nativeBackendControllerMakeArgumentsStarted,
            .nativeBackendControllerMakeArgumentsPrepared,
            .nativeBackendControllerMakeCallStarted,
            .nativeBackendControllerMakeEntered,
            .runtimeLoaderResolutionStarted,
            .runtimeLoaderResolved,
            .nativeFrameworkReferenceStarted,
            .nativeAdapterConstructionStarted,
            .wireGuardAdapterInitEntered,
            .wireGuardAdapterProviderReferenceStored,
            .wireGuardAdapterSwiftLogHandlerStored,
            .wireGuardAdapterLoggerInstallationDeferred,
            .wireGuardAdapterInitCompleted,
            .wireGuardAdapterWGTurnOnCallStarted,
            .wireGuardAdapterWGTurnOnCallReturned,
            .wireGuardAdapterSetupLogHandlerEntered,
            .wireGuardAdapterLoggerContextPreparationStarted,
            .wireGuardAdapterLoggerContextPrepared,
            .wireGuardAdapterLoggerCallbackPreparationStarted,
            .wireGuardAdapterLoggerCallbackPrepared,
            .wireGuardAdapterWGSetLoggerCallStarted,
            .wireGuardAdapterWGSetLoggerCallReturned,
            .wireGuardAdapterSetupLogHandlerReturned,
            .nativeBackendControllerMakeCallReturned
        ]
        var events: [TunnelDiagnosticEvent] = []
        for (index, stage) in stages.enumerated() {
            let event = TunnelDiagnosticEvent(
                timestamp: Date(timeIntervalSince1970: 2_000 + Double(index) / 1_000),
                monotonicNanoseconds: UInt64(index + 1),
                sourceSequence: UInt64(index + 1),
                attemptID: attemptID,
                source: .provider,
                stage: stage,
                outcome: stage == .wireGuardAdapterWGSetLoggerCallStarted
                    || stage == .wireGuardAdapterWGTurnOnCallStarted
                    ? .started
                    : .succeeded,
                details: stage == .wireGuardAdapterWGTurnOnCallStarted
                    ? [
                        "physicalFootprintBytes": "16777216",
                        "residentSizeBytes": "12582912",
                        "availableMemoryBytes": "67108864",
                        "PrivateKey": "must-never-survive"
                    ]
                    : [:]
            )
            events.append(event)
            try TunnelNativeConstructionCheckpointJournal.append(
                event,
                build: build,
                rootDirectoryURL: rootURL
            )
        }
        try await store.record(events[0], build: build)

        let snapshot = try #require(try await store.attempt(id: attemptID))
        #expect(snapshot.events.map(\.stage) == stages)
        #expect(snapshot.events.filter { $0.id == events[0].id }.count == 1)
        #expect(snapshot.extensionBuild == build)
        let report = TunnelDiagnosticReportExporter.report(for: snapshot)
        #expect(report.contains("sourceRevision: 7cce16b-dirty"))
        #expect(report.contains("physicalFootprintBytes=16777216"))
        #expect(report.contains("residentSizeBytes=12582912"))
        #expect(report.contains("availableMemoryBytes=67108864"))
        #expect(report.contains("must-never-survive") == false)
        #expect(report.localizedCaseInsensitiveContains("PrivateKey") == false)
    }

    @Test
    func controllerMakeBoundaryCheckpointsDefineThePreInitializerInterval() {
        let expected: [TunnelStartupStage] = [
            .nativeBackendControllerResolutionStarted,
            .nativeBackendControllerMakeArgumentsStarted,
            .nativeBackendControllerMakeArgumentsPrepared,
            .nativeBackendControllerMakeCallStarted,
            .nativeBackendControllerMakeEntered,
            .runtimeLoaderResolutionStarted,
            .runtimeLoaderResolved,
            .nativeFrameworkReferenceStarted,
            .nativeAdapterConstructionStarted,
            .wireGuardAdapterInitEntered,
            .nativeAdapterConstructed,
            .nativeBackendControllerMakeCallReturned,
            .nativeBackendControllerResolved
        ]

        #expect(Set(expected).count == expected.count)
        #expect(expected.firstIndex(of: .nativeBackendControllerMakeCallStarted)! < expected.firstIndex(of: .nativeBackendControllerMakeEntered)!)
        #expect(expected.firstIndex(of: .nativeBackendControllerMakeEntered)! < expected.firstIndex(of: .runtimeLoaderResolutionStarted)!)
        #expect(expected.firstIndex(of: .nativeAdapterConstructionStarted)! < expected.firstIndex(of: .wireGuardAdapterInitEntered)!)
        #expect(expected.firstIndex(of: .wireGuardAdapterInitEntered)! < expected.firstIndex(of: .nativeBackendControllerMakeCallReturned)!)
    }

    @Test
    func setupLogHandlerIsDeferredUntilAfterFirstGoBackendCall() {
        let expected: [TunnelStartupStage] = [
            .wireGuardAdapterLoggerInstallationDeferred,
            .wireGuardAdapterInitCompleted,
            .wireGuardAdapterWGTurnOnCallStarted,
            .wireGuardAdapterWGTurnOnCallReturned,
            .wireGuardAdapterSetupLogHandlerEntered,
            .wireGuardAdapterLoggerContextPreparationStarted,
            .wireGuardAdapterLoggerContextPrepared,
            .wireGuardAdapterLoggerCallbackPreparationStarted,
            .wireGuardAdapterLoggerCallbackPrepared,
            .wireGuardAdapterWGSetLoggerCallStarted,
            .wireGuardAdapterWGSetLoggerCallReturned,
            .wireGuardAdapterLoggerInstallationBypassed,
            .wireGuardAdapterSetupLogHandlerReturned,
            .adapterStarted
        ]
        let turnOnReturnedIndex = expected.firstIndex(of: .wireGuardAdapterWGTurnOnCallReturned) ?? -1
        let setupEnteredIndex = expected.firstIndex(of: .wireGuardAdapterSetupLogHandlerEntered) ?? -1
        let setLoggerStartedIndex = expected.firstIndex(of: .wireGuardAdapterWGSetLoggerCallStarted) ?? -1
        let setLoggerReturnedIndex = expected.firstIndex(of: .wireGuardAdapterWGSetLoggerCallReturned) ?? -1
        #expect(Set(expected).count == expected.count)
        #expect(turnOnReturnedIndex >= 0 && turnOnReturnedIndex < setupEnteredIndex)
        #expect(setLoggerStartedIndex >= 0 && setLoggerStartedIndex < setLoggerReturnedIndex)
    }

    private func temporaryDirectory(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("TunnelStartupDiagnosticsTests-\(name)-\(UUID().uuidString)", isDirectory: true)
    }

    private func chainDepth(_ error: TunnelDiagnosticError) -> Int {
        guard let underlying = error.underlying.first else { return 1 }
        return 1 + chainDepth(underlying)
    }

    private func diagnosticEvent(
        _ stage: TunnelStartupStage,
        attemptID: UUID
    ) -> TunnelDiagnosticEvent {
        TunnelDiagnosticEvent(
            attemptID: attemptID,
            source: .provider,
            stage: stage,
            outcome: .succeeded
        )
    }
}

private actor RecordingAppGroupSentinelMessenger: TunnelKeychainSentinelMessaging {
    private struct SentinelFile: Codable {
        var correlationID: UUID
        var appNonce: String
        var providerNonce: String?
    }

    private let containerURL: URL
    private(set) var requestCount = 0

    init(containerURL: URL) {
        self.containerURL = containerURL
    }

    func sendKeychainSentinel(
        _ request: TunnelMessageRequest
    ) async throws -> TunnelKeychainSentinelMessageResult {
        requestCount += 1
        guard case .keychainSentinel(let payload)? = request.payload else {
            throw TunnelMessageErrorCode.malformedRequest
        }
        let fileURL = containerURL
            .appendingPathComponent("TunnelDiagnostics", isDirectory: true)
            .appendingPathComponent("SelfTests", isDirectory: true)
            .appendingPathComponent("app-group-\(payload.correlationID.uuidString.lowercased()).json")
        var sentinel = try JSONDecoder().decode(
            SentinelFile.self,
            from: Data(contentsOf: fileURL)
        )
        sentinel.providerNonce = UUID().uuidString
        try JSONEncoder().encode(sentinel).write(to: fileURL, options: [.atomic])
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .keychainSentinel(TunnelKeychainSentinelResponse(
                found: false,
                correlationID: payload.correlationID,
                appGroupSentinel: TunnelAppGroupSentinelResponse(
                    correlationID: payload.correlationID,
                    providerReadSucceeded: true,
                    providerWriteSucceeded: true
                )
            ))
        )
        return TunnelKeychainSentinelMessageResult(
            response: response,
            diagnostic: TunnelKeychainSentinelDiagnostic(
                stage: .providerMessageSend,
                status: .succeeded,
                category: .none
            )
        )
    }
}

private final class LockedCompletionCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var errors: [NSError?] = []

    var count: Int {
        lock.withLock { errors.count }
    }

    var firstError: NSError? {
        lock.withLock { errors.first ?? nil }
    }

    func record(_ error: Error?) {
        lock.withLock {
            errors.append(error as NSError?)
        }
    }
}
