//
//  TunnelTelemetryTests.swift
//  VPNTests
//
//  Phase F2A: app <-> PacketTunnelExtension IPC and authoritative telemetry
//  tests. No real VPN, NetworkExtension session, or internet is required.
//

import Foundation
import NetworkExtension
import Observation
import Testing
@testable import VPN

struct TunnelMessageProtocolTests {
    @Test
    func requestEncodesSchemaVersionAndRequestID() throws {
        let requestID = UUID()
        let request = TunnelMessageRequest(requestID: requestID, kind: .ping)
        let data = try JSONEncoder().encode(request)
        let decoded = try JSONDecoder().decode(TunnelMessageRequest.self, from: data)

        #expect(decoded.schemaVersion == TunnelMessageProtocol.schemaVersion)
        #expect(decoded.requestID == requestID)
        #expect(decoded.kind == .ping)
    }

    @Test
    func responseRequestIDMustMatch() async {
        let request = TunnelMessageRequest(kind: .ping)
        let wrongResponse = TunnelMessageResponse.success(
            request: TunnelMessageRequest(requestID: UUID(), kind: .ping),
            payload: .pong(TunnelPongSnapshot(extensionProcessAlive: true, schemaVersion: 1))
        )
        let session = StubTunnelProviderSession(status: .connected, response: try? encode(wrongResponse))
        let messenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .seconds(1))

        await expectTunnelMessageError(.requestIDMismatch) {
            _ = try await messenger.send(request)
        }
    }

    @Test
    func schemaMismatchIsRejected() async {
        let session = StubTunnelProviderSession(status: .connected, response: Data())
        let messenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .seconds(1))

        await expectTunnelMessageError(.schemaMismatch) {
            _ = try await messenger.send(TunnelMessageRequest(schemaVersion: 999, kind: .ping))
        }
    }

    @Test
    func malformedRequestGetsTypedError() async throws {
        let handler = TunnelAppMessageHandler()
        let responseData = await handler.handle(Data("not-json".utf8))
        let response = try decodedResponse(responseData)

        #expect(response.success == false)
        #expect(response.error?.code == .malformedRequest)
    }

    @Test
    func unknownMessageKindGetsUnsupportedRequest() async throws {
        let requestData = Data(#"{"schemaVersion":1,"requestID":"11111111-1111-1111-1111-111111111111","kind":"restartXray"}"#.utf8)
        let handler = TunnelAppMessageHandler()
        let response = try decodedResponse(await handler.handle(requestData))

        #expect(response.requestID.uuidString == "11111111-1111-1111-1111-111111111111")
        #expect(response.success == false)
        #expect(response.error?.code == .unsupportedRequest)
    }

    @Test
    func handlerRespondsExactlyOnce() async throws {
        let request = TunnelMessageRequest(kind: .ping)
        let handler = TunnelAppMessageHandler()
        let response = try decodedResponse(await handler.handle(try encode(request)))

        #expect(response.requestID == request.requestID)
        #expect(response.success)
    }
}

struct TunnelProviderMessagingTests {
    @Test
    func nilProviderResponseIsHandled() async {
        let session = StubTunnelProviderSession(status: .connected, response: nil)
        let messenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .seconds(1))

        await expectTunnelMessageError(.providerResponseMissing) {
            _ = try await messenger.send(TunnelMessageRequest(kind: .ping))
        }
    }

    @Test
    func messagingTimeoutIsHandled() async {
        let session = StubTunnelProviderSession(status: .connected, response: nil, invokesCallback: false)
        let messenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .milliseconds(20))

        await expectTunnelMessageError(.timeout) {
            _ = try await messenger.send(TunnelMessageRequest(kind: .ping))
        }
        #expect(await session.sendCount == 1)
    }

    @Test
    func disconnectedStatusPreventsMessageSend() async {
        let session = StubTunnelProviderSession(status: .disconnected, response: Data())
        let messenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .seconds(1))

        await expectTunnelMessageError(.providerStatusNotConnected) {
            _ = try await messenger.send(TunnelMessageRequest(kind: .ping))
        }

        #expect(await session.sendCount == 0)
    }

    @Test
    func connectedStatusAllowsMessageSend() async throws {
        let request = TunnelMessageRequest(kind: .ping)
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .pong(TunnelPongSnapshot(extensionProcessAlive: true, schemaVersion: TunnelMessageProtocol.schemaVersion))
        )
        let session = StubTunnelProviderSession(status: .connected, response: try encode(response))
        let messenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .seconds(1))

        _ = try await messenger.send(request)

        #expect(await session.sendCount == 1)
    }

    @Test
    func messageSendFailureIsReturnedAndSendsOnce() async {
        let session = StubTunnelProviderSession(
            status: .connected,
            response: nil,
            sendError: TunnelMessageErrorCode.providerUnavailable
        )
        let messenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .seconds(1))

        await expectTunnelMessageError(.providerUnavailable) {
            _ = try await messenger.send(TunnelMessageRequest(kind: .ping))
        }

        #expect(await session.sendCount == 1)
    }

    @Test
    func timeoutSendsOnceAndLateReleaseDoesNotResumeAgain() async {
        let session = StubTunnelProviderSession(status: .connected, response: Data(), blocksUntilReleased: true)
        let messenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .milliseconds(20))

        await expectTunnelMessageError(.timeout) {
            _ = try await messenger.send(TunnelMessageRequest(kind: .ping))
        }
        #expect(await session.sendCount == 1)

        await session.releaseAll()
        await settleMainActor()
        #expect(await session.sendCount == 1)
    }

    @Test
    func doubleProviderCallbackOnlyResumesOnce() async throws {
        let request = TunnelMessageRequest(kind: .ping)
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .pong(TunnelPongSnapshot(extensionProcessAlive: true, schemaVersion: TunnelMessageProtocol.schemaVersion))
        )
        let session = StubTunnelProviderSession(
            status: .connected,
            response: try encode(response),
            sendsDuplicateCallback: true
        )
        let messenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .seconds(1))

        let decoded = try await messenger.send(request)

        #expect(decoded.requestID == request.requestID)
        #expect(await session.sendCount == 1)
    }

    @Test
    func appMessagingDoesNotStartOrStopVPN() async throws {
        let request = TunnelMessageRequest(kind: .ping)
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .pong(TunnelPongSnapshot(extensionProcessAlive: true, schemaVersion: TunnelMessageProtocol.schemaVersion))
        )
        let session = StubTunnelProviderSession(status: .connected, response: try encode(response))
        let messenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .seconds(1))

        _ = try await messenger.send(request)

        #expect(await session.startCount == 0)
        #expect(await session.stopCount == 0)
    }

    #if DEBUG
    @Test
    func existingDiagnosticManagerIsReused() async throws {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let manager = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: providerID)
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: store, providerBundleIdentifier: providerID)

        _ = try await bootstrapper.sessionForSentinel()

        #expect(await store.makeCount == 0)
        #expect(await manager.saveCount == 1)
        #expect(await manager.loadCount == 1)
        #expect(await manager.isEnabled)
        #expect(await manager.lastConfiguration == nil)
        #expect(await manager.events.contains("prepareExistingSentinel"))
        #expect(await manager.events.contains("configureSentinel") == false)
    }

    @Test
    func absentDiagnosticManagerIsCreatedOnce() async throws {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: store, providerBundleIdentifier: providerID)

        _ = try await bootstrapper.sessionForSentinel()

        #expect(await store.makeCount == 1)
        #expect(await store.managerCount == 1)
        let manager = try #require(await store.firstManager)
        #expect(await manager.lastConfiguration?.diagnosticPurpose == TunnelSentinelProviderConfiguration.diagnosticPurpose)
    }

    @Test
    func duplicateDiagnosticManagersDoNotCreateAnotherManager() async throws {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let first = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: providerID)
        let second = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: providerID)
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [first, second])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: store, providerBundleIdentifier: providerID)

        _ = try await bootstrapper.sessionForSentinel()

        #expect(await store.makeCount == 0)
        #expect(await first.saveCount == 1)
        #expect(await second.saveCount == 0)
    }

    @Test
    func k1SentinelConfigurationIsUpgradedToCleanK2Dictionary() async throws {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let manager = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: providerID)
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: store, providerBundleIdentifier: providerID)

        _ = try await bootstrapper.sessionForSentinel()
        let runtimeConfiguration = try RuntimeProviderConfiguration(profileID: UUID(), sharedRecordRevision: "rev-k2")
        _ = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: runtimeConfiguration)

        let propertyList = await manager.providerConfigurationPropertyList()
        #expect(Set(propertyList?.keys.map { $0 } ?? []) == RuntimeProviderConfiguration.allowedKeys)
        #expect(propertyList?["diagnosticPurpose"] == nil)
        #expect(try RuntimeProviderConfiguration.parse(propertyList) == runtimeConfiguration)
        #expect(await store.makeCount == 0)
        #expect(await manager.saveCount == 2)
        #expect(await manager.loadCount == 2)
    }

    @Test
    func k2K1K2TransitionsReplaceProviderConfigurationEveryTime() async throws {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let manager = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: providerID)
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [manager]),
            providerBundleIdentifier: providerID
        )
        let first = try RuntimeProviderConfiguration(profileID: UUID(), sharedRecordRevision: "rev-first")
        let second = try RuntimeProviderConfiguration(profileID: UUID(), sharedRecordRevision: "rev-second")

        _ = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: first)
        _ = try await bootstrapper.sessionForSentinel()
        #expect(try RuntimeProviderConfiguration.parse(await manager.providerConfigurationPropertyList()) == first)
        _ = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: second)

        let propertyList = await manager.providerConfigurationPropertyList()
        #expect(Set(propertyList?.keys.map { $0 } ?? []) == RuntimeProviderConfiguration.allowedKeys)
        #expect(try RuntimeProviderConfiguration.parse(propertyList) == second)
        #expect(propertyList?["diagnosticPurpose"] == nil)
    }

    @Test
    func k1SentinelOnValidK2ManagerDoesNotOverwriteRuntimeProviderConfiguration() async throws {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let runtimeConfiguration = try RuntimeProviderConfiguration(profileID: UUID(), sharedRecordRevision: "rev-preserve")
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .verifyKeychainSentinel,
            payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: correlationID))
        )
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .keychainSentinel(TunnelKeychainSentinelResponse(found: true, correlationID: correlationID))
        )
        let session = StubTunnelProviderSession(status: .disconnected, response: try encode(response))
        let manager = RecordingDiagnosticTunnelProviderManager(
            providerBundleIdentifier: providerID,
            session: session,
            initialProviderConfiguration: runtimeConfiguration.propertyList
        )
        let messenger = NetworkExtensionKeychainSentinelMessenger(
            bootstrapper: DiagnosticTunnelProviderSessionBootstrapper(
                managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [manager]),
                providerBundleIdentifier: providerID
            ),
            timeout: .seconds(1)
        )

        _ = try await messenger.sendKeychainSentinel(request)

        #expect(try RuntimeProviderConfiguration.parse(await manager.providerConfigurationPropertyList()) == runtimeConfiguration)
        #expect(await manager.events.contains("prepareExistingSentinel"))
        #expect(await manager.events.contains("configureSentinel") == false)
        #expect(await session.startCount == 0)
        #expect(await session.stopCount == 0)

        let requestJSON = try stringJSON(request)
        #expect(requestJSON.contains(TunnelSentinelProviderConfiguration.diagnosticPurpose))
        #expect(await manager.providerConfigurationPropertyList()?["diagnosticPurpose"] == nil)
    }

    @Test
    func runtimeValidationSaveReloadCompletesBeforeSessionAcquisition() async throws {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let manager = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: providerID)
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [manager]),
            providerBundleIdentifier: providerID
        )
        let runtimeConfiguration = try RuntimeProviderConfiguration(profileID: UUID(), sharedRecordRevision: "rev-order")

        _ = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: runtimeConfiguration)

        let events = await manager.events
        #expect(events.firstIndex(of: "configureRuntimeValidation")! < events.firstIndex(of: "save")!)
        #expect(events.firstIndex(of: "save")! < events.firstIndex(of: "load")!)
        #expect(events.firstIndex(of: "load")! < events.firstIndex(of: "providerConfigurationPropertyList")!)
        #expect(events.firstIndex(of: "providerConfigurationPropertyList")! < events.firstIndex(of: "session")!)
        #expect(await manager.sessionCount == 1)
    }

    @Test
    func matchingDisconnectedStaleManagerIsRetargetedToXrayProvider() async throws {
        let runtimeConfiguration = try RuntimeProviderConfiguration(
            profileID: UUID(),
            sharedRecordRevision: "rev-stale-provider"
        )
        let manager = RecordingDiagnosticTunnelProviderManager(
            providerBundleIdentifier: PacketTunnelProviderRouting.wireGuardBundleIdentifier,
            initialProviderConfiguration: runtimeConfiguration.propertyList
        )
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            managerStore: store,
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        )

        _ = try await bootstrapper.sessionForRuntimeValidation(
            providerConfiguration: runtimeConfiguration
        )

        #expect(await store.makeCount == 0)
        #expect(
            await manager.providerBundleIdentifier()
                == PacketTunnelProviderRouting.xrayBundleIdentifier
        )
        #expect(await manager.lastRuntimeConfiguration == runtimeConfiguration)
    }

    @Test
    func activeStaleManagerIsNeverRetargeted() async throws {
        let runtimeConfiguration = try RuntimeProviderConfiguration(
            profileID: UUID(),
            sharedRecordRevision: "rev-active-provider"
        )
        let session = StubTunnelProviderSession(status: .connected, response: nil)
        let manager = RecordingDiagnosticTunnelProviderManager(
            providerBundleIdentifier: PacketTunnelProviderRouting.wireGuardBundleIdentifier,
            session: session,
            initialProviderConfiguration: runtimeConfiguration.propertyList
        )
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            managerStore: store,
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        )

        _ = try await bootstrapper.sessionForRuntimeValidation(
            providerConfiguration: runtimeConfiguration
        )

        #expect(await store.makeCount == 1)
        #expect(
            await manager.providerBundleIdentifier()
                == PacketTunnelProviderRouting.wireGuardBundleIdentifier
        )
        #expect(await manager.lastRuntimeConfiguration == nil)
    }

    @Test
    func mismatchedStaleManagerIsNeverRetargeted() async throws {
        let desired = try RuntimeProviderConfiguration(
            profileID: UUID(),
            sharedRecordRevision: "rev-desired-provider"
        )
        let stale = try RuntimeProviderConfiguration(
            profileID: UUID(),
            sharedRecordRevision: "rev-unrelated-provider"
        )
        let manager = RecordingDiagnosticTunnelProviderManager(
            providerBundleIdentifier: PacketTunnelProviderRouting.wireGuardBundleIdentifier,
            initialProviderConfiguration: stale.propertyList
        )
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            managerStore: store,
            providerBundleIdentifier: PacketTunnelProviderRouting.xrayBundleIdentifier
        )

        _ = try await bootstrapper.sessionForRuntimeValidation(
            providerConfiguration: desired
        )

        #expect(await store.makeCount == 1)
        #expect(
            await manager.providerBundleIdentifier()
                == PacketTunnelProviderRouting.wireGuardBundleIdentifier
        )
        #expect(await manager.lastRuntimeConfiguration == nil)
    }

    @Test
    func persistedProviderConfigurationMismatchStopsBeforeIPCSession() async throws {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let intended = try RuntimeProviderConfiguration(profileID: UUID(), sharedRecordRevision: "rev-intended")
        let stale = try RuntimeProviderConfiguration(profileID: UUID(), sharedRecordRevision: "rev-stale")
        let manager = RecordingDiagnosticTunnelProviderManager(
            providerBundleIdentifier: providerID,
            providerConfigurationOverrideAfterLoad: stale.propertyList
        )
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [manager]),
            providerBundleIdentifier: providerID
        )

        await expectRuntimeValidationFailure(stage: .providerConfiguration, category: .providerConfigurationPersistedMismatch) {
            _ = try await bootstrapper.sessionForRuntimeValidation(providerConfiguration: intended)
        }

        #expect(await manager.sessionCount == 0)
    }

    @Test
    func sentinelPathDoesNotStartOrStopVPNAndAllowsDisconnectedStatus() async throws {
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .verifyKeychainSentinel,
            payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: correlationID))
        )
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .keychainSentinel(TunnelKeychainSentinelResponse(found: true, correlationID: correlationID))
        )
        let session = StubTunnelProviderSession(status: .disconnected, response: try encode(response))
        let manager = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: "su.24kvn.kvn-app.PacketTunnelExtension", session: session)
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: store)
        let messenger = NetworkExtensionKeychainSentinelMessenger(bootstrapper: bootstrapper, timeout: .seconds(1))

        _ = try await messenger.sendKeychainSentinel(request)

        #expect(await session.sendCount == 1)
        #expect(await session.startCount == 0)
        #expect(await session.stopCount == 0)
    }

    @Test
    func disconnectedDiagnosticIPCIsAllowedOnlyForSentinel() async throws {
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .verifyKeychainSentinel,
            payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: correlationID))
        )
        let response = TunnelMessageResponse.success(
            request: request,
            payload: .keychainSentinel(TunnelKeychainSentinelResponse(found: true, correlationID: correlationID))
        )
        let session = StubTunnelProviderSession(status: .disconnected, response: try encode(response))
        let manager = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: "su.24kvn.kvn-app.PacketTunnelExtension", session: session)
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])
        let sentinelMessenger = NetworkExtensionKeychainSentinelMessenger(
            bootstrapper: DiagnosticTunnelProviderSessionBootstrapper(managerStore: store),
            timeout: .seconds(1)
        )
        let ordinaryMessenger = NetworkExtensionTunnelMessenger(sessionProvider: StubTunnelSessionProvider(session: session), timeout: .seconds(1))

        _ = try await sentinelMessenger.sendKeychainSentinel(request)
        await expectTunnelMessageError(.providerStatusNotConnected) {
            _ = try await ordinaryMessenger.send(TunnelMessageRequest(kind: .ping))
        }
    }

    @Test
    func sentinelMessengerRejectsNonSentinelRequests() async {
        let messenger = NetworkExtensionKeychainSentinelMessenger(
            bootstrapper: DiagnosticTunnelProviderSessionBootstrapper(managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [])),
            timeout: .seconds(1)
        )

        await expectTunnelMessageError(.unsupportedRequest) {
            _ = try await messenger.sendKeychainSentinel(TunnelMessageRequest(kind: .ping))
        }
    }

    @Test
    func diagnosticManagerLoadFailureIsStaged() async {
        let store = RecordingDiagnosticTunnelProviderManagerStore(
            managers: [],
            loadError: TunnelMessageErrorCode.providerUnavailable
        )
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: store)

        await expectSentinelDiagnosticFailure(stage: .managerLoad, category: .managerLoadFailed) {
            _ = try await bootstrapper.sessionForSentinel()
        }
    }

    @Test
    func diagnosticManagerLoadFailureIncludesNEVPNSymbolicCode() async {
        let error = NSError(
            domain: NEVPNErrorDomain,
            code: NEVPNError.Code.configurationReadWriteFailed.rawValue
        )
        let store = RecordingDiagnosticTunnelProviderManagerStore(managers: [], loadError: error)
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: store)

        await expectSentinelDiagnosticFailure(
            stage: .managerLoad,
            category: .managerLoadFailed,
            errorDomain: NEVPNErrorDomain,
            errorCode: NEVPNError.Code.configurationReadWriteFailed.rawValue,
            errorSymbol: "configurationReadWriteFailed"
        ) {
            _ = try await bootstrapper.sessionForSentinel()
        }
    }

    @Test
    func diagnosticManagerCreateFailureIsStaged() async {
        let store = RecordingDiagnosticTunnelProviderManagerStore(
            managers: [],
            makeError: TunnelMessageErrorCode.providerUnavailable
        )
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(managerStore: store)

        await expectSentinelDiagnosticFailure(stage: .managerCreate, category: .managerCreateFailed) {
            _ = try await bootstrapper.sessionForSentinel()
        }
    }

    @Test
    func diagnosticManagerSaveFailureIsStaged() async {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let manager = RecordingDiagnosticTunnelProviderManager(
            providerBundleIdentifier: providerID,
            saveError: TunnelMessageErrorCode.providerUnavailable
        )
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [manager]),
            providerBundleIdentifier: providerID
        )

        await expectSentinelDiagnosticFailure(stage: .managerSave, category: .managerSaveFailed, managerAction: .reused) {
            _ = try await bootstrapper.sessionForSentinel()
        }
    }

    @Test
    func diagnosticManagerReloadFailureIsStaged() async {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let manager = RecordingDiagnosticTunnelProviderManager(
            providerBundleIdentifier: providerID,
            loadError: TunnelMessageErrorCode.providerUnavailable
        )
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [manager]),
            providerBundleIdentifier: providerID
        )

        await expectSentinelDiagnosticFailure(stage: .managerReload, category: .managerReloadFailed, managerAction: .reused) {
            _ = try await bootstrapper.sessionForSentinel()
        }
    }

    @Test
    func providerBundleMismatchIsStaged() async {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let manager = RecordingDiagnosticTunnelProviderManager(
            providerBundleIdentifier: providerID,
            configuredProviderIDOverride: "wrong.bundle"
        )
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [manager]),
            providerBundleIdentifier: providerID
        )

        await expectSentinelDiagnosticFailure(
            stage: .providerSession,
            category: .providerBundleMismatch,
            managerAction: .reused,
            providerBundleIDMatches: false
        ) {
            _ = try await bootstrapper.sessionForSentinel()
        }
    }

    @Test
    func providerSessionFailureIsStaged() async {
        let providerID = "su.24kvn.kvn-app.PacketTunnelExtension"
        let manager = RecordingDiagnosticTunnelProviderManager(
            providerBundleIdentifier: providerID,
            sessionError: TunnelMessageErrorCode.providerUnavailable
        )
        let bootstrapper = DiagnosticTunnelProviderSessionBootstrapper(
            managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [manager]),
            providerBundleIdentifier: providerID
        )

        await expectSentinelDiagnosticFailure(
            stage: .providerSession,
            category: .providerSessionUnavailable,
            managerAction: .reused,
            providerBundleIDMatches: true
        ) {
            _ = try await bootstrapper.sessionForSentinel()
        }
    }

    @Test
    func sentinelProviderSendFailureIsStagedWithoutStartingVPN() async {
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .verifyKeychainSentinel,
            payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: correlationID))
        )
        let session = StubTunnelProviderSession(
            status: .disconnected,
            response: nil,
            sendError: TunnelMessageErrorCode.providerUnavailable
        )
        let manager = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: "su.24kvn.kvn-app.PacketTunnelExtension", session: session)
        let messenger = NetworkExtensionKeychainSentinelMessenger(
            bootstrapper: DiagnosticTunnelProviderSessionBootstrapper(managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])),
            timeout: .seconds(1)
        )

        await expectSentinelDiagnosticFailure(
            stage: .providerMessageSend,
            category: .providerNotRunningWhileDisconnected,
            vpnStatus: "disconnected",
            managerAction: .reused,
            providerBundleIDMatches: true
        ) {
            _ = try await messenger.sendKeychainSentinel(request)
        }
        #expect(await session.startCount == 0)
        #expect(await session.stopCount == 0)
        #expect(await session.sendCount == 1)
    }

    @Test
    func sentinelProviderTimeoutIsStagedAndLateCallbackIsIgnored() async {
        let correlationID = UUID()
        let request = TunnelMessageRequest(
            kind: .verifyKeychainSentinel,
            payload: .keychainSentinel(TunnelKeychainSentinelRequest(correlationID: correlationID))
        )
        let session = StubTunnelProviderSession(status: .disconnected, response: Data(), blocksUntilReleased: true)
        let manager = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: "su.24kvn.kvn-app.PacketTunnelExtension", session: session)
        let messenger = NetworkExtensionKeychainSentinelMessenger(
            bootstrapper: DiagnosticTunnelProviderSessionBootstrapper(managerStore: RecordingDiagnosticTunnelProviderManagerStore(managers: [manager])),
            timeout: .milliseconds(20)
        )

        await expectSentinelDiagnosticFailure(
            stage: .providerTimeout,
            category: .providerTimeout,
            vpnStatus: "disconnected",
            managerAction: .reused,
            providerBundleIDMatches: true
        ) {
            _ = try await messenger.sendKeychainSentinel(request)
        }

        await session.releaseAll()
        await settleMainActor()
        #expect(await session.sendCount == 1)
    }
    #endif

    @Test
    @MainActor
    func staleMessageResponseCannotOverwriteNewerResponse() async throws {
        let firstRuntime = BlockingRuntimeResponse(snapshot: .notRunning(), blocksUntilReleased: true)
        let secondRuntime = BlockingRuntimeResponse(snapshot: runningSnapshot(), blocksUntilReleased: false)
        let messenger = ScriptedTunnelMessenger(runtimeResponses: [firstRuntime, secondRuntime])
        let viewModel = TunnelTelemetryDiagnosticsViewModel(messenger: messenger, snapshotStore: nil, coreUpdater: nil)

        viewModel.refresh(profiles: [], activeProfileID: nil, connectionState: .disconnected)
        await firstRuntime.waitForSendCount(1)
        viewModel.refresh(profiles: [], activeProfileID: nil, connectionState: .connected)
        await secondRuntime.waitForSendCount(1)
        await secondRuntime.waitForReturnCount(1)
        await waitForRefreshResult(viewModel, runtimeState: .running)
        await firstRuntime.releaseAll()
        await firstRuntime.waitForReturnCount(1)
        await settleMainActor()

        #expect(viewModel.runtimeSnapshot?.runtimeState == .running)
    }

    @Test
    @MainActor
    func staleMessageFailureCannotOverwriteNewerResponse() async throws {
        let firstRuntime = BlockingRuntimeResponse(error: .providerUnavailable, blocksUntilReleased: true)
        let secondRuntime = BlockingRuntimeResponse(snapshot: runningSnapshot(), blocksUntilReleased: false)
        let messenger = ScriptedTunnelMessenger(runtimeResponses: [firstRuntime, secondRuntime])
        let viewModel = TunnelTelemetryDiagnosticsViewModel(messenger: messenger, snapshotStore: nil, coreUpdater: nil)

        viewModel.refresh(profiles: [], activeProfileID: nil, connectionState: .disconnected)
        await firstRuntime.waitForSendCount(1)
        viewModel.refresh(profiles: [], activeProfileID: nil, connectionState: .connected)
        await secondRuntime.waitForSendCount(1)
        await secondRuntime.waitForReturnCount(1)
        await waitForRefreshResult(viewModel, runtimeState: .running)
        await firstRuntime.releaseAll()
        await firstRuntime.waitForReturnCount(1)
        await settleMainActor()

        #expect(viewModel.runtimeSnapshot?.runtimeState == .running)
        #expect(viewModel.errorKey == nil)
    }

    @Test
    @MainActor
    func staleMessageSuccessCannotOverwriteNewerFailure() async throws {
        let firstRuntime = BlockingRuntimeResponse(snapshot: runningSnapshot(), blocksUntilReleased: true)
        let secondRuntime = BlockingRuntimeResponse(error: .providerUnavailable, blocksUntilReleased: false)
        let messenger = ScriptedTunnelMessenger(runtimeResponses: [firstRuntime, secondRuntime])
        let viewModel = TunnelTelemetryDiagnosticsViewModel(messenger: messenger, snapshotStore: nil, coreUpdater: nil)

        viewModel.refresh(profiles: [], activeProfileID: nil, connectionState: .disconnected)
        await firstRuntime.waitForSendCount(1)
        viewModel.refresh(profiles: [], activeProfileID: nil, connectionState: .connected)
        await secondRuntime.waitForSendCount(1)
        await secondRuntime.waitForReturnCount(1)
        await waitForRefreshResult(viewModel, errorKey: TunnelMessageErrorCode.providerUnavailable.localizationKey)
        await firstRuntime.releaseAll()
        await firstRuntime.waitForReturnCount(1)
        await settleMainActor()

        #expect(viewModel.runtimeSnapshot == nil)
        #expect(viewModel.errorKey == TunnelMessageErrorCode.providerUnavailable.localizationKey)
    }

    @Test
    @MainActor
    func oldRequestCleanupCannotClearCurrentRequestState() async throws {
        let firstRuntime = BlockingRuntimeResponse(snapshot: .notRunning(), blocksUntilReleased: true)
        let secondRuntime = BlockingRuntimeResponse(snapshot: runningSnapshot(), blocksUntilReleased: true)
        let messenger = ScriptedTunnelMessenger(runtimeResponses: [firstRuntime, secondRuntime])
        let viewModel = TunnelTelemetryDiagnosticsViewModel(messenger: messenger, snapshotStore: nil, coreUpdater: nil)

        viewModel.refresh(profiles: [], activeProfileID: nil, connectionState: .disconnected)
        await firstRuntime.waitForSendCount(1)
        viewModel.refresh(profiles: [], activeProfileID: nil, connectionState: .connected)
        await secondRuntime.waitForSendCount(1)
        await firstRuntime.releaseAll()
        await firstRuntime.waitForReturnCount(1)
        await settleMainActor()

        #expect(viewModel.isRefreshing)

        await secondRuntime.releaseAll()
        await secondRuntime.waitForReturnCount(1)
        await waitUntil { viewModel.isRefreshing == false }
        #expect(viewModel.runtimeSnapshot?.runtimeState == .running)
    }

    @Test
    func scriptedTelemetryMessengerRejectsXrayValidationRequests() async {
        let messenger = ScriptedTunnelMessenger(runtimeResponses: [])
        let request = TunnelMessageRequest(
            kind: .validateXrayConfiguration,
            payload: .xrayConfigurationValidation(
                TunnelXrayConfigurationValidationRequest(
                    correlationID: UUID(),
                    expectedProfileID: UUID(),
                    expectedRevisionToken: 1,
                    requestGeneration: 1
                )
            )
        )

        await expectTunnelMessageError(.unsupportedRequest) {
            _ = try await messenger.send(request)
        }
    }

    @Test
    func scriptedTelemetryMessengerRejectsXrayLifecycleSmokeTestRequests() async {
        let messenger = ScriptedTunnelMessenger(runtimeResponses: [])
        let request = TunnelMessageRequest(
            kind: .runXrayLifecycleSmokeTest,
            payload: .xrayLifecycleSmokeTest(
                TunnelXrayLifecycleSmokeTestRequest(
                    correlationID: UUID(),
                    expectedProfileID: UUID(),
                    expectedRevisionToken: 1,
                    requestGeneration: 1
                )
            )
        )

        await expectTunnelMessageError(.unsupportedRequest) {
            _ = try await messenger.send(request)
        }
    }
}

struct TunnelTelemetryStoreTests {
    @Test
    func runtimeSnapshotContainsNoCredentials() async throws {
        let store = TunnelTelemetryStore()
        await store.markStarting(
            profileID: "vless://secret@example.invalid:443",
            candidateID: "credential-token-private-key",
            backendKind: .xray,
            protocolKind: .vless,
            transportKind: "tcp"
        )
        let snapshot = await store.runtimeSnapshot()
        let json = try stringJSON(snapshot)

        #expect(snapshot.activeProfileID == nil)
        #expect(snapshot.candidateID == nil)
        #expect(json.contains("vless://") == false)
        #expect(json.contains("credential-token-private-key") == false)
    }

    @Test
    func eventSnapshotsContainNoRawURLsOrConfigs() async throws {
        let store = TunnelTelemetryStore(maximumEventCount: 4)
        await store.markFailure(
            TunnelFailureSnapshot(
                category: .configurationInvalid,
                occurredAt: Date(timeIntervalSince1970: 1),
                errorDomain: "TunnelRuntime",
                errorCode: 7
            )
        )

        let json = try stringJSON(await store.recentEvents())
        #expect(json.contains("://") == false)
        #expect(json.contains("password") == false)
        #expect(json.contains("uuid") == false)
    }

    @Test
    func telemetryStoreIsSerializedAndEventHistoryIsBounded() async {
        let store = TunnelTelemetryStore(maximumEventCount: 3)

        await withTaskGroup(of: Void.self) { group in
            for index in 0..<10 {
                group.addTask {
                    await store.markFailure(
                        TunnelFailureSnapshot(
                            category: .runtimeExited,
                            occurredAt: Date(timeIntervalSince1970: Double(index)),
                            errorDomain: nil,
                            errorCode: nil
                        ),
                        now: Date(timeIntervalSince1970: Double(index))
                    )
                }
            }
        }

        #expect(await store.recentEvents().count == 3)
        #expect(await store.runtimeSnapshot().runtimeState == .failed)
    }

    @Test
    func realTun2SocksStatsMappingUsesActualCounters() {
        let stats = Tun2SocksStatsSnapshot(bytesUploaded: 10, bytesDownloaded: 20, packetsUploaded: 3, packetsDownloaded: 4)
        let counters = stats.trafficCounters()

        #expect(counters.bytesUploaded == 10)
        #expect(counters.bytesDownloaded == 20)
        #expect(counters.packetsUploaded == 3)
        #expect(counters.packetsDownloaded == 4)
    }

    @Test
    func xrayStateMappingUsesSanitizedComponentState() {
        #expect(XrayRuntimeStateMapper.componentState(from: "running") == .running)
        #expect(XrayRuntimeStateMapper.componentState(from: "failed") == .failed)
        #expect(XrayRuntimeStateMapper.componentState(from: nil) == .unavailable)
        #expect(XrayRuntimeStateMapper.componentState(from: "raw-state-without-config") == .unknown)
    }

    @Test
    func processAliveDoesNotImplyHealthyAndNotRunningIsTruthful() async {
        let handler = TunnelAppMessageHandler()
        guard let requestData = try? encode(TunnelMessageRequest(kind: .getRuntimeSnapshot)) else {
            Issue.record("failed to encode request")
            return
        }
        let responseData = await handler.handle(requestData)
        let response = try? decodedResponse(responseData)
        guard case .runtime(let snapshot)? = response?.payload else {
            Issue.record("expected runtime payload")
            return
        }

        #expect(snapshot.runtimeState == .notRunning)
        #expect(snapshot.health.state == .stopped)
        #expect(snapshot.xrayState == .unavailable)
        #expect(snapshot.tun2SocksState == .unavailable)
    }

    @Test
    func fatalRuntimeErrorMapsToReachableFalse() {
        let failure = TunnelFailureSnapshot(
            category: .runtimeExited,
            occurredAt: Date(timeIntervalSince1970: 1),
            errorDomain: nil,
            errorCode: nil
        )
        var snapshot = TunnelRuntimeSnapshot.notRunning(generatedAt: Date(timeIntervalSince1970: 2))
        snapshot.candidateID = "candidate-1"
        snapshot.health = TunnelHealthSnapshot(
            state: .failed,
            generatedAt: Date(timeIntervalSince1970: 2),
            origin: .packetTunnelExtension,
            lastSuccessfulTrafficAt: nil,
            lastFailure: failure,
            isLive: true
        )
        snapshot.lastFailure = failure

        let sample = TunnelTelemetryHealthMapper().healthSample(from: snapshot)

        #expect(sample?.reachable == false)
        #expect(sample?.failure == TunnelFailureCategory.runtimeExited.rawValue)
        #expect(sample?.latencyMs == nil)
        #expect(sample?.packetLossPercent == nil)
    }

    @Test
    func missingMetricsRemainNilAndCountersAreNotThroughput() {
        var snapshot = TunnelRuntimeSnapshot.notRunning()
        snapshot.candidateID = "candidate-1"
        snapshot.health = TunnelHealthSnapshot(
            state: .healthy,
            generatedAt: Date(timeIntervalSince1970: 1),
            origin: .packetTunnelExtension,
            lastSuccessfulTrafficAt: nil,
            lastFailure: nil,
            isLive: true
        )
        snapshot.counters = TunnelTrafficCounters(bytesUploaded: 100, bytesDownloaded: 200, packetsUploaded: nil, packetsDownloaded: nil)

        let sample = TunnelTelemetryHealthMapper().healthSample(from: snapshot)

        #expect(sample?.latencyMs == nil)
        #expect(sample?.jitterMs == nil)
        #expect(sample?.packetLossPercent == nil)
        #expect(sample?.downloadBps == nil)
        #expect(sample?.uploadBps == nil)
    }
}

struct TunnelTelemetrySnapshotStoreTests {
    @Test
    func appGroupSnapshotIsAtomicAndOldSnapshotIsMarkedStale() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        let store = TunnelTelemetrySnapshotStore(fileURL: directory.appendingPathComponent("last-runtime-snapshot.json"))
        let oldDate = Date(timeIntervalSince1970: 1)

        try await store.write(runtime: .notRunning(generatedAt: oldDate), events: [], now: oldDate)
        let read = try #require(try await store.read(now: Date(timeIntervalSince1970: 1_000), staleAfter: 10))

        #expect(read.isStale)
        #expect(read.stored.runtime.origin == .appGroupLastKnownSnapshot)
        #expect(read.stored.runtime.health.isLive == false)
    }
}

struct TunnelTelemetryCoreUpdateTests {
    @Test
    func authoritativeTelemetryUpdatesOnlyCurrentCandidate() async throws {
        let core = RecordingTelemetryCoreService()
        let updater = TunnelTelemetryCoreUpdater(coreService: core)
        let profile = makeTelemetryProfile(id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!)
        var snapshot = healthySnapshot(candidateID: profile.id.uuidString)

        let result = try await updater.apply(runtime: snapshot, profiles: [profile], activeProfileID: profile.id)

        #expect(result.updatedCandidateID == profile.id.uuidString)
        #expect(await core.updatedCandidateIDs == [profile.id.uuidString])

        snapshot.candidateID = "33333333-3333-3333-3333-333333333333"
        let skipped = try await updater.apply(runtime: snapshot, profiles: [profile], activeProfileID: profile.id)
        #expect(skipped.updatedCandidateID == nil)
        #expect(await core.updatedCandidateIDs == [profile.id.uuidString])
    }

    @Test
    func incomparableOriginsDoNotTriggerAutomaticAction() async throws {
        let manager = CountingTelemetryConnectionManager()
        let activeStore = LocalTelemetryActiveProfileStore()
        let profile = makeTelemetryProfile()
        await activeStore.saveActiveProfileID(profile.id)
        let core = RecordingTelemetryCoreService()
        let updater = TunnelTelemetryCoreUpdater(coreService: core)

        let result = try await updater.apply(runtime: healthySnapshot(candidateID: profile.id.uuidString), profiles: [profile], activeProfileID: profile.id)

        #expect(result.recommendation?.shouldSwitch == true)
        #expect(result.comparability == .insufficientComparability)
        #expect(await manager.connectCount == 0)
        #expect(await manager.disconnectCount == 0)
        #expect(await activeStore.activeProfileID() == profile.id)
    }
}

struct TunnelTelemetryLocalizationTests {
    @Test
    func telemetryLocalizationKeysExistInEnglishAndRussian() throws {
        let keys = [
            "diagnostics.tunnel_telemetry",
            "diagnostics.telemetry_notice",
            "diagnostics.telemetry.refresh",
            "diagnostics.telemetry.error.not_connected",
            "diagnostics.telemetry.keychain_smoke.diagnostics",
            "diagnostics.telemetry.keychain_smoke.stage",
            "diagnostics.telemetry.keychain_smoke.error_category",
            "diagnostics.telemetry.keychain_smoke.cleanup",
            "diagnostics.telemetry.runtime_state.notRunning",
            "diagnostics.telemetry.health_state.stopped"
        ]
        try Stage0TestResources.requireLocalizations(for: keys)
    }
}

private final class StubTunnelProviderSession: TunnelProviderSessionConnection, @unchecked Sendable {
    let response: Data?
    let blocksUntilReleased: Bool
    let invokesCallback: Bool
    let sendsDuplicateCallback: Bool
    let sendError: (any Error)?
    private let fixedStatus: TunnelProviderSessionStatus
    private let lock = NSLock()
    private var blockers: [@Sendable (Result<Data?, any Error>) -> Void] = []
    private var waiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private var _sendCount = 0
    private var _startCount = 0
    private var _stopCount = 0

    init(
        status: TunnelProviderSessionStatus,
        response: Data?,
        blocksUntilReleased: Bool = false,
        invokesCallback: Bool = true,
        sendsDuplicateCallback: Bool = false,
        sendError: (any Error)? = nil
    ) {
        self.fixedStatus = status
        self.response = response
        self.blocksUntilReleased = blocksUntilReleased
        self.invokesCallback = invokesCallback
        self.sendsDuplicateCallback = sendsDuplicateCallback
        self.sendError = sendError
    }

    func status() async -> TunnelProviderSessionStatus {
        fixedStatus
    }

    var sendCount: Int {
        get async {
            lock.withLock { _sendCount }
        }
    }

    var startCount: Int {
        get async {
            lock.withLock { _startCount }
        }
    }

    var stopCount: Int {
        get async {
            lock.withLock { _stopCount }
        }
    }

    func sendProviderMessage(
        _ data: Data,
        responseHandler: @escaping @Sendable (Result<Data?, any Error>) -> Void
    ) {
        let readyWaiters = lock.withLock {
            _sendCount += 1
            return readyWaitersLocked()
        }
        readyWaiters.forEach { $0.resume() }

        if let sendError {
            responseHandler(.failure(sendError))
            if sendsDuplicateCallback {
                responseHandler(.failure(sendError))
            }
            return
        }

        guard invokesCallback else {
            return
        }

        if blocksUntilReleased {
            lock.withLock {
                blockers.append(responseHandler)
            }
            return
        }

        responseHandler(.success(response))
        if sendsDuplicateCallback {
            responseHandler(.success(response))
        }
    }

    func releaseAll() async {
        let callbacks = lock.withLock {
            let callbacks = blockers
            blockers.removeAll()
            return callbacks
        }
        for callback in callbacks {
            callback(.success(response))
            if sendsDuplicateCallback {
                callback(.success(response))
            }
        }
    }

    func waitForSendCount(_ count: Int) async {
        if lock.withLock({ _sendCount >= count }) {
            return
        }

        await withCheckedContinuation { continuation in
            let shouldResume = lock.withLock {
                if _sendCount >= count {
                    return true
                }
                waiters.append((count, continuation))
                return false
            }
            if shouldResume {
                continuation.resume()
            }
        }
    }

    private func readyWaitersLocked() -> [CheckedContinuation<Void, Never>] {
        let ready = waiters.filter { _sendCount >= $0.0 }.map(\.1)
        waiters.removeAll { _sendCount >= $0.0 }
        return ready
    }
}

private nonisolated struct StubTunnelSessionProvider: TunnelProviderSessionProviding {
    let session: StubTunnelProviderSession

    func currentSession() async throws -> any TunnelProviderSessionConnection {
        session
    }
}

#if DEBUG
private actor RecordingDiagnosticTunnelProviderManagerStore: DiagnosticTunnelProviderManagerStore {
    private var managers: [RecordingDiagnosticTunnelProviderManager]
    private let loadError: (any Error)?
    private let makeError: (any Error)?
    private(set) var makeCount = 0

    init(
        managers: [RecordingDiagnosticTunnelProviderManager],
        loadError: (any Error)? = nil,
        makeError: (any Error)? = nil
    ) {
        self.managers = managers
        self.loadError = loadError
        self.makeError = makeError
    }

    var managerCount: Int {
        managers.count
    }

    var firstManager: RecordingDiagnosticTunnelProviderManager? {
        managers.first
    }

    func loadAllManagers() async throws -> [any DiagnosticTunnelProviderManager] {
        if let loadError {
            throw loadError
        }
        return managers
    }

    func makeManager() async throws -> any DiagnosticTunnelProviderManager {
        if let makeError {
            throw makeError
        }
        makeCount += 1
        let manager = RecordingDiagnosticTunnelProviderManager(providerBundleIdentifier: nil)
        managers.append(manager)
        return manager
    }
}

private actor RecordingDiagnosticTunnelProviderManager: DiagnosticTunnelProviderManager {
    private var providerID: String?
    private let session: StubTunnelProviderSession
    private let configuredProviderIDOverride: String?
    private let saveError: (any Error)?
    private let loadError: (any Error)?
    private let sessionError: (any Error)?
    private let providerConfigurationOverrideAfterLoad: [String: Any]?
    private var rawProviderConfiguration: [String: Any]?
    private(set) var isEnabled = false
    private(set) var lastConfiguration: TunnelSentinelProviderConfiguration?
    private(set) var lastRuntimeConfiguration: RuntimeProviderConfiguration?
    private(set) var saveCount = 0
    private(set) var loadCount = 0
    private(set) var sessionCount = 0
    private(set) var events: [String] = []

    init(
        providerBundleIdentifier: String?,
        session: StubTunnelProviderSession = StubTunnelProviderSession(status: .disconnected, response: nil),
        configuredProviderIDOverride: String? = nil,
        saveError: (any Error)? = nil,
        loadError: (any Error)? = nil,
        sessionError: (any Error)? = nil,
        initialProviderConfiguration: [String: Any]? = nil,
        providerConfigurationOverrideAfterLoad: [String: Any]? = nil
    ) {
        self.providerID = providerBundleIdentifier
        self.session = session
        self.configuredProviderIDOverride = configuredProviderIDOverride
        self.saveError = saveError
        self.loadError = loadError
        self.sessionError = sessionError
        self.rawProviderConfiguration = initialProviderConfiguration
        self.providerConfigurationOverrideAfterLoad = providerConfigurationOverrideAfterLoad
    }

    func providerBundleIdentifier() async -> String? {
        events.append("providerBundleIdentifier")
        return providerID
    }

    func providerConfigurationPropertyList() async -> [String: Any]? {
        events.append("providerConfigurationPropertyList")
        return rawProviderConfiguration
    }

    func prepareExistingForSentinel(providerBundleIdentifier: String) async {
        events.append("prepareExistingSentinel")
        providerID = configuredProviderIDOverride ?? providerBundleIdentifier
        isEnabled = true
    }

    func configureForSentinel(
        providerBundleIdentifier: String,
        configuration: TunnelSentinelProviderConfiguration
    ) async {
        events.append("configureSentinel")
        providerID = configuredProviderIDOverride ?? providerBundleIdentifier
        lastConfiguration = configuration
        lastRuntimeConfiguration = nil
        rawProviderConfiguration = configuration.propertyList
        isEnabled = true
    }

    func configureForRuntimeValidation(
        providerBundleIdentifier: String,
        configuration: RuntimeProviderConfiguration
    ) async {
        events.append("configureRuntimeValidation")
        providerID = configuredProviderIDOverride ?? providerBundleIdentifier
        lastRuntimeConfiguration = configuration
        lastConfiguration = nil
        rawProviderConfiguration = configuration.propertyList
        isEnabled = true
    }

    func saveToPreferences() async throws {
        events.append("save")
        saveCount += 1
        if let saveError {
            throw saveError
        }
    }

    func loadFromPreferences() async throws {
        events.append("load")
        loadCount += 1
        if let loadError {
            throw loadError
        }
        if let providerConfigurationOverrideAfterLoad {
            rawProviderConfiguration = providerConfigurationOverrideAfterLoad
        }
    }

    func tunnelProviderSession() async throws -> any TunnelProviderSessionConnection {
        events.append("session")
        sessionCount += 1
        if let sessionError {
            throw sessionError
        }
        return session
    }
}
#endif

private actor BlockingRuntimeResponse {
    private let snapshot: TunnelRuntimeSnapshot?
    private let error: TunnelMessageErrorCode?
    private let blocksUntilReleased: Bool
    private var blockers: [CheckedContinuation<Void, Never>] = []
    private var sendWaiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private var returnWaiters: [(Int, CheckedContinuation<Void, Never>)] = []
    private(set) var sendCount = 0
    private(set) var returnCount = 0

    init(snapshot: TunnelRuntimeSnapshot, blocksUntilReleased: Bool) {
        self.snapshot = snapshot
        self.error = nil
        self.blocksUntilReleased = blocksUntilReleased
    }

    init(error: TunnelMessageErrorCode, blocksUntilReleased: Bool) {
        self.snapshot = nil
        self.error = error
        self.blocksUntilReleased = blocksUntilReleased
    }

    func response(for request: TunnelMessageRequest) async throws -> TunnelMessageResponse {
        sendCount += 1
        notifySendWaiters()
        if blocksUntilReleased {
            await withCheckedContinuation { continuation in
                blockers.append(continuation)
            }
        }
        returnCount += 1
        notifyReturnWaiters()
        if let error {
            throw error
        }
        let snapshot = try #require(snapshot)
        return .success(request: request, payload: .runtime(snapshot))
    }

    func releaseAll() {
        let continuations = blockers
        blockers.removeAll()
        for continuation in continuations {
            continuation.resume()
        }
    }

    func waitForSendCount(_ count: Int) async {
        if sendCount >= count {
            return
        }

        await withCheckedContinuation { continuation in
            sendWaiters.append((count, continuation))
        }
    }

    func waitForReturnCount(_ count: Int) async {
        if returnCount >= count {
            return
        }

        await withCheckedContinuation { continuation in
            returnWaiters.append((count, continuation))
        }
    }

    private func notifySendWaiters() {
        let ready = sendWaiters.filter { sendCount >= $0.0 }
        sendWaiters.removeAll { sendCount >= $0.0 }
        for waiter in ready {
            waiter.1.resume()
        }
    }

    private func notifyReturnWaiters() {
        let ready = returnWaiters.filter { returnCount >= $0.0 }
        returnWaiters.removeAll { returnCount >= $0.0 }
        for waiter in ready {
            waiter.1.resume()
        }
    }
}

private actor ScriptedTunnelMessenger: TunnelProviderMessaging {
    private var runtimeResponses: [BlockingRuntimeResponse]

    init(runtimeResponses: [BlockingRuntimeResponse]) {
        self.runtimeResponses = runtimeResponses
    }

    func status() async -> TunnelProviderSessionStatus {
        .connected
    }

    func send(_ request: TunnelMessageRequest) async throws -> TunnelMessageResponse {
        switch request.kind {
        case .getCapabilities:
            return .success(request: request, payload: .capabilities(.current))
        case .getRuntimeSnapshot:
            let runtime = runtimeResponses.removeFirst()
            return try await runtime.response(for: request)
        case .getHealthSnapshot:
            return .success(request: request, payload: .health(TunnelRuntimeSnapshot.notRunning().health))
        case .getRecentEvents:
            return .success(request: request, payload: .events([]))
        case .ping:
            return .success(
                request: request,
                payload: .pong(TunnelPongSnapshot(extensionProcessAlive: true, schemaVersion: TunnelMessageProtocol.schemaVersion))
            )
        case .verifyKeychainSentinel:
            throw TunnelMessageErrorCode.unsupportedRequest
        case .validateRuntimeConfiguration:
            throw TunnelMessageErrorCode.unsupportedRequest
        case .validateXrayConfiguration:
            throw TunnelMessageErrorCode.unsupportedRequest
        case .runXrayLifecycleSmokeTest:
            throw TunnelMessageErrorCode.unsupportedRequest
        case .runXrayRemoteEgressProbe:
            throw TunnelMessageErrorCode.unsupportedRequest
        case .probeActiveXrayEgress:
            throw TunnelMessageErrorCode.unsupportedRequest
        case .runUDPControlProbe:
            throw TunnelMessageErrorCode.unsupportedRequest
        case .runLibXrayPingProbe:
            throw TunnelMessageErrorCode.unsupportedRequest
        case .getDiagnosticProviderMode:
            throw TunnelMessageErrorCode.unsupportedRequest
        case .unknown:
            throw TunnelMessageErrorCode.unsupportedRequest
        }
    }
}

private actor RecordingTelemetryCoreService: PortableCoreHealthServicing {
    private(set) var updatedCandidateIDs: [String] = []
    private(set) var syncedProfiles: [VPNProfile] = []
    private(set) var networkTypes: [KVNNetworkType] = []
    private(set) var selectBestCount = 0

    func syncCandidates(from profiles: [VPNProfile]) async throws {
        syncedProfiles = profiles
    }

    func updateHealth(candidateID: String, sample: KVNHealthSampleDTO) async throws {
        updatedCandidateIDs.append(candidateID)
    }

    func setNetworkType(_ type: KVNNetworkType) async throws {
        networkTypes.append(type)
    }

    func selectBest(now: Date) async throws -> KVNSelectionDecisionDTO {
        selectBestCount += 1
        return KVNSelectionDecisionDTO(
            selected: updatedCandidateIDs.last,
            current: updatedCandidateIDs.last,
            shouldSwitch: true,
            currentScore: 41,
            selectedScore: 80,
            reason: .significantlyBetter,
            timestampMs: UInt64(now.timeIntervalSince1970 * 1_000),
            breakdown: nil
        )
    }
}

private actor CountingTelemetryConnectionManager: VPNConnectionManaging {
    private(set) var connectCount = 0
    private(set) var disconnectCount = 0

    func currentState() async -> VPNConnectionState {
        .connected
    }

    nonisolated func stateUpdates() -> AsyncStream<VPNConnectionState> {
        AsyncStream { continuation in
            continuation.yield(.connected)
        }
    }

    func connect(using profile: VPNProfile) async throws {
        connectCount += 1
    }

    func disconnect() async {
        disconnectCount += 1
    }
}

private actor LocalTelemetryActiveProfileStore: ActiveProfileStoring {
    private var id: UUID?

    func activeProfileID() async -> UUID? {
        id
    }

    func saveActiveProfileID(_ id: UUID?) async {
        self.id = id
    }
}

private nonisolated func encode(_ value: some Encodable) throws -> Data {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    return try encoder.encode(value)
}

private nonisolated func decodedResponse(_ data: Data) throws -> TunnelMessageResponse {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return try decoder.decode(TunnelMessageResponse.self, from: data)
}

private nonisolated func stringJSON(_ value: some Encodable) throws -> String {
    String(data: try encode(value), encoding: .utf8) ?? ""
}

private nonisolated func runtimeResponse(state: TunnelRuntimeState) -> TunnelMessageResponse {
    let snapshot = state == .running ? runningSnapshot() : TunnelRuntimeSnapshot.notRunning()
    return TunnelMessageResponse.success(request: TunnelMessageRequest(kind: .getRuntimeSnapshot), payload: .runtime(snapshot))
}

private nonisolated func runningSnapshot() -> TunnelRuntimeSnapshot {
    var snapshot = TunnelRuntimeSnapshot.notRunning()
    snapshot.runtimeState = .running
    snapshot.health = TunnelHealthSnapshot(
        state: .healthy,
        generatedAt: Date(),
        origin: .packetTunnelExtension,
        lastSuccessfulTrafficAt: nil,
        lastFailure: nil,
        isLive: true
    )
    return snapshot
}

private nonisolated func healthySnapshot(candidateID: String) -> TunnelRuntimeSnapshot {
    var snapshot = TunnelRuntimeSnapshot.notRunning(generatedAt: Date(timeIntervalSince1970: 2))
    snapshot.runtimeState = .running
    snapshot.candidateID = candidateID
    snapshot.activeProfileID = candidateID
    snapshot.health = TunnelHealthSnapshot(
        state: .healthy,
        generatedAt: Date(timeIntervalSince1970: 2),
        origin: .packetTunnelExtension,
        lastSuccessfulTrafficAt: Date(timeIntervalSince1970: 2),
        lastFailure: nil,
        isLive: true
    )
    return snapshot
}

private nonisolated func makeTelemetryProfile(id: UUID = UUID()) -> VPNProfile {
    var profile = VPNProfile.draft(
        name: "Telemetry Node",
        protocolType: .vless,
        serverAddress: "telemetry.example.invalid",
        port: 443,
        credentialReference: "credential-ref",
        transportSettings: VPNTransportSettings(network: "tcp"),
        tlsSettings: VPNTLSSettings(isEnabled: true, serverName: "telemetry.example.invalid"),
        protocolConfiguration: .vless(VLESSProfileConfiguration(flow: nil, encryption: "none")),
        source: .manual
    )
    profile.id = id
    return profile
}

private func expectTunnelMessageError(_ expected: TunnelMessageErrorCode, operation: () async throws -> Void) async {
    do {
        try await operation()
        Issue.record("expected \(expected)")
    } catch let error as TunnelMessageErrorCode {
        #expect(error == expected)
    } catch {
        Issue.record("expected \(expected), got \(error)")
    }
}

private func expectSentinelDiagnosticFailure(
    stage: TunnelKeychainSentinelDiagnosticStage,
    category: TunnelKeychainSentinelDiagnosticCategory,
    vpnStatus: String? = nil,
    managerAction: TunnelKeychainSentinelManagerAction? = nil,
    providerBundleIDMatches: Bool? = nil,
    errorDomain: String? = nil,
    errorCode: Int? = nil,
    errorSymbol: String? = nil,
    operation: () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("expected sentinel diagnostic failure")
    } catch let failure as TunnelKeychainSentinelDiagnosticFailure {
        #expect(failure.diagnostic.stage == stage)
        #expect(failure.diagnostic.category == category)
        if let vpnStatus {
            #expect(failure.diagnostic.vpnStatus == vpnStatus)
        }
        if let managerAction {
            #expect(failure.diagnostic.managerAction == managerAction)
        }
        if let providerBundleIDMatches {
            #expect(failure.diagnostic.providerBundleIDMatches == providerBundleIDMatches)
        }
        if let errorDomain {
            #expect(failure.diagnostic.errorDomain == errorDomain)
        }
        if let errorCode {
            #expect(failure.diagnostic.errorCode == errorCode)
        }
        if let errorSymbol {
            #expect(failure.diagnostic.errorSymbol == errorSymbol)
        }
    } catch {
        Issue.record("expected sentinel diagnostic failure, got \(error)")
    }
}

private func expectRuntimeValidationFailure(
    stage: TunnelRuntimeConfigurationValidationStage,
    category: TunnelRuntimeConfigurationValidationCategory,
    operation: () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("expected runtime validation failure")
    } catch let failure as TunnelRuntimeConfigurationValidationFailure {
        #expect(failure.diagnostic.stage == stage)
        #expect(failure.diagnostic.category == category)
    } catch {
        Issue.record("expected runtime validation failure, got \(error)")
    }
}

@MainActor
private func waitUntil(_ condition: @escaping @MainActor () -> Bool) async {
    for _ in 0..<100 {
        if condition() {
            return
        }
        await Task.yield()
    }
}

@MainActor
private func waitForRefreshResult(
    _ viewModel: TunnelTelemetryDiagnosticsViewModel,
    runtimeState: TunnelRuntimeState
) async {
    await waitForObservedCondition {
        viewModel.isRefreshing == false &&
            viewModel.runtimeSnapshot?.runtimeState == runtimeState
    }
    #expect(viewModel.isRefreshing == false)
    #expect(viewModel.runtimeSnapshot?.runtimeState == runtimeState)
}

@MainActor
private func waitForRefreshResult(
    _ viewModel: TunnelTelemetryDiagnosticsViewModel,
    errorKey: String
) async {
    await waitForObservedCondition {
        viewModel.isRefreshing == false &&
            viewModel.errorKey == errorKey
    }
    #expect(viewModel.isRefreshing == false)
    #expect(viewModel.errorKey == errorKey)
}

@MainActor
private func waitForObservedCondition(_ condition: @escaping () -> Bool) async {
    if condition() {
        return
    }

    let waiter = ObservationWaiter()
    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
        func resumeIfReady() {
            if waiter.resumeIfNeeded(condition()) {
                continuation.resume()
            }
        }

        func observe() {
            let satisfied = withObservationTracking {
                condition()
            } onChange: {
                Task { @MainActor in
                    if waiter.hasResumed == false {
                        observe()
                    }
                }
            }
            if satisfied {
                resumeIfReady()
            }
        }

        observe()
    }
}

private final class ObservationWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false

    var hasResumed: Bool {
        lock.withLock { resumed }
    }

    func resumeIfNeeded(_ shouldResume: Bool) -> Bool {
        lock.withLock {
            guard shouldResume, resumed == false else {
                return false
            }
            resumed = true
            return true
        }
    }
}

@MainActor
private func settleMainActor() async {
    await Task.yield()
    await Task.yield()
}
