//
//  VPNDashboardViewModel.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation
import Observation

private enum SubscriptionProfileMutation {
    case saved(UUID)
    case deleted(UUID)
    case none
}

private enum SubscriptionApplicationError: LocalizedError {
    case runtimePublicationFailed

    var errorDescription: String? {
        "The profile runtime configuration could not be published to the packet tunnel."
    }
}

private enum SmartConnectionAttemptError: LocalizedError {
    case didNotReachConnectedState
    case noEligibleProfiles
    case noManualProfileSelected
    case profileUnavailable

    var errorDescription: String? {
        switch self {
        case .didNotReachConnectedState:
            "The VPN connection did not reach the connected state."
        case .noEligibleProfiles:
            "No complete, enabled VPN profiles are available."
        case .noManualProfileSelected:
            "Select a VPN profile in Manual mode."
        case .profileUnavailable:
            "The selected VPN profile is not available for connection."
        }
    }
}

private struct SmartConnectionSessionQualityAccumulator {
    private static let maximumTailObservations = 20

    private var latencySum = 0.0
    private(set) var latencyValidSampleCount = 0
    private var packetLossSum = 0.0
    private(set) var packetLossValidSampleCount = 0
    private var tailLatencyObservations: [Double] = []
    private var tailPacketLossObservations: [Double] = []

    init(pendingRecord: SmartConnectionPendingQualityRecord? = nil) {
        guard let pendingRecord else { return }
        latencyValidSampleCount = max(0, pendingRecord.latencyCount)
        latencySum = latencyValidSampleCount == 0
            ? 0
            : max(0, pendingRecord.latencySum)
        packetLossValidSampleCount = max(0, pendingRecord.packetLossCount)
        packetLossSum = packetLossValidSampleCount == 0
            ? 0
            : min(
                Double(packetLossValidSampleCount) * 100,
                max(0, pendingRecord.packetLossSum)
            )
        if let tailLatency = pendingRecord.tailLatencyMilliseconds {
            tailLatencyObservations = Array(
                repeating: max(0, tailLatency),
                count: min(Self.maximumTailObservations, latencyValidSampleCount)
            )
        }
        if let tailLoss = pendingRecord.tailPacketLossPercent {
            tailPacketLossObservations = Array(
                repeating: min(100, max(0, tailLoss)),
                count: min(Self.maximumTailObservations, packetLossValidSampleCount)
            )
        }
    }

    var latencyMeanMilliseconds: Double? {
        guard latencyValidSampleCount > 0 else { return nil }
        return latencySum / Double(latencyValidSampleCount)
    }

    var packetLossMeanPercent: Double? {
        guard packetLossValidSampleCount > 0 else { return nil }
        return packetLossSum / Double(packetLossValidSampleCount)
    }

    var tailLatencyMilliseconds: Double? {
        Self.mean(of: tailLatencyObservations)
    }

    var tailPacketLossPercent: Double? {
        Self.mean(of: tailPacketLossObservations)
    }

    var qualityAggregate: SmartConnectionSessionQualityAggregate {
        SmartConnectionSessionQualityAggregate(
            latencySum: latencySum,
            latencyCount: latencyValidSampleCount,
            tailLatencyMilliseconds: tailLatencyMilliseconds,
            packetLossSum: packetLossSum,
            packetLossCount: packetLossValidSampleCount,
            tailPacketLossPercent: tailPacketLossPercent
        )
    }

    mutating func record(
        latencyMilliseconds: Double?,
        packetLossPercent: Double?
    ) {
        if let latencyMilliseconds {
            let observation = max(0, latencyMilliseconds)
            latencyValidSampleCount += 1
            latencySum += observation
            Self.appendTailObservation(
                observation,
                to: &tailLatencyObservations
            )
        }
        if let packetLossPercent {
            let observation = min(100, max(0, packetLossPercent))
            packetLossValidSampleCount += 1
            packetLossSum += observation
            Self.appendTailObservation(
                observation,
                to: &tailPacketLossObservations
            )
        }
    }

    private static func appendTailObservation(
        _ observation: Double,
        to observations: inout [Double]
    ) {
        observations.append(observation)
        if observations.count > maximumTailObservations {
            observations.removeFirst(observations.count - maximumTailObservations)
        }
    }

    private static func mean(of observations: [Double]) -> Double? {
        guard observations.isEmpty == false else { return nil }
        return observations.reduce(0, +) / Double(observations.count)
    }
}

private struct SmartConnectionLearningSession {
    var profileID: UUID
    var protocolType: VPNProtocol
    var context: NetworkContext
    var connectedAt: Date
    var telemetrySessionID: String?
    var checkpointRuntimeSeconds: TimeInterval?
    var countsInitialRuntimeFromZero: Bool
    var qualityAccumulator = SmartConnectionSessionQualityAccumulator()
    var anomalyDetector = SmartConnectionAnomalyDetector()
}

@MainActor
@Observable
final class VPNDashboardViewModel {
    private let serverProvider: ServerProviding
    private let serverProber: ServerProbing
    private let connectionManager: VPNConnectionManaging
    private let serverSelector: ServerSelecting
    private let profileRepository: VPNProfileRepository
    private let subscriptionRepository: SubscriptionRepository
    private let subscriptionUpdater: SubscriptionUpdating
    private let importer: VPNProfileImporting
    private let credentialStore: CredentialStoring
    private let activeProfileStore: ActiveProfileStoring
    private let manualProfileSelectionStore: ManualProfileSelectionStoring
    private let runtimeProfileSynchronizer: (any RuntimeProfileSynchronizing)?
    private let connectionTelemetryManager: any DashboardConnectionTelemetryManaging
    private let learningStore: any SmartConnectionLearningStoring
    private let networkContextSource: any SmartConnectionNetworkContextProviding
    private let candidatePlanner: SmartConnectionCandidatePlanner
    private let smartConnectionClock: any SmartConnectionClock
    private let networkContextDebounceSleeper: any SmartConnectionDebounceSleeping
    private let networkContextDebounceDuration: Duration
    private let connectionActionHapticFeedback: any ConnectionActionHapticFeedbackProviding

    private var activeOperationID: UUID?
    private var stateObservationTask: Task<Void, Never>?
    private var telemetryObservationTask: Task<Void, Never>?
    private var networkContextObservationTask: Task<Void, Never>?
    private var networkContextPromotionTask: Task<Void, Never>?
    private var saveOperationID: UUID?
    private var inFlightImportedCredentialReferences = Set<String>()
    private var subscriptionOperationID: UUID?
    private var refreshingSubscriptionID: UUID?
    private var discardedRefreshSubscriptionID: UUID?
    private var isInitialLoadInFlight = false
    private var hasLoadedProfiles = false
    private var learningSession: SmartConnectionLearningSession?
    private var isIntentionalDisconnectInFlight = false

    var connectionState: VPNConnectionState = .disconnected
    private(set) var hasAuthoritativeManagerConflict = false
    var selectedServer: VPNServer?
    var selectedProtocol: VPNProtocolSelection = .automatic
    var activeProfileID: UUID?
    private(set) var connectionMode: ConnectionSelectionMode = .automatic
    private(set) var manualSelectedProfileID: UUID?
    private(set) var automaticRecommendedProfileID: UUID?
    private(set) var currentAutomaticAttemptProfileID: UUID?
    private(set) var automaticCandidatePlan: SmartConnectionCandidatePlan = .empty(
        context: .unknown,
        now: .distantPast
    )
    private(set) var currentNetworkContext: NetworkContext = .unknown
    private(set) var smartConnectionLearning: SmartConnectionLearningSnapshot = .empty
    private(set) var smartConnectionQualityState: SmartConnectionQualityState = .normal
    var effectiveProtocol: VPNProtocol?
    var servers: [VPNServer] = []
    var profiles: [VPNProfile] = []
    var subscriptions: [VPNSubscription] = []
    var currentMetrics: ConnectionMetrics?
    var connectionTelemetry: DashboardConnectionTelemetrySnapshot = .unavailable
    var errorMessage: String?
    var importResult: VPNImportResult?
    var importErrorMessage: String?
    var subscriptionPreviewProfiles: [VPNProfile] = []
    var subscriptionPreview: SubscriptionPreview?
    var subscriptionUpdatePlan: SubscriptionUpdatePlan?
    var subscriptionRefreshState: VPNSubscriptionRefreshState = .idle
    var profileSaveState: ProfileSaveState = .idle
    var profileSaveMessage: String?

    init(
        serverProvider: ServerProviding = MockServerProvider(),
        serverProber: ServerProbing = MockServerProber(),
        connectionManager: VPNConnectionManaging = MockVPNConnectionManager(),
        serverSelector: ServerSelecting = MockServerSelector(),
        profileRepository: VPNProfileRepository = FileVPNProfileRepository(),
        subscriptionRepository: SubscriptionRepository = FileSubscriptionRepository(),
        subscriptionUpdater: SubscriptionUpdating? = nil,
        credentialStore: CredentialStoring = KeychainCredentialStore(),
        activeProfileStore: ActiveProfileStoring = UserDefaultsActiveProfileStore(),
        manualProfileSelectionStore: ManualProfileSelectionStoring =
            UserDefaultsManualProfileSelectionStore(),
        importer: VPNProfileImporting? = nil,
        runtimeProfileSynchronizer: (any RuntimeProfileSynchronizing)? = nil,
        connectionTelemetryManager: any DashboardConnectionTelemetryManaging =
            DisabledDashboardConnectionTelemetryManager(),
        learningStore: any SmartConnectionLearningStoring =
            FileSmartConnectionLearningStore(),
        networkContextSource: any SmartConnectionNetworkContextProviding =
            FixedSmartConnectionNetworkContextSource(context: .unknown),
        candidatePlanner: SmartConnectionCandidatePlanner =
            SmartConnectionCandidatePlanner(),
        smartConnectionClock: any SmartConnectionClock =
            SystemSmartConnectionClock(),
        networkContextDebounceSleeper: any SmartConnectionDebounceSleeping =
            TaskSmartConnectionDebounceSleeper(),
        networkContextDebounceDuration: Duration = .milliseconds(2_500),
        connectionActionHapticFeedback: any ConnectionActionHapticFeedbackProviding =
            SystemConnectionActionHapticFeedback()
    ) {
        self.serverProvider = serverProvider
        self.serverProber = serverProber
        self.connectionManager = connectionManager
        self.serverSelector = serverSelector
        self.profileRepository = profileRepository
        self.subscriptionRepository = subscriptionRepository
        self.subscriptionUpdater = subscriptionUpdater ?? URLSessionSubscriptionUpdater(
            credentialStore: credentialStore
        )
        self.credentialStore = credentialStore
        self.activeProfileStore = activeProfileStore
        self.manualProfileSelectionStore = manualProfileSelectionStore
        self.importer = importer ?? VPNLinkParser(credentialStore: credentialStore)
        self.runtimeProfileSynchronizer = runtimeProfileSynchronizer
        self.connectionTelemetryManager = connectionTelemetryManager
        self.learningStore = learningStore
        self.networkContextSource = networkContextSource
        self.candidatePlanner = candidatePlanner
        self.smartConnectionClock = smartConnectionClock
        self.networkContextDebounceSleeper = networkContextDebounceSleeper
        self.networkContextDebounceDuration = networkContextDebounceDuration
        self.connectionActionHapticFeedback = connectionActionHapticFeedback
        observeConnectionState()
        observeConnectionTelemetry()
    }

    var selectedProfile: VPNProfile? {
        if let currentAutomaticAttemptProfileID,
           let profile = profiles.first(where: { $0.id == currentAutomaticAttemptProfileID }) {
            return profile
        }

        if [.connecting, .connected, .disconnecting].contains(connectionState),
           let activeProfileID,
           let profile = profiles.first(where: { $0.id == activeProfileID }) {
            return profile
        }

        switch connectionMode {
        case .automatic:
            return automaticRecommendedProfile
        case .manual:
            return manualSelectedProfile
        }
    }

    var manualSelectedProfile: VPNProfile? {
        guard let manualSelectedProfileID else { return nil }
        return profiles.first { $0.id == manualSelectedProfileID }
    }

    var automaticRecommendedProfile: VPNProfile? {
        guard let automaticRecommendedProfileID else { return nil }
        return profiles.first { $0.id == automaticRecommendedProfileID }
    }

    var automaticRecommendation: SmartConnectionRankedCandidate? {
        guard let automaticRecommendedProfileID else { return nil }
        return automaticCandidatePlan.rankedCandidates.first {
            $0.profileID == automaticRecommendedProfileID
        }
    }

    var connectionSelectionPresentation: ConnectionSelectionPresentation {
        ConnectionSelectionPresentation(
            mode: connectionMode,
            selectableProfileIDs: connectionMode == .manual
                ? profiles.map(\.id)
                : [],
            recommendedProfileID: connectionMode == .automatic
                ? automaticRecommendedProfileID
                : nil
        )
    }

    var showsDemoModeNotice: Bool {
        guard let selectedProfile else {
            return true
        }
        return connectionManager.routesTrafficThroughProductionCore(using: selectedProfile) == false
    }

    var isSavingProfile: Bool {
        if case .saving = profileSaveState {
            return true
        }

        return false
    }

    var canToggleConnection: Bool {
        activeOperationID == nil
            && hasAuthoritativeManagerConflict == false
            && selectedProfile?.isEnabled != false
    }

    var canConnect: Bool {
        guard activeOperationID == nil else {
            return false
        }

        guard let selectedProfile else { return false }
        return SmartConnectionCandidatePlanner.isEligible(selectedProfile)
    }

    var selectedProfileStatusText: String? {
        guard let selectedProfile else {
            return nil
        }

        if selectedProfile.isEnabled == false {
            return "Disabled"
        }
        return selectedProfile.runtimeCapability.statusText
    }

    func loadInitialData() async {
        guard isInitialLoadInFlight == false else {
            return
        }
        isInitialLoadInFlight = true
        defer {
            isInitialLoadInFlight = false
        }

        do {
            // Legacy demo server metadata is non-authoritative. Complete profiles
            // remain usable even if that optional source is unavailable.
            servers = (try? await serverProvider.fetchServers()) ?? []
            profiles = try await profileRepository.profiles()
            hasLoadedProfiles = true
            activeProfileID = await activeProfileStore.activeProfileID()
            clearMissingOrInvalidActiveProfileIfNeeded()
            manualSelectedProfileID =
                await manualProfileSelectionStore.manualSelectedProfileID()
            if manualSelectedProfileID == nil,
               let activeProfileID,
               profiles.contains(where: { $0.id == activeProfileID }) {
                manualSelectedProfileID = activeProfileID
                await manualProfileSelectionStore.saveManualSelectedProfileID(
                    activeProfileID
                )
            }
            clearMissingOrInvalidManualProfileIfNeeded()
            currentNetworkContext = await networkContextSource.currentNetworkContext()
            await refreshSmartConnectionRecommendation(context: currentNetworkContext)
            observeNetworkContext()
            subscriptions = try await subscriptionRepository.subscriptions()
            refreshEffectiveProtocol()
            let authoritativeConnection =
                await connectionManager.refreshAuthoritativeConnection()
            await applyAuthoritativeConnection(authoritativeConnection)
            if authoritativeConnection.hasMultipleActiveManagers == false {
                errorMessage = nil
            }
        } catch is CancellationError {
            return
        } catch {
            connectionState = .failed
            errorMessage = error.localizedDescription
        }
    }

    func applicationDidBecomeActive() async {
        guard activeOperationID == nil else {
            return
        }
        let authoritativeConnection =
            await connectionManager.refreshAuthoritativeConnection()
        await applyAuthoritativeConnection(authoritativeConnection)
    }

    func userDidTapMainConnectionButton() async {
        switch connectionState {
        case .disconnected, .failed, .connected:
            connectionActionHapticFeedback.playMediumImpact()
        case .testing, .connecting, .disconnecting:
            break
        }
        await toggleConnection()
    }

    func cancelCurrentOperation() {
        activeOperationID = nil
    }

    func selectServer(_ server: VPNServer) {
        selectedServer = server
        setActiveProfileID(nil)
        refreshEffectiveProtocol()

        if server.isAvailable == false {
            errorMessage = "This server is currently unavailable."
        } else {
            validateSelectedProtocol()
        }
    }

    func selectProfile(_ profile: VPNProfile) {
        guard profile.isComplete else {
            errorMessage = "Profile is incomplete. Missing: \(profile.missingRequiredFields.joined(separator: ", "))."
            return
        }

        let capability = profile.runtimeCapability
        guard capability.isReady else {
            errorMessage = capability.statusText
            return
        }

        guard profile.isEnabled else {
            errorMessage = "Profile is disabled."
            return
        }

        connectionMode = .manual
        setManualSelectedProfileID(profile.id)
        setActiveProfileID(profile.id)
        selectedProtocol = .manual(profile.protocolType)
        effectiveProtocol = profile.protocolType
        currentMetrics = nil
        errorMessage = nil
    }

    func selectConnectionMode(_ mode: ConnectionSelectionMode) {
        guard connectionMode != mode else { return }
        connectionMode = mode
        errorMessage = nil
        if mode == .automatic {
            Task { @MainActor [weak self] in
                await self?.refreshSmartConnectionRecommendation()
            }
        }
        refreshEffectiveProtocol()
    }

    func selectProtocol(_ protocolSelection: VPNProtocolSelection) {
        selectedProtocol = protocolSelection
        setActiveProfileID(nil)
        refreshEffectiveProtocol()
        validateSelectedProtocol()
    }

    func isProtocolCompatible(_ protocolSelection: VPNProtocolSelection) -> Bool {
        guard let selectedServer else {
            return true
        }

        switch protocolSelection {
        case .automatic:
            return serverSelector.automaticProtocol(for: selectedServer) != nil
        case .manual(let vpnProtocol):
            return selectedServer.supportedProtocols.contains(vpnProtocol)
        }
    }

    func selectBestServer() async {
        guard let operationID = beginOperation(state: .testing) else {
            return
        }

        do {
            let availableServers = servers.isEmpty ? try await serverProvider.fetchServers() : servers
            guard isCurrentOperation(operationID) else { return }
            servers = availableServers
            selectedServer = try await serverSelector.bestServer(from: availableServers, using: serverProber)

            guard isCurrentOperation(operationID) else { return }
            if let selectedServer {
                currentMetrics = try await serverProber.metrics(for: selectedServer)
            }

            refreshEffectiveProtocol()
            if isCurrentOperation(operationID) {
                connectionState = .disconnected
                errorMessage = nil
                finishOperation(operationID)
            }
        } catch is CancellationError {
            cancelIfCurrent(operationID)
        } catch {
            failOperation(operationID, message: error.localizedDescription)
        }
    }

    func toggleConnection() async {
        switch connectionState {
        case .connected:
            await disconnect()
        case .disconnected, .failed:
            await connect()
        case .testing, .connecting, .disconnecting:
            break
        }
    }

    func connect() async {
        guard let operationID = beginOperation(state: .connecting) else {
            return
        }

        currentMetrics = nil
        errorMessage = nil
        do {
            switch connectionMode {
            case .automatic:
                try await connectAutomatically(operationID: operationID)
            case .manual:
                try await connectManually(operationID: operationID)
            }
            guard isCurrentOperation(operationID) else {
                throw CancellationError()
            }
            finishOperation(operationID)
            currentAutomaticAttemptProfileID = nil
            errorMessage = nil
        } catch is CancellationError {
            currentAutomaticAttemptProfileID = nil
            cancelIfCurrent(operationID)
            await connectionTelemetryManager.stop()
        } catch {
            currentAutomaticAttemptProfileID = nil
            failOperation(operationID, message: error.localizedDescription)
            await connectionTelemetryManager.stop()
            await refreshSmartConnectionRecommendation()
        }
    }

    func disconnect() async {
        guard let operationID = beginOperation(state: .disconnecting) else {
            return
        }

        isIntentionalDisconnectInFlight = true
        defer {
            isIntentionalDisconnectInFlight = false
        }
        await finishLearningSession(unexpectedDisconnect: false)
        await connectionManager.disconnect()
        guard isCurrentOperation(operationID) else { return }

        let authoritativeConnection =
            await connectionManager.refreshAuthoritativeConnection()
        guard isCurrentOperation(operationID) else { return }

        currentMetrics = nil
        finishOperation(operationID)
        await applyAuthoritativeConnection(authoritativeConnection)
        await refreshSmartConnectionRecommendation()
        errorMessage = nil
    }

    func parseImportText(_ text: String) async {
        importResult = nil
        importErrorMessage = nil

        do {
            importResult = try await importer.parse(text)
        } catch {
            importErrorMessage = error.localizedDescription
        }
    }

    func reviewNativeConfiguration(
        _ text: String,
        expectedProtocol: VPNProtocol,
        displayName: String
    ) async throws -> VPNImportResult {
        guard expectedProtocol == .wireGuard || expectedProtocol == .amneziaWG else {
            throw VPNImportError.invalidPayload("Select WireGuard or AmneziaWG for a native configuration.")
        }
        var result = try await importer.parse(text)
        guard case .profile(var profile) = result.kind,
              profile.protocolType == expectedProtocol else {
            _ = await discardImportResult(result)
            throw VPNImportError.invalidPayload(
                "The native configuration is \(profileProtocolName(in: result)); select the matching protocol mode."
            )
        }
        let trimmedName = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedName.isEmpty == false {
            profile.name = trimmedName
            profile.updatedAt = Date()
            result.kind = .profile(profile)
            result.displayName = trimmedName
        }
        return result
    }

    func routeImportPayload(data: Data, title: String) async throws -> ImportPayloadRoute {
        let router = ImportPayloadRouter(
            importer: importer,
            subscriptionParser: SubscriptionContentParser(linkParser: importer)
        )
        return try await router.route(data: data, title: title)
    }

    func routeImportPayload(text: String, title: String) async throws -> ImportPayloadRoute {
        let router = ImportPayloadRouter(
            importer: importer,
            subscriptionParser: SubscriptionContentParser(linkParser: importer)
        )
        return try await router.route(text: text, title: title)
    }

    func routeQRCodeImageData(_ data: Data, title: String, detector: QRCodeImageDetecting = VisionQRCodeImageDetector()) async throws -> ImportPayloadRoute {
        let router = ImportPayloadRouter(
            importer: importer,
            subscriptionParser: SubscriptionContentParser(linkParser: importer)
        )
        let processor = QRCodeImageImportProcessor(detector: detector, router: router)
        return try await processor.process(data: data, title: title)
    }

    func qrCodePayloads(in data: Data, detector: QRCodeImageDetecting = VisionQRCodeImageDetector()) async throws -> [String] {
        try await detector.detectPayloads(in: data)
    }

    func saveImportResult() async {
        _ = await saveImportResultAndSelect()
    }

    @discardableResult
    func saveImportResultAndSelect() async -> Bool {
        guard let importResult else {
            return false
        }

        return await saveImportResultAndSelect(importResult)
    }

    @discardableResult
    func saveImportResultAndSelect(_ reviewedResult: VPNImportResult) async -> Bool {

        guard saveOperationID == nil else {
            return false
        }

        do {
            switch reviewedResult.kind {
            case .profile(let profile):
                let preparedReferences = profile.credentialReferences
                inFlightImportedCredentialReferences.formUnion(preparedReferences)
                do {
                    let didSave = try await saveProfileAndSelect(profile)
                    inFlightImportedCredentialReferences.subtract(preparedReferences)
                    if didSave == false {
                        try await deleteUnreferencedCredentialReferences(preparedReferences)
                    }
                    if didSave, importResult?.id == reviewedResult.id {
                        importResult = nil
                    }
                    return didSave
                } catch let saveError {
                    inFlightImportedCredentialReferences.subtract(preparedReferences)
                    do {
                        try await deleteUnreferencedCredentialReferences(preparedReferences)
                    } catch {
                        throw error
                    }
                    throw saveError
                }
            case .subscription(let subscription):
                try await subscriptionRepository.save(subscription)
                subscriptions = try await subscriptionRepository.subscriptions()
            }

            if importResult?.id == reviewedResult.id {
                importResult = nil
            }
            importErrorMessage = nil
            return true
        } catch {
            importErrorMessage = error.localizedDescription
            return false
        }
    }

    @discardableResult
    func discardImportResult(_ reviewedResult: VPNImportResult) async -> Bool {
        guard case .profile(let profile) = reviewedResult.kind else {
            return true
        }

        do {
            try await deleteUnreferencedCredentialReferences(
                profile.credentialReferences,
                additionalReferences: inFlightImportedCredentialReferences
            )
            if importResult?.id == reviewedResult.id {
                importResult = nil
            }
            return true
        } catch {
            importErrorMessage = error.localizedDescription
            return false
        }
    }

    @discardableResult
    func discardImportRoute(_ route: ImportPayloadRoute) async -> Bool {
        switch route {
        case .single(let result):
            return await discardImportResult(result)
        case .batch(let draft):
            let references = draft.profiles.reduce(into: Set<String>()) { references, item in
                references.formUnion(item.profile.credentialReferences)
            }
            do {
                try await deleteUnreferencedCredentialReferences(
                    references,
                    additionalReferences: inFlightImportedCredentialReferences
                )
                return true
            } catch {
                importErrorMessage = error.localizedDescription
                return false
            }
        case .qrPayloads:
            return true
        }
    }

    func saveProfile(_ profile: VPNProfile) async {
        _ = await saveProfileDraft(profile)
    }

    @discardableResult
    func saveProfileDraft(_ profile: VPNProfile, credentialValue: String? = nil) async -> Bool {
        guard saveOperationID == nil else {
            return false
        }

        do {
            var profileToSave = profile
            var createdCredentialReference: String?

            if let credentialValue, credentialValue.isEmpty == false {
                let reference = try await credentialStore.store(credentialValue, label: "\(profile.protocolType.displayName) credential")
                createdCredentialReference = reference
                profileToSave.credentialReference = reference
            }

            do {
                return try await saveProfileAndSelect(profileToSave)
            } catch {
                if let createdCredentialReference {
                    try? await credentialStore.delete(reference: createdCredentialReference)
                }
                throw error
            }
        } catch {
            errorMessage = error.localizedDescription
            profileSaveState = .failed(error.localizedDescription)
            profileSaveMessage = error.localizedDescription
            return false
        }
    }

    func deleteProfile(_ profile: VPNProfile) async {
        do {
            try await profileRepository.delete(id: profile.id)
            do {
                try await runtimeProfileSynchronizer?.profileDeleted(id: profile.id)
            } catch {
                try? await profileRepository.save(profile)
                try? await synchronizeRuntimeProfile(profile)
                throw error
            }
            try await deleteProfileCredentials(profile)
            profiles = try await profileRepository.profiles()
            if activeProfileID == profile.id {
                setActiveProfileID(nil)
            }
            if manualSelectedProfileID == profile.id {
                setManualSelectedProfileID(nil)
            }
            await synchronizeSmartConnectionProfiles()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func renameProfile(_ profile: VPNProfile, to name: String) async {
        do {
            try await profileRepository.rename(id: profile.id, to: name)
            let updatedProfiles = try await profileRepository.profiles()
            guard let updatedProfile = updatedProfiles.first(where: { $0.id == profile.id }) else {
                throw SubscriptionApplicationError.runtimePublicationFailed
            }
            do {
                try await synchronizeRuntimeProfile(updatedProfile)
            } catch {
                try? await profileRepository.save(profile)
                try? await synchronizeRuntimeProfile(profile)
                throw error
            }
            profiles = updatedProfiles
            await synchronizeSmartConnectionProfiles()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func setProfileEnabled(_ profile: VPNProfile, isEnabled: Bool) async {
        do {
            try await profileRepository.setEnabled(isEnabled, id: profile.id)
            let updatedProfiles = try await profileRepository.profiles()
            guard let updatedProfile = updatedProfiles.first(where: { $0.id == profile.id }) else {
                throw SubscriptionApplicationError.runtimePublicationFailed
            }
            do {
                try await synchronizeRuntimeProfile(updatedProfile)
            } catch {
                try? await profileRepository.save(profile)
                try? await synchronizeRuntimeProfile(profile)
                throw error
            }
            profiles = updatedProfiles
            if isEnabled == false, activeProfileID == profile.id {
                setActiveProfileID(nil)
            }
            await synchronizeSmartConnectionProfiles()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func addSubscription(name: String, urlText: String, allowInsecureHTTP: Bool = false) async {
        await saveSubscriptionFromURL(name: name, urlText: urlText, allowInsecureHTTP: allowInsecureHTTP)
    }

    func previewSubscription(urlText: String, name: String, allowInsecureHTTP: Bool = false) async {
        guard subscriptionOperationID == nil else { return }

        let operationID = UUID()
        subscriptionOperationID = operationID
        subscriptionRefreshState = .validating
        importErrorMessage = nil
        subscriptionPreview = nil
        var createdReference: String?

        do {
            let (subscription, url) = try await makeSubscriptionDraft(name: name, urlText: urlText, allowInsecureHTTP: allowInsecureHTTP)
            createdReference = subscription.credentialReference
            guard subscriptionOperationID == operationID else { return }
            subscriptionRefreshState = .downloading
            let preview = try await subscriptionUpdater.preview(subscription, url: url)
            guard subscriptionOperationID == operationID else { return }

            subscriptionPreview = preview
            subscriptionPreviewProfiles = preview.profiles.map(\.profile)
            subscriptionRefreshState = .reviewing
        } catch {
            if let createdReference {
                try? await credentialStore.delete(reference: createdReference)
            }
            importErrorMessage = error.localizedDescription
            subscriptionRefreshState = .failed
        }

        if subscriptionOperationID == operationID {
            subscriptionOperationID = nil
        }
    }

    @discardableResult
    func importSubscriptionFromURL(name: String, urlText: String, allowInsecureHTTP: Bool = false) async -> Bool {
        guard subscriptionOperationID == nil else { return false }

        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        await previewSubscription(
            urlText: urlText,
            name: trimmedName.isEmpty ? "Subscription" : trimmedName,
            allowInsecureHTTP: allowInsecureHTTP
        )

        guard subscriptionPreview != nil else {
            return false
        }

        return await saveSubscriptionPreview() != nil
    }

    @discardableResult
    func saveSubscriptionImportResult(_ subscription: VPNSubscription, sourceText: String? = nil, allowInsecureHTTP: Bool = false) async -> Bool {
        guard subscriptionOperationID == nil else { return false }

        let operationID = UUID()
        subscriptionOperationID = operationID
        subscriptionRefreshState = .downloading
        importErrorMessage = nil
        subscriptionPreview = nil
        var subscriptionToPreview = subscription
        var createdReference: String?

        do {
            let urlText: String
            if let sourceText, sourceText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false {
                urlText = sourceText.trimmingCharacters(in: .whitespacesAndNewlines)
            } else if let reference = subscription.credentialReference,
                      let storedURL = try await credentialStore.secret(for: reference) {
                urlText = storedURL
            } else {
                throw SubscriptionError.credentialsUnavailable
            }

            guard let url = URL(string: urlText),
                  let scheme = url.scheme?.lowercased(),
                  ["http", "https"].contains(scheme),
                  url.host?.isEmpty == false else {
                throw SubscriptionError.invalidURL
            }
            if scheme == "http", allowInsecureHTTP == false {
                throw SubscriptionError.invalidURL
            }

            if subscriptionToPreview.credentialReference == nil {
                let reference = try await credentialStore.store(urlText, label: "Subscription URL")
                createdReference = reference
                subscriptionToPreview.credentialReference = reference
            }
            subscriptionToPreview.sanitizedHost = SecretMasker.sanitizedHost(from: url)
            subscriptionToPreview.sanitizedURLDisplay = SecretMasker.sanitizedURLDisplay(url)

            let preview = try await subscriptionUpdater.preview(subscriptionToPreview, url: url)
            guard subscriptionOperationID == operationID else { return false }
            subscriptionPreview = preview
            subscriptionPreviewProfiles = preview.profiles.map(\.profile)
            subscriptionRefreshState = .reviewing
            subscriptionOperationID = nil
            return await saveSubscriptionPreview() != nil
        } catch {
            if let createdReference {
                try? await credentialStore.delete(reference: createdReference)
            }
            importErrorMessage = error.localizedDescription
            subscriptionRefreshState = .failed
            if subscriptionOperationID == operationID {
                subscriptionOperationID = nil
            }
            return false
        }
    }

    @discardableResult
    func saveSubscriptionPreview() async -> VPNSubscription? {
        guard subscriptionOperationID == nil, var preview = subscriptionPreview else { return nil }

        let operationID = UUID()
        subscriptionOperationID = operationID
        subscriptionRefreshState = .saving
        importErrorMessage = nil

        do {
            let selectedProfiles = preview.profiles.filter { $0.isSelected && $0.state == .valid }.map(\.profile)
            guard selectedProfiles.isEmpty == false else {
                throw SubscriptionError.noProfilesFound
            }

            preview.subscription.profileCount = selectedProfiles.count
            preview.subscription.lastRefreshAt = Date()
            preview.subscription.lastSuccessfulRefreshAt = Date()
            preview.subscription.lastError = nil
            preview.subscription.refreshState = .completed
            try await subscriptionRepository.save(preview.subscription)
            for profile in selectedProfiles {
                try await profileRepository.save(profile)
                try await synchronizeRuntimeProfile(profile)
            }

            profiles = try await profileRepository.profiles()
            await synchronizeSmartConnectionProfiles()
            subscriptions = try await subscriptionRepository.subscriptions()
            subscriptionPreview = nil
            subscriptionPreviewProfiles = []
            subscriptionRefreshState = .completed
            subscriptionOperationID = nil
            return preview.subscription
        } catch {
            importErrorMessage = error.localizedDescription
            subscriptionRefreshState = .failed
            subscriptionOperationID = nil
            return nil
        }
    }

    func refreshSubscription(_ subscription: VPNSubscription) async {
        guard subscriptionOperationID == nil else { return }

        let operationID = UUID()
        subscriptionOperationID = operationID
        refreshingSubscriptionID = subscription.id
        discardedRefreshSubscriptionID = nil
        subscriptionRefreshState = .downloading
        importErrorMessage = nil
        if let pendingPlan = subscriptionUpdatePlan {
            do {
                try await deleteUnreferencedCredentialReferences(
                    incomingCredentialReferences(in: pendingPlan)
                )
            } catch {
                importErrorMessage = error.localizedDescription
                subscriptionRefreshState = .failed
                subscriptionOperationID = nil
                refreshingSubscriptionID = nil
                discardedRefreshSubscriptionID = nil
                return
            }
        }
        subscriptionUpdatePlan = nil

        do {
            guard let reference = subscription.credentialReference,
                  let urlText = try await credentialStore.secret(for: reference),
                  let url = URL(string: urlText) else {
                throw SubscriptionError.credentialsUnavailable
            }

            let plan = try await subscriptionUpdater.planRefresh(subscription, existingProfiles: profiles, url: url)
            if discardedRefreshSubscriptionID == subscription.id {
                try await deleteUnreferencedCredentialReferences(incomingCredentialReferences(in: plan))
                subscriptionUpdatePlan = nil
                subscriptionRefreshState = .cancelled
                importErrorMessage = nil
                subscriptionOperationID = nil
                refreshingSubscriptionID = nil
                discardedRefreshSubscriptionID = nil
                return
            }
            guard subscriptionOperationID == operationID else {
                try await deleteUnreferencedCredentialReferences(incomingCredentialReferences(in: plan))
                return
            }

            subscriptionUpdatePlan = plan
            subscriptionRefreshState = .reviewing
        } catch {
            var updatedSubscription = subscription
            updatedSubscription.lastRefreshAt = Date()
            updatedSubscription.lastError = error.localizedDescription
            updatedSubscription.refreshState = .failed
            try? await subscriptionRepository.save(updatedSubscription)
            subscriptions = (try? await subscriptionRepository.subscriptions()) ?? subscriptions
            importErrorMessage = error.localizedDescription
            subscriptionRefreshState = .failed
        }

        if subscriptionOperationID == operationID {
            subscriptionOperationID = nil
            refreshingSubscriptionID = nil
            discardedRefreshSubscriptionID = nil
        }
    }

    func applySubscriptionUpdate(missingPolicy: MissingSubscriptionProfilePolicy = .keep) async {
        guard subscriptionOperationID == nil, let plan = subscriptionUpdatePlan else { return }

        let operationID = UUID()
        subscriptionOperationID = operationID
        subscriptionRefreshState = .saving

        let profilesBeforeUpdate: [VPNProfile]
        let subscriptionsBeforeUpdate: [VPNSubscription]
        do {
            profilesBeforeUpdate = try await profileRepository.profiles()
            subscriptionsBeforeUpdate = try await subscriptionRepository.subscriptions()
        } catch {
            importErrorMessage = error.localizedDescription
            subscriptionRefreshState = .failed
            subscriptionOperationID = nil
            return
        }

        let referencesBeforeUpdate = credentialReferences(
            profiles: profilesBeforeUpdate,
            subscriptions: subscriptionsBeforeUpdate
        )
        let preparedReferences = incomingCredentialReferences(in: plan)
            .subtracting(referencesBeforeUpdate)
        let supersededReferences = supersededCredentialReferences(
            in: plan,
            missingPolicy: missingPolicy
        )
        var savedProfileIDs: Set<UUID> = []
        var deletedProfileIDs: Set<UUID> = []
        var operationError: (any Error)?

        do {
            for change in plan.changes where change.isSelected {
                switch try await applySubscriptionChange(change, missingPolicy: missingPolicy) {
                case .saved(let profileID):
                    savedProfileIDs.insert(profileID)
                case .deleted(let profileID):
                    deletedProfileIDs.insert(profileID)
                case .none:
                    break
                }
            }
        } catch {
            operationError = error
        }

        var committedProfiles: [VPNProfile]?
        do {
            let storedProfiles = try await profileRepository.profiles()
            committedProfiles = storedProfiles
            profiles = storedProfiles
            await synchronizeSmartConnectionProfiles()
            subscriptions = try await subscriptionRepository.subscriptions()
        } catch {
            operationError = error
        }

        var runtimeReferences: Set<String>?
        if let runtimeProfileSynchronizer, let committedProfiles {
            do {
                for profileID in savedProfileIDs.sorted(by: { $0.uuidString < $1.uuidString }) {
                    guard let profile = committedProfiles.first(where: { $0.id == profileID }) else {
                        continue
                    }
                    guard profile.isEnabled else {
                        try await runtimeProfileSynchronizer.profileDeleted(id: profileID)
                        continue
                    }
                    let summary = try await runtimeProfileSynchronizer.profileSaved(profile)
                    if summary.publishedProfileIDs.contains(profileID) == false {
                        throw SubscriptionApplicationError.runtimePublicationFailed
                    }
                }
                for profileID in deletedProfileIDs.sorted(by: { $0.uuidString < $1.uuidString }) {
                    try await runtimeProfileSynchronizer.profileDeleted(id: profileID)
                }
                runtimeReferences = try await runtimeProfileSynchronizer.credentialReferences()
            } catch {
                operationError = error
                // Publication failure does not roll durable state back. If the
                // runtime store is still readable, use its actual references as
                // cleanup guards; otherwise retain superseded credentials.
                runtimeReferences = try? await runtimeProfileSynchronizer.credentialReferences()
            }
        }

        do {
            // Prepared references are published only after a durable profile save,
            // so any one not referenced by durable state is safe to roll back.
            try await deleteUnreferencedCredentialReferences(preparedReferences)
        } catch {
            operationError = error
        }

        if let runtimeReferences {
            do {
                try await deleteUnreferencedCredentialReferences(
                    supersededReferences,
                    additionalReferences: runtimeReferences
                )
            } catch {
                operationError = error
            }
        }

        do {
            var finalizedSubscription = plan.subscription
            finalizedSubscription.lastRefreshAt = Date()
            finalizedSubscription.profileCount = (committedProfiles ?? profilesBeforeUpdate).filter {
                $0.sourceSubscriptionID == plan.subscription.id
            }.count
            if let currentError = operationError {
                finalizedSubscription.lastError = currentError.localizedDescription
                finalizedSubscription.refreshState = .failed
            } else {
                finalizedSubscription.lastSuccessfulRefreshAt = Date()
                finalizedSubscription.lastError = nil
                finalizedSubscription.refreshState = .completed
            }
            try await subscriptionRepository.save(finalizedSubscription)
            subscriptions = try await subscriptionRepository.subscriptions()
        } catch {
            operationError = error
        }

        // A failed application may have rolled back prepared references. Force a
        // fresh provider fetch rather than retaining a plan with invalid handles.
        subscriptionUpdatePlan = nil
        if let operationError {
            importErrorMessage = operationError.localizedDescription
            subscriptionRefreshState = .failed
        } else {
            subscriptionRefreshState = .completed
            importErrorMessage = nil
        }

        if subscriptionOperationID == operationID {
            subscriptionOperationID = nil
        }
    }

    func discardSubscriptionUpdate(for subscriptionID: UUID) async {
        if subscriptionOperationID != nil,
           refreshingSubscriptionID == subscriptionID,
           subscriptionRefreshState == .downloading {
            discardedRefreshSubscriptionID = subscriptionID
            subscriptionRefreshState = .cancelled
            return
        }

        guard subscriptionOperationID == nil,
              let plan = subscriptionUpdatePlan,
              plan.subscription.id == subscriptionID else {
            return
        }

        do {
            try await deleteUnreferencedCredentialReferences(incomingCredentialReferences(in: plan))
            subscriptionUpdatePlan = nil
            subscriptionRefreshState = .cancelled
        } catch {
            importErrorMessage = error.localizedDescription
            subscriptionRefreshState = .failed
        }
    }

    func saveSubscriptionFromURL(name: String, urlText: String, allowInsecureHTTP: Bool = false) async {
        var createdReference: String?
        do {
            let (subscription, _) = try await makeSubscriptionDraft(name: name, urlText: urlText, allowInsecureHTTP: allowInsecureHTTP)
            createdReference = subscription.credentialReference
            try await subscriptionRepository.save(subscription)
            subscriptions = try await subscriptionRepository.subscriptions()
            importErrorMessage = nil
        } catch {
            if let createdReference {
                try? await credentialStore.delete(reference: createdReference)
            }
            importErrorMessage = error.localizedDescription
        }
    }

    func deleteSubscription(_ subscription: VPNSubscription, mode: VPNSubscriptionRemovalMode = .deleteProfiles) async {
        do {
            let linkedProfiles = profiles.filter { $0.sourceSubscriptionID == subscription.id }
            for profile in linkedProfiles {
                switch mode {
                case .deleteProfiles:
                    try await profileRepository.delete(id: profile.id)
                    try await runtimeProfileSynchronizer?.profileDeleted(id: profile.id)
                    try await deleteProfileCredentials(profile)
                    if activeProfileID == profile.id {
                        setActiveProfileID(nil)
                    }
                case .keepProfiles:
                    var localProfile = profile
                    localProfile.source = .importedURL
                    localProfile.sourceSubscriptionID = nil
                    localProfile.externalIdentity = nil
                    localProfile.lastSeenAt = nil
                    try await profileRepository.save(localProfile)
                    try await synchronizeRuntimeProfile(localProfile)
                }
            }

            try await subscriptionRepository.delete(id: subscription.id)
            if let reference = subscription.credentialReference {
                try await deleteUnreferencedCredentialReferences([reference])
            }
            profiles = try await profileRepository.profiles()
            await synchronizeSmartConnectionProfiles()
            subscriptions = try await subscriptionRepository.subscriptions()
        } catch {
            importErrorMessage = error.localizedDescription
        }
    }

    func setSubscriptionEnabled(_ subscription: VPNSubscription, isEnabled: Bool) async {
        do {
            try await subscriptionRepository.setEnabled(isEnabled, id: subscription.id)
            subscriptions = try await subscriptionRepository.subscriptions()
        } catch {
            importErrorMessage = error.localizedDescription
        }
    }

    func renameSubscription(_ subscription: VPNSubscription, to name: String) async {
        do {
            try await subscriptionRepository.rename(id: subscription.id, to: name)
            subscriptions = try await subscriptionRepository.subscriptions()
        } catch {
            importErrorMessage = error.localizedDescription
        }
    }

    func setSubscriptionPreviewSelection(id: SubscriptionProfilePreview.ID, isSelected: Bool) {
        guard var preview = subscriptionPreview,
              let index = preview.profiles.firstIndex(where: { $0.id == id }) else {
            return
        }
        preview.profiles[index].isSelected = isSelected && preview.profiles[index].state == .valid
        subscriptionPreview = preview
    }

    func setAllSubscriptionPreviewProfilesSelected(_ isSelected: Bool) {
        guard var preview = subscriptionPreview else { return }
        preview.profiles = preview.profiles.map { item in
            var updated = item
            updated.isSelected = isSelected && item.state == .valid
            return updated
        }
        subscriptionPreview = preview
    }

    func cancelSubscriptionFlow() async {
        var candidateReferences = Set<String>()
        if let reference = subscriptionPreview?.providerURLReference, reference.isEmpty == false {
            candidateReferences.insert(reference)
        }
        if let preview = subscriptionPreview {
            candidateReferences.formUnion(
                preview.profiles.reduce(into: Set<String>()) { references, item in
                    references.formUnion(item.profile.credentialReferences)
                }
            )
        }
        if let plan = subscriptionUpdatePlan {
            candidateReferences.formUnion(incomingCredentialReferences(in: plan))
        }
        do {
            try await deleteUnreferencedCredentialReferences(candidateReferences)
            subscriptionPreview = nil
            subscriptionUpdatePlan = nil
            subscriptionPreviewProfiles = []
            subscriptionRefreshState = .cancelled
        } catch {
            importErrorMessage = error.localizedDescription
            subscriptionRefreshState = .failed
        }
        subscriptionOperationID = nil
        refreshingSubscriptionID = nil
        discardedRefreshSubscriptionID = nil
    }

    private func makeSubscriptionDraft(name: String, urlText: String, allowInsecureHTTP: Bool = false) async throws -> (VPNSubscription, URL) {
        let trimmedURL = urlText.trimmingCharacters(in: .whitespacesAndNewlines)
        let result = try await importer.parse(trimmedURL)
        guard case .subscription(var subscription) = result.kind, let url = URL(string: trimmedURL) else {
            throw SubscriptionError.invalidURL
        }

        if url.scheme?.lowercased() == "http", allowInsecureHTTP == false {
            throw SubscriptionError.invalidURL
        }

        subscription.name = name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? subscription.name : name
        subscription.sanitizedHost = SecretMasker.sanitizedHost(from: url)
        subscription.sanitizedURLDisplay = SecretMasker.sanitizedURLDisplay(url)

        if subscription.credentialReference == nil {
            subscription.credentialReference = try await credentialStore.store(trimmedURL, label: "Subscription URL")
        }

        return (subscription, url)
    }

    private func applySubscriptionChange(
        _ change: SubscriptionProfileChange,
        missingPolicy: MissingSubscriptionProfilePolicy
    ) async throws -> SubscriptionProfileMutation {
        switch change.kind {
        case .added:
            if let incomingProfile = change.incomingProfile {
                try await profileRepository.save(incomingProfile)
                return .saved(incomingProfile.id)
            }
        case .updated:
            if let incomingProfile = change.incomingProfile, let existingProfile = change.existingProfile {
                try await profileRepository.save(mergeProviderUpdate(existing: existingProfile, incoming: incomingProfile))
                return .saved(existingProfile.id)
            }
        case .missing:
            guard let existingProfile = change.existingProfile else { return .none }
            switch missingPolicy {
            case .keep:
                break
            case .disable:
                try await profileRepository.setEnabled(false, id: existingProfile.id)
                return .saved(existingProfile.id)
            case .remove:
                try await profileRepository.delete(id: existingProfile.id)
                if activeProfileID == existingProfile.id {
                    setActiveProfileID(nil)
                }
                return .deleted(existingProfile.id)
            }
        case .unchanged, .invalid, .duplicate:
            break
        }
        return .none
    }

    private func mergeProviderUpdate(existing: VPNProfile, incoming: VPNProfile) -> VPNProfile {
        var merged = incoming
        merged.id = existing.id
        merged.name = existing.customDisplayName ?? existing.name
        merged.createdAt = existing.createdAt
        merged.importedAt = existing.importedAt ?? incoming.importedAt
        merged.customDisplayName = existing.customDisplayName
        merged.isEnabled = existing.isEnabled
        merged.isFavorite = existing.isFavorite
        merged.localNotes = existing.localNotes
        merged.routingSettings = existing.routingSettings
        return merged
    }

    private func deleteProfileCredentials(_ profile: VPNProfile) async throws {
        try await deleteUnreferencedCredentialReferences(profile.credentialReferences)
    }

    private func incomingCredentialReferences(in plan: SubscriptionUpdatePlan) -> Set<String> {
        plan.changes.reduce(into: Set<String>()) { references, change in
            if let incomingProfile = change.incomingProfile {
                references.formUnion(incomingProfile.credentialReferences)
            }
        }
    }

    private func supersededCredentialReferences(
        in plan: SubscriptionUpdatePlan,
        missingPolicy: MissingSubscriptionProfilePolicy
    ) -> Set<String> {
        plan.changes.reduce(into: Set<String>()) { references, change in
            guard change.isSelected, let existingProfile = change.existingProfile else {
                return
            }
            switch change.kind {
            case .updated:
                let incomingReferences = change.incomingProfile?.credentialReferences ?? []
                references.formUnion(existingProfile.credentialReferences.subtracting(incomingReferences))
            case .missing where missingPolicy == .remove:
                references.formUnion(existingProfile.credentialReferences)
            case .added, .unchanged, .missing, .invalid, .duplicate:
                break
            }
        }
    }

    private func credentialReferences(
        profiles: [VPNProfile],
        subscriptions: [VPNSubscription]
    ) -> Set<String> {
        var references = profiles.reduce(into: Set<String>()) { references, profile in
            references.formUnion(profile.credentialReferences)
        }
        references.formUnion(subscriptions.compactMap(\.credentialReference))
        return references
    }

    private func deleteUnreferencedCredentialReferences(
        _ candidates: Set<String>,
        additionalReferences: Set<String> = []
    ) async throws {
        guard candidates.isEmpty == false else { return }
        let storedProfiles = try await profileRepository.profiles()
        let storedSubscriptions = try await subscriptionRepository.subscriptions()
        var referenced = credentialReferences(
            profiles: storedProfiles,
            subscriptions: storedSubscriptions
        )
        referenced.formUnion(additionalReferences)

        var firstError: (any Error)?
        for reference in candidates.subtracting(referenced).sorted() {
            do {
                try await credentialStore.delete(reference: reference)
            } catch {
                if firstError == nil {
                    firstError = error
                }
            }
        }
        if let firstError {
            throw firstError
        }
    }

    private func connectManually(operationID: UUID) async throws {
        guard let profile = manualSelectedProfile else {
            throw SmartConnectionAttemptError.noManualProfileSelected
        }
        guard SmartConnectionCandidatePlanner.isEligible(profile) else {
            throw SmartConnectionAttemptError.profileUnavailable
        }

        try await attemptConnection(
            profile: profile,
            context: currentNetworkContext,
            operationID: operationID
        )
    }

    private func connectAutomatically(operationID: UUID) async throws {
        await refreshSmartConnectionRecommendation()
        let plan = automaticCandidatePlan
        guard plan.candidateIDs.isEmpty == false else {
            throw SmartConnectionAttemptError.noEligibleProfiles
        }

        // This profile-value map and candidate order form one immutable attempt
        // snapshot. A profile can appear at most once and the plan is bounded.
        var profilesByID: [UUID: VPNProfile] = [:]
        for profile in profiles where profilesByID[profile.id] == nil {
            profilesByID[profile.id] = profile
        }

        var lastFailure: (any Error)?
        for profileID in plan.candidateIDs {
            try Task.checkCancellation()
            guard isCurrentOperation(operationID) else {
                throw CancellationError()
            }
            guard let profile = profilesByID[profileID] else {
                continue
            }

            currentAutomaticAttemptProfileID = profileID
            if plan.explorationCandidateID == profileID {
                await learningStore.recordExploration(
                    profileID: profile.id,
                    protocolType: profile.protocolType,
                    context: plan.context,
                    at: smartConnectionClock.now()
                )
                smartConnectionLearning = await learningStore.snapshot(for: profiles)
            }
            do {
                try await attemptConnection(
                    profile: profile,
                    context: plan.context,
                    operationID: operationID
                )
                return
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                lastFailure = error
                guard isCurrentOperation(operationID) else {
                    throw CancellationError()
                }
                // The production managers already clean failed starts. This
                // explicit bounded teardown also prevents residual state from
                // contaminating the next candidate attempt.
                await connectionManager.disconnect()
            }
        }

        throw lastFailure ?? SmartConnectionAttemptError.noEligibleProfiles
    }

    private func attemptConnection(
        profile: VPNProfile,
        context: NetworkContext,
        operationID: UUID
    ) async throws {
        guard SmartConnectionCandidatePlanner.isEligible(profile) else {
            throw SmartConnectionAttemptError.profileUnavailable
        }

        activeProfileID = profile.id
        await activeProfileStore.saveActiveProfileID(profile.id)
        selectedProtocol = .manual(profile.protocolType)
        effectiveProtocol = profile.protocolType
        let startedAt = smartConnectionClock.now()

        do {
            try Task.checkCancellation()
            try await connectionManager.connect(using: profile)
            guard isCurrentOperation(operationID) else {
                throw CancellationError()
            }

            let authoritativeConnection =
                await connectionManager.authoritativeConnection()
            guard isCurrentOperation(operationID) else {
                throw CancellationError()
            }
            guard authoritativeConnection.state == .connected,
                  authoritativeConnection.profileID == nil
                    || authoritativeConnection.profileID == profile.id else {
                throw SmartConnectionAttemptError.didNotReachConnectedState
            }

            let connectedAt = smartConnectionClock.now()
            await learningStore.recordConnectionSuccess(
                profileID: profile.id,
                protocolType: profile.protocolType,
                context: context,
                connectDuration: max(0, connectedAt.timeIntervalSince(startedAt)),
                at: connectedAt
            )
            smartConnectionLearning = await learningStore.snapshot(for: profiles)
            learningSession = SmartConnectionLearningSession(
                profileID: profile.id,
                protocolType: profile.protocolType,
                context: context,
                connectedAt: connectedAt,
                telemetrySessionID: nil,
                checkpointRuntimeSeconds: nil,
                countsInitialRuntimeFromZero: true
            )
            await applyAuthoritativeConnection(authoritativeConnection)
        } catch {
            if shouldPenalizeConnectionFailure(
                error,
                profileID: profile.id,
                operationID: operationID
            ) {
                let failureDate = smartConnectionClock.now()
                await learningStore.recordConnectionFailure(
                    profileID: profile.id,
                    protocolType: profile.protocolType,
                    context: context,
                    at: failureDate
                )
                smartConnectionLearning = await learningStore.snapshot(for: profiles)
            }
            throw error
        }
    }

    private func shouldPenalizeConnectionFailure(
        _ error: any Error,
        profileID: UUID,
        operationID: UUID
    ) -> Bool {
        if error is CancellationError || Task.isCancelled {
            return false
        }
        let nsError = error as NSError
        if nsError.domain == NSURLErrorDomain,
           nsError.code == NSURLErrorCancelled {
            return false
        }
        guard isCurrentOperation(operationID),
              profiles.contains(where: { $0.id == profileID }) else {
            return false
        }
        return true
    }

    private func refreshSmartConnectionRecommendation(
        context suppliedContext: NetworkContext? = nil
    ) async {
        // Lifecycle defense: an unknown inventory is not an authoritative
        // empty inventory and cannot trigger persistent deletion pruning.
        guard hasLoadedProfiles else { return }
        let context = suppliedContext ?? currentNetworkContext
        currentNetworkContext = context
        let learning = await learningStore.snapshot(for: profiles)
        smartConnectionLearning = learning
        let plan = candidatePlanner.plan(
            profiles: profiles,
            context: context,
            learning: learning,
            now: smartConnectionClock.now()
        )
        automaticCandidatePlan = plan
        automaticRecommendedProfileID = plan.rankedCandidates.first?.profileID
    }

    private func synchronizeSmartConnectionProfiles() async {
        clearMissingOrInvalidManualProfileIfNeeded()
        await learningStore.prune(profiles: profiles)
        await refreshSmartConnectionRecommendation(context: currentNetworkContext)
    }

    private func refreshEffectiveProtocol() {
        if let selectedProfile {
            effectiveProtocol = selectedProfile.protocolType
            return
        }

        guard let selectedServer else {
            effectiveProtocol = nil
            return
        }

        switch selectedProtocol {
        case .automatic:
            effectiveProtocol = serverSelector.automaticProtocol(for: selectedServer)
        case .manual(let vpnProtocol):
            effectiveProtocol = selectedServer.supportedProtocols.contains(vpnProtocol) ? vpnProtocol : nil
        }
    }

    private func validateSelectedProtocol() {
        guard selectedProfile == nil else {
            return
        }

        if selectedProtocol != .automatic && effectiveProtocol == nil {
            errorMessage = "Selected protocol is not supported by this server."
        } else {
            errorMessage = nil
        }
    }

    private func observeConnectionState() {
        stateObservationTask = Task { @MainActor [weak self, connectionManager] in
            for await _ in connectionManager.stateUpdates() {
                let authoritativeConnection =
                    await connectionManager.authoritativeConnection()
                guard let self, self.activeOperationID == nil else {
                    continue
                }
                // A failed user Start action owns its final presentation. A
                // queued teardown notification from the last bounded attempt
                // must not immediately erase that error with `.disconnected`.
                // Foreground restoration still performs an explicit refresh.
                if self.connectionState == .failed,
                   authoritativeConnection.state == .disconnected,
                   authoritativeConnection.isSystemActive == false {
                    continue
                }
                await self.applyAuthoritativeConnection(authoritativeConnection)
            }
        }
    }

    private func observeConnectionTelemetry() {
        telemetryObservationTask = Task {
            @MainActor [weak self, connectionTelemetryManager] in
            for await snapshot in connectionTelemetryManager.updates() {
                guard let self else {
                    return
                }
                self.connectionTelemetry = snapshot
                await self.consumeTelemetryForLearning(snapshot)
            }
        }
    }

    private func observeNetworkContext() {
        guard hasLoadedProfiles, networkContextObservationTask == nil else {
            return
        }
        networkContextObservationTask = Task {
            @MainActor [weak self, networkContextSource] in
            for await context in networkContextSource.networkContextUpdates() {
                guard let self else { return }
                self.scheduleNetworkContextPromotion(context)
            }
        }
    }

    private func scheduleNetworkContextPromotion(_ context: NetworkContext) {
        networkContextPromotionTask?.cancel()
        networkContextPromotionTask = nil
        guard currentNetworkContext != context else {
            // Returning to the authoritative context is still a newer event.
            // It cancels a pending transient promotion without starting a timer.
            return
        }
        networkContextPromotionTask = Task {
            @MainActor [weak self, networkContextDebounceSleeper] in
            guard let self else { return }
            do {
                try await networkContextDebounceSleeper.sleep(
                    for: self.networkContextDebounceDuration
                )
                try Task.checkCancellation()
            } catch {
                return
            }
            guard self.currentNetworkContext != context else { return }
            self.currentNetworkContext = context
            guard self.activeOperationID == nil,
                  self.connectionState == .disconnected
                    || self.connectionState == .failed else {
                return
            }
            await self.refreshSmartConnectionRecommendation(context: context)
        }
    }

    private func consumeTelemetryForLearning(
        _ snapshot: DashboardConnectionTelemetrySnapshot
    ) async {
        guard var session = learningSession,
              let runtimeSeconds = snapshot.runtimeSeconds else {
            return
        }

        if let sessionID = snapshot.sessionID,
           session.telemetrySessionID != sessionID {
            session.telemetrySessionID = sessionID
            session.checkpointRuntimeSeconds =
                session.countsInitialRuntimeFromZero ? 0 : runtimeSeconds
            session.countsInitialRuntimeFromZero = false
            let commitKey = SmartConnectionLearningTransform.commitKey(
                profileID: session.profileID,
                protocolType: session.protocolType,
                context: session.context,
                sessionID: sessionID
            )
            let pendingRecord = smartConnectionLearning.pendingQualityRecords?
                .first { $0.commitKey == commitKey }
            session.qualityAccumulator = SmartConnectionSessionQualityAccumulator(
                pendingRecord: pendingRecord
            )
            session.anomalyDetector = SmartConnectionAnomalyDetector()
            smartConnectionQualityState = .normal
        }

        guard session.telemetrySessionID != nil,
              session.telemetrySessionID == snapshot.sessionID else {
            return
        }

        let latency = snapshot.latencyMilliseconds.map(Double.init)
        session.qualityAccumulator.record(
            latencyMilliseconds: latency,
            packetLossPercent: snapshot.packetLossPercent
        )
        let baseline = smartConnectionLearning.contextStatistics(
            profileID: session.profileID,
            protocolType: session.protocolType,
            context: session.context
        )
        smartConnectionQualityState = session.anomalyDetector.observe(
            latencyMilliseconds: latency,
            packetLossPercent: snapshot.packetLossPercent,
            baselineLatencyMilliseconds: baseline.ewmaLatencyMilliseconds,
            baselinePacketLossPercent: baseline.ewmaPacketLossPercent
        )
        learningSession = session

        guard let checkpointRuntimeSeconds = session.checkpointRuntimeSeconds,
              runtimeSeconds - checkpointRuntimeSeconds >= 60 else {
            return
        }

        let summary = SmartConnectionSessionSummary(
            additionalSuccessfulSessionSeconds: max(
                0,
                runtimeSeconds - checkpointRuntimeSeconds
            ),
            latencyMilliseconds: session.qualityAccumulator.latencyMeanMilliseconds,
            packetLossPercent: session.qualityAccumulator.packetLossMeanPercent,
            sessionEnded: false,
            unexpectedDisconnect: false,
            sessionID: session.telemetrySessionID,
            tailLatencyMilliseconds:
                session.qualityAccumulator.tailLatencyMilliseconds,
            tailPacketLossPercent:
                session.qualityAccumulator.tailPacketLossPercent,
            qualityAggregate: session.qualityAccumulator.qualityAggregate,
            qualityAggregateIsCumulative: true
        )
        session.checkpointRuntimeSeconds = runtimeSeconds
        learningSession = session
        await learningStore.recordSessionSummary(
            summary,
            profileID: session.profileID,
            protocolType: session.protocolType,
            context: session.context,
            at: smartConnectionClock.now()
        )
        smartConnectionLearning = await learningStore.snapshot(for: profiles)
    }

    private func finishLearningSession(unexpectedDisconnect: Bool) async {
        guard var session = learningSession else { return }
        learningSession = nil

        let telemetryMatches = session.telemetrySessionID != nil
            && session.telemetrySessionID == connectionTelemetry.sessionID
        if telemetryMatches {
            session.qualityAccumulator.record(
                latencyMilliseconds: session.qualityAccumulator.latencyValidSampleCount == 0
                    ? connectionTelemetry.latencyMilliseconds.map(Double.init)
                    : nil,
                packetLossPercent: session.qualityAccumulator.packetLossValidSampleCount == 0
                    ? connectionTelemetry.packetLossPercent
                    : nil
            )
        }
        let runtimeSeconds = telemetryMatches
            ? connectionTelemetry.runtimeSeconds
            : nil
        let checkpoint = session.checkpointRuntimeSeconds ?? runtimeSeconds ?? 0
        let summary = SmartConnectionSessionSummary(
            additionalSuccessfulSessionSeconds: max(
                0,
                (runtimeSeconds ?? checkpoint) - checkpoint
            ),
            latencyMilliseconds: session.qualityAccumulator.latencyMeanMilliseconds,
            packetLossPercent: session.qualityAccumulator.packetLossMeanPercent,
            sessionEnded: true,
            unexpectedDisconnect: unexpectedDisconnect,
            sessionID: session.telemetrySessionID,
            tailLatencyMilliseconds:
                session.qualityAccumulator.tailLatencyMilliseconds,
            tailPacketLossPercent:
                session.qualityAccumulator.tailPacketLossPercent,
            qualityAggregate: session.qualityAccumulator.qualityAggregate,
            qualityAggregateIsCumulative: true
        )
        await learningStore.recordSessionSummary(
            summary,
            profileID: session.profileID,
            protocolType: session.protocolType,
            context: session.context,
            at: smartConnectionClock.now()
        )
        smartConnectionLearning = await learningStore.snapshot(for: profiles)
        smartConnectionQualityState = .normal
    }

    private func applyAuthoritativeConnection(
        _ authoritativeConnection: VPNAuthoritativeConnection
    ) async {
        if let learningSession,
           authoritativeConnection.isSystemActive,
           let authoritativeProfileID = authoritativeConnection.profileID,
           authoritativeProfileID != learningSession.profileID,
           isIntentionalDisconnectInFlight == false {
            await finishLearningSession(unexpectedDisconnect: true)
        }
        if learningSession != nil,
           authoritativeConnection.state == .disconnected
            || authoritativeConnection.state == .failed,
           isIntentionalDisconnectInFlight == false {
            await finishLearningSession(unexpectedDisconnect: true)
        }

        connectionState = authoritativeConnection.state
        hasAuthoritativeManagerConflict =
            authoritativeConnection.hasMultipleActiveManagers

        if authoritativeConnection.isSystemActive,
           let restoredProfileID = authoritativeConnection.profileID,
           let profile = profiles.first(where: { $0.id == restoredProfileID }) {
            if activeProfileID != restoredProfileID {
                activeProfileID = restoredProfileID
                await activeProfileStore.saveActiveProfileID(restoredProfileID)
            }
            selectedProtocol = .manual(profile.protocolType)
            effectiveProtocol = profile.protocolType
        }

        if authoritativeConnection.hasMultipleActiveManagers {
            errorMessage = "Multiple active VPN configurations were reported by iOS. No connection was started or stopped."
        }

        await connectionTelemetryManager.reconcile(with: authoritativeConnection)

        if authoritativeConnection.state == .connected,
           learningSession == nil,
           let restoredProfileID = authoritativeConnection.profileID,
           let profile = profiles.first(where: { $0.id == restoredProfileID }) {
            learningSession = SmartConnectionLearningSession(
                profileID: profile.id,
                protocolType: profile.protocolType,
                context: currentNetworkContext,
                connectedAt: smartConnectionClock.now(),
                telemetrySessionID: nil,
                checkpointRuntimeSeconds: nil,
                countsInitialRuntimeFromZero: false
            )
        }

        if activeOperationID == nil,
           authoritativeConnection.state == .disconnected
            || authoritativeConnection.state == .failed {
            await refreshSmartConnectionRecommendation()
        }
    }

    private func saveProfileAndSelect(_ profile: VPNProfile) async throws -> Bool {
        guard profile.isComplete else {
            profileSaveState = .incomplete(profile.missingRequiredFields)
            profileSaveMessage = "Profile is incomplete. Missing: \(profile.missingRequiredFields.joined(separator: ", "))."
            return false
        }

        let capability = profile.runtimeCapability
        guard capability.isReady else {
            profileSaveState = .unsupported(capability.statusText)
            profileSaveMessage = capability.statusText
            return false
        }

        let operationID = UUID()
        saveOperationID = operationID
        profileSaveState = .saving
        profileSaveMessage = nil

        do {
            let previousProfile = try await profileRepository.profiles().first { $0.id == profile.id }
            try await profileRepository.save(profile)
            do {
                try await synchronizeRuntimeProfile(profile)
            } catch {
                if let previousProfile {
                    try? await profileRepository.save(previousProfile)
                    try? await synchronizeRuntimeProfile(previousProfile)
                } else {
                    try? await profileRepository.delete(id: profile.id)
                    try? await runtimeProfileSynchronizer?.profileDeleted(id: profile.id)
                }
                throw error
            }
            guard saveOperationID == operationID else {
                return false
            }

            profiles = try await profileRepository.profiles()
            // Persist the active profile deterministically (await) so the store
            // reflects it before this call returns — no fire-and-forget race.
            activeProfileID = profile.id
            await activeProfileStore.saveActiveProfileID(profile.id)
            manualSelectedProfileID = profile.id
            await manualProfileSelectionStore.saveManualSelectedProfileID(
                profile.id
            )
            connectionMode = .manual
            selectedProtocol = .manual(profile.protocolType)
            effectiveProtocol = profile.protocolType
            currentMetrics = nil
            importErrorMessage = nil
            profileSaveState = .saved
            profileSaveMessage = "Profile saved"
            saveOperationID = nil
            await learningStore.prune(profiles: profiles)
            await refreshSmartConnectionRecommendation()
            return true
        } catch {
            guard saveOperationID == operationID else {
                return false
            }
            profileSaveState = .failed(error.localizedDescription)
            profileSaveMessage = error.localizedDescription
            saveOperationID = nil
            throw error
        }
    }

    private func setActiveProfileID(_ id: UUID?) {
        activeProfileID = id
        Task {
            await activeProfileStore.saveActiveProfileID(id)
        }
    }

    private func setManualSelectedProfileID(_ id: UUID?) {
        manualSelectedProfileID = id
        Task {
            await manualProfileSelectionStore.saveManualSelectedProfileID(id)
        }
    }

    private func synchronizeRuntimeProfile(_ profile: VPNProfile) async throws {
        guard let runtimeProfileSynchronizer else { return }
        guard profile.isEnabled else {
            try await runtimeProfileSynchronizer.profileDeleted(id: profile.id)
            return
        }
        guard profile.runtimeCapability.isReady else {
            try await runtimeProfileSynchronizer.profileDeleted(id: profile.id)
            return
        }
        let summary = try await runtimeProfileSynchronizer.profileSaved(profile)
        guard summary.publishedProfileIDs.contains(profile.id) else {
            throw SubscriptionApplicationError.runtimePublicationFailed
        }
    }

    private func profileProtocolName(in result: VPNImportResult) -> String {
        guard case .profile(let profile) = result.kind else {
            return "not a VPN profile"
        }
        return profile.protocolType.displayName
    }

    private func clearMissingOrInvalidActiveProfileIfNeeded() {
        guard let activeProfileID else {
            return
        }

        guard let profile = profiles.first(where: { $0.id == activeProfileID }),
              profile.isEnabled,
              profile.runtimeCapability.isReady else {
            setActiveProfileID(nil)
            return
        }

        selectedProtocol = .manual(profile.protocolType)
        effectiveProtocol = profile.protocolType
    }

    private func clearMissingOrInvalidManualProfileIfNeeded() {
        guard let manualSelectedProfileID else { return }
        guard profiles.contains(where: { $0.id == manualSelectedProfileID }) else {
            self.manualSelectedProfileID = nil
            Task {
                await manualProfileSelectionStore.saveManualSelectedProfileID(nil)
            }
            return
        }
    }

    private func beginOperation(state: VPNConnectionState) -> UUID? {
        guard activeOperationID == nil else {
            return nil
        }

        let operationID = UUID()
        activeOperationID = operationID
        connectionState = state
        return operationID
    }

    private func isCurrentOperation(_ operationID: UUID) -> Bool {
        activeOperationID == operationID && Task.isCancelled == false
    }

    private func finishOperation(_ operationID: UUID) {
        if activeOperationID == operationID {
            activeOperationID = nil
        }
    }

    private func failOperation(_ operationID: UUID, message: String) {
        guard activeOperationID == operationID else {
            return
        }

        connectionState = .failed
        errorMessage = message
        activeOperationID = nil
    }

    private func cancelIfCurrent(_ operationID: UUID) {
        guard activeOperationID == operationID else {
            return
        }

        activeOperationID = nil
        connectionState = .disconnected
    }
}
