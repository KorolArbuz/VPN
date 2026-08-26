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
    private let runtimeProfileSynchronizer: (any RuntimeProfileSynchronizing)?
    private let connectionTelemetryManager: any DashboardConnectionTelemetryManaging
    private let startHapticFeedback: any StartHapticFeedbackProviding

    private var activeOperationID: UUID?
    private var stateObservationTask: Task<Void, Never>?
    private var telemetryObservationTask: Task<Void, Never>?
    private var saveOperationID: UUID?
    private var inFlightImportedCredentialReferences = Set<String>()
    private var subscriptionOperationID: UUID?
    private var refreshingSubscriptionID: UUID?
    private var discardedRefreshSubscriptionID: UUID?
    private var isInitialLoadInFlight = false

    var connectionState: VPNConnectionState = .disconnected
    private(set) var hasAuthoritativeManagerConflict = false
    var selectedServer: VPNServer?
    var selectedProtocol: VPNProtocolSelection = .automatic
    var activeProfileID: UUID?
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
        importer: VPNProfileImporting? = nil,
        runtimeProfileSynchronizer: (any RuntimeProfileSynchronizing)? = nil,
        connectionTelemetryManager: any DashboardConnectionTelemetryManaging =
            DisabledDashboardConnectionTelemetryManager(),
        startHapticFeedback: any StartHapticFeedbackProviding =
            SystemStartHapticFeedback()
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
        self.importer = importer ?? VPNLinkParser(credentialStore: credentialStore)
        self.runtimeProfileSynchronizer = runtimeProfileSynchronizer
        self.connectionTelemetryManager = connectionTelemetryManager
        self.startHapticFeedback = startHapticFeedback
        observeConnectionState()
        observeConnectionTelemetry()
    }

    var selectedProfile: VPNProfile? {
        guard let activeProfileID else {
            return nil
        }

        return profiles.first { $0.id == activeProfileID }
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

        if let selectedProfile {
            return selectedProfile.isEnabled && selectedProfile.runtimeCapability.isReady
        }

        return selectedServer != nil && effectiveProtocol != nil
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
            let fetchedServers = try await serverProvider.fetchServers()
            servers = fetchedServers

            profiles = try await profileRepository.profiles()
            activeProfileID = await activeProfileStore.activeProfileID()
            clearMissingOrInvalidActiveProfileIfNeeded()
            subscriptions = try await subscriptionRepository.subscriptions()

            if selectedServer == nil {
                selectedServer = try await serverSelector.bestServer(from: servers, using: serverProber)
            }

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
        if connectionState == .disconnected || connectionState == .failed {
            startHapticFeedback.playLightStartImpact()
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

        setActiveProfileID(profile.id)
        selectedProtocol = .manual(profile.protocolType)
        effectiveProtocol = profile.protocolType
        currentMetrics = nil
        errorMessage = nil
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
        guard activeOperationID == nil else {
            return
        }

        do {
            let profile = try profileForConnection()
            guard profile.isEnabled else {
                errorMessage = "Profile is disabled."
                return
            }
            guard profile.isComplete else {
                errorMessage = "Profile is incomplete. Missing: \(profile.missingRequiredFields.joined(separator: ", "))."
                return
            }
            if selectedProfile != nil {
                let capability = profile.runtimeCapability
                guard capability.isReady else {
                    errorMessage = capability.statusText
                    return
                }
            }

            guard let operationID = beginOperation(state: .connecting) else {
                return
            }

            currentMetrics = nil
            try await connectionManager.connect(using: profile)
            guard isCurrentOperation(operationID) else { return }

            let authoritativeConnection =
                await connectionManager.authoritativeConnection()
            guard isCurrentOperation(operationID) else { return }
            guard authoritativeConnection.state == .connected else {
                failOperation(
                    operationID,
                    message: "The VPN connection did not reach the connected state."
                )
                return
            }

            finishOperation(operationID)
            await applyAuthoritativeConnection(authoritativeConnection)
            errorMessage = nil
        } catch is CancellationError {
            activeOperationID = nil
            await connectionTelemetryManager.stop()
        } catch {
            connectionState = .failed
            errorMessage = error.localizedDescription
            activeOperationID = nil
            await connectionTelemetryManager.stop()
        }
    }

    func disconnect() async {
        guard let operationID = beginOperation(state: .disconnecting) else {
            return
        }

        await connectionManager.disconnect()
        guard isCurrentOperation(operationID) else { return }

        let authoritativeConnection =
            await connectionManager.refreshAuthoritativeConnection()
        guard isCurrentOperation(operationID) else { return }

        currentMetrics = nil
        finishOperation(operationID)
        await applyAuthoritativeConnection(authoritativeConnection)
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

    private func profileForConnection() throws -> VPNProfile {
        if let selectedProfile {
            return selectedProfile
        }

        guard let selectedServer else {
            throw MockVPNError.noAvailableServers
        }

        refreshEffectiveProtocol()

        guard let effectiveProtocol else {
            throw MockVPNError.protocolUnavailable
        }

        return VPNProfile.bundledMock(server: selectedServer, protocolType: effectiveProtocol)
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
            }
        }
    }

    private func applyAuthoritativeConnection(
        _ authoritativeConnection: VPNAuthoritativeConnection
    ) async {
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
            selectedProtocol = .manual(profile.protocolType)
            effectiveProtocol = profile.protocolType
            currentMetrics = nil
            importErrorMessage = nil
            profileSaveState = .saved
            profileSaveMessage = "Profile saved"
            saveOperationID = nil
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
