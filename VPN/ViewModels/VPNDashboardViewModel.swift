//
//  VPNDashboardViewModel.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation
import Observation

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

    private var activeOperationID: UUID?
    private var stateObservationTask: Task<Void, Never>?
    private var saveOperationID: UUID?
    private var subscriptionOperationID: UUID?
    private var isInitialLoadInFlight = false

    var connectionState: VPNConnectionState = .disconnected
    var selectedServer: VPNServer?
    var selectedProtocol: VPNProtocolSelection = .automatic
    var activeProfileID: UUID?
    var effectiveProtocol: VPNProtocol?
    var servers: [VPNServer] = []
    var profiles: [VPNProfile] = []
    var subscriptions: [VPNSubscription] = []
    var currentMetrics: ConnectionMetrics?
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
        subscriptionUpdater: SubscriptionUpdating = URLSessionSubscriptionUpdater(),
        credentialStore: CredentialStoring = KeychainCredentialStore(),
        activeProfileStore: ActiveProfileStoring = UserDefaultsActiveProfileStore(),
        importer: VPNProfileImporting? = nil
    ) {
        self.serverProvider = serverProvider
        self.serverProber = serverProber
        self.connectionManager = connectionManager
        self.serverSelector = serverSelector
        self.profileRepository = profileRepository
        self.subscriptionRepository = subscriptionRepository
        self.subscriptionUpdater = subscriptionUpdater
        self.credentialStore = credentialStore
        self.activeProfileStore = activeProfileStore
        self.importer = importer ?? VPNLinkParser(credentialStore: credentialStore)
        observeConnectionState()
    }

    var selectedProfile: VPNProfile? {
        guard let activeProfileID else {
            return nil
        }

        return profiles.first { $0.id == activeProfileID }
    }

    var isSavingProfile: Bool {
        if case .saving = profileSaveState {
            return true
        }

        return false
    }

    var canToggleConnection: Bool {
        activeOperationID == nil && selectedProfile?.isEnabled != false
    }

    var canConnect: Bool {
        guard activeOperationID == nil else {
            return false
        }

        if let selectedProfile {
            return selectedProfile.isEnabled && selectedProfile.isComplete
        }

        return selectedServer != nil && effectiveProtocol != nil
    }

    var selectedProfileStatusText: String? {
        guard let selectedProfile else {
            return nil
        }

        if selectedProfile.isComplete {
            return selectedProfile.isEnabled ? "Ready" : "Disabled"
        }

        return "Incomplete: \(selectedProfile.missingRequiredFields.joined(separator: ", "))"
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
            let managerState = await connectionManager.currentState()
            if managerState != .disconnected || connectionState == .testing {
                connectionState = managerState
            }
            errorMessage = nil
        } catch is CancellationError {
            return
        } catch {
            connectionState = .failed
            errorMessage = error.localizedDescription
        }
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

            guard let operationID = beginOperation(state: .connecting) else {
                return
            }

            let metrics = try await connectionManager.connect(using: profile)
            guard isCurrentOperation(operationID) else { return }

            currentMetrics = metrics
            connectionState = .connected
            errorMessage = nil
            finishOperation(operationID)
        } catch is CancellationError {
            activeOperationID = nil
        } catch {
            connectionState = .failed
            errorMessage = error.localizedDescription
            activeOperationID = nil
        }
    }

    func disconnect() async {
        guard let operationID = beginOperation(state: .disconnecting) else {
            return
        }

        await connectionManager.disconnect()
        guard isCurrentOperation(operationID) else { return }

        currentMetrics = nil
        connectionState = .disconnected
        errorMessage = nil
        finishOperation(operationID)
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

        guard saveOperationID == nil else {
            return false
        }

        do {
            switch importResult.kind {
            case .profile(let profile):
                do {
                    return try await saveProfileAndSelect(profile)
                } catch {
                    if let credentialReference = profile.credentialReference {
                        try? await credentialStore.delete(reference: credentialReference)
                    }
                    if let publicKeyReference = profile.tlsSettings.publicKeyReference {
                        try? await credentialStore.delete(reference: publicKeyReference)
                    }
                    throw error
                }
            case .subscription(let subscription):
                try await subscriptionRepository.save(subscription)
                subscriptions = try await subscriptionRepository.subscriptions()
            }

            self.importResult = nil
            importErrorMessage = nil
            return true
        } catch {
            importErrorMessage = error.localizedDescription
            return false
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
            if let credentialReference = profile.credentialReference {
                try await credentialStore.delete(reference: credentialReference)
            }
            if let publicKeyReference = profile.tlsSettings.publicKeyReference {
                try await credentialStore.delete(reference: publicKeyReference)
            }
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
            profiles = try await profileRepository.profiles()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func setProfileEnabled(_ profile: VPNProfile, isEnabled: Bool) async {
        do {
            try await profileRepository.setEnabled(isEnabled, id: profile.id)
            profiles = try await profileRepository.profiles()
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
        subscriptionRefreshState = .downloading
        importErrorMessage = nil
        subscriptionUpdatePlan = nil

        do {
            guard let reference = subscription.credentialReference,
                  let urlText = try await credentialStore.secret(for: reference),
                  let url = URL(string: urlText) else {
                throw SubscriptionError.credentialsUnavailable
            }

            let plan = try await subscriptionUpdater.planRefresh(subscription, existingProfiles: profiles, url: url)
            guard subscriptionOperationID == operationID else { return }

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
        }
    }

    func applySubscriptionUpdate(missingPolicy: MissingSubscriptionProfilePolicy = .keep) async {
        guard subscriptionOperationID == nil, let plan = subscriptionUpdatePlan else { return }

        let operationID = UUID()
        subscriptionOperationID = operationID
        subscriptionRefreshState = .saving

        do {
            for change in plan.changes where change.isSelected {
                try await applySubscriptionChange(change, missingPolicy: missingPolicy)
            }

            var updatedSubscription = plan.subscription
            updatedSubscription.lastRefreshAt = Date()
            updatedSubscription.lastSuccessfulRefreshAt = Date()
            updatedSubscription.lastError = nil
            updatedSubscription.refreshState = .completed
            updatedSubscription.profileCount = (try await profileRepository.profiles()).filter { $0.sourceSubscriptionID == plan.subscription.id }.count
            try await subscriptionRepository.save(updatedSubscription)

            profiles = try await profileRepository.profiles()
            subscriptions = try await subscriptionRepository.subscriptions()
            subscriptionUpdatePlan = nil
            subscriptionRefreshState = .completed
            importErrorMessage = nil
        } catch {
            importErrorMessage = error.localizedDescription
            subscriptionRefreshState = .failed
        }

        if subscriptionOperationID == operationID {
            subscriptionOperationID = nil
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
                    try await deleteProfileCredentials(profile)
                    try await profileRepository.delete(id: profile.id)
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
                }
            }

            try await subscriptionRepository.delete(id: subscription.id)
            if let reference = subscription.credentialReference {
                try await credentialStore.delete(reference: reference)
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
        if let reference = subscriptionPreview?.providerURLReference, reference.isEmpty == false {
            try? await credentialStore.delete(reference: reference)
        }
        subscriptionPreview = nil
        subscriptionUpdatePlan = nil
        subscriptionPreviewProfiles = []
        subscriptionRefreshState = .cancelled
        subscriptionOperationID = nil
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

    private func applySubscriptionChange(_ change: SubscriptionProfileChange, missingPolicy: MissingSubscriptionProfilePolicy) async throws {
        switch change.kind {
        case .added:
            if let incomingProfile = change.incomingProfile {
                try await profileRepository.save(incomingProfile)
            }
        case .updated:
            if let incomingProfile = change.incomingProfile, let existingProfile = change.existingProfile {
                try await profileRepository.save(mergeProviderUpdate(existing: existingProfile, incoming: incomingProfile))
            }
        case .missing:
            guard let existingProfile = change.existingProfile else { return }
            switch missingPolicy {
            case .keep:
                break
            case .disable:
                try await profileRepository.setEnabled(false, id: existingProfile.id)
            case .remove:
                try await deleteProfileCredentials(existingProfile)
                try await profileRepository.delete(id: existingProfile.id)
                if activeProfileID == existingProfile.id {
                    setActiveProfileID(nil)
                }
            }
        case .unchanged, .invalid, .duplicate:
            break
        }
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
        return merged
    }

    private func deleteProfileCredentials(_ profile: VPNProfile) async throws {
        if let credentialReference = profile.credentialReference {
            try await credentialStore.delete(reference: credentialReference)
        }
        if let publicKeyReference = profile.tlsSettings.publicKeyReference {
            try await credentialStore.delete(reference: publicKeyReference)
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
        guard let selectedServer else {
            effectiveProtocol = selectedProfile?.protocolType
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
        stateObservationTask = Task { [weak self, connectionManager] in
            for await state in connectionManager.stateUpdates() {
                await MainActor.run {
                    self?.connectionState = state
                }
            }
        }
    }

    private func saveProfileAndSelect(_ profile: VPNProfile) async throws -> Bool {
        guard profile.isComplete else {
            profileSaveState = .incomplete(profile.missingRequiredFields)
            profileSaveMessage = "Profile is incomplete. Missing: \(profile.missingRequiredFields.joined(separator: ", "))."
            return false
        }

        let operationID = UUID()
        saveOperationID = operationID
        profileSaveState = .saving
        profileSaveMessage = nil

        do {
            try await profileRepository.save(profile)
            guard saveOperationID == operationID else {
                return false
            }

            profiles = try await profileRepository.profiles()
            setActiveProfileID(profile.id)
            selectedProtocol = .manual(profile.protocolType)
            effectiveProtocol = profile.protocolType
            currentMetrics = nil
            importResult = nil
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

    private func clearMissingOrInvalidActiveProfileIfNeeded() {
        guard let activeProfileID else {
            return
        }

        guard let profile = profiles.first(where: { $0.id == activeProfileID }),
              profile.isEnabled,
              profile.isComplete else {
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
