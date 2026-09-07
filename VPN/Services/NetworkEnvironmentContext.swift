//
//  NetworkEnvironmentContext.swift
//  VPN
//
//  Permission-neutral NetworkContext V2 enrichment foundation.
//

import Foundation

nonisolated enum SmartConnectionEnvironmentResolutionAccess: Sendable {
    /// A future entitlement/permission-compliant local observation that does
    /// not create traffic which could traverse a VPN tunnel.
    case localObservation

    /// A request to an owned first-party metadata service. This is allowed only
    /// while the authoritative VPN status is disconnected or invalid.
    case ordinaryNetworkRequest
}

nonisolated protocol SmartConnectionNetworkEnvironmentResolving: Sendable {
    var resolutionAccess: SmartConnectionEnvironmentResolutionAccess { get }

    func resolveEnvironment(
        for coarseContext: NetworkContext
    ) async throws -> SmartConnectionEnvironmentIdentity?
}

/// Production default for Build 9. The capability audit found no legally
/// available local SSID and no owned ASN endpoint, so no environment traffic or
/// identity collection occurs.
nonisolated struct DisabledSmartConnectionNetworkEnvironmentResolver:
    SmartConnectionNetworkEnvironmentResolving {
    let resolutionAccess: SmartConnectionEnvironmentResolutionAccess = .localObservation

    func resolveEnvironment(
        for coarseContext: NetworkContext
    ) async throws -> SmartConnectionEnvironmentIdentity? {
        nil
    }
}

/// Response contract for a future endpoint hosted by the product owner. It
/// intentionally carries no IP address: the backend may observe the request
/// address transiently, but the app accepts only the underlying ASN integer.
nonisolated struct SmartConnectionOwnedNetworkMetadata:
    Codable,
    Equatable,
    Sendable {
    static let currentSchemaVersion = 1

    var schemaVersion: Int
    var underlyingASN: UInt32?

    init(
        schemaVersion: Int = Self.currentSchemaVersion,
        underlyingASN: UInt32?
    ) {
        self.schemaVersion = schemaVersion
        self.underlyingASN = underlyingASN == 0 ? nil : underlyingASN
    }

    var isSupported: Bool {
        schemaVersion == Self.currentSchemaVersion
    }
}

nonisolated protocol SmartConnectionOwnedNetworkMetadataFetching: Sendable {
    func fetchUnderlyingNetworkMetadata() async throws
        -> SmartConnectionOwnedNetworkMetadata
}

/// Adapter for a future owned first-party client. No URLSession transport,
/// endpoint URL, or public third-party service is supplied by this repository.
nonisolated struct OwnedASNNetworkEnvironmentResolver:
    SmartConnectionNetworkEnvironmentResolving {
    let resolutionAccess: SmartConnectionEnvironmentResolutionAccess =
        .ordinaryNetworkRequest

    private let client: any SmartConnectionOwnedNetworkMetadataFetching

    init(client: any SmartConnectionOwnedNetworkMetadataFetching) {
        self.client = client
    }

    func resolveEnvironment(
        for coarseContext: NetworkContext
    ) async throws -> SmartConnectionEnvironmentIdentity? {
        let metadata = try await client.fetchUnderlyingNetworkMetadata()
        guard metadata.isSupported else {
            return nil
        }
        let identity = SmartConnectionEnvironmentIdentity(
            underlyingASN: metadata.underlyingASN
        )
        return identity.isEmpty ? nil : identity
    }
}

/// One safely observed underlying environment. It remains in the existing
/// bounded Smart Connection learning snapshot; it is never a second database.
nonisolated struct SmartConnectionSafeEnvironmentObservation:
    Codable,
    Equatable,
    Sendable {
    var coarseContext: NetworkContext
    var environmentIdentity: SmartConnectionEnvironmentIdentity
    var identitySource: SmartConnectionNetworkIdentitySource
    var observedAt: Date

    init(
        coarseContext: NetworkContext,
        environmentIdentity: SmartConnectionEnvironmentIdentity,
        observedAt: Date
    ) {
        self.coarseContext = coarseContext.matchingCoarseContext
        self.environmentIdentity = environmentIdentity
        identitySource = environmentIdentity.preferredSource
        self.observedAt = observedAt
    }

    var isValid: Bool {
        coarseContext.schemaVersion == NetworkContext.coarseSchemaVersion
            && coarseContext.isSupportedForLearning
            && environmentIdentity.isEmpty == false
            && identitySource == environmentIdentity.preferredSource
            && identitySource != .coarseOnly
    }

    var exactContext: NetworkContext? {
        guard isValid else {
            return nil
        }
        return NetworkContext.observedV2(
            coarseContext: coarseContext,
            environmentIdentity: environmentIdentity
        )
    }
}

nonisolated enum SmartConnectionEnvironmentResolutionDisposition:
    Equatable,
    Sendable {
    case accepted
    case unavailable
    case blockedByActiveVPN
    case failed
    case cancelled
    case stale
}

nonisolated struct SmartConnectionEnvironmentResolutionResult:
    Equatable,
    Sendable {
    var context: NetworkContext
    var disposition: SmartConnectionEnvironmentResolutionDisposition
    var safeObservation: SmartConnectionSafeEnvironmentObservation?
}

/// Serializes optional enrichment after the existing coarse-context debounce.
/// Every request advances a generation and cancels its predecessor. A resolver
/// that ignores cancellation still cannot publish after a newer generation.
actor SmartConnectionNetworkContextEnricher {
    private enum ResolutionOutcome: Sendable {
        case resolved(SmartConnectionEnvironmentIdentity?)
        case failed
        case cancelled
    }

    private let resolver: any SmartConnectionNetworkEnvironmentResolving
    private var generation: UInt64 = 0
    private var inFlightTask: Task<ResolutionOutcome, Never>?
    private var retainedSafeObservation: SmartConnectionSafeEnvironmentObservation?

    init(
        resolver: any SmartConnectionNetworkEnvironmentResolving =
            DisabledSmartConnectionNetworkEnvironmentResolver(),
        lastSafelyKnownObservation: SmartConnectionSafeEnvironmentObservation? = nil
    ) {
        self.resolver = resolver
        if lastSafelyKnownObservation?.isValid == true {
            retainedSafeObservation = lastSafelyKnownObservation
        }
    }

    func resolve(
        coarseContext: NetworkContext,
        authoritativeConnection: VPNAuthoritativeConnection,
        observedAt: Date
    ) async -> SmartConnectionEnvironmentResolutionResult {
        generation &+= 1
        let requestGeneration = generation
        inFlightTask?.cancel()
        inFlightTask = nil

        let coarseContext = coarseContext.matchingCoarseContext
        guard Self.isResolutionAllowed(
            access: resolver.resolutionAccess,
            authoritativeConnection: authoritativeConnection
        ) else {
            return SmartConnectionEnvironmentResolutionResult(
                context: coarseContext,
                disposition: .blockedByActiveVPN,
                safeObservation: nil
            )
        }

        let resolver = resolver
        let task = Task { () -> ResolutionOutcome in
            do {
                let identity = try await resolver.resolveEnvironment(
                    for: coarseContext
                )
                return .resolved(identity)
            } catch is CancellationError {
                return .cancelled
            } catch {
                return .failed
            }
        }
        inFlightTask = task

        let outcome = await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }

        guard requestGeneration == generation else {
            return SmartConnectionEnvironmentResolutionResult(
                context: coarseContext,
                disposition: .stale,
                safeObservation: nil
            )
        }
        inFlightTask = nil

        guard Task.isCancelled == false else {
            return SmartConnectionEnvironmentResolutionResult(
                context: coarseContext,
                disposition: .cancelled,
                safeObservation: nil
            )
        }

        switch outcome {
        case .cancelled:
            return SmartConnectionEnvironmentResolutionResult(
                context: coarseContext,
                disposition: .cancelled,
                safeObservation: nil
            )
        case .failed:
            return SmartConnectionEnvironmentResolutionResult(
                context: coarseContext,
                disposition: .failed,
                safeObservation: nil
            )
        case .resolved(let identity):
            guard let identity,
                  identity.isEmpty == false,
                  let exactContext = NetworkContext.observedV2(
                      coarseContext: coarseContext,
                      environmentIdentity: identity
                  ) else {
                return SmartConnectionEnvironmentResolutionResult(
                    context: coarseContext,
                    disposition: .unavailable,
                    safeObservation: nil
                )
            }
            let observation = SmartConnectionSafeEnvironmentObservation(
                coarseContext: coarseContext,
                environmentIdentity: identity,
                observedAt: observedAt
            )
            retainedSafeObservation = observation
            return SmartConnectionEnvironmentResolutionResult(
                context: exactContext,
                disposition: .accepted,
                safeObservation: observation
            )
        }
    }

    /// Cancels any request that began under an older route or VPN state.
    func invalidate() {
        generation &+= 1
        inFlightTask?.cancel()
        inFlightTask = nil
    }

    /// Restoration retains the last safe value for later use/audit, but never
    /// treats it as a fresh observation of the current physical network.
    func restoreLastSafelyKnownObservation(
        _ observation: SmartConnectionSafeEnvironmentObservation?
    ) {
        guard let observation, observation.isValid else {
            return
        }
        retainedSafeObservation = observation
    }

    func lastSafelyKnownObservation()
        -> SmartConnectionSafeEnvironmentObservation? {
        retainedSafeObservation
    }

    static func isResolutionAllowed(
        access: SmartConnectionEnvironmentResolutionAccess,
        authoritativeConnection: VPNAuthoritativeConnection
    ) -> Bool {
        guard access == .ordinaryNetworkRequest else {
            return true
        }

        guard authoritativeConnection.isSystemActive == false,
              (authoritativeConnection.state == .disconnected
                || authoritativeConnection.state == .failed) else {
            return false
        }

        switch authoritativeConnection.systemStatus {
        case .disconnected, .invalid:
            return true
        case .connected, .connecting, .reasserting, .disconnecting:
            return false
        case nil:
            // Missing system status is not proof that a tunnel is inactive.
            return false
        }
    }
}
