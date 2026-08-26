import Foundation

protocol RuntimeConfigurationValidationLoading: Sendable {
    func validateRuntimeConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelRuntimeConfigurationValidationResponse
}

protocol XrayConfigurationValidating: Sendable {
    func validateXrayConfiguration(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayConfigurationValidationResponse
}

protocol XrayLifecycleSmokeTesting: Sendable {
    func runXrayLifecycleSmokeTest(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayLifecycleSmokeTestResponse
}

protocol XrayRemoteEgressProbing: Sendable {
    func runXrayRemoteEgressProbe(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayRemoteEgressProbeResponse

    func probeActiveXrayEgress(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelXrayRemoteEgressProbeResponse
}

protocol PacketTunnelUDPControlProbing: Sendable {
    func runUDPControlProbe(
        correlationID: UUID,
        requestGeneration: UInt64?
    ) async -> TunnelUDPControlProbeResponse
}

protocol LibXrayPingProbing: Sendable {
    func runLibXrayPingProbe(
        correlationID: UUID,
        expectedProfileID: UUID?,
        expectedRevisionToken: Int64?,
        requestGeneration: UInt64?
    ) async -> TunnelLibXrayPingProbeResponse
}
