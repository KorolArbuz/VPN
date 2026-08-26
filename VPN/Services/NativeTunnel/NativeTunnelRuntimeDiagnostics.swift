//
//  NativeTunnelRuntimeDiagnostics.swift
//  VPN
//

import Foundation
import OSLog

nonisolated struct NativeRuntimeProfileDiagnosticResult: Equatable, Sendable {
    var requestedProfileID: UUID
    var runtimeProfileExists: Bool
    var profileIDMatches: Bool
    var protocolName: String?
    var recordRevision: String?
    var enabled: Bool
    var credentialReferencesValid: Bool
    var credentialsAvailable: Bool
    var awgFieldCompleteness: Bool
    var missingFields: [String]
    var interfaceAddressCount: Int
    var dnsServerCount: Int
    var mtu: UInt16?
    var peerCount: Int
    var allowedIPCount: Int
    var endpointPresent: Bool
    var privateKeyPresent: Bool
    var presharedKeyPresent: Bool
}

actor NativeTunnelRuntimeDiagnosticService {
    private let store: (any NativeWireGuardProfileStoring)?
    private let credentialStore: any CredentialStoring
    private let logger = Logger(subsystem: "su.24kvn.kvn-app", category: "Tunnel.Runtime")

    init(
        store: (any NativeWireGuardProfileStoring)? = FileNativeWireGuardProfileStore.appGroupStore(),
        credentialStore: any CredentialStoring = KeychainCredentialStore()
    ) {
        self.store = store
        self.credentialStore = credentialStore
    }

    func inspect(profileID: UUID) async -> NativeRuntimeProfileDiagnosticResult {
        guard let store else {
            return unavailable(profileID: profileID, missingFields: ["AppGroup"])
        }
        let record: NativeWireGuardProfileRecord
        do {
            record = try await store.read(profileID: profileID)
        } catch {
            return unavailable(profileID: profileID, missingFields: ["RuntimeProfile"])
        }

        var referencesValid = true
        var credentialsAvailable = true
        for reference in record.credentialReferences {
            guard CredentialReferenceValidator.isValid(reference) else {
                referencesValid = false
                credentialsAvailable = false
                continue
            }
            do {
                guard let value = try await credentialStore.secret(for: reference),
                      Data(base64Encoded: value.trimmingCharacters(in: .whitespacesAndNewlines))?.count == 32 else {
                    credentialsAvailable = false
                    continue
                }
            } catch {
                credentialsAvailable = false
            }
        }

        let missingFields = Self.missingFields(in: record)
        let result = NativeRuntimeProfileDiagnosticResult(
            requestedProfileID: profileID,
            runtimeProfileExists: true,
            profileIDMatches: record.profileID == profileID,
            protocolName: record.mode.rawValue,
            recordRevision: record.recordRevision,
            enabled: record.enabled,
            credentialReferencesValid: referencesValid,
            credentialsAvailable: credentialsAvailable,
            awgFieldCompleteness: record.mode == .wireGuard || missingFields.isEmpty,
            missingFields: missingFields,
            interfaceAddressCount: record.interfaceAddresses.count,
            dnsServerCount: record.dnsServers.count,
            mtu: record.mtu,
            peerCount: record.peers.count,
            allowedIPCount: record.peers.reduce(0) { $0 + $1.allowedIPs.count },
            endpointPresent: record.peers.contains { $0.endpoint != nil },
            privateKeyPresent: record.privateKeyReference.isEmpty == false,
            presharedKeyPresent: record.peers.contains { $0.presharedKeyReference != nil }
        )
        logger.notice(
            "native runtime diagnostic profile=\(profileID.uuidString, privacy: .public) protocol=\(record.mode.rawValue, privacy: .public) revision=\(record.recordRevision, privacy: .public) referencesValid=\(referencesValid, privacy: .public) credentialsAvailable=\(credentialsAvailable, privacy: .public) missingFieldCount=\(missingFields.count, privacy: .public)"
        )
        return result
    }

    private func unavailable(
        profileID: UUID,
        missingFields: [String]
    ) -> NativeRuntimeProfileDiagnosticResult {
        NativeRuntimeProfileDiagnosticResult(
            requestedProfileID: profileID,
            runtimeProfileExists: false,
            profileIDMatches: false,
            protocolName: nil,
            recordRevision: nil,
            enabled: false,
            credentialReferencesValid: false,
            credentialsAvailable: false,
            awgFieldCompleteness: false,
            missingFields: missingFields,
            interfaceAddressCount: 0,
            dnsServerCount: 0,
            mtu: nil,
            peerCount: 0,
            allowedIPCount: 0,
            endpointPresent: false,
            privateKeyPresent: false,
            presharedKeyPresent: false
        )
    }

    private static func missingFields(in record: NativeWireGuardProfileRecord) -> [String] {
        guard record.mode == .amneziaWG else { return [] }
        var fields: [String] = []
        let awg = record.amnezia
        if awg?.junkPacketCount == nil { fields.append("Jc") }
        if awg?.junkPacketMinSize == nil { fields.append("Jmin") }
        if awg?.junkPacketMaxSize == nil { fields.append("Jmax") }
        if awg?.initPacketJunkSize == nil { fields.append("S1") }
        if awg?.responsePacketJunkSize == nil { fields.append("S2") }
        if awg?.cookieReplyPacketJunkSize == nil { fields.append("S3") }
        if awg?.transportPacketJunkSize == nil { fields.append("S4") }
        if normalized(awg?.initPacketMagicHeader) == nil { fields.append("H1") }
        if normalized(awg?.responsePacketMagicHeader) == nil { fields.append("H2") }
        if normalized(awg?.underloadPacketMagicHeader) == nil { fields.append("H3") }
        if normalized(awg?.transportPacketMagicHeader) == nil { fields.append("H4") }
        if record.interfaceAddresses.isEmpty { fields.append("Address") }
        if record.peers.isEmpty { fields.append("Peer") }
        if record.peers.contains(where: { $0.allowedIPs.isEmpty }) { fields.append("AllowedIPs") }
        if record.peers.contains(where: { $0.endpoint == nil }) { fields.append("Endpoint") }
        if record.privateKeyReference.isEmpty { fields.append("PrivateKeyReference") }
        if record.peers.contains(where: { $0.publicKey.isEmpty }) { fields.append("PublicKey") }
        return fields
    }

    private static func normalized(_ value: String?) -> String? {
        let value = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return value?.isEmpty == false ? value : nil
    }
}
