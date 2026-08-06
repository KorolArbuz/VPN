//
//  VPNProfileRepository.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import Foundation

nonisolated protocol VPNProfileRepository: Sendable {
    func profiles() async throws -> [VPNProfile]
    func save(_ profile: VPNProfile) async throws
    func delete(id: VPNProfile.ID) async throws
    func setEnabled(_ isEnabled: Bool, id: VPNProfile.ID) async throws
    func rename(id: VPNProfile.ID, to name: String) async throws
}

actor InMemoryVPNProfileRepository: VPNProfileRepository {
    private var storedProfiles: [VPNProfile] = []

    func profiles() async throws -> [VPNProfile] {
        storedProfiles
    }

    func save(_ profile: VPNProfile) async throws {
        var updatedProfile = profile
        updatedProfile.updatedAt = Date()

        if let index = storedProfiles.firstIndex(where: { $0.id == profile.id }) {
            storedProfiles[index] = updatedProfile
        } else {
            storedProfiles.append(updatedProfile)
        }
    }

    func delete(id: VPNProfile.ID) async throws {
        storedProfiles.removeAll { $0.id == id }
    }

    func setEnabled(_ isEnabled: Bool, id: VPNProfile.ID) async throws {
        guard let index = storedProfiles.firstIndex(where: { $0.id == id }) else {
            return
        }

        storedProfiles[index].isEnabled = isEnabled
        storedProfiles[index].updatedAt = Date()
    }

    func rename(id: VPNProfile.ID, to name: String) async throws {
        guard let index = storedProfiles.firstIndex(where: { $0.id == id }) else {
            return
        }

        storedProfiles[index].name = name
        storedProfiles[index].updatedAt = Date()
    }
}
