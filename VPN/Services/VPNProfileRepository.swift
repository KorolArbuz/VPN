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

actor FileVPNProfileRepository: VPNProfileRepository {
    private let fileURL: URL
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    init(fileURL: URL? = nil) {
        if let fileURL {
            self.fileURL = fileURL
        } else {
            let applicationSupportURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? FileManager.default.temporaryDirectory
            self.fileURL = applicationSupportURL
                .appendingPathComponent("VPN", isDirectory: true)
                .appendingPathComponent("profiles.json")
        }

        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    func profiles() async throws -> [VPNProfile] {
        try loadProfiles()
    }

    func save(_ profile: VPNProfile) async throws {
        var profiles = try loadProfiles()
        var updatedProfile = profile
        updatedProfile.updatedAt = Date()

        if let index = profiles.firstIndex(where: { $0.id == profile.id }) {
            profiles[index] = updatedProfile
        } else {
            profiles.append(updatedProfile)
        }

        try writeProfiles(profiles)
    }

    func delete(id: VPNProfile.ID) async throws {
        var profiles = try loadProfiles()
        profiles.removeAll { $0.id == id }
        try writeProfiles(profiles)
    }

    func setEnabled(_ isEnabled: Bool, id: VPNProfile.ID) async throws {
        var profiles = try loadProfiles()
        guard let index = profiles.firstIndex(where: { $0.id == id }) else {
            return
        }

        profiles[index].isEnabled = isEnabled
        profiles[index].updatedAt = Date()
        try writeProfiles(profiles)
    }

    func rename(id: VPNProfile.ID, to name: String) async throws {
        var profiles = try loadProfiles()
        guard let index = profiles.firstIndex(where: { $0.id == id }) else {
            return
        }

        profiles[index].name = name
        profiles[index].updatedAt = Date()
        try writeProfiles(profiles)
    }

    private func loadProfiles() throws -> [VPNProfile] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return []
        }

        do {
            let data = try Data(contentsOf: fileURL)
            return try decoder.decode([VPNProfile].self, from: data)
        } catch {
            return []
        }
    }

    private func writeProfiles(_ profiles: [VPNProfile]) throws {
        let directoryURL = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        let data = try encoder.encode(profiles)
        try data.write(to: fileURL, options: [.atomic])
    }
}
