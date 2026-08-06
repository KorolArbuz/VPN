//
//  ActiveProfileStore.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated protocol ActiveProfileStoring: Sendable {
    func activeProfileID() async -> UUID?
    func saveActiveProfileID(_ id: UUID?) async
}

actor UserDefaultsActiveProfileStore: ActiveProfileStoring {
    private let defaults: UserDefaults
    private let key: String

    init(defaults: UserDefaults = .standard, key: String = "activeProfileID") {
        self.defaults = defaults
        self.key = key
    }

    func activeProfileID() async -> UUID? {
        guard let value = defaults.string(forKey: key) else {
            return nil
        }

        return UUID(uuidString: value)
    }

    func saveActiveProfileID(_ id: UUID?) async {
        if let id {
            defaults.set(id.uuidString, forKey: key)
        } else {
            defaults.removeObject(forKey: key)
        }
    }
}
