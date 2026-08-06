//
//  ProfileSaveState.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import Foundation

nonisolated enum ProfileSaveState: Equatable, Sendable {
    case idle
    case saving
    case saved
    case failed(String)
    case duplicate
    case incomplete([String])
}
