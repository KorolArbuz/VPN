//
//  ProfileActionRow.swift
//  VPN
//
//  Created by Denis Chizhov on 07.08.2026.
//

import SwiftUI

struct ProfileActionRow: View {
    let title: String
    let subtitle: String
    let systemImage: String
    var isEnabled: Bool = true

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: systemImage)
                .font(.title3)
                .foregroundStyle(isEnabled ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                .frame(width: 30)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(title)
                        .font(.headline)

                    if isEnabled == false {
                        Text("Coming Soon")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(.quaternary, in: Capsule())
                            .foregroundStyle(.secondary)
                    }
                }

                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 8)
        }
        .padding(.vertical, 6)
        .opacity(isEnabled ? 1 : 0.55)
    }
}

#Preview {
    List {
        ProfileActionRow(title: "Paste Link", subtitle: "Import a VLESS, Trojan or Hysteria link.", systemImage: "link")
        ProfileActionRow(title: "Manual Setup", subtitle: "Enter server details yourself.", systemImage: "slider.horizontal.3")
    }
}
