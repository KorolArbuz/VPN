//
//  ConnectionSelectionView.swift
//  VPN
//
//  Complete VPN profiles are the only selectable connection unit.
//

import SwiftUI

struct ConnectionSelectionView: View {
    @Bindable var viewModel: VPNDashboardViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker(
                        String(
                            localized: "connection.mode.title",
                            defaultValue: "Connection mode"
                        ),
                        selection: modeBinding
                    ) {
                        ForEach(ConnectionSelectionMode.allCases) { mode in
                            Text(mode.title).tag(mode)
                        }
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("connection-mode-picker")
                }

                switch viewModel.connectionSelectionPresentation.mode {
                case .automatic:
                    automaticContent
                case .manual:
                    ManualProfileSelectionSection(viewModel: viewModel)
                }
            }
            .navigationTitle("connection.title")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("common.done") {
                        dismiss()
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var automaticContent: some View {
        if viewModel.profiles.isEmpty {
            Section {
                SmartConnectionEmptyState()
            }
        } else if let profile = automaticDisplayProfile,
                  let candidate = automaticDisplayCandidate {
            Section {
                SmartConnectionRecommendationCard(
                    profile: profile,
                    candidate: candidate,
                    isBeingAttempted:
                        viewModel.currentAutomaticAttemptProfileID == profile.id
                )
            }
        } else {
            Section {
                HStack(spacing: 12) {
                    ProgressView()
                    Text(String(
                        localized: "connection.smart.preparing",
                        defaultValue: "Preparing a recommendation…"
                    ))
                        .foregroundStyle(.secondary)
                }
                .accessibilityIdentifier("automatic-recommendation-preparing")
            }
        }
    }

    private var modeBinding: Binding<ConnectionSelectionMode> {
        Binding(
            get: { viewModel.connectionMode },
            set: { viewModel.selectConnectionMode($0) }
        )
    }

    private var automaticDisplayProfile: VPNProfile? {
        if let profileID = viewModel.currentAutomaticAttemptProfileID,
           let profile = viewModel.profiles.first(where: { $0.id == profileID }) {
            return profile
        }
        return viewModel.automaticRecommendedProfile
    }

    private var automaticDisplayCandidate: SmartConnectionRankedCandidate? {
        guard let profileID = automaticDisplayProfile?.id else { return nil }
        return viewModel.automaticCandidatePlan.rankedCandidates.first {
            $0.profileID == profileID
        }
    }
}

private struct SmartConnectionEmptyState: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text(String(
                    localized: "connection.smart.no_profiles.title",
                    defaultValue: "Add a VPN profile"
                ))
            } icon: {
                Image(systemName: "doc.badge.plus")
            }
            .font(.headline)
            Text(String(
                localized: "connection.smart.no_profiles.description",
                defaultValue: "Import or create a profile before connecting."
            ))
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
        .accessibilityIdentifier("automatic-recommendation-empty")
    }
}

private struct SmartConnectionRecommendationCard: View {
    let profile: VPNProfile
    let candidate: SmartConnectionRankedCandidate
    let isBeingAttempted: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label {
                Text(
                    isBeingAttempted
                        ? String(
                            localized: "connection.smart.connecting_fallback",
                            defaultValue: "Trying the next best connection"
                        )
                        : String(
                            localized: "connection.smart.best_connection",
                            defaultValue: "Best Connection"
                        )
                )
            } icon: {
                Image(systemName: isBeingAttempted ? "arrow.trianglehead.2.clockwise" : "sparkles")
            }
            .font(.headline)
            .foregroundStyle(.tint)

            HStack(alignment: .top, spacing: 12) {
                Image(systemName: profile.protocolType.iconName)
                    .font(.title2)
                    .foregroundStyle(.tint)
                    .frame(width: 32)

                VStack(alignment: .leading, spacing: 4) {
                    Text(profile.name)
                        .font(.headline)
                    Text(profile.protocolType.displayName)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Text(profile.serverAddress)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }

            if candidate.latencyMilliseconds != nil
                || candidate.packetLossPercent != nil {
                qualitySummary
            }

            VStack(alignment: .leading, spacing: 6) {
                ForEach(candidate.reasons.prefix(3), id: \.self) { reason in
                    Label {
                        Text(reason.title)
                    } icon: {
                        Image(systemName: "checkmark.circle")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("automatic-recommendation-card")
    }

    private var qualitySummary: some View {
        HStack(spacing: 8) {
            if let latency = candidate.latencyMilliseconds {
                Label(
                    "\(Int(latency.rounded())) ms",
                    systemImage: "speedometer"
                )
            }
            if candidate.latencyMilliseconds != nil,
               candidate.packetLossPercent != nil {
                Text("·")
                    .foregroundStyle(.tertiary)
            }
            if let loss = candidate.packetLossPercent {
                Label(
                    loss.formatted(
                        .percent
                            .scale(1)
                            .precision(.fractionLength(0...1))
                    ),
                    systemImage: "waveform.path.ecg"
                )
            }
        }
        .font(.caption.weight(.medium))
        .foregroundStyle(.secondary)
    }
}

private struct ManualProfileSelectionSection: View {
    let viewModel: VPNDashboardViewModel

    var body: some View {
        Section {
            if viewModel.profiles.isEmpty {
                Text("connection.no_saved_profiles")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.profiles) { profile in
                    Button {
                        viewModel.selectProfile(profile)
                    } label: {
                        ManualProfileRow(
                            profile: profile,
                            isSelected:
                                viewModel.manualSelectedProfileID == profile.id
                        )
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier(
                        "manual-profile-\(profile.id.uuidString)"
                    )
                }
            }
        } header: {
            Text(String(
                localized: "connection.profile.section",
                defaultValue: "Profile"
            ))
        }
        .accessibilityIdentifier("manual-profile-list")
    }
}

private struct ManualProfileRow: View {
    let profile: VPNProfile
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: profile.protocolType.iconName)
                .foregroundStyle(.tint)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 3) {
                Text(profile.name)
                    .foregroundStyle(.primary)
                Text(profile.protocolType.displayName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(endpointSummary)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
            }

            Spacer()

            if isSelected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
            }
        }
        .contentShape(Rectangle())
    }

    private var endpointSummary: String {
        guard let port = profile.port else {
            return profile.serverAddress
        }
        return "\(profile.serverAddress):\(port)"
    }
}

#Preview {
    ConnectionSelectionView(viewModel: VPNDashboardViewModel())
}
