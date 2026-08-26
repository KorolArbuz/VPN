//
//  SmartConnectionScoring.swift
//  VPN
//
//  Explainable deterministic ranking for complete VPN profiles.
//

import Foundation

nonisolated struct SmartConnectionScoreCalculator: Sendable {
    private enum Component {
        case reliability
        case latency
        case packetLoss
        case connectSpeed
        case stability
    }

    /// Neutral quality is 70. Each evidence level is shrunk toward the next
    /// broader prior: protocol (12 samples), profile (10), then context (8).
    private let neutralQuality = 70.0
    private let historyHalfLifeDays = 90.0

    func score(
        profile: VPNProfile,
        context: NetworkContext,
        learning: SmartConnectionLearningSnapshot,
        now: Date,
        explorationBonus: Double = 0
    ) -> SmartConnectionRankedCandidate {
        let contextStatistics = learning.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: context
        )
        let profileStatistics = learning.profileStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType
        )
        let protocolStatistics = learning.protocolStatistics(profile.protocolType)

        let reliability = hierarchicalQuality(
            component: .reliability,
            context: contextStatistics,
            profile: profileStatistics,
            protocolStatistics: protocolStatistics,
            now: now
        )
        let latency = hierarchicalQuality(
            component: .latency,
            context: contextStatistics,
            profile: profileStatistics,
            protocolStatistics: protocolStatistics,
            now: now
        )
        let packetLoss = hierarchicalQuality(
            component: .packetLoss,
            context: contextStatistics,
            profile: profileStatistics,
            protocolStatistics: protocolStatistics,
            now: now
        )
        let connectSpeed = hierarchicalQuality(
            component: .connectSpeed,
            context: contextStatistics,
            profile: profileStatistics,
            protocolStatistics: protocolStatistics,
            now: now
        )
        let stability = hierarchicalQuality(
            component: .stability,
            context: contextStatistics,
            profile: profileStatistics,
            protocolStatistics: protocolStatistics,
            now: now
        )

        // Every input is normalized to 0...100 before weighting. Raw
        // milliseconds, percentages, and seconds are never directly combined.
        let baseScore = clamp(
            reliability * 0.40
                + latency * 0.20
                + packetLoss * 0.15
                + connectSpeed * 0.15
                + stability * 0.10
        )
        let recentFailurePenalty = max(
            failurePenalty(statistics: contextStatistics, now: now),
            failurePenalty(statistics: profileStatistics, now: now) * 0.35
        )
        let recentSuccessBonus = max(
            successRecencyBonus(statistics: contextStatistics, now: now),
            successRecencyBonus(statistics: profileStatistics, now: now) * 0.5
        )
        let exploitationScore = clamp(
            baseScore - recentFailurePenalty + recentSuccessBonus
        )
        let effectiveScore = clamp(exploitationScore + explorationBonus)
        let breakdown = SmartConnectionScoreBreakdown(
            reliability: reliability,
            latency: latency,
            packetLoss: packetLoss,
            connectSpeed: connectSpeed,
            stability: stability,
            baseScore: baseScore,
            recentFailurePenalty: recentFailurePenalty,
            recentSuccessBonus: recentSuccessBonus,
            explorationBonus: explorationBonus,
            effectiveScore: effectiveScore
        )

        return SmartConnectionRankedCandidate(
            profileID: profile.id,
            protocolType: profile.protocolType,
            contextAttemptCount: contextStatistics.attemptCount,
            latencyMilliseconds: contextStatistics.ewmaLatencyMilliseconds
                ?? profileStatistics.ewmaLatencyMilliseconds,
            packetLossPercent: contextStatistics.ewmaPacketLossPercent
                ?? profileStatistics.ewmaPacketLossPercent,
            reasons: reasons(for: breakdown, contextAttempts: contextStatistics.attemptCount),
            breakdown: breakdown
        )
    }

    func effectiveContextAttemptCount(
        profile: VPNProfile,
        context: NetworkContext,
        learning: SmartConnectionLearningSnapshot,
        now: Date
    ) -> Double {
        let statistics = learning.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: context
        )
        return effectiveSamples(
            count: statistics.attemptCount,
            lastUpdatedAt: statistics.lastUpdatedAt,
            now: now
        )
    }

    func isUnderFailureCooldown(
        profile: VPNProfile,
        context: NetworkContext,
        learning: SmartConnectionLearningSnapshot,
        now: Date
    ) -> Bool {
        let statistics = learning.contextStatistics(
            profileID: profile.id,
            protocolType: profile.protocolType,
            context: context
        )
        guard statistics.consecutiveFailures > 0,
              let lastFailureAt = statistics.lastFailureAt else {
            return false
        }
        return now.timeIntervalSince(lastFailureAt) < 6 * 60 * 60
    }

    /// 100 at <= 50 ms, linearly saturating to 0 at >= 1,000 ms.
    static func latencyQuality(milliseconds: Double) -> Double {
        inverseLinearQuality(value: milliseconds, best: 50, worst: 1_000)
    }

    /// 100 at 0% loss, linearly saturating to 0 at >= 20% loss.
    static func packetLossQuality(percent: Double) -> Double {
        inverseLinearQuality(value: percent, best: 0, worst: 20)
    }

    /// 100 at <= 1 second, linearly saturating to 0 at >= 30 seconds.
    static func connectSpeedQuality(seconds: Double) -> Double {
        inverseLinearQuality(value: seconds, best: 1, worst: 30)
    }

    /// Immediate penalty is 14 points per consecutive failure, capped at 45.
    /// It recovers with a 24-hour half-life and never permanently blacklists.
    func failurePenalty(
        statistics: SmartConnectionStatistics,
        now: Date
    ) -> Double {
        guard statistics.consecutiveFailures > 0,
              let lastFailureAt = statistics.lastFailureAt else {
            return 0
        }
        let ageHours = max(0, now.timeIntervalSince(lastFailureAt) / 3_600)
        let immediate = min(45, 14 * Double(statistics.consecutiveFailures))
        return immediate * pow(0.5, ageHours / 24)
    }

    private func hierarchicalQuality(
        component: Component,
        context: SmartConnectionStatistics,
        profile: SmartConnectionStatistics,
        protocolStatistics: SmartConnectionStatistics,
        now: Date
    ) -> Double {
        var quality = neutralQuality
        quality = blend(
            evidence(for: component, statistics: protocolStatistics, now: now),
            toward: quality,
            priorStrength: 12
        )
        quality = blend(
            evidence(for: component, statistics: profile, now: now),
            toward: quality,
            priorStrength: 10
        )
        quality = blend(
            evidence(for: component, statistics: context, now: now),
            toward: quality,
            priorStrength: 8
        )
        return clamp(quality)
    }

    private func evidence(
        for component: Component,
        statistics: SmartConnectionStatistics,
        now: Date
    ) -> (quality: Double, samples: Double)? {
        let quality: Double
        let rawSampleCount: Int
        switch component {
        case .reliability:
            guard statistics.attemptCount > 0 else { return nil }
            quality = Double(statistics.successfulConnectionCount)
                / Double(statistics.attemptCount) * 100
            rawSampleCount = statistics.attemptCount
        case .latency:
            guard let latency = statistics.ewmaLatencyMilliseconds,
                  statistics.latencySampleCount > 0 else { return nil }
            quality = Self.latencyQuality(milliseconds: latency)
            rawSampleCount = statistics.latencySampleCount
        case .packetLoss:
            guard let loss = statistics.ewmaPacketLossPercent,
                  statistics.packetLossSampleCount > 0 else { return nil }
            quality = Self.packetLossQuality(percent: loss)
            rawSampleCount = statistics.packetLossSampleCount
        case .connectSpeed:
            guard let duration = statistics.ewmaConnectDurationSeconds,
                  statistics.connectDurationSampleCount > 0 else { return nil }
            quality = Self.connectSpeedQuality(seconds: duration)
            rawSampleCount = statistics.connectDurationSampleCount
        case .stability:
            let sampleCount = max(
                statistics.completedSessionCount,
                statistics.unexpectedDisconnectCount
            )
            guard sampleCount > 0 else { return nil }
            let successfulConnections = max(
                1,
                statistics.successfulConnectionCount
            )
            let unexpectedRate = min(
                1,
                Double(statistics.unexpectedDisconnectCount)
                    / Double(successfulConnections)
            )
            let disconnectQuality = (1 - unexpectedRate) * 100
            let averageSessionSeconds = statistics.successfulSessionSeconds
                / Double(max(1, statistics.completedSessionCount))
            let durationQuality = 70
                + min(1, averageSessionSeconds / 1_800) * 30
            quality = disconnectQuality * 0.75 + durationQuality * 0.25
            rawSampleCount = sampleCount
        }

        let samples = effectiveSamples(
            count: rawSampleCount,
            lastUpdatedAt: statistics.lastUpdatedAt,
            now: now
        )
        guard samples > 0 else { return nil }
        return (clamp(quality), samples)
    }

    private func blend(
        _ evidence: (quality: Double, samples: Double)?,
        toward prior: Double,
        priorStrength: Double
    ) -> Double {
        guard let evidence else {
            return prior
        }
        return (
            evidence.quality * evidence.samples + prior * priorStrength
        ) / (evidence.samples + priorStrength)
    }

    private func effectiveSamples(
        count: Int,
        lastUpdatedAt: Date?,
        now: Date
    ) -> Double {
        guard count > 0 else { return 0 }
        guard let lastUpdatedAt else { return Double(count) }
        let ageDays = max(0, now.timeIntervalSince(lastUpdatedAt) / 86_400)
        return Double(count) * pow(0.5, ageDays / historyHalfLifeDays)
    }

    private func successRecencyBonus(
        statistics: SmartConnectionStatistics,
        now: Date
    ) -> Double {
        guard statistics.successfulConnectionCount > 0,
              let lastSuccessAt = statistics.lastSuccessAt else {
            return 0
        }
        let ageDays = max(0, now.timeIntervalSince(lastSuccessAt) / 86_400)
        let confidence = min(
            1,
            Double(statistics.successfulConnectionCount) / 4
        )
        return 4 * confidence * pow(0.5, ageDays / 14)
    }

    private func reasons(
        for breakdown: SmartConnectionScoreBreakdown,
        contextAttempts: Int
    ) -> [SmartConnectionRecommendationReason] {
        guard contextAttempts >= 3 else {
            return [.learningThisNetwork, .availableData]
        }

        let rankedReasons: [(
            quality: Double,
            reason: SmartConnectionRecommendationReason
        )] = [
            (breakdown.reliability, .mostReliable),
            (breakdown.latency, .lowestLatency),
            (breakdown.packetLoss, .lowestLoss),
            (breakdown.connectSpeed, .fastestConnection),
            (breakdown.stability, .stableSessions)
        ]
        let useful = rankedReasons
            .filter { $0.quality >= 72 }
            .sorted {
                if $0.quality == $1.quality {
                    return $0.reason.rawValue < $1.reason.rawValue
                }
                return $0.quality > $1.quality
            }
            .prefix(3)
            .map(\.reason)
        return useful.isEmpty ? [.availableData] : useful
    }

    private static func inverseLinearQuality(
        value: Double,
        best: Double,
        worst: Double
    ) -> Double {
        guard value > best else { return 100 }
        guard value < worst else { return 0 }
        return (worst - value) / (worst - best) * 100
    }

    private func clamp(_ value: Double) -> Double {
        min(100, max(0, value))
    }
}

nonisolated struct SmartConnectionCandidatePlanner: Sendable {
    private let scoreCalculator: SmartConnectionScoreCalculator
    private let maximumAttempts: Int
    private let explorationEligibilityDistance = 8.0
    private let maximumExplorationBonus = 5.0
    private let fullContextConfidenceSamples = 8.0

    init(
        scoreCalculator: SmartConnectionScoreCalculator =
            SmartConnectionScoreCalculator(),
        maximumAttempts: Int = 3
    ) {
        self.scoreCalculator = scoreCalculator
        self.maximumAttempts = max(1, maximumAttempts)
    }

    func plan(
        profiles: [VPNProfile],
        context: NetworkContext,
        learning: SmartConnectionLearningSnapshot,
        now: Date
    ) -> SmartConnectionCandidatePlan {
        let eligibleProfiles = profiles.filter(Self.isEligible)
        guard eligibleProfiles.isEmpty == false else {
            return .empty(context: context, now: now)
        }

        let exploitationCandidates = eligibleProfiles.map { profile in
            scoreCalculator.score(
                profile: profile,
                context: context,
                learning: learning,
                now: now
            )
        }
        let bestExploitationScore = exploitationCandidates
            .map(\.breakdown.effectiveScore)
            .max() ?? 0
        let profilesByID = Dictionary(
            uniqueKeysWithValues: eligibleProfiles.map { ($0.id, $0) }
        )

        let exploredCandidates = exploitationCandidates.map { candidate in
            guard let profile = profilesByID[candidate.profileID],
                  candidate.breakdown.effectiveScore
                    >= bestExploitationScore - explorationEligibilityDistance,
                  scoreCalculator.isUnderFailureCooldown(
                    profile: profile,
                    context: context,
                    learning: learning,
                    now: now
                  ) == false else {
                return candidate
            }

            let effectiveSamples = scoreCalculator.effectiveContextAttemptCount(
                profile: profile,
                context: context,
                learning: learning,
                now: now
            )
            let uncertainty = max(
                0,
                1 - min(1, effectiveSamples / fullContextConfidenceSamples)
            )
            let bonus = min(
                maximumExplorationBonus,
                maximumExplorationBonus * uncertainty
            )
            return scoreCalculator.score(
                profile: profile,
                context: context,
                learning: learning,
                now: now,
                explorationBonus: bonus
            )
        }

        let ranked = exploredCandidates.sorted { first, second in
            if first.breakdown.effectiveScore != second.breakdown.effectiveScore {
                return first.breakdown.effectiveScore
                    > second.breakdown.effectiveScore
            }
            if first.breakdown.baseScore != second.breakdown.baseScore {
                return first.breakdown.baseScore > second.breakdown.baseScore
            }
            return first.profileID.uuidString < second.profileID.uuidString
        }

        return SmartConnectionCandidatePlan(
            id: UUID(),
            createdAt: now,
            context: context,
            maximumAttempts: min(maximumAttempts, ranked.count),
            rankedCandidates: ranked
        )
    }

    static func isEligible(_ profile: VPNProfile) -> Bool {
        profile.isEnabled
            && profile.isComplete
            && profile.runtimeCapability.isReady
    }
}
