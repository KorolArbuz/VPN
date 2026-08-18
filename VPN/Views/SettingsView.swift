//
//  SettingsView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI

struct SettingsView: View {
    private let viewModel: VPNDashboardViewModel?
    @State private var healthDiagnostics: PortableHealthDiagnosticsViewModel
    @State private var tunnelTelemetry: TunnelTelemetryDiagnosticsViewModel
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(AppLanguage.storageKey) private var languageRawValue = AppLanguage.system.rawValue
    @AppStorage(PortableCoreProbeFeature.storageKey) private var probingEnabled = false

    @MainActor
    init(
        viewModel: VPNDashboardViewModel? = nil,
        healthDiagnostics: PortableHealthDiagnosticsViewModel? = nil,
        tunnelTelemetry: TunnelTelemetryDiagnosticsViewModel? = nil
    ) {
        self.viewModel = viewModel
        _healthDiagnostics = State(initialValue: healthDiagnostics ?? PortableHealthDiagnosticsViewModel())
        _tunnelTelemetry = State(initialValue: tunnelTelemetry ?? TunnelTelemetryDiagnosticsViewModel())
    }

    var body: some View {
        List {
            Section("settings.language") {
                Picker("settings.language", selection: $languageRawValue) {
                    ForEach(AppLanguage.allCases) { language in
                        Text(LocalizedStringKey(language.localizedTitleKey))
                            .tag(language.rawValue)
                    }
                }
                .pickerStyle(.inline)
            }

            Section("App") {
                LabeledContent("settings.connection_engine", value: "Mock")
                LabeledContent("Mode", value: "Demo")
                LabeledContent("NetworkExtension", value: "Not configured")
                LabeledContent("Diagnostics", value: "Local only")
            }

            Section("Security") {
                Label("Credentials are stored by reference in this prototype.", systemImage: "lock.shield")
                    .foregroundStyle(.secondary)
                Label("vpn.demo_mode", systemImage: "info.circle")
                    .foregroundStyle(.secondary)
            }

            #if DEBUG
            Section("diagnostics.transport_health") {
                Toggle("diagnostics.probing_enabled", isOn: $probingEnabled)

                Text("diagnostics.passive_notice")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                if healthDiagnostics.lastRunContext?.routeContext == .currentSystemPath {
                    Label("diagnostics.current_system_path_notice", systemImage: "point.topleft.down.curvedto.point.bottomright.up")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                if healthDiagnostics.isRunning {
                    ProgressView("diagnostics.probe.running")
                }

                if let errorKey = healthDiagnostics.errorKey {
                    Label(LocalizedStringKey(errorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                HStack {
                    Button("diagnostics.run_health_check") {
                        healthDiagnostics.runHealthCheck(
                            profiles: viewModel?.profiles ?? [],
                            connectionState: viewModel?.connectionState ?? .disconnected,
                            probingEnabled: probingEnabled
                        )
                    }
                    .disabled(healthDiagnostics.isRunning || viewModel == nil)

                    Spacer()

                    if healthDiagnostics.isRunning {
                        Button("common.cancel") {
                            healthDiagnostics.cancel()
                        }
                    }
                }

                ForEach(healthDiagnostics.summaries) { summary in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text(summary.displayName)
                                .font(.headline)
                            Spacer()
                            Text(summary.protocolType.displayName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }

                        Text(verbatim: "\(summary.host):\(summary.port)")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        LabeledContent("diagnostics.probe.status", value: statusText(summary))
                        LabeledContent("diagnostics.probe.connect_latency", value: millisecondsText(summary.connectLatencyMs))
                        LabeledContent("diagnostics.probe.jitter", value: millisecondsText(summary.jitterMs))
                        LabeledContent("diagnostics.probe.tls_handshake", value: millisecondsText(summary.handshakeMs))

                        if let failure = summary.failure {
                            Label(LocalizedStringKey(failure.localizationKey), systemImage: "info.circle")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                }

                if let recommendation = healthDiagnostics.recommendation {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.recommendation")
                            .font(.headline)

                        LabeledContent("diagnostics.selected_candidate", value: shortID(recommendation.selected))
                        LabeledContent("diagnostics.current_candidate", value: shortID(recommendation.current))
                        LabeledContent("diagnostics.should_switch", value: localizedValue(recommendation.shouldSwitch ? "common.yes" : "common.no"))
                        LabeledContent("diagnostics.selection_reason", value: localizedValue(recommendation.reason.localizationKey))

                        if let score = recommendation.selectedScore {
                            LabeledContent("diagnostics.selected_score", value: scoreText(score))
                        }

                        if let confidence = recommendation.breakdown?.confidence {
                            LabeledContent("diagnostics.confidence", value: percentText(confidence))
                        }
                    }
                    .padding(.vertical, 4)
                }
            }

            Section("diagnostics.tunnel_telemetry") {
                Text("diagnostics.telemetry_notice")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                if tunnelTelemetry.isRefreshing {
                    ProgressView("diagnostics.telemetry.refreshing")
                }

                if let errorKey = tunnelTelemetry.errorKey {
                    Label(LocalizedStringKey(errorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                HStack {
                    Button("diagnostics.telemetry.refresh") {
                        tunnelTelemetry.refresh(
                            profiles: viewModel?.profiles ?? [],
                            activeProfileID: viewModel?.activeProfileID,
                            connectionState: viewModel?.connectionState ?? .disconnected
                        )
                    }
                    .disabled(tunnelTelemetry.isRefreshing || viewModel == nil)

                    Spacer()

                    if tunnelTelemetry.isRefreshing {
                        Button("common.cancel") {
                            tunnelTelemetry.cancel()
                        }
                    }
                }

                LabeledContent("diagnostics.telemetry.system_status", value: providerStatusText(tunnelTelemetry.providerStatus))
                LabeledContent("diagnostics.telemetry.extension", value: localizedValue(tunnelTelemetry.extensionReachable ? "diagnostics.telemetry.extension.reachable" : "diagnostics.telemetry.extension.unreachable"))
                LabeledContent("diagnostics.provider_mode.label", value: diagnosticProviderModeText(tunnelTelemetry.diagnosticProviderMode))

                HStack {
                    Button("diagnostics.provider_mode.reconcile") {
                        tunnelTelemetry.reconcileDiagnosticProviderState()
                    }
                    .disabled(tunnelTelemetry.isReconcilingDiagnosticProviderState || tunnelTelemetry.isRefreshing)

                    Spacer()

                    if tunnelTelemetry.isReconcilingDiagnosticProviderState {
                        ProgressView()
                    }
                }

                if tunnelTelemetry.diagnosticProviderStateIsUnsynchronized {
                    Label("diagnostics.provider_mode.unsynchronized", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if tunnelTelemetry.diagnosticProviderStateIsUnsynchronized || tunnelTelemetry.isRecoveringDiagnosticProvider {
                    HStack {
                        Button("diagnostics.provider_mode.recover") {
                            tunnelTelemetry.recoverDiagnosticProvider()
                        }
                        .disabled(tunnelTelemetry.diagnosticProviderRecoveryIsAvailable == false)

                        Spacer()

                        if tunnelTelemetry.isRecoveringDiagnosticProvider {
                            ProgressView()
                        }
                    }
                }

                if let diagnosticProviderRecoveryErrorKey = tunnelTelemetry.diagnosticProviderRecoveryErrorKey {
                    Label(LocalizedStringKey(diagnosticProviderRecoveryErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                Divider()

                HStack {
                    Button("diagnostics.telemetry.keychain_smoke.run") {
                        tunnelTelemetry.runKeychainSentinelSmokeTest()
                    }
                    .disabled(tunnelTelemetry.isRunningKeychainSmokeTest)

                    Spacer()

                    if tunnelTelemetry.isRunningKeychainSmokeTest {
                        ProgressView()
                    }
                }

                if tunnelTelemetry.keychainSmokeResult.count == 2 {
                    Label("diagnostics.telemetry.keychain_smoke.passed", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                }

                if let keychainSmokeErrorKey = tunnelTelemetry.keychainSmokeErrorKey {
                    Label(LocalizedStringKey(keychainSmokeErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let diagnostic = tunnelTelemetry.keychainSmokeDiagnostic {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.telemetry.keychain_smoke.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.telemetry.keychain_smoke.status", value: keychainSmokeStatusText(diagnostic.status))
                        LabeledContent("diagnostics.telemetry.keychain_smoke.stage", value: diagnostic.stage.rawValue)
                        LabeledContent("diagnostics.telemetry.keychain_smoke.manager", value: managerActionText(diagnostic.managerAction))
                        if let vpnStatus = diagnostic.vpnStatus {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.vpn_status", value: vpnStatus)
                        }
                        if let matches = diagnostic.providerBundleIDMatches {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.provider_bundle_match", value: boolText(matches))
                        }
                        if let reached = diagnostic.extensionRequestReached {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.extension_reached", value: boolText(reached))
                        }
                        if diagnostic.category != .none {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.error_category", value: diagnostic.category.rawValue)
                        }
                        if let osStatus = diagnostic.osStatus {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.osstatus", value: "\(osStatus)")
                        }
                        if let errorDomain = diagnostic.errorDomain,
                           let errorCode = diagnostic.errorCode {
                            let value = [errorDomain, "\(errorCode)", diagnostic.errorSymbol]
                                .compactMap { $0 }
                                .joined(separator: " / ")
                            LabeledContent("diagnostics.telemetry.keychain_smoke.ne_error", value: value)
                        }
                        if let correlationIDPrefix = diagnostic.correlationIDPrefix {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.correlation", value: correlationIDPrefix)
                        }
                        if let cleanupSucceeded = diagnostic.cleanupSucceeded {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.cleanup", value: boolText(cleanupSucceeded))
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                Divider()

                HStack {
                    Button("diagnostics.runtime_validation.run") {
                        tunnelTelemetry.validateRuntimeConfiguration(profile: viewModel?.selectedProfile)
                    }
                    .disabled(
                        tunnelTelemetry.isValidatingRuntimeConfiguration ||
                        tunnelTelemetry.isRunningXrayRemoteEgressProbe ||
                        tunnelTelemetry.isRunningActiveXrayEgressProbe ||
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.diagnosticProviderIsOccupied ||
                        viewModel?.selectedProfile == nil
                    )

                    Spacer()

                    if tunnelTelemetry.isValidatingRuntimeConfiguration {
                        ProgressView()
                    }
                }

                if let result = tunnelTelemetry.runtimeValidationResult, result.success {
                    Label("diagnostics.runtime_validation.passed", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                }

                if let runtimeValidationErrorKey = tunnelTelemetry.runtimeValidationErrorKey {
                    Label(LocalizedStringKey(runtimeValidationErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = tunnelTelemetry.runtimeValidationResult {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.runtime_validation.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.runtime_validation.provider_config", value: boolText(result.providerConfigurationValid))
                        LabeledContent("diagnostics.runtime_validation.record_found", value: boolText(result.profileFound))
                        LabeledContent("diagnostics.runtime_validation.profile_match", value: boolText(result.profileIdentityMatched))
                        LabeledContent("diagnostics.runtime_validation.revision_match", value: boolText(result.revisionMatched))
                        LabeledContent("diagnostics.runtime_validation.schema", value: boolText(result.schemaValid))
                        LabeledContent("diagnostics.runtime_validation.protocol_supported", value: boolText(result.supportedProtocol))
                        LabeledContent("diagnostics.runtime_validation.credential_reference", value: boolText(result.credentialReferenceValid))
                        LabeledContent("diagnostics.runtime_validation.credential_found", value: boolText(result.credentialFound))
                        LabeledContent("diagnostics.runtime_validation.credential_format", value: boolText(result.credentialFormatValid))
                        if let protocolName = result.protocolName {
                            LabeledContent("diagnostics.runtime_validation.protocol", value: protocolName)
                        }
                        if let transportName = result.transportName {
                            LabeledContent("diagnostics.runtime_validation.transport", value: transportName)
                        }
                        if let securityName = result.securityName {
                            LabeledContent("diagnostics.runtime_validation.security", value: securityName)
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                if let diagnostic = tunnelTelemetry.runtimeValidationDiagnostic {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("diagnostics.runtime_validation.stage", value: diagnostic.stage.rawValue)
                        if diagnostic.category != .none {
                            LabeledContent("diagnostics.runtime_validation.category", value: diagnostic.category.rawValue)
                        }
                        if let reached = diagnostic.extensionRequestReached {
                            LabeledContent("diagnostics.runtime_validation.extension_reached", value: boolText(reached))
                        }
                        if let prefix = diagnostic.correlationIDPrefix {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.correlation", value: prefix)
                        }
                        if let providerConfiguration = diagnostic.providerConfiguration {
                            if let subreason = providerConfiguration.parseSubreason {
                                LabeledContent("diagnostics.runtime_validation.provider_config_subreason", value: subreason.rawValue)
                            }
                            if let keyCount = providerConfiguration.keyCount {
                                LabeledContent("diagnostics.runtime_validation.provider_config_key_count", value: "\(keyCount)")
                            }
                            if let keyNames = providerConfiguration.keyNames, keyNames.isEmpty == false {
                                LabeledContent("diagnostics.runtime_validation.provider_config_keys", value: keyNames.joined(separator: ", "))
                            }
                            if let valueTypes = providerConfiguration.valueTypesByKey, valueTypes.isEmpty == false {
                                LabeledContent("diagnostics.runtime_validation.provider_config_types", value: providerConfigurationTypeText(valueTypes))
                            }
                            if let value = providerConfiguration.appPersistedMatchesIntent {
                                LabeledContent("diagnostics.runtime_validation.app_persisted_matches_intent", value: boolText(value))
                            }
                            if let value = providerConfiguration.extensionMatchesPersisted {
                                LabeledContent("diagnostics.runtime_validation.extension_matches_persisted", value: boolText(value))
                            }
                            if let value = providerConfiguration.extensionMatchesRequest {
                                LabeledContent("diagnostics.runtime_validation.extension_matches_request", value: boolText(value))
                            }
                            if let value = providerConfiguration.staleK1ConfigurationObserved {
                                LabeledContent("diagnostics.runtime_validation.stale_k1_observed", value: boolText(value))
                            }
                            if let value = providerConfiguration.staleProfileConfigurationObserved {
                                LabeledContent("diagnostics.runtime_validation.stale_profile_observed", value: boolText(value))
                            }
                            if let value = providerConfiguration.configurationPropagationTimedOut {
                                LabeledContent("diagnostics.runtime_validation.configuration_propagation_timed_out", value: boolText(value))
                            }
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                Divider()

                HStack {
                    Button("diagnostics.xray_validation.run") {
                        tunnelTelemetry.validateXrayConfiguration(profile: viewModel?.selectedProfile)
                    }
                    .disabled(
                        tunnelTelemetry.isValidatingXrayConfiguration ||
                        tunnelTelemetry.isRunningXrayLifecycleSmokeTest ||
                        tunnelTelemetry.isRunningXrayRemoteEgressProbe ||
                        tunnelTelemetry.isRunningActiveXrayEgressProbe ||
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.diagnosticProviderIsOccupied ||
                        viewModel?.selectedProfile == nil
                    )

                    Spacer()

                    if tunnelTelemetry.isValidatingXrayConfiguration {
                        ProgressView()
                    }
                }

                if let result = tunnelTelemetry.xrayValidationResult, result.success {
                    Label("diagnostics.xray_validation.passed", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                }

                if let xrayValidationErrorKey = tunnelTelemetry.xrayValidationErrorKey {
                    Label(LocalizedStringKey(xrayValidationErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = tunnelTelemetry.xrayValidationResult {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.xray_validation.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.xray_validation.runtime_config", value: boolText(result.runtimeConfigurationValid))
                        LabeledContent("diagnostics.xray_validation.builder", value: boolText(result.builderSucceeded))
                        LabeledContent("diagnostics.xray_validation.libxray_available", value: boolText(result.libXrayAvailable))
                        LabeledContent("diagnostics.xray_validation.libxray_api", value: boolText(result.libXrayAPIVersionSupported))
                        LabeledContent("diagnostics.xray_validation.testxray_invoked", value: boolText(result.testXrayInvoked))
                        LabeledContent("diagnostics.xray_validation.testxray_passed", value: boolText(result.testXrayPassed))
                        if let protocolName = result.protocolName {
                            LabeledContent("diagnostics.xray_validation.protocol", value: protocolName)
                        }
                        if let transportName = result.transportName {
                            LabeledContent("diagnostics.xray_validation.transport", value: transportName)
                        }
                        if let securityName = result.securityName {
                            LabeledContent("diagnostics.xray_validation.security", value: securityName)
                        }
                        if let h3ALPNConfigured = result.h3ALPNConfigured {
                            LabeledContent("diagnostics.hysteria2.h3_alpn", value: boolText(h3ALPNConfigured))
                        }
                        if let sniConfigured = result.sniConfigured {
                            LabeledContent("diagnostics.hysteria2.sni_configured", value: boolText(sniConfigured))
                        }
                        if let durationMs = result.durationMs {
                            LabeledContent("diagnostics.xray_validation.duration", value: millisecondsText(durationMs))
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                if let diagnostic = tunnelTelemetry.xrayValidationDiagnostic {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("diagnostics.xray_validation.stage", value: diagnostic.stage.rawValue)
                        if diagnostic.category != .none {
                            LabeledContent("diagnostics.xray_validation.category", value: diagnostic.category.rawValue)
                        }
                        if let reached = diagnostic.extensionRequestReached {
                            LabeledContent("diagnostics.xray_validation.extension_reached", value: boolText(reached))
                        }
                        if let prefix = diagnostic.correlationIDPrefix {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.correlation", value: prefix)
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                Divider()

                Text("diagnostics.xray_lifecycle.warning")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                HStack {
                    Button("diagnostics.xray_lifecycle.run") {
                        tunnelTelemetry.runXrayLifecycleSmokeTest(profile: viewModel?.selectedProfile)
                    }
                    .disabled(
                        tunnelTelemetry.isRunningXrayLifecycleSmokeTest ||
                        tunnelTelemetry.isRunningXrayRemoteEgressProbe ||
                        tunnelTelemetry.isRunningActiveXrayEgressProbe ||
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.diagnosticProviderIsOccupied ||
                        tunnelTelemetry.isValidatingXrayConfiguration ||
                        viewModel?.selectedProfile == nil
                    )

                    Spacer()

                    if tunnelTelemetry.isRunningXrayLifecycleSmokeTest {
                        ProgressView()
                    }
                }

                if let result = tunnelTelemetry.xrayLifecycleSmokeTestResult, result.success {
                    Label("diagnostics.xray_lifecycle.passed", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                }

                if let xrayLifecycleSmokeTestErrorKey = tunnelTelemetry.xrayLifecycleSmokeTestErrorKey {
                    Label(LocalizedStringKey(xrayLifecycleSmokeTestErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = tunnelTelemetry.xrayLifecycleSmokeTestResult {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.xray_lifecycle.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.xray_lifecycle.runtime_config", value: boolText(result.runtimeConfigurationLoaded))
                        LabeledContent("diagnostics.xray_lifecycle.builder", value: boolText(result.xrayConfigurationBuilt))
                        LabeledContent("diagnostics.xray_lifecycle.testxray_passed", value: boolText(result.testXrayPassed))
                        LabeledContent("diagnostics.xray_lifecycle.runxray_invoked", value: boolText(result.runXrayInvoked))
                        LabeledContent("diagnostics.xray_lifecycle.running_state", value: boolText(result.runningStateObserved))
                        LabeledContent("diagnostics.xray_lifecycle.socks_ready", value: boolText(result.socksListenerReady))
                        LabeledContent("diagnostics.xray_lifecycle.socks_greeting", value: boolText(result.socksGreetingAccepted))
                        LabeledContent("diagnostics.xray_lifecycle.stopxray_invoked", value: boolText(result.stopXrayInvoked))
                        LabeledContent("diagnostics.xray_lifecycle.stopped_state", value: boolText(result.stoppedStateObserved))
                        LabeledContent("diagnostics.xray_lifecycle.port_closed", value: boolText(result.localPortClosed))
                        if result.rollbackAttempted {
                            LabeledContent("diagnostics.xray_lifecycle.rollback", value: boolText(result.rollbackSucceeded))
                        }
                        if let protocolName = result.protocolName {
                            LabeledContent("diagnostics.xray_lifecycle.protocol", value: protocolName)
                        }
                        if let transportName = result.transportName {
                            LabeledContent("diagnostics.xray_lifecycle.transport", value: transportName)
                        }
                        if let securityName = result.securityName {
                            LabeledContent("diagnostics.xray_lifecycle.security", value: securityName)
                        }
                        if let h3ALPNConfigured = result.h3ALPNConfigured {
                            LabeledContent("diagnostics.hysteria2.h3_alpn", value: boolText(h3ALPNConfigured))
                        }
                        if let sniConfigured = result.sniConfigured {
                            LabeledContent("diagnostics.hysteria2.sni_configured", value: boolText(sniConfigured))
                        }
                        if let startDurationMs = result.startDurationMs {
                            LabeledContent("diagnostics.xray_lifecycle.start_duration", value: millisecondsText(startDurationMs))
                        }
                        if let readinessDurationMs = result.readinessDurationMs {
                            LabeledContent("diagnostics.xray_lifecycle.readiness_duration", value: millisecondsText(readinessDurationMs))
                        }
                        if let stopDurationMs = result.stopDurationMs {
                            LabeledContent("diagnostics.xray_lifecycle.stop_duration", value: millisecondsText(stopDurationMs))
                        }
                        if let totalDurationMs = result.totalDurationMs {
                            LabeledContent("diagnostics.xray_lifecycle.total_duration", value: millisecondsText(totalDurationMs))
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                if let diagnostic = tunnelTelemetry.xrayLifecycleSmokeTestDiagnostic {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("diagnostics.xray_lifecycle.stage", value: diagnostic.stage.rawValue)
                        if diagnostic.category != .none {
                            LabeledContent("diagnostics.xray_lifecycle.category", value: diagnostic.category.rawValue)
                        }
                        if let reached = diagnostic.extensionRequestReached {
                            LabeledContent("diagnostics.xray_lifecycle.extension_reached", value: boolText(reached))
                        }
                        if let prefix = diagnostic.correlationIDPrefix {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.correlation", value: prefix)
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                Divider()

                Text("diagnostics.xray_remote_egress.warning")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                HStack {
                    Button("diagnostics.xray_remote_egress.run") {
                        tunnelTelemetry.runXrayRemoteEgressProbe(profile: viewModel?.selectedProfile)
                    }
                    .disabled(
                        tunnelTelemetry.isRunningXrayRemoteEgressProbe ||
                        tunnelTelemetry.isRunningActiveXrayEgressProbe ||
                        tunnelTelemetry.isRunningXrayLifecycleSmokeTest ||
                        tunnelTelemetry.isValidatingXrayConfiguration ||
                        tunnelTelemetry.isStartingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStoppingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStartingDataPlaneTunnel ||
                        tunnelTelemetry.isStoppingDataPlaneTunnel ||
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.diagnosticProviderIsOccupied ||
                        viewModel?.selectedProfile == nil
                    )

                    Spacer()

                    if tunnelTelemetry.isRunningXrayRemoteEgressProbe {
                        ProgressView()
                    }
                }

                if let result = tunnelTelemetry.xrayRemoteEgressProbeResult, result.success {
                    Label("diagnostics.xray_remote_egress.passed", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                }

                if let xrayRemoteEgressProbeErrorKey = tunnelTelemetry.xrayRemoteEgressProbeErrorKey {
                    Label(LocalizedStringKey(xrayRemoteEgressProbeErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = tunnelTelemetry.xrayRemoteEgressProbeResult {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.xray_remote_egress.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.xray_remote_egress.builder", value: boolText(result.xrayBuildPassed))
                        LabeledContent("diagnostics.xray_remote_egress.testxray", value: boolText(result.testXrayPassed))
                        LabeledContent("diagnostics.xray_remote_egress.xray_running", value: boolText(result.xrayRunning))
                        LabeledContent("diagnostics.xray_remote_egress.local_socks", value: boolText(result.localSocksReady))
                        LabeledContent("diagnostics.xray_remote_egress.socks_connect_requested", value: boolText(result.socksConnectRequested))
                        LabeledContent("diagnostics.xray_remote_egress.socks_connect_accepted", value: boolText(result.socksConnectAccepted))
                        LabeledContent("diagnostics.xray_remote_egress.payload_write", value: boolText(result.payloadWriteSucceeded))
                        LabeledContent("diagnostics.xray_remote_egress.remote_first_byte", value: boolText(result.remoteFirstByteReceived))
                        LabeledContent("diagnostics.xray_remote_egress.remote_response", value: boolText(result.remoteResponseValidated))
                        LabeledContent("diagnostics.xray_remote_egress.remote_egress", value: boolText(result.remoteEgressSucceeded))
                        LabeledContent("diagnostics.xray_remote_egress.remote_category", value: result.remoteConnectCategory.rawValue)
                        LabeledContent("diagnostics.xray_remote_egress.cleanup", value: boolText(result.cleanupSucceeded))
                        if let protocolName = result.protocolName {
                            LabeledContent("diagnostics.xray_lifecycle.protocol", value: protocolName)
                        }
                        if let transportName = result.transportName {
                            LabeledContent("diagnostics.xray_lifecycle.transport", value: transportName)
                        }
                        if let securityName = result.securityName {
                            LabeledContent("diagnostics.xray_lifecycle.security", value: securityName)
                        }
                        if let h3ALPNConfigured = result.h3ALPNConfigured {
                            LabeledContent("diagnostics.hysteria2.h3_alpn", value: boolText(h3ALPNConfigured))
                        }
                        if let sniConfigured = result.sniConfigured {
                            LabeledContent("diagnostics.hysteria2.sni_configured", value: boolText(sniConfigured))
                        }
                        if let allowInsecureConfigured = result.allowInsecureConfigured {
                            LabeledContent("diagnostics.hysteria2.allow_insecure", value: boolText(allowInsecureConfigured))
                        }
                        if let startDurationMs = result.startDurationMs {
                            LabeledContent("diagnostics.xray_lifecycle.start_duration", value: millisecondsText(startDurationMs))
                        }
                        if let readinessDurationMs = result.readinessDurationMs {
                            LabeledContent("diagnostics.xray_lifecycle.readiness_duration", value: millisecondsText(readinessDurationMs))
                        }
                        if let remoteConnectDurationMs = result.remoteConnectDurationMs {
                            LabeledContent("diagnostics.xray_remote_egress.remote_duration", value: millisecondsText(remoteConnectDurationMs))
                        }
                        if let stopDurationMs = result.stopDurationMs {
                            LabeledContent("diagnostics.xray_lifecycle.stop_duration", value: millisecondsText(stopDurationMs))
                        }
                        if let totalDurationMs = result.totalDurationMs {
                            LabeledContent("diagnostics.xray_lifecycle.total_duration", value: millisecondsText(totalDurationMs))
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                if let diagnostic = tunnelTelemetry.xrayRemoteEgressProbeDiagnostic {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("diagnostics.xray_lifecycle.stage", value: diagnostic.stage.rawValue)
                        if diagnostic.category != .none {
                            LabeledContent("diagnostics.xray_lifecycle.category", value: diagnostic.category.rawValue)
                        }
                        if let reached = diagnostic.extensionRequestReached {
                            LabeledContent("diagnostics.xray_lifecycle.extension_reached", value: boolText(reached))
                        }
                        if let prefix = diagnostic.correlationIDPrefix {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.correlation", value: prefix)
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                Divider()

                Text("diagnostics.runtime_only.warning")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                HStack {
                    Button("diagnostics.runtime_only.start") {
                        tunnelTelemetry.startRuntimeOnlyTunnel(profile: viewModel?.selectedProfile)
                    }
                    .disabled(
                        tunnelTelemetry.isStartingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStoppingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isRunningXrayLifecycleSmokeTest ||
                        tunnelTelemetry.isRunningXrayRemoteEgressProbe ||
                        tunnelTelemetry.isRunningActiveXrayEgressProbe ||
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isValidatingXrayConfiguration ||
                        viewModel?.selectedProfile == nil ||
                        tunnelTelemetry.persistentDiagnosticStartIsEligible == false
                    )

                    Button("diagnostics.runtime_only.stop") {
                        tunnelTelemetry.stopRuntimeOnlyTunnel()
                    }
                    .disabled(
                        tunnelTelemetry.isStartingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStoppingRuntimeOnlyTunnel ||
                        tunnelTelemetry.runtimeOnlyDiagnosticModeIsRunning == false
                    )

                    Spacer()

                    if tunnelTelemetry.isStartingRuntimeOnlyTunnel || tunnelTelemetry.isStoppingRuntimeOnlyTunnel {
                        ProgressView()
                    }
                }

                if let runtimeOnlyTunnelErrorKey = tunnelTelemetry.runtimeOnlyTunnelErrorKey {
                    Label(LocalizedStringKey(runtimeOnlyTunnelErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = tunnelTelemetry.runtimeOnlyTunnelResult {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.runtime_only.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.xray_lifecycle.runtime_config", value: boolText(result.runtimeConfigurationLoaded))
                        LabeledContent("diagnostics.xray_lifecycle.builder", value: boolText(result.xrayConfigurationBuilt))
                        LabeledContent("diagnostics.xray_lifecycle.testxray_passed", value: boolText(result.testXrayPassed))
                        LabeledContent("diagnostics.xray_lifecycle.runxray_invoked", value: boolText(result.runXrayInvoked))
                        LabeledContent("diagnostics.xray_lifecycle.running_state", value: boolText(result.runningStateObserved))
                        LabeledContent("diagnostics.xray_lifecycle.socks_ready", value: boolText(result.socksListenerReady))
                        LabeledContent("diagnostics.xray_lifecycle.socks_greeting", value: boolText(result.socksGreetingAccepted))
                        LabeledContent("diagnostics.xray_lifecycle.stopxray_invoked", value: boolText(result.stopXrayInvoked))
                        LabeledContent("diagnostics.xray_lifecycle.stopped_state", value: boolText(result.stoppedStateObserved))
                        LabeledContent("diagnostics.xray_lifecycle.port_closed", value: boolText(result.localPortClosed))
                        if result.rollbackAttempted {
                            LabeledContent("diagnostics.xray_lifecycle.rollback", value: boolText(result.rollbackSucceeded))
                        }
                        if let protocolName = result.protocolName {
                            LabeledContent("diagnostics.xray_lifecycle.protocol", value: protocolName)
                        }
                        if let transportName = result.transportName {
                            LabeledContent("diagnostics.xray_lifecycle.transport", value: transportName)
                        }
                        if let securityName = result.securityName {
                            LabeledContent("diagnostics.xray_lifecycle.security", value: securityName)
                        }
                        if let h3ALPNConfigured = result.h3ALPNConfigured {
                            LabeledContent("diagnostics.hysteria2.h3_alpn", value: boolText(h3ALPNConfigured))
                        }
                        if let sniConfigured = result.sniConfigured {
                            LabeledContent("diagnostics.hysteria2.sni_configured", value: boolText(sniConfigured))
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                if let diagnostic = tunnelTelemetry.runtimeOnlyTunnelDiagnostic {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("diagnostics.xray_lifecycle.stage", value: diagnostic.stage.rawValue)
                        if diagnostic.category != .none {
                            LabeledContent("diagnostics.xray_lifecycle.category", value: diagnostic.category.rawValue)
                        }
                        if let reached = diagnostic.extensionRequestReached {
                            LabeledContent("diagnostics.xray_lifecycle.extension_reached", value: boolText(reached))
                        }
                        if let prefix = diagnostic.correlationIDPrefix {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.correlation", value: prefix)
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                Divider()

                Text("diagnostics.data_plane.warning")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                HStack {
                    Button("diagnostics.data_plane.start") {
                        tunnelTelemetry.startDataPlaneTunnel(profile: viewModel?.selectedProfile)
                    }
                    .disabled(
                        tunnelTelemetry.isStartingDataPlaneTunnel ||
                        tunnelTelemetry.isStoppingDataPlaneTunnel ||
                        tunnelTelemetry.isStartingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStoppingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isRunningXrayLifecycleSmokeTest ||
                        tunnelTelemetry.isRunningXrayRemoteEgressProbe ||
                        tunnelTelemetry.isRunningActiveXrayEgressProbe ||
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isValidatingXrayConfiguration ||
                        viewModel?.selectedProfile == nil ||
                        tunnelTelemetry.persistentDiagnosticStartIsEligible == false
                    )

                    Button("diagnostics.data_plane.stop") {
                        tunnelTelemetry.stopDataPlaneTunnel()
                    }
                    .disabled(
                        tunnelTelemetry.isStartingDataPlaneTunnel ||
                        tunnelTelemetry.isStoppingDataPlaneTunnel ||
                        tunnelTelemetry.dataPlaneDiagnosticModeIsRunning == false
                    )

                    Spacer()

                    if tunnelTelemetry.isStartingDataPlaneTunnel || tunnelTelemetry.isStoppingDataPlaneTunnel {
                        ProgressView()
                    }
                }

                if let dataPlaneTunnelErrorKey = tunnelTelemetry.dataPlaneTunnelErrorKey {
                    Label(LocalizedStringKey(dataPlaneTunnelErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = tunnelTelemetry.dataPlaneTunnelResult {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.data_plane.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.xray_lifecycle.runtime_config", value: boolText(result.runtimeConfigurationLoaded))
                        LabeledContent("diagnostics.xray_lifecycle.builder", value: boolText(result.xrayConfigurationBuilt))
                        LabeledContent("diagnostics.xray_lifecycle.testxray_passed", value: boolText(result.testXrayPassed))
                        LabeledContent("diagnostics.xray_lifecycle.runxray_invoked", value: boolText(result.runXrayInvoked))
                        LabeledContent("diagnostics.xray_lifecycle.running_state", value: boolText(result.runningStateObserved))
                        LabeledContent("diagnostics.xray_lifecycle.socks_ready", value: boolText(result.socksListenerReady))
                        LabeledContent("diagnostics.xray_lifecycle.socks_greeting", value: boolText(result.socksGreetingAccepted))
                        if result.rollbackAttempted {
                            LabeledContent("diagnostics.xray_lifecycle.rollback", value: boolText(result.rollbackSucceeded))
                        }
                        if let protocolName = result.protocolName {
                            LabeledContent("diagnostics.xray_lifecycle.protocol", value: protocolName)
                        }
                        if let transportName = result.transportName {
                            LabeledContent("diagnostics.xray_lifecycle.transport", value: transportName)
                        }
                        if let securityName = result.securityName {
                            LabeledContent("diagnostics.xray_lifecycle.security", value: securityName)
                        }
                        if let h3ALPNConfigured = result.h3ALPNConfigured {
                            LabeledContent("diagnostics.hysteria2.h3_alpn", value: boolText(h3ALPNConfigured))
                        }
                        if let sniConfigured = result.sniConfigured {
                            LabeledContent("diagnostics.hysteria2.sni_configured", value: boolText(sniConfigured))
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                if let diagnostic = tunnelTelemetry.dataPlaneTunnelDiagnostic {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("diagnostics.xray_lifecycle.stage", value: diagnostic.stage.rawValue)
                        if diagnostic.category != .none {
                            LabeledContent("diagnostics.xray_lifecycle.category", value: diagnostic.category.rawValue)
                        }
                        if let reached = diagnostic.extensionRequestReached {
                            LabeledContent("diagnostics.xray_lifecycle.extension_reached", value: boolText(reached))
                        }
                        if let prefix = diagnostic.correlationIDPrefix {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.correlation", value: prefix)
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                Divider()

                Text("diagnostics.active_xray_egress.warning")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                HStack {
                    Button("diagnostics.active_xray_egress.run") {
                        tunnelTelemetry.probeActiveXrayEgress(profile: viewModel?.selectedProfile)
                    }
                    .disabled(
                        tunnelTelemetry.isRunningActiveXrayEgressProbe ||
                        tunnelTelemetry.isRunningXrayRemoteEgressProbe ||
                        tunnelTelemetry.isRunningXrayLifecycleSmokeTest ||
                        tunnelTelemetry.isValidatingXrayConfiguration ||
                        tunnelTelemetry.isStartingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStoppingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStartingDataPlaneTunnel ||
                        tunnelTelemetry.isStoppingDataPlaneTunnel ||
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        (tunnelTelemetry.runtimeOnlyDiagnosticModeIsRunning == false &&
                         tunnelTelemetry.dataPlaneDiagnosticModeIsRunning == false) ||
                        viewModel?.selectedProfile == nil
                    )

                    Spacer()

                    if tunnelTelemetry.isRunningActiveXrayEgressProbe {
                        ProgressView()
                    }
                }

                if let result = tunnelTelemetry.activeXrayEgressProbeResult, result.success {
                    Label("diagnostics.active_xray_egress.passed", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                }

                if let activeXrayEgressProbeErrorKey = tunnelTelemetry.activeXrayEgressProbeErrorKey {
                    Label(LocalizedStringKey(activeXrayEgressProbeErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = tunnelTelemetry.activeXrayEgressProbeResult {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.active_xray_egress.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.xray_remote_egress.xray_running", value: boolText(result.xrayRunning))
                        LabeledContent("diagnostics.xray_remote_egress.local_socks", value: boolText(result.localSocksReady))
                        LabeledContent("diagnostics.xray_remote_egress.socks_connect_requested", value: boolText(result.socksConnectRequested))
                        LabeledContent("diagnostics.xray_remote_egress.socks_connect_accepted", value: boolText(result.socksConnectAccepted))
                        LabeledContent("diagnostics.xray_remote_egress.payload_write", value: boolText(result.payloadWriteSucceeded))
                        LabeledContent("diagnostics.xray_remote_egress.remote_first_byte", value: boolText(result.remoteFirstByteReceived))
                        LabeledContent("diagnostics.xray_remote_egress.remote_response", value: boolText(result.remoteResponseValidated))
                        LabeledContent("diagnostics.xray_remote_egress.remote_egress", value: boolText(result.remoteEgressSucceeded))
                        LabeledContent("diagnostics.xray_remote_egress.remote_category", value: result.remoteConnectCategory.rawValue)
                        if let probeContext = result.probeContext {
                            LabeledContent("diagnostics.active_xray_egress.context", value: probeContext.rawValue)
                        }
                        if let protocolName = result.protocolName {
                            LabeledContent("diagnostics.xray_lifecycle.protocol", value: protocolName)
                        }
                        if let transportName = result.transportName {
                            LabeledContent("diagnostics.xray_lifecycle.transport", value: transportName)
                        }
                        if let securityName = result.securityName {
                            LabeledContent("diagnostics.xray_lifecycle.security", value: securityName)
                        }
                        if let remoteConnectDurationMs = result.remoteConnectDurationMs {
                            LabeledContent("diagnostics.xray_remote_egress.remote_duration", value: millisecondsText(remoteConnectDurationMs))
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                if let diagnostic = tunnelTelemetry.activeXrayEgressProbeDiagnostic {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("diagnostics.xray_lifecycle.stage", value: diagnostic.stage.rawValue)
                        if diagnostic.category != .none {
                            LabeledContent("diagnostics.xray_lifecycle.category", value: diagnostic.category.rawValue)
                        }
                        if let reached = diagnostic.extensionRequestReached {
                            LabeledContent("diagnostics.xray_lifecycle.extension_reached", value: boolText(reached))
                        }
                        if let prefix = diagnostic.correlationIDPrefix {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.correlation", value: prefix)
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                Divider()

                Text("diagnostics.udp_control.warning")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                HStack {
                    Button("diagnostics.udp_control.run") {
                        tunnelTelemetry.runUDPControlProbe()
                    }
                    .disabled(
                        tunnelTelemetry.isRunningUDPControlProbe ||
                        tunnelTelemetry.isRunningActiveXrayEgressProbe ||
                        tunnelTelemetry.isRunningXrayRemoteEgressProbe ||
                        tunnelTelemetry.isRunningXrayLifecycleSmokeTest ||
                        tunnelTelemetry.isValidatingXrayConfiguration ||
                        tunnelTelemetry.isStartingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStoppingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStartingDataPlaneTunnel ||
                        tunnelTelemetry.isStoppingDataPlaneTunnel ||
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.runtimeOnlyDiagnosticModeIsRunning == false
                    )

                    Spacer()

                    if tunnelTelemetry.isRunningUDPControlProbe {
                        ProgressView()
                    }
                }

                if let result = tunnelTelemetry.udpControlProbeResult, result.success {
                    Label("diagnostics.udp_control.passed", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                }

                if let udpControlProbeErrorKey = tunnelTelemetry.udpControlProbeErrorKey {
                    Label(LocalizedStringKey(udpControlProbeErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = tunnelTelemetry.udpControlProbeResult {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.udp_control.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.udp_control.started", value: boolText(result.udpControlStarted))
                        LabeledContent("diagnostics.udp_control.connection_ready", value: boolText(result.udpConnectionReady))
                        LabeledContent("diagnostics.udp_control.write", value: boolText(result.udpWriteSucceeded))
                        LabeledContent("diagnostics.udp_control.response_received", value: boolText(result.udpResponseReceived))
                        LabeledContent("diagnostics.udp_control.response_validated", value: boolText(result.udpResponseValidated))
                        LabeledContent("diagnostics.udp_control.succeeded", value: boolText(result.udpControlSucceeded))
                        LabeledContent("diagnostics.udp_control.category", value: result.failureCategory.rawValue)
                        if let path = result.pathSnapshot {
                            LabeledContent("diagnostics.udp_control.path_status", value: path.pathStatus.rawValue)
                            LabeledContent("diagnostics.udp_control.uses_wifi", value: boolText(path.usesWiFi))
                            LabeledContent("diagnostics.udp_control.uses_cellular", value: boolText(path.usesCellular))
                            LabeledContent("diagnostics.udp_control.uses_wired", value: boolText(path.usesWiredEthernet))
                            LabeledContent("diagnostics.udp_control.supports_ipv4", value: boolText(path.supportsIPv4))
                            LabeledContent("diagnostics.udp_control.supports_ipv6", value: boolText(path.supportsIPv6))
                            LabeledContent("diagnostics.udp_control.supports_dns", value: boolText(path.supportsDNS))
                        }
                        if let durationMs = result.durationMs {
                            LabeledContent("diagnostics.udp_control.duration", value: millisecondsText(durationMs))
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                if let diagnostic = tunnelTelemetry.udpControlProbeDiagnostic {
                    VStack(alignment: .leading, spacing: 8) {
                        if diagnostic.category != .none {
                            LabeledContent("diagnostics.xray_lifecycle.category", value: diagnostic.category.rawValue)
                        }
                        if let reached = diagnostic.extensionRequestReached {
                            LabeledContent("diagnostics.xray_lifecycle.extension_reached", value: boolText(reached))
                        }
                        if let prefix = diagnostic.correlationIDPrefix {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.correlation", value: prefix)
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                Divider()

                Text("diagnostics.libxray_ping_only.warning")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                HStack {
                    Button("diagnostics.libxray_ping_only.start") {
                        tunnelTelemetry.startLibXrayPingOnlyTunnel(profile: viewModel?.selectedProfile)
                    }
                    .disabled(
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.isRunningXrayLifecycleSmokeTest ||
                        tunnelTelemetry.isRunningXrayRemoteEgressProbe ||
                        tunnelTelemetry.isRunningActiveXrayEgressProbe ||
                        tunnelTelemetry.isRunningUDPControlProbe ||
                        tunnelTelemetry.isValidatingXrayConfiguration ||
                        tunnelTelemetry.isStartingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStoppingRuntimeOnlyTunnel ||
                        tunnelTelemetry.isStartingDataPlaneTunnel ||
                        tunnelTelemetry.isStoppingDataPlaneTunnel ||
                        viewModel?.selectedProfile == nil ||
                        tunnelTelemetry.persistentDiagnosticStartIsEligible == false
                    )

                    Button("diagnostics.libxray_ping_only.stop") {
                        tunnelTelemetry.stopLibXrayPingOnlyTunnel()
                    }
                    .disabled(
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.libXrayPingOnlyDiagnosticModeIsRunning == false
                    )

                    Spacer()

                    if tunnelTelemetry.isStartingLibXrayPingOnlyTunnel || tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel {
                        ProgressView()
                    }
                }

                if let libXrayPingOnlyTunnelErrorKey = tunnelTelemetry.libXrayPingOnlyTunnelErrorKey {
                    Label(LocalizedStringKey(libXrayPingOnlyTunnelErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = tunnelTelemetry.libXrayPingOnlyTunnelResult {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.libxray_ping_only.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.xray_lifecycle.runxray_invoked", value: boolText(result.runXrayInvoked))
                        LabeledContent("diagnostics.xray_lifecycle.socks_ready", value: boolText(result.socksListenerReady))
                        LabeledContent("diagnostics.data_plane.network_settings", value: boolText(false))
                        if let protocolName = result.protocolName {
                            LabeledContent("diagnostics.xray_lifecycle.protocol", value: protocolName)
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                HStack {
                    Button("diagnostics.libxray_ping.run") {
                        tunnelTelemetry.runLibXrayPingProbe(profile: viewModel?.selectedProfile)
                    }
                    .disabled(
                        tunnelTelemetry.isRunningLibXrayPingProbe ||
                        tunnelTelemetry.isStartingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isStoppingLibXrayPingOnlyTunnel ||
                        tunnelTelemetry.isRunningXrayLifecycleSmokeTest ||
                        tunnelTelemetry.isRunningXrayRemoteEgressProbe ||
                        tunnelTelemetry.isRunningActiveXrayEgressProbe ||
                        tunnelTelemetry.isRunningUDPControlProbe ||
                        tunnelTelemetry.isValidatingXrayConfiguration ||
                        tunnelTelemetry.libXrayPingOnlyDiagnosticModeIsRunning == false ||
                        viewModel?.selectedProfile == nil
                    )

                    Spacer()

                    if tunnelTelemetry.isRunningLibXrayPingProbe {
                        ProgressView()
                    }
                }

                if let result = tunnelTelemetry.libXrayPingProbeResult, result.success {
                    Label("diagnostics.libxray_ping.passed", systemImage: "checkmark.circle")
                        .foregroundStyle(.green)
                }

                if let libXrayPingProbeErrorKey = tunnelTelemetry.libXrayPingProbeErrorKey {
                    Label(LocalizedStringKey(libXrayPingProbeErrorKey), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = tunnelTelemetry.libXrayPingProbeResult {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.libxray_ping.diagnostics")
                            .font(.headline)
                        LabeledContent("diagnostics.libxray_ping.config_built", value: boolText(result.xrayConfigurationBuilt))
                        LabeledContent("diagnostics.libxray_ping.accepted", value: boolText(result.pingAccepted))
                        LabeledContent("diagnostics.libxray_ping.completed", value: boolText(result.pingCompleted))
                        LabeledContent("diagnostics.libxray_ping.succeeded", value: boolText(result.pingSucceeded))
                        LabeledContent("diagnostics.libxray_ping.timed_out", value: boolText(result.timedOut))
                        LabeledContent("diagnostics.libxray_ping.native_error", value: boolText(result.nativeErrorPresent))
                        LabeledContent("diagnostics.libxray_ping.category", value: result.sanitizedFailureCategory.rawValue)
                        if let protocolName = result.protocolName {
                            LabeledContent("diagnostics.xray_lifecycle.protocol", value: protocolName)
                        }
                        if let transportName = result.transportName {
                            LabeledContent("diagnostics.xray_lifecycle.transport", value: transportName)
                        }
                        if let securityName = result.securityName {
                            LabeledContent("diagnostics.xray_lifecycle.security", value: securityName)
                        }
                        if let h3ALPNConfigured = result.h3ALPNConfigured {
                            LabeledContent("diagnostics.hysteria2.h3_alpn", value: boolText(h3ALPNConfigured))
                        }
                        if let sniConfigured = result.sniConfigured {
                            LabeledContent("diagnostics.hysteria2.sni_configured", value: boolText(sniConfigured))
                        }
                        if let allowInsecureConfigured = result.allowInsecureConfigured {
                            LabeledContent("diagnostics.hysteria2.allow_insecure", value: boolText(allowInsecureConfigured))
                        }
                        if let delayMs = result.delayMs {
                            LabeledContent("diagnostics.libxray_ping.delay", value: "\(delayMs) ms")
                        }
                        if let durationMs = result.durationMs {
                            LabeledContent("diagnostics.udp_control.duration", value: millisecondsText(durationMs))
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                if let diagnostic = tunnelTelemetry.libXrayPingProbeDiagnostic {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("diagnostics.xray_lifecycle.stage", value: diagnostic.stage.rawValue)
                        if diagnostic.category != .none {
                            LabeledContent("diagnostics.xray_lifecycle.category", value: diagnostic.category.rawValue)
                        }
                        if let reached = diagnostic.extensionRequestReached {
                            LabeledContent("diagnostics.xray_lifecycle.extension_reached", value: boolText(reached))
                        }
                        if let prefix = diagnostic.correlationIDPrefix {
                            LabeledContent("diagnostics.telemetry.keychain_smoke.correlation", value: prefix)
                        }
                    }
                    .font(.footnote)
                    .padding(.vertical, 4)
                }

                if let snapshot = tunnelTelemetry.runtimeSnapshot {
                    LabeledContent("diagnostics.telemetry.runtime_state", value: runtimeStateText(snapshot.runtimeState))
                    LabeledContent("diagnostics.telemetry.health_state", value: healthStateText(snapshot.health.state))
                    LabeledContent("diagnostics.telemetry.active_candidate", value: shortID(snapshot.candidateID ?? snapshot.activeProfileID))
                    LabeledContent("diagnostics.telemetry.backend", value: snapshot.backendKind.rawValue)
                    LabeledContent("diagnostics.telemetry.protocol", value: snapshot.protocolKind.rawValue)
                    LabeledContent("diagnostics.telemetry.xray_state", value: componentStateText(snapshot.xrayState))
                    LabeledContent("diagnostics.telemetry.tun2socks_state", value: componentStateText(snapshot.tun2SocksState))
                    LabeledContent("diagnostics.telemetry.uploaded", value: bytesText(snapshot.counters.bytesUploaded))
                    LabeledContent("diagnostics.telemetry.downloaded", value: bytesText(snapshot.counters.bytesDownloaded))
                    LabeledContent("diagnostics.telemetry.packets_uploaded", value: counterText(snapshot.counters.packetsUploaded))
                    LabeledContent("diagnostics.telemetry.packets_downloaded", value: counterText(snapshot.counters.packetsDownloaded))
                    LabeledContent("diagnostics.telemetry.uptime", value: durationText(snapshot.uptimeSeconds))
                    LabeledContent("diagnostics.telemetry.last_state_change", value: dateText(snapshot.lastStateChangeAt))
                    LabeledContent("diagnostics.telemetry.last_traffic", value: dateText(snapshot.lastSuccessfulTrafficAt))
                    LabeledContent("diagnostics.telemetry.reconnect_count", value: "\(snapshot.reconnectCount)")
                    LabeledContent("diagnostics.telemetry.origin", value: telemetryOriginText(snapshot.origin))

                    if let failure = snapshot.lastFailure {
                        LabeledContent("diagnostics.telemetry.last_failure", value: failure.category.rawValue)
                    }
                }

                if let fallback = tunnelTelemetry.lastKnownSnapshot {
                    Label(
                        fallback.isStale ? "diagnostics.telemetry.snapshot_stale" : "diagnostics.telemetry.snapshot_cached",
                        systemImage: "clock.arrow.circlepath"
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }

                if let recommendation = tunnelTelemetry.recommendation {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("diagnostics.telemetry.kvncore")
                            .font(.headline)
                        LabeledContent("diagnostics.selected_candidate", value: shortID(recommendation.selected))
                        LabeledContent("diagnostics.should_switch", value: localizedValue(recommendation.shouldSwitch ? "common.yes" : "common.no"))
                        LabeledContent("diagnostics.telemetry.comparability", value: comparabilityText(tunnelTelemetry.comparability))
                        if let score = recommendation.selectedScore {
                            LabeledContent("diagnostics.selected_score", value: scoreText(score))
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            #endif
        }
        .navigationTitle("settings.title")
        #if DEBUG
        .onChange(of: scenePhase) {
            if scenePhase == .active {
                tunnelTelemetry.reconcileDiagnosticProviderState()
            }
        }
        #endif
    }

    private func statusText(_ summary: TransportProbeSummary) -> String {
        if summary.reachable {
            return localizedValue("diagnostics.probe.status.reachable")
        }

        return localizedValue("diagnostics.probe.status.unreachable")
    }

    private func millisecondsText(_ value: Double?) -> String {
        guard let value else {
            return localizedValue("diagnostics.value.unknown")
        }

        return "\(Int(value.rounded())) ms"
    }

    private func scoreText(_ value: Double) -> String {
        String(format: "%.1f", value)
    }

    private func percentText(_ value: Double) -> String {
        "\(Int((value * 100).rounded()))%"
    }

    private func shortID(_ value: String?) -> String {
        guard let value, value.isEmpty == false else {
            return localizedValue("diagnostics.value.none")
        }

        return String(value.prefix(8))
    }

    private func localizedValue(_ key: String) -> String {
        String(localized: String.LocalizationValue(key))
    }

    private func boolText(_ value: Bool) -> String {
        localizedValue(value ? "common.yes" : "common.no")
    }

    private func providerConfigurationTypeText(_ valueTypes: [String: String]) -> String {
        valueTypes.keys.sorted().map { key in
            "\(key): \(valueTypes[key] ?? "unknown")"
        }.joined(separator: ", ")
    }

    private func keychainSmokeStatusText(_ status: TunnelKeychainSentinelDiagnosticStatus) -> String {
        switch status {
        case .succeeded:
            localizedValue("diagnostics.telemetry.keychain_smoke.status.succeeded")
        case .failed:
            localizedValue("diagnostics.telemetry.keychain_smoke.status.failed")
        }
    }

    private func managerActionText(_ action: TunnelKeychainSentinelManagerAction) -> String {
        switch action {
        case .none:
            localizedValue("diagnostics.value.unknown")
        case .reused:
            localizedValue("diagnostics.telemetry.keychain_smoke.manager.reused")
        case .created:
            localizedValue("diagnostics.telemetry.keychain_smoke.manager.created")
        }
    }

    private func runtimeStateText(_ state: TunnelRuntimeState) -> String {
        localizedValue("diagnostics.telemetry.runtime_state.\(state.rawValue)")
    }

    private func componentStateText(_ state: TunnelComponentState) -> String {
        localizedValue("diagnostics.telemetry.component_state.\(state.rawValue)")
    }

    private func healthStateText(_ state: TunnelHealthState) -> String {
        localizedValue("diagnostics.telemetry.health_state.\(state.rawValue)")
    }

    private func telemetryOriginText(_ origin: TunnelTelemetryOrigin) -> String {
        switch origin {
        case .packetTunnelExtension:
            localizedValue("diagnostics.telemetry.origin.extension")
        case .appGroupLastKnownSnapshot:
            localizedValue("diagnostics.telemetry.origin.snapshot")
        }
    }

    private func comparabilityText(_ value: TunnelTelemetryComparability) -> String {
        switch value {
        case .notUpdated:
            localizedValue("diagnostics.telemetry.comparability.not_updated")
        case .authoritativeCurrentOnly:
            localizedValue("diagnostics.telemetry.comparability.authoritative_current_only")
        case .insufficientComparability:
            localizedValue("diagnostics.telemetry.comparability.insufficient")
        }
    }

    private func providerStatusText(_ status: TunnelProviderSessionStatus) -> String {
        switch status {
        case .invalid:
            localizedValue("diagnostics.telemetry.provider_status.invalid")
        case .disconnected:
            localizedValue("diagnostics.telemetry.provider_status.disconnected")
        case .connecting:
            localizedValue("diagnostics.telemetry.provider_status.connecting")
        case .connected:
            localizedValue("diagnostics.telemetry.provider_status.connected")
        case .reasserting:
            localizedValue("diagnostics.telemetry.provider_status.reasserting")
        case .disconnecting:
            localizedValue("diagnostics.telemetry.provider_status.disconnecting")
        case .unknown:
            localizedValue("diagnostics.value.unknown")
        }
    }

    private func diagnosticProviderModeText(_ mode: TunnelDiagnosticProviderMode) -> String {
        localizedValue("diagnostics.provider_mode.\(mode.rawValue)")
    }

    private func bytesText(_ value: UInt64?) -> String {
        guard let value else {
            return localizedValue("diagnostics.value.unknown")
        }

        return ByteCountFormatter.string(fromByteCount: Int64(value), countStyle: .binary)
    }

    private func counterText(_ value: UInt64?) -> String {
        guard let value else {
            return localizedValue("diagnostics.value.unknown")
        }

        return "\(value)"
    }

    private func durationText(_ value: Double?) -> String {
        guard let value else {
            return localizedValue("diagnostics.value.unknown")
        }

        return "\(Int(value.rounded())) s"
    }

    private func dateText(_ value: Date?) -> String {
        guard let value else {
            return localizedValue("diagnostics.value.unknown")
        }

        return value.formatted(date: .omitted, time: .shortened)
    }
}

private extension KVNSelectionReason {
    var localizationKey: String {
        switch self {
        case .initialSelection:
            "diagnostics.selection_reason.initial_selection"
        case .currentUnavailable:
            "diagnostics.selection_reason.current_unavailable"
        case .significantlyBetter:
            "diagnostics.selection_reason.significantly_better"
        case .failureThresholdReached:
            "diagnostics.selection_reason.failure_threshold_reached"
        case .manualOverride:
            "diagnostics.selection_reason.manual_override"
        case .policyChange:
            "diagnostics.selection_reason.policy_change"
        case .noChange:
            "diagnostics.selection_reason.no_change"
        case .noHealthyCandidates:
            "diagnostics.selection_reason.no_healthy_candidates"
        }
    }
}

#Preview {
    NavigationStack {
        SettingsView()
    }
}
