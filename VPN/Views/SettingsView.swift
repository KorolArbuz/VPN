//
//  SettingsView.swift
//  VPN
//
//  Created by Denis Chizhov on 06.08.2026.
//

import SwiftUI
import UIKit

private enum StartupDiagnosticsStrings {
    static let engineNative = LocalizedStringResource(
        "diagnostics.startup.engine.native",
        defaultValue: "Native NetworkExtension",
        comment: "Production VPN engine shown in Settings diagnostics."
    )
    static let engineFallback = LocalizedStringResource(
        "diagnostics.startup.engine.fallback",
        defaultValue: "Fallback connection manager",
        comment: "Non-production VPN engine shown in Settings diagnostics."
    )
    static let mode = LocalizedStringResource(
        "diagnostics.startup.mode",
        defaultValue: "Runtime mode",
        comment: "Label for the current VPN runtime mode."
    )
    static let modeProduction = LocalizedStringResource(
        "diagnostics.startup.mode.production",
        defaultValue: "Production",
        comment: "Value indicating the real production VPN path is in use."
    )
    static let modeDemo = LocalizedStringResource(
        "diagnostics.startup.mode.demo",
        defaultValue: "Demo",
        comment: "Value indicating the non-production demo VPN path is in use."
    )
    static let networkExtensionConfigured = LocalizedStringResource(
        "diagnostics.startup.network_extension.configured",
        defaultValue: "Production provider configured",
        comment: "Value indicating the production NetworkExtension provider is selected."
    )
    static let networkExtensionNotSelected = LocalizedStringResource(
        "diagnostics.startup.network_extension.not_selected",
        defaultValue: "Production provider not selected",
        comment: "Value indicating the production NetworkExtension provider is not selected."
    )
    static let diagnosticsPersisted = LocalizedStringResource(
        "diagnostics.startup.diagnostics.persisted",
        defaultValue: "Persisted App Group timeline",
        comment: "Value describing where startup diagnostics are retained."
    )
    static let title = LocalizedStringResource(
        "diagnostics.startup.title",
        defaultValue: "Latest connection attempt",
        comment: "Title of the latest native tunnel startup diagnostics section."
    )
    static let attempt = LocalizedStringResource(
        "diagnostics.startup.attempt",
        defaultValue: "Attempt",
        comment: "Label for the shortened activation attempt identifier."
    )
    static let started = LocalizedStringResource(
        "diagnostics.startup.started",
        defaultValue: "Started",
        comment: "Label for the startup attempt timestamp."
    )
    static let appBuild = LocalizedStringResource(
        "diagnostics.startup.app_build",
        defaultValue: "App build",
        comment: "Label for the containing application's version and build."
    )
    static let extensionBuild = LocalizedStringResource(
        "diagnostics.startup.extension_build",
        defaultValue: "Extension build",
        comment: "Label for the PacketTunnelExtension version and build."
    )
    static let buildMismatch = LocalizedStringResource(
        "diagnostics.startup.build_mismatch",
        defaultValue: "App and PacketTunnelExtension builds do not match.",
        comment: "Warning shown when app and embedded extension build numbers differ."
    )
    static let stageApp = LocalizedStringResource(
        "diagnostics.startup.stage.app",
        defaultValue: "App start request",
        comment: "Startup stage for the app-side connection request."
    )
    static let stageProvider = LocalizedStringResource(
        "diagnostics.startup.stage.provider",
        defaultValue: "Provider process",
        comment: "Startup stage for entering the packet tunnel provider process."
    )
    static let stageStartTunnel = LocalizedStringResource(
        "diagnostics.startup.stage.start_tunnel",
        defaultValue: "startTunnel entered",
        comment: "Startup stage for entering PacketTunnelProvider.startTunnel."
    )
    static let stageRuntime = LocalizedStringResource(
        "diagnostics.startup.stage.runtime",
        defaultValue: "Runtime profile",
        comment: "Startup stage for loading the native runtime profile."
    )
    static let stageCredentials = LocalizedStringResource(
        "diagnostics.startup.stage.credentials",
        defaultValue: "Credentials",
        comment: "Startup stage for resolving secure WireGuard credentials."
    )
    static let stageConfiguration = LocalizedStringResource(
        "diagnostics.startup.stage.configuration",
        defaultValue: "AWG configuration",
        comment: "Startup stage for compiling the AmneziaWG configuration."
    )
    static let stageAdapter = LocalizedStringResource(
        "diagnostics.startup.stage.adapter",
        defaultValue: "Native adapter",
        comment: "Startup stage for starting WireGuardAdapter."
    )
    static let stageNetworkSettings = LocalizedStringResource(
        "diagnostics.startup.stage.network_settings",
        defaultValue: "Network settings",
        comment: "Startup stage for applying NEPacketTunnelNetworkSettings."
    )
    static let stageCompletion = LocalizedStringResource(
        "diagnostics.startup.stage.completion",
        defaultValue: "Tunnel completion",
        comment: "Startup stage for completing PacketTunnelProvider startup."
    )
    static let failedStage = LocalizedStringResource(
        "diagnostics.startup.failed_stage",
        defaultValue: "Failed stage",
        comment: "Label for the first recorded failed startup stage."
    )
    static let failureCategory = LocalizedStringResource(
        "diagnostics.startup.failure_category",
        defaultValue: "Failure category",
        comment: "Label for a sanitized native tunnel failure category."
    )
    static let nativeCode = LocalizedStringResource(
        "diagnostics.startup.native_code",
        defaultValue: "Native code",
        comment: "Label for a numeric native WireGuard backend error code."
    )
    static let error = LocalizedStringResource(
        "diagnostics.startup.error",
        defaultValue: "Error",
        comment: "Label for a sanitized error domain and code."
    )
    static let timeline = LocalizedStringResource(
        "diagnostics.startup.timeline",
        defaultValue: "Startup timeline",
        comment: "Title for the ordered native tunnel startup event timeline."
    )
    static let copyReport = LocalizedStringResource(
        "diagnostics.startup.copy_report",
        defaultValue: "Copy diagnostic report",
        comment: "Button that copies a secret-free native tunnel diagnostic report."
    )
    static let noAttempt = LocalizedStringResource(
        "diagnostics.startup.no_attempt",
        defaultValue: "No connection attempt has been recorded yet.",
        comment: "Placeholder when no persisted native tunnel attempt exists."
    )
    static let checkProvider = LocalizedStringResource(
        "diagnostics.startup.check_provider",
        defaultValue: "Check tunnel provider",
        comment: "Button that performs a PacketTunnelExtension IPC preflight."
    )
    static let providerState = LocalizedStringResource(
        "diagnostics.startup.provider_state",
        defaultValue: "Provider status",
        comment: "Label for the detailed PacketTunnelExtension preflight state."
    )
    static let checkAppGroup = LocalizedStringResource(
        "diagnostics.startup.check_app_group",
        defaultValue: "Check App Group",
        comment: "Button that performs a safe app/provider shared-container sentinel test."
    )
    static let appGroupAppWrite = LocalizedStringResource(
        "diagnostics.startup.app_group.app_write",
        defaultValue: "App write",
        comment: "App Group self-test stage where the containing app writes its sentinel."
    )
    static let appGroupProviderRead = LocalizedStringResource(
        "diagnostics.startup.app_group.provider_read",
        defaultValue: "Provider read",
        comment: "App Group self-test stage where the provider reads the app sentinel."
    )
    static let appGroupProviderWrite = LocalizedStringResource(
        "diagnostics.startup.app_group.provider_write",
        defaultValue: "Provider write",
        comment: "App Group self-test stage where the provider writes its sentinel."
    )
    static let appGroupAppRead = LocalizedStringResource(
        "diagnostics.startup.app_group.app_read",
        defaultValue: "App read",
        comment: "App Group self-test stage where the app reads the provider sentinel."
    )
    static let appGroupCleanup = LocalizedStringResource(
        "diagnostics.startup.app_group.cleanup",
        defaultValue: "Cleanup",
        comment: "App Group self-test stage where disposable sentinels are removed."
    )
    static let checkRuntime = LocalizedStringResource(
        "diagnostics.startup.check_runtime",
        defaultValue: "Check runtime profile",
        comment: "Button that validates the selected native runtime profile without exposing secrets."
    )
    static let runtimeExists = LocalizedStringResource(
        "diagnostics.startup.runtime.exists",
        defaultValue: "Runtime profile exists",
        comment: "Runtime profile diagnostic result."
    )
    static let runtimeProfileMatch = LocalizedStringResource(
        "diagnostics.startup.runtime.profile_match",
        defaultValue: "Profile ID matches selected",
        comment: "Runtime profile diagnostic result."
    )
    static let runtimeProtocol = LocalizedStringResource(
        "diagnostics.startup.runtime.protocol",
        defaultValue: "Protocol",
        comment: "Runtime profile diagnostic protocol label."
    )
    static let runtimeRevision = LocalizedStringResource(
        "diagnostics.startup.runtime.revision",
        defaultValue: "Revision",
        comment: "Runtime profile diagnostic revision label."
    )
    static let runtimeEnabled = LocalizedStringResource(
        "diagnostics.startup.runtime.enabled",
        defaultValue: "Enabled",
        comment: "Runtime profile diagnostic enabled-state label."
    )
    static let runtimeReferences = LocalizedStringResource(
        "diagnostics.startup.runtime.references",
        defaultValue: "Credential references valid",
        comment: "Runtime profile diagnostic credential-reference validation label."
    )
    static let runtimeCredentials = LocalizedStringResource(
        "diagnostics.startup.runtime.credentials",
        defaultValue: "Credentials available",
        comment: "Runtime profile diagnostic result; does not expose credential values."
    )
    static let runtimeAWGComplete = LocalizedStringResource(
        "diagnostics.startup.runtime.awg_complete",
        defaultValue: "AWG fields complete",
        comment: "Runtime profile diagnostic result for required AmneziaWG fields."
    )
    static let runtimeMissing = LocalizedStringResource(
        "diagnostics.startup.runtime.missing",
        defaultValue: "Missing fields",
        comment: "Runtime profile diagnostic list of missing non-secret fields."
    )
    static let ok = LocalizedStringResource(
        "diagnostics.startup.ok",
        defaultValue: "OK",
        comment: "A startup stage completed or was reached successfully."
    )
    static let failed = LocalizedStringResource(
        "diagnostics.startup.failed",
        defaultValue: "FAILED",
        comment: "A startup stage failed."
    )
    static let notReached = LocalizedStringResource(
        "diagnostics.startup.not_reached",
        defaultValue: "NOT REACHED",
        comment: "A startup stage was not reached before an earlier failure."
    )
    static let unknown = LocalizedStringResource(
        "diagnostics.startup.unknown",
        defaultValue: "UNKNOWN",
        comment: "No reliable startup-stage information is available."
    )
}

nonisolated struct SettingsConnectionRuntimeStatus: Equatable, Sendable {
    var usesProductionCore: Bool

    var engineValueKey: String {
        usesProductionCore ? "diagnostics.startup.engine.native" : "diagnostics.startup.engine.fallback"
    }

    var modeValueKey: String {
        usesProductionCore ? "diagnostics.startup.mode.production" : "diagnostics.startup.mode.demo"
    }

    var networkExtensionValueKey: String {
        usesProductionCore ? "diagnostics.startup.network_extension.configured" : "diagnostics.startup.network_extension.not_selected"
    }

    var diagnosticsValueKey: String {
        "diagnostics.startup.diagnostics.persisted"
    }
}

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
                let runtimeStatus = SettingsConnectionRuntimeStatus(
                    usesProductionCore: viewModel?.showsDemoModeNotice == false
                )
                LabeledContent("settings.connection_engine", value: localizedValue(runtimeStatus.engineValueKey))
                LabeledContent("diagnostics.startup.mode", value: localizedValue(runtimeStatus.modeValueKey))
                LabeledContent("NetworkExtension", value: localizedValue(runtimeStatus.networkExtensionValueKey))
                LabeledContent("Diagnostics", value: localizedValue(runtimeStatus.diagnosticsValueKey))
            }

            Section("Security") {
                Label("Credentials are stored by reference in this prototype.", systemImage: "lock.shield")
                    .foregroundStyle(.secondary)
                if viewModel?.showsDemoModeNotice != false {
                    Label("vpn.demo_mode", systemImage: "info.circle")
                        .foregroundStyle(.secondary)
                }
            }

            startupDiagnosticsSection

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
        .task {
            tunnelTelemetry.loadLatestStartupDiagnostics()
        }
        #if DEBUG
        .onChange(of: scenePhase) {
            if scenePhase == .active {
                tunnelTelemetry.reconcileDiagnosticProviderState()
            }
        }
        #endif
    }

    @ViewBuilder
    private var startupDiagnosticsSection: some View {
        Section("diagnostics.startup.title") {
            if let attempt = tunnelTelemetry.latestStartupAttempt {
                LabeledContent(
                    "diagnostics.startup.attempt",
                    value: String(attempt.metadata.attemptID.uuidString.prefix(8))
                )
                LabeledContent(
                    "diagnostics.startup.started",
                    value: startupTimeText(attempt.metadata.startedAt)
                )
                LabeledContent(
                    "diagnostics.startup.app_build",
                    value: "\(attempt.appBuild.version) (\(attempt.appBuild.build))"
                )
                LabeledContent(
                    "diagnostics.startup.extension_build",
                    value: attempt.extensionBuild.map { "\($0.version) (\($0.build))" }
                        ?? localizedValue("diagnostics.startup.not_reached")
                )

                if attempt.buildMismatch {
                    Label("diagnostics.startup.build_mismatch", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                Divider()

                ForEach(Array(startupStageRows.enumerated()), id: \.offset) { _, row in
                    LabeledContent(
                        LocalizedStringKey(row.labelKey),
                        value: startupStageStatusText(startupStageStatus(row.stage, in: attempt))
                    )
                }

                if let lastEvent = startupFailureEvent(in: attempt) {
                    Divider()
                    LabeledContent("diagnostics.startup.failed_stage", value: lastEvent.stage.rawValue)
                    LabeledContent(
                        "diagnostics.startup.failure_category",
                        value: lastEvent.failureCategory?.rawValue ?? NativeTunnelFailureCategory.unknown.rawValue
                    )
                    if let nativeCode = lastEvent.details["nativeCode"] {
                        LabeledContent("diagnostics.startup.native_code", value: nativeCode)
                    }
                    if let error = lastEvent.error {
                        LabeledContent(
                            "diagnostics.startup.error",
                            value: "\(error.domain) / \(error.code)"
                        )
                    }
                }

                Divider()

                Text("diagnostics.startup.timeline")
                    .font(.headline)
                ForEach(attempt.events.suffix(32)) { event in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(startupTimeText(event.timestamp))
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(event.stage.rawValue)
                                .font(.caption)
                            if let category = event.failureCategory {
                                Text(category.rawValue)
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                            }
                        }
                    }
                }

                Button("diagnostics.startup.copy_report") {
                    UIPasteboard.general.string = tunnelTelemetry.latestDiagnosticReport
                }
                .disabled(tunnelTelemetry.latestDiagnosticReport == nil)
            } else {
                Text("diagnostics.startup.no_attempt")
                    .foregroundStyle(.secondary)
            }

            Divider()

            HStack {
                Button("diagnostics.startup.check_provider") {
                    tunnelTelemetry.runProviderPreflight()
                }
                .disabled(tunnelTelemetry.isRunningProviderPreflight)
                Spacer()
                if tunnelTelemetry.isRunningProviderPreflight {
                    ProgressView()
                }
            }
            if let result = tunnelTelemetry.providerPreflightResult {
                LabeledContent("diagnostics.startup.provider_state", value: result.state.rawValue)
                LabeledContent(
                    "diagnostics.telemetry.system_status",
                    value: providerStatusText(result.sessionStatus)
                )
                if let domain = result.errorDomain, let code = result.errorCode {
                    LabeledContent("diagnostics.startup.error", value: "\(domain) / \(code)")
                }
            }

            Divider()

            HStack {
                Button("diagnostics.startup.check_app_group") {
                    tunnelTelemetry.runAppGroupSelfTest()
                }
                .disabled(tunnelTelemetry.isRunningAppGroupSelfTest)
                Spacer()
                if tunnelTelemetry.isRunningAppGroupSelfTest {
                    ProgressView()
                }
            }
            if let result = tunnelTelemetry.appGroupSelfTestResult {
                LabeledContent("diagnostics.startup.app_group.app_write", value: boolText(result.appWriteSucceeded))
                LabeledContent("diagnostics.startup.app_group.provider_read", value: boolText(result.providerReadSucceeded))
                LabeledContent("diagnostics.startup.app_group.provider_write", value: boolText(result.providerWriteSucceeded))
                LabeledContent("diagnostics.startup.app_group.app_read", value: boolText(result.appReadSucceeded))
                LabeledContent("diagnostics.startup.app_group.cleanup", value: boolText(result.cleanupSucceeded))
                if let category = result.failureCategory {
                    LabeledContent("diagnostics.startup.failure_category", value: category)
                }
            }

            Divider()

            HStack {
                Button("diagnostics.startup.check_runtime") {
                    tunnelTelemetry.inspectNativeRuntimeProfile(profile: viewModel?.selectedProfile)
                }
                .disabled(
                    tunnelTelemetry.isRunningNativeRuntimeDiagnostic
                        || (viewModel?.selectedProfile?.protocolType != .wireGuard
                            && viewModel?.selectedProfile?.protocolType != .amneziaWG)
                )
                Spacer()
                if tunnelTelemetry.isRunningNativeRuntimeDiagnostic {
                    ProgressView()
                }
            }
            if let result = tunnelTelemetry.nativeRuntimeDiagnosticResult {
                LabeledContent("diagnostics.startup.runtime.exists", value: boolText(result.runtimeProfileExists))
                LabeledContent("diagnostics.startup.runtime.profile_match", value: boolText(result.profileIDMatches))
                LabeledContent("diagnostics.startup.runtime.protocol", value: result.protocolName ?? localizedValue("diagnostics.value.unknown"))
                LabeledContent("diagnostics.startup.runtime.revision", value: result.recordRevision ?? localizedValue("diagnostics.value.unknown"))
                LabeledContent("diagnostics.startup.runtime.enabled", value: boolText(result.enabled))
                LabeledContent("diagnostics.startup.runtime.references", value: boolText(result.credentialReferencesValid))
                LabeledContent("diagnostics.startup.runtime.credentials", value: boolText(result.credentialsAvailable))
                LabeledContent("diagnostics.startup.runtime.awg_complete", value: boolText(result.awgFieldCompleteness))
                if result.missingFields.isEmpty == false {
                    LabeledContent("diagnostics.startup.runtime.missing", value: result.missingFields.joined(separator: ", "))
                }
            }
        }
    }

    private var startupStageRows: [(labelKey: String, stage: TunnelStartupStage)] {
        [
            ("diagnostics.startup.stage.app", .appConnectRequested),
            ("diagnostics.startup.stage.provider", .providerProcessEntered),
            ("diagnostics.startup.stage.start_tunnel", .providerStartTunnelEntered),
            ("diagnostics.startup.stage.runtime", .runtimeProfileLoaded),
            ("diagnostics.startup.stage.credentials", .credentialsResolved),
            ("diagnostics.startup.stage.configuration", .awgConfigurationBuilt),
            ("diagnostics.startup.stage.adapter", .adapterStarted),
            ("diagnostics.startup.stage.network_settings", .networkSettingsApplied),
            ("diagnostics.startup.stage.completion", .tunnelStartCompleted)
        ]
    }

    private enum StartupStageDisplayStatus {
        case ok
        case failed
        case notReached
        case unknown
    }

    private func startupStageStatus(
        _ stage: TunnelStartupStage,
        in attempt: TunnelDiagnosticAttemptSnapshot
    ) -> StartupStageDisplayStatus {
        if let event = attempt.events.last(where: { $0.stage == stage }) {
            switch event.outcome {
            case .succeeded:
                return .ok
            case .failed:
                return .failed
            case .started, .informational:
                return .ok
            }
        }
        if attempt.events.contains(where: { $0.outcome == .failed }) {
            return .notReached
        }
        return .unknown
    }

    private func startupFailureEvent(
        in attempt: TunnelDiagnosticAttemptSnapshot
    ) -> TunnelDiagnosticEvent? {
        attempt.events.last(where: {
            $0.source == .provider && $0.outcome == .failed
        }) ?? attempt.events.last(where: { $0.outcome == .failed })
    }

    private func startupStageStatusText(_ status: StartupStageDisplayStatus) -> String {
        switch status {
        case .ok:
            localizedValue("diagnostics.startup.ok")
        case .failed:
            localizedValue("diagnostics.startup.failed")
        case .notReached:
            localizedValue("diagnostics.startup.not_reached")
        case .unknown:
            localizedValue("diagnostics.startup.unknown")
        }
    }

    private func startupTimeText(_ date: Date) -> String {
        date.formatted(.dateTime.hour().minute().second().secondFraction(.fractional(3)))
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
