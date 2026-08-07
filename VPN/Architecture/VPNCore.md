# VPNCoreKit Architecture

VPNCoreKit is the app-side control layer for VPN runtime orchestration. It is intentionally separate from SwiftUI, UIKit, NetworkExtension, Packet Tunnel targets, and external protocol engines.

## Boundary

The app owns profile import, profile storage, credential references, and UI state. VPNCoreKit owns:

- compiling `VPNProfile` into `CoreConfiguration`;
- selecting a registered backend;
- coordinating prepare/start/stop;
- publishing sanitized runtime events;
- producing diagnostics without secrets.

The core never receives raw VPN URLs, passwords, tokens, private keys, or user UUID values. It receives only credential references and resolves availability through `CredentialResolving`.

## Lifecycle

`VPNProfile -> ProfileConfigurationCompiling -> CoreConfiguration -> VPNCoreBackendRegistry -> VPNCoreBackend`

`VPNCoreCoordinator` is the state machine source of truth:

`idle -> preparing -> ready -> starting -> running -> stopping -> stopped`

Failures move to `failed`. A later `stop()` moves the runtime into `stopped` and clears active backend/configuration.

## Backend Contract

Backends implement `VPNCoreBackend`:

- declare supported `CoreProtocol` values;
- prepare one `CoreConfiguration`;
- start and stop;
- expose events and statistics.

Real protocol implementations are not implemented in this app layer. Future backends should adapt proven engines rather than reimplement protocol cryptography or transports from scratch.

## Credentials

`CoreConfiguration` contains `credentialReference`, not the credential itself. A future Packet Tunnel target should use a shared credential resolver backed by Keychain access groups. Logs must never include raw credentials or full credential references.

## Packet Tunnel Future

When provisioning supports Network Extensions, the app-side coordinator can hand a sanitized startup contract to PacketTunnelExtension. The extension will use a PacketFlowAdapter to bridge backend packet I/O with `NEPacketTunnelFlow`. This repository currently contains no real TUN, PacketFlowAdapter, or external engine integration.
