# KVN Core Architecture

Portable, cross-platform **control plane** for the KVN multi-protocol VPN
client. It decides *which* candidate to connect to and *when* to switch. It
carries no traffic, launches no backend, performs no I/O, reads no clock, and
holds no secrets — those remain in the platform/data-plane layers.

> Status: Phases A–E, F1, and F2A are implemented and validated. Swift
> integration remains passive, KVNCore is linked only to the app target, and
> PacketTunnelExtension still does not link KVNCore. Automatic failover,
> profile switching, reconnect commands, and Phase F2B have not started.

---

## 1. Control plane vs data plane

```
            UI (SwiftUI)                     ← Apple, Phase E+
                │
        Apple Platform Layer                 ← Swift / NetworkExtension / Keychain
                │
        KVNCoreSwiftBridge (Phase E)         ← thin Swift adapter over the C ABI
                │  C ABI (kvn_core.h)
                ▼
   ┌─────────────────────────────┐
   │  KVN Core (Rust, this repo)  │           CONTROL PLANE
   │  health · scoring · selector │
   │  policy · routing · state    │
   └─────────────────────────────┘
                │  recommendations only (SwitchRecommended, RouteAction, …)
                ▼
   Platform Backend Coordinator (Swift)      DATA PLANE
        Xray · Hysteria · WireGuard · system
```

* **Control plane = Rust** (`core/`). Pure, deterministic, safe.
* **Data plane = platform** (Xray/LibXray, Hysteria, WireGuard, Tun2SocksKit,
  NEPacketTunnelProvider). The core never links or imports any of it.

The Rust core produces recommendations; the platform coordinator performs the
actual reconnect. This separation is what makes the core portable to iOS,
macOS, Android, Windows, and Linux unchanged.

---

## 2. Rust workspace layout

```
core/
├── Cargo.toml                 workspace (members: kvn-core, kvn-core-ffi)
│                              [profile.release] panic = "unwind"  (see §6)
├── Cargo.lock                 TRACKED — reproducible dependency resolution
├── kvn-core/                  pure control plane (no unsafe, no FFI, no I/O)
│   └── src/ model health policy config selector routing state stats backend engine
└── kvn-core-ffi/              C ABI (the ONLY crate with `unsafe`)
    ├── include/kvn_core.h      public C header
    ├── include/module.modulemap  module KVNCore { header "kvn_core.h" export * }
    └── src/ lib.rs dto.rs
scripts/build-kvn-core-apple.sh  Apple packaging (Phase D)
docs/KVNCoreArchitecture.md      this document
Generated/KVNCore.xcframework    build artifact — NOT tracked (see §12)
```

### `kvn-core` responsibilities
Portable model (`ProtocolKind`, `BackendKind`, `NetworkType`, `Endpoint`,
`CandidateId`/`ProfileId`), bounded EWMA health history, deterministic
connection scoring with telemetry confidence, network-aware protocol
preferences, anti-flapping/hysteresis selection, circuit breaker/cooldown,
routing table (exact/suffix/CIDR/tag/catch-all), connection state machine,
statistics aggregation, and typed errors.

### Not in the core
SwiftUI, Keychain, App Groups, permissions, QR/camera/photos,
NETunnelProviderManager, NEPacketTunnelProvider, packetFlow, and launching
Xray/Hysteria/WireGuard.

---

## 3. C ABI

Header: `core/kvn-core-ffi/include/kvn_core.h`. Portable C (`<stdint.h>`,
`<stddef.h>` only; no Apple includes), usable from Swift/Obj-C, Android
NDK/JNI, Windows and Linux.

* **Opaque handle** `KVNCoreHandle *` — Rust layout never exposed.
* **JSON boundary.** Structured calls take a UTF-8, NUL-terminated JSON request
  (with `schema_version`) and return an owned JSON **envelope** through an
  out-parameter plus a stable `int32_t` status code:
  ```json
  {"schema_version":1,"ok":true,"data":{ … }}
  {"schema_version":1,"ok":false,"error":{"code":"…","message":"sanitized"}}
  ```
* **Stable status codes** (explicit values): `OK=0, INVALID_ARGUMENT=1,
  INVALID_HANDLE=2, INVALID_UTF8=3, INVALID_JSON=4, SCHEMA_MISMATCH=5,
  NOT_FOUND=6, INVALID_STATE=7, INTERNAL_ERROR=8, PANIC=9`.
* **ABI version:** `kvn_core_abi_version() == 1`.
* **Schema version:** `kvn_core_schema_version() == 1` (see §7).

### Ownership / lifetime
* `KVNCoreHandle *`: owned by the caller from `kvn_core_create` to
  `kvn_core_destroy`; dangling afterwards. `destroy(NULL)` is a no-op.
* Every returned `char *` (envelopes, `kvn_core_last_error`) is Rust-heap,
  caller-owned, and freed **exactly once** with `kvn_core_free_string` — never
  libc/Swift `free`, never twice.
* `kvn_core_version()` returns a **static** pointer — never free it.

### Thread safety
A handle is `Send + Sync`; every call takes an internal mutex, so concurrent
calls on one handle are safe but serialized. Distinct handles share nothing
(including last-error). A poisoned mutex is recovered, so one bad call cannot
brick a handle. `destroy` must not race in-flight calls on the same handle.

---

## 4. Backend boundary

The core only reasons about `BackendCapabilities` (tcp/udp/ipv6/mux/supported
protocols). If capabilities are configured, a candidate whose backend cannot
carry its protocol is excluded from selection. The core never starts a backend;
the platform coordinator does, then reports success/failure and health back.

---

## 5. Security

Never accepted or emitted: UUIDs, passwords, private keys, tokens, raw VPN
URIs, subscription URLs, or full Xray configs. The wire DTOs have no field to
carry a secret (no free-form metadata map), so smuggled fields have nowhere to
land and cannot be echoed back. Loggable/serializable: candidate id, protocol,
backend, score, latency/jitter/loss, state, selection reason, sanitized errors.
Regression tests assert no credential markers appear in any serialized output.

---

## 6. Panic containment (`panic = "unwind"` requirement)

Every exported `extern "C"` function wraps its body in
`std::panic::catch_unwind`; a caught panic becomes `KVN_CORE_PANIC` and never
unwinds into C. **This depends on unwinding panics.** `core/Cargo.toml` pins
`[profile.release] panic = "unwind"`. Do **not** switch to `panic = "abort"`
for Apple/CI release builds — it would abort the process instead of returning
`KVN_CORE_PANIC`. `catch_unwind` lives only in `kvn-core-ffi`; `kvn-core` has
none.

The panic self-test symbol `kvn_core_debug_force_panic` is gated behind
`cfg(test)` / the non-default `ffi-test-hooks` feature and is **absent from
production artifacts**.

---

## 7. Versioning

* **C ABI version** — `KVN_CORE_ABI_VERSION = 1`. Bumped only on a breaking
  change to the C symbol contract.
* **JSON schema version** — `SCHEMA_VERSION = 1`. Every request must carry it;
  the boundary currently requires strict equality and returns
  `SCHEMA_MISMATCH` otherwise. Unknown *optional* JSON fields are ignored
  (forward-compatible). A future schema 2 will need an explicit accept-range /
  migration policy.

---

## 8. Apple packaging (Phase D)

```
kvn-core  (Rust, pure)
   │
kvn-core-ffi  (Rust, C ABI, staticlib)
   │  cargo build --release --target <apple-target>
   ▼
libkvn_core_ffi.a   (per target)
   │  xcodebuild -create-xcframework  (+ Headers/kvn_core.h + module.modulemap)
   ▼
Generated/KVNCore.xcframework
   │
Phase E: KVNCoreSwiftBridge  (implemented, passive)
```

### Supported Apple architectures / slices
| Slice | Platform | Arch(es) | Rust target(s) |
|-------|----------|----------|----------------|
| `ios-arm64` | iOS device | arm64 | `aarch64-apple-ios` |
| `ios-arm64_x86_64-simulator` | iOS Simulator | arm64 + x86_64 | `aarch64-apple-ios-sim` + `x86_64-apple-ios` |

* **Static linking.** Static libraries only (not a dynamic framework); the app
  linker dead-strips unused code at final link.
* **Simulator universal.** `lipo` combines the two *simulator* arches into one
  slice. Device and simulator are **never** combined with `lipo` — they are
  separate XCFramework slices. Set `KVN_INCLUDE_X86_SIM=0` to build an
  arm64-only simulator slice (acceptable for Apple-Silicon-only development).
* The identical `kvn_core.h` + `module.modulemap` ship in every slice, exposing
  the Clang module **`KVNCore`**.
* **Header nesting (collision avoidance).** The headers are published under a
  `KVNCore/` subdirectory (`Headers/KVNCore/{kvn_core.h,module.modulemap}`).
  Two *static* library XCFrameworks cannot both place `module.modulemap` at the
  root of the shared `$(BUILT_PRODUCTS_DIR)/include` dir — Xcode fails with
  "Multiple commands produce …/include/module.modulemap". Tun2SocksKit's
  `HevSocks5Tunnel.xcframework` already publishes one there, so nesting ours
  under `KVNCore/` yields `include/KVNCore/module.modulemap` (no collision).
  Clang/Swift still resolve `import KVNCore` from the root `-I include`.

### How to rebuild
```bash
./scripts/build-kvn-core-apple.sh
```
Runs from any working directory, needs no Xcode UI, and is CI-safe. It verifies
tools/targets, builds release static libs, assembles the simulator slice,
removes only its own `Generated/KVNCore.xcframework`, recreates it, and inspects
the result.

### Output path & ownership
Output: `Generated/KVNCore.xcframework`. It is a **local/CI build artifact**,
owned by whoever runs the script, regenerated on demand.

---

## 9. Why the XCFramework is not tracked in Git

The compiled artifact is tens of MB and machine/toolchain-specific; committing
it bloats history and previously caused rejected pushes. `.gitignore` excludes
`core/target/`, `target/`, and `Generated/KVNCore.xcframework/`. Reproducibility
is guaranteed instead by tracking **`core/Cargo.lock`** plus the pinned
toolchain, so any developer/CI rebuilds an equivalent artifact from source.

---

## 10. iOS integration (Phase E — implemented, passive)

`KVNCoreSwiftBridge` wraps the C ABI: create/destroy, encode request JSON,
decode response envelopes into Swift types, map status codes to typed Swift
errors, and manage handle lifetime. Scoring/selection logic stays in Rust.
Integration is **passive behind a feature flag**
(`portable.core.selection.enabled`, default false); the existing VPN flow keeps
working and automatic failover stays disconnected from the production tunnel.

---

## 11. Future platforms

* **Android:** same `libkvn_core_ffi` built for `aarch64-linux-android` et al.,
  same `kvn_core.h`, called via JNI. No core changes.
* **Windows/Linux:** same crate built as `staticlib`/`cdylib`, same C ABI.
* **macOS:** add `aarch64-apple-darwin` / `x86_64-apple-darwin` slices to the
  XCFramework using the same script pattern.

The control-plane logic and the C contract are identical across all of them —
only the thin platform adapter differs.

---

## 12. Phase E — iOS Swift bridge (passive integration)

```
SwiftUI / app
      ↓
PortableCoreService      (actor — app-level owner, serializes access)
      ↓
KVNCoreBridge            (nonisolated final class — owns one opaque handle)
      ↓
KVNCore C ABI            (import KVNCore, module from the XCFramework)
      ↓
Rust control plane
```

Location: `VPN/VPN/Core/Portable/` — `KVNCoreError.swift`, `KVNCoreDTO.swift`,
`KVNCoreBridge.swift`, `KVNCoreMapper.swift`, `PortableCoreFeature.swift`,
`PortableCoreService.swift`. Tests: `VPNTests/PortableCoreTests.swift`.

* **Bridge lifetime.** `KVNCoreBridge.init` calls `kvn_core_create`, validates
  `kvn_core_abi_version`/`kvn_core_schema_version` against
  `expectedABIVersion`/`expectedSchemaVersion` (both `1`), and throws a typed
  error on mismatch (destroying the handle so it never leaks). `deinit` calls
  `kvn_core_destroy` exactly once. The raw handle never escapes the bridge.
* **Threading.** `KVNCoreBridge` is `@unchecked Sendable` with `nonisolated`
  methods; the Rust handle serializes internally. `PortableCoreService` is an
  `actor` and is the single app-level owner — views never create their own
  handle. Low-level DTOs are plain `Sendable` value types (no MainActor).
* **Error mapping.** `KVNCoreStatus`/`KVNCoreError` mirror the stable C codes;
  responses are decoded through the typed `KVNEnvelope<T>` and mapped to Swift
  errors. Raw Rust debug output is never surfaced.
* **Memory ownership.** Every response `char*` is turned into a Swift `String`
  and freed with `kvn_core_free_string` via `defer`. The static
  `kvn_core_version()` pointer is never freed.
* **Profile mapping / secret boundary.** `KVNCoreMapper` maps `VPNProfile` →
  `KVNCandidateDTO` using only non-secret connectivity metadata (record id as
  candidate/profile id, host, port, protocol, backend, enabled, region/country
  if present, favorite→priority). It NEVER copies credentialReference, UUIDs,
  passwords, tokens, keys, raw URIs/URLs, Xray config, or arbitrary metadata
  values. A regression test asserts no secret survives serialization.
* **Protocol/backend mapping.** vless/trojan/vmess/shadowsocks/tuic → `xray`;
  hysteria2 → `hysteria`; wireguard → `wireguard`; ikev2 → `system`.
* **Feature flag.** `PortableCoreFeature` (`portable.core.selection.enabled`,
  UserDefaults, **default false**). When false, `PortableCoreService.recommendation`
  returns `nil` and the core has zero effect on selection.
* **Passive recommendations.** The service can register candidates, feed health,
  and compute a `SelectionDecision`, but it performs **no** VPN reconnect —
  even when `should_switch == true`. Automatic failover is deferred to Phase F.
* **Connection state vs core state.** The existing Swift connection manager
  remains the single source of truth for actual NetworkExtension VPN status.
  `KVNConnectionStateDTO` is control-plane state only and must never be read as
  real tunnel status.

### Developer build workflow (Phase E)
1. Build the artifact: `./scripts/build-kvn-core-apple.sh`
2. In Xcode, the app (`VPN`) target links `Generated/KVNCore.xcframework`
   (Link Binary With Libraries, **Do Not Embed** — it is a static library).
3. Build/run the app or tests. If the XCFramework is missing, the app link
   fails clearly; re-run step 1.

No Xcode Run Script build phase is added yet; the XCFramework stays untracked.

---

## 13. Phase F1/F2A validation status

Phase F1 adds app-process transport health probes that feed truthful,
sanitized measurements into `PortableCoreService`. Phase F2A adds read-only
app-to-PacketTunnelExtension IPC and authoritative runtime telemetry snapshots.
Both phases remain diagnostics/passive only:

* no automatic reconnect;
* no automatic profile switching;
* no KVNCore link in PacketTunnelExtension;
* no PacketTunnel command messages;
* no fabricated packet loss, server load, throughput, or healthy state.

### Phase F2A message path

```
VPN app
  ↓ NETunnelProviderSession.sendProviderMessage
PacketTunnelProvider.handleAppMessage
  ↓ TunnelAppMessageHandler
TunnelTelemetryStore
  ↓ sanitized Codable response
VPN diagnostics + passive PortableCoreService health update
```

The F2A request set is read-only: `ping`, `getCapabilities`,
`getRuntimeSnapshot`, `getHealthSnapshot`, and `getRecentEvents`.

### Xcode validation

External unsandboxed Xcode validation on iPhone 17 / iOS 26.5 Simulator:

| Gate | Result |
| --- | --- |
| Serial full scheme run #1 | TEST SUCCEEDED |
| Serial full scheme run #2 | TEST SUCCEEDED |
| Serial full scheme run #3 | TEST SUCCEEDED |
| Parallel/default full scheme run #1 | TEST SUCCEEDED |
| Parallel/default full scheme run #2 | TEST SUCCEEDED |
| Parallel/default full scheme run #3 | TEST SUCCEEDED |

Each full scheme run executed 197 Swift tests across 15 suites plus 10 UI
tests, with zero failures. The executed suites included legacy `VPNTests`,
`PortableCoreTests`, `TransportHealthTests`, tunnel message protocol tests,
provider messaging tests, telemetry store/snapshot/core-update tests, and
localization/security tests.

### Rust validation

Current Rust validation remains green:

* `cargo fmt --check`
* `cargo clippy --workspace --all-targets -- -D warnings`
* `cargo test --workspace` — 53 tests passed

### Git hygiene

`Generated/KVNCore.xcframework/` and `core/target/` are generated artifacts and
remain ignored. `core/Cargo.lock` remains tracked. `xcuserdata` is not part of
the intended commit set for these phases.
