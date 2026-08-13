#!/usr/bin/env bash
#
# build-kvn-core-apple.sh
#
# Builds the kvn-core-ffi Rust static library for Apple targets and packages it
# into Generated/KVNCore.xcframework (static libraries + C header + modulemap).
#
# Phase D: BUILD/PACKAGING ONLY. This script never touches the Xcode project,
# signing, entitlements, or the app targets. The generated XCFramework is a
# local/CI build artifact and is intentionally NOT tracked in Git.
#
# Usage (from anywhere):
#   ./scripts/build-kvn-core-apple.sh
#
# Environment toggles:
#   KVN_INCLUDE_X86_SIM=0   Skip the x86_64 simulator arch even if installed.
#
set -euo pipefail

# --- Robust path resolution (works regardless of caller's CWD) --------------
SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SCRIPT_SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
  SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
  [[ "$SCRIPT_SOURCE" != /* ]] && SCRIPT_SOURCE="$DIR/$SCRIPT_SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -P "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"

CORE_DIR="$REPO_ROOT/core"
MANIFEST="$CORE_DIR/Cargo.toml"
INCLUDE_DIR="$CORE_DIR/kvn-core-ffi/include"
GENERATED_DIR="$REPO_ROOT/Generated"
XCFRAMEWORK="$GENERATED_DIR/KVNCore.xcframework"
LIB_NAME="libkvn_core_ffi.a"
MODULE_NAME="KVNCore"

log() { printf '\033[1;34m[kvn-core-apple]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[kvn-core-apple] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- Tool checks ------------------------------------------------------------
for tool in cargo rustup xcodebuild lipo; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done
[ -f "$MANIFEST" ] || die "cargo manifest not found at $MANIFEST"
[ -f "$INCLUDE_DIR/kvn_core.h" ] || die "header not found at $INCLUDE_DIR/kvn_core.h"
[ -f "$INCLUDE_DIR/module.modulemap" ] || die "modulemap not found at $INCLUDE_DIR/module.modulemap"

# --- Target selection -------------------------------------------------------
DEVICE_TARGET="aarch64-apple-ios"
SIM_ARM_TARGET="aarch64-apple-ios-sim"
SIM_X86_TARGET="x86_64-apple-ios"

installed_targets="$(rustup target list --installed)"
target_installed() { grep -qx "$1" <<<"$installed_targets"; }

target_installed "$DEVICE_TARGET"  || die "missing rust target: $DEVICE_TARGET (rustup target add $DEVICE_TARGET)"
target_installed "$SIM_ARM_TARGET" || die "missing rust target: $SIM_ARM_TARGET (rustup target add $SIM_ARM_TARGET)"

INCLUDE_X86_SIM="${KVN_INCLUDE_X86_SIM:-1}"
USE_X86_SIM=0
if [ "$INCLUDE_X86_SIM" = "1" ] && target_installed "$SIM_X86_TARGET"; then
  USE_X86_SIM=1
fi

# --- Build release static libs ---------------------------------------------
# No features => the debug panic hook symbol is excluded from the artifact.
# --profile inherits panic = "unwind" (pinned in core/Cargo.toml).
build_target() {
  local t="$1"
  log "building release staticlib for $t"
  cargo build --release --manifest-path "$MANIFEST" -p kvn-core-ffi --target "$t"
}

build_target "$DEVICE_TARGET"
build_target "$SIM_ARM_TARGET"
[ "$USE_X86_SIM" = "1" ] && build_target "$SIM_X86_TARGET"

lib_path() { echo "$CORE_DIR/target/$1/release/$LIB_NAME"; }

DEVICE_LIB="$(lib_path "$DEVICE_TARGET")"
[ -f "$DEVICE_LIB" ] || die "device library missing: $DEVICE_LIB"

# --- Assemble the simulator slice (universal only within the SAME platform) -
STAGING="$(mktemp -d "${TMPDIR:-/tmp}/kvn-core-apple.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT

SIM_ARM_LIB="$(lib_path "$SIM_ARM_TARGET")"
[ -f "$SIM_ARM_LIB" ] || die "simulator (arm64) library missing: $SIM_ARM_LIB"

if [ "$USE_X86_SIM" = "1" ]; then
  SIM_X86_LIB="$(lib_path "$SIM_X86_TARGET")"
  [ -f "$SIM_X86_LIB" ] || die "simulator (x86_64) library missing: $SIM_X86_LIB"
  SIM_LIB="$STAGING/$LIB_NAME"
  log "lipo simulator arm64 + x86_64 -> universal simulator lib"
  lipo -create "$SIM_ARM_LIB" "$SIM_X86_LIB" -output "$SIM_LIB"
else
  log "using arm64-only simulator slice (x86_64 simulator not included)"
  SIM_LIB="$SIM_ARM_LIB"
fi

# --- Guarded removal of ONLY our own output --------------------------------
mkdir -p "$GENERATED_DIR"
case "$XCFRAMEWORK" in
  */Generated/KVNCore.xcframework) : ;;
  *) die "refusing to remove unexpected path: $XCFRAMEWORK" ;;
esac
if [ -e "$XCFRAMEWORK" ]; then
  log "removing existing $XCFRAMEWORK"
  rm -rf "$XCFRAMEWORK"
fi

# --- Stage headers under a module-named subdirectory -----------------------
# Two static-library XCFrameworks cannot both publish `module.modulemap` at the
# root of the shared `$(BUILT_PRODUCTS_DIR)/include` dir (Xcode emits
# "Multiple commands produce .../include/module.modulemap"). Tun2SocksKit's
# HevSocks5Tunnel already ships one there. Nesting our headers under
# `KVNCore/` publishes `include/KVNCore/module.modulemap` instead — no
# collision — and Clang/Swift still resolve `import KVNCore` from `-I include`.
HEADERS_STAGE="$STAGING/headers"
mkdir -p "$HEADERS_STAGE/$MODULE_NAME"
cp "$INCLUDE_DIR/kvn_core.h" "$HEADERS_STAGE/$MODULE_NAME/"
cp "$INCLUDE_DIR/module.modulemap" "$HEADERS_STAGE/$MODULE_NAME/"

# --- Create the XCFramework (static libs + identical nested headers) --------
log "creating $XCFRAMEWORK"
xcodebuild -create-xcframework \
  -library "$DEVICE_LIB" -headers "$HEADERS_STAGE" \
  -library "$SIM_LIB"    -headers "$HEADERS_STAGE" \
  -output "$XCFRAMEWORK"

# --- Inspection -------------------------------------------------------------
log "inspecting produced slices"
find "$XCFRAMEWORK" -name "$LIB_NAME" -print | while read -r slice; do
  echo "--- $slice"
  file "$slice"
  lipo -info "$slice" || true
done

echo
log "XCFramework Info.plist:"
plutil -p "$XCFRAMEWORK/Info.plist" 2>/dev/null || cat "$XCFRAMEWORK/Info.plist"

echo
log "module name: $MODULE_NAME"
log "done: $XCFRAMEWORK"
