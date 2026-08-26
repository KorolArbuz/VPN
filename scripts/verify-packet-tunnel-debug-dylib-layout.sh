#!/bin/bash

set -euo pipefail

usage() {
    echo "usage: $0 <DerivedData-path> [configuration-products-directory] [expected-build-number]" >&2
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

if [[ $# -lt 1 || $# -gt 3 ]]; then
    usage
    exit 64
fi

readonly derived_data_path=$1
readonly products_directory_name=${2:-Debug-iphoneos}
readonly expected_build_number=${3:-}
readonly products_path="$derived_data_path/Build/Products/$products_directory_name"
readonly app_bundle="$products_path/VPN.app"
readonly embedded_extension="$app_bundle/PlugIns/PacketTunnelExtension.appex"
readonly standalone_extension="$products_path/PacketTunnelExtension.appex"
readonly embedded_xray_extension="$app_bundle/PlugIns/PacketTunnelXrayExtension.appex"
readonly standalone_xray_extension="$products_path/PacketTunnelXrayExtension.appex"
readonly expected_app_bundle_identifier=${EXPECTED_APP_BUNDLE_IDENTIFIER:-su.24kvn.kvn-app}
readonly expected_extension_bundle_identifier=${EXPECTED_EXTENSION_BUNDLE_IDENTIFIER:-su.24kvn.kvn-app.PacketTunnelExtension}
readonly expected_xray_extension_bundle_identifier=${EXPECTED_XRAY_EXTENSION_BUNDLE_IDENTIFIER:-su.24kvn.kvn-app.PacketTunnelXrayExtension}

[[ -d "$derived_data_path" ]] || fail "DerivedData directory does not exist: $derived_data_path"
[[ -d "$products_path" ]] || fail "products directory does not exist: $products_path"
[[ -d "$app_bundle" ]] || fail "application bundle does not exist: $app_bundle"
[[ -s "$app_bundle/Info.plist" ]] || fail "application Info.plist is missing or empty: $app_bundle/Info.plist"

extension_bundle=""
if [[ -d "$embedded_extension" ]]; then
    extension_bundle=$embedded_extension
elif [[ -d "$standalone_extension" ]]; then
    extension_bundle=$standalone_extension
else
    fail "PacketTunnelExtension.appex is absent from both embedded and standalone product locations"
fi
readonly extension_bundle
readonly extension_executable="$extension_bundle/PacketTunnelExtension"

xray_extension_bundle=""
if [[ -d "$embedded_xray_extension" ]]; then
    xray_extension_bundle=$embedded_xray_extension
elif [[ -d "$standalone_xray_extension" ]]; then
    xray_extension_bundle=$standalone_xray_extension
else
    fail "PacketTunnelXrayExtension.appex is absent from both embedded and standalone product locations"
fi
readonly xray_extension_bundle
readonly xray_extension_executable="$xray_extension_bundle/PacketTunnelXrayExtension"

[[ -s "$extension_bundle/Info.plist" ]] || fail "extension Info.plist is missing or empty: $extension_bundle/Info.plist"
[[ -f "$extension_executable" ]] || fail "extension executable does not exist: $extension_executable"
[[ -s "$extension_executable" ]] || fail "extension executable is empty: $extension_executable"
[[ -x "$extension_executable" ]] || fail "extension executable is not executable: $extension_executable"
pass "extension bundle and executable exist and are non-empty"

shopt -s nullglob
debug_dylibs=("$extension_bundle"/*debug.dylib)
if (( ${#debug_dylibs[@]} != 0 )); then
    printf 'FAIL: debug dylib files exist at the extension bundle root:\n' >&2
    printf '  %s\n' "${debug_dylibs[@]}" >&2
    exit 1
fi
pass "no *debug.dylib file exists at the extension bundle root"

otool_output=$(xcrun otool -L "$extension_executable")
if grep -Fq 'PacketTunnelExtension.debug.dylib' <<<"$otool_output"; then
    fail "extension executable depends on PacketTunnelExtension.debug.dylib"
fi
pass "extension executable has no debug-dylib dependency"

if xcrun strings -a "$extension_executable" | grep -Fq 'PacketTunnelExtension.debug.dylib'; then
    fail "extension executable contains the PacketTunnelExtension.debug.dylib install-name string"
fi
pass "extension executable contains no debug-dylib install-name string"

file_output=$(file -b "$extension_executable")
[[ "$file_output" == *"Mach-O"* ]] || fail "extension executable is not Mach-O: $file_output"
[[ "$file_output" == *"arm64"* ]] || fail "extension executable is not arm64: $file_output"

build_version_output=$(xcrun vtool -show-build "$extension_executable")
if ! grep -Eq 'platform[[:space:]]+IOS([[:space:]]|$)' <<<"$build_version_output"; then
    fail "extension executable is not an iOS device Mach-O"
fi
if grep -Fq 'IOSSIMULATOR' <<<"$build_version_output"; then
    fail "extension executable targets the iOS Simulator"
fi
pass "extension executable is an arm64 iOS device Mach-O"

[[ -s "$xray_extension_bundle/Info.plist" ]] || fail "Xray extension Info.plist is missing or empty: $xray_extension_bundle/Info.plist"
[[ -f "$xray_extension_executable" ]] || fail "Xray extension executable does not exist: $xray_extension_executable"
[[ -s "$xray_extension_executable" ]] || fail "Xray extension executable is empty: $xray_extension_executable"
[[ -x "$xray_extension_executable" ]] || fail "Xray extension executable is not executable: $xray_extension_executable"
pass "Xray extension bundle and executable exist and are non-empty"

xray_debug_dylibs=("$xray_extension_bundle"/*debug.dylib)
if (( ${#xray_debug_dylibs[@]} != 0 )); then
    printf 'FAIL: debug dylib files exist at the Xray extension bundle root:\n' >&2
    printf '  %s\n' "${xray_debug_dylibs[@]}" >&2
    exit 1
fi
pass "no *debug.dylib file exists at the Xray extension bundle root"

xray_otool_output=$(xcrun otool -L "$xray_extension_executable")
if grep -Fq 'PacketTunnelXrayExtension.debug.dylib' <<<"$xray_otool_output"; then
    fail "Xray extension executable depends on PacketTunnelXrayExtension.debug.dylib"
fi
if xcrun strings -a "$xray_extension_executable" | grep -Fq 'PacketTunnelXrayExtension.debug.dylib'; then
    fail "Xray extension executable contains the debug-dylib install-name string"
fi
pass "Xray extension executable has no debug-dylib file, dependency, or install-name"

xray_file_output=$(file -b "$xray_extension_executable")
[[ "$xray_file_output" == *"Mach-O"* ]] || fail "Xray extension executable is not Mach-O: $xray_file_output"
[[ "$xray_file_output" == *"arm64"* ]] || fail "Xray extension executable is not arm64: $xray_file_output"
xray_build_version_output=$(xcrun vtool -show-build "$xray_extension_executable")
if ! grep -Eq 'platform[[:space:]]+IOS([[:space:]]|$)' <<<"$xray_build_version_output"; then
    fail "Xray extension executable is not an iOS device Mach-O"
fi
if grep -Fq 'IOSSIMULATOR' <<<"$xray_build_version_output"; then
    fail "Xray extension executable targets the iOS Simulator"
fi
pass "Xray extension executable is an arm64 iOS device Mach-O"

plist_value() {
    local plist_path=$1
    local key=$2
    local value

    value=$(plutil -extract "$key" raw -o - "$plist_path")
    [[ -n "$value" ]] || fail "$key is empty in $plist_path"
    printf '%s' "$value"
}

app_bundle_identifier=$(plist_value "$app_bundle/Info.plist" CFBundleIdentifier)
app_version=$(plist_value "$app_bundle/Info.plist" CFBundleShortVersionString)
app_build=$(plist_value "$app_bundle/Info.plist" CFBundleVersion)
extension_bundle_identifier=$(plist_value "$extension_bundle/Info.plist" CFBundleIdentifier)
extension_version=$(plist_value "$extension_bundle/Info.plist" CFBundleShortVersionString)
extension_build=$(plist_value "$extension_bundle/Info.plist" CFBundleVersion)
xray_extension_bundle_identifier=$(plist_value "$xray_extension_bundle/Info.plist" CFBundleIdentifier)
xray_extension_version=$(plist_value "$xray_extension_bundle/Info.plist" CFBundleShortVersionString)
xray_extension_build=$(plist_value "$xray_extension_bundle/Info.plist" CFBundleVersion)

[[ "$app_bundle_identifier" == "$expected_app_bundle_identifier" ]] \
    || fail "unexpected application bundle identifier: $app_bundle_identifier"
[[ "$extension_bundle_identifier" == "$expected_extension_bundle_identifier" ]] \
    || fail "unexpected extension bundle identifier: $extension_bundle_identifier"
[[ "$xray_extension_bundle_identifier" == "$expected_xray_extension_bundle_identifier" ]] \
    || fail "unexpected Xray extension bundle identifier: $xray_extension_bundle_identifier"
[[ "$extension_version" == "$app_version" ]] \
    || fail "application/extension marketing versions differ: $app_version vs $extension_version"
[[ "$extension_build" == "$app_build" ]] \
    || fail "application/extension build numbers differ: $app_build vs $extension_build"
[[ "$xray_extension_version" == "$app_version" ]] \
    || fail "application/Xray extension marketing versions differ: $app_version vs $xray_extension_version"
[[ "$xray_extension_build" == "$app_build" ]] \
    || fail "application/Xray extension build numbers differ: $app_build vs $xray_extension_build"

if [[ -n "$expected_build_number" ]]; then
    [[ "$app_build" == "$expected_build_number" ]] \
        || fail "application build is $app_build; expected $expected_build_number"
    [[ "$extension_build" == "$expected_build_number" ]] \
        || fail "extension build is $extension_build; expected $expected_build_number"
    [[ "$xray_extension_build" == "$expected_build_number" ]] \
        || fail "Xray extension build is $xray_extension_build; expected $expected_build_number"
fi
pass "application and both extension identities match (version $app_version, build $app_build)"

echo "extension_bundle=$extension_bundle"
echo "extension_executable=$extension_executable"
echo "xray_extension_bundle=$xray_extension_bundle"
echo "xray_extension_executable=$xray_extension_executable"
echo "app_bundle_identifier=$app_bundle_identifier"
echo "extension_bundle_identifier=$extension_bundle_identifier"
echo "xray_extension_bundle_identifier=$xray_extension_bundle_identifier"
echo "marketing_version=$app_version"
echo "build_number=$app_build"
echo "debug_dylib_file_present=no"
echo "debug_dylib_dependency_present=no"
echo "debug_dylib_install_name_present=no"
echo "xray_debug_dylib_file_present=no"
echo "xray_debug_dylib_dependency_present=no"
echo "xray_debug_dylib_install_name_present=no"
