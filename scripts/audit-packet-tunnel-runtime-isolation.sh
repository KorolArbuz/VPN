#!/bin/bash

set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
usage: audit-packet-tunnel-runtime-isolation.sh \
    <PacketTunnelExtension-executable> \
    <PacketTunnelXrayExtension-executable> \
    <PacketTunnelExtension-link-map> \
    <PacketTunnelXrayExtension-link-map> \
    [--report <report-path>]
USAGE
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[[ $# -ge 4 ]] || {
    usage
    exit 64
}

wireguard_binary=$1
xray_binary=$2
wireguard_link_map=$3
xray_link_map=$4
shift 4

report_path=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --report)
            [[ $# -ge 2 ]] || fail "--report requires a path"
            report_path=$2
            shift 2
            ;;
        *)
            fail "unsupported argument: $1"
            ;;
    esac
done

for input_path in \
    "$wireguard_binary" \
    "$xray_binary" \
    "$wireguard_link_map" \
    "$xray_link_map"; do
    [[ -f "$input_path" && -s "$input_path" ]] \
        || fail "required non-empty audit input is missing: $input_path"
done

if [[ -n "$report_path" ]]; then
    [[ ! -e "$report_path" ]] || fail "refusing to overwrite report: $report_path"
    [[ -d "$(dirname "$report_path")" ]] \
        || fail "report parent directory does not exist: $(dirname "$report_path")"
else
    report_path=$(mktemp "${TMPDIR:-/tmp}/packet-tunnel-runtime-isolation.XXXXXX")
fi

audit_tmp=$(mktemp -d "${TMPDIR:-/tmp}/packet-tunnel-runtime-isolation-work.XXXXXX")
cleanup() {
    rm -rf "$audit_tmp"
}
trap cleanup EXIT

xcrun nm -a "$wireguard_binary" > "$audit_tmp/wireguard.nm"
xcrun nm -a "$xray_binary" > "$audit_tmp/xray.nm"
xcrun otool -L "$wireguard_binary" > "$audit_tmp/wireguard.otool"
xcrun otool -L "$xray_binary" > "$audit_tmp/xray.otool"
xcrun strings -a "$wireguard_binary" > "$audit_tmp/wireguard.strings"
xcrun strings -a "$xray_binary" > "$audit_tmp/xray.strings"

emit() {
    printf '%s\n' "$*" | tee -a "$report_path"
}

definition_record_count() {
    local nm_path=$1
    local symbol_name=$2
    awk -v expected="$symbol_name" \
        '$1 ~ /^[[:xdigit:]]+$/ && $NF == expected && $(NF - 1) != "U" { count += 1 } END { print count + 0 }' \
        "$nm_path"
}

live_address_count() {
    local nm_path=$1
    local symbol_name=$2
    awk -v expected="$symbol_name" \
        '$1 ~ /^[[:xdigit:]]+$/ && $NF == expected && $(NF - 1) != "U" { print toupper($1) }' \
        "$nm_path" | sort -u | awk 'END { print NR + 0 }'
}

symbol_addresses() {
    local nm_path=$1
    local symbol_name=$2
    awk -v expected="$symbol_name" \
        '$1 ~ /^[[:xdigit:]]+$/ && $NF == expected && $(NF - 1) != "U" { print toupper($1) }' \
        "$nm_path" | sort -u | paste -sd, -
}

require_definition_count() {
    local label=$1
    local nm_path=$2
    local symbol_name=$3
    local expected=$4
    local record_count
    local count
    local addresses
    record_count=$(definition_record_count "$nm_path" "$symbol_name")
    count=$(live_address_count "$nm_path" "$symbol_name")
    addresses=$(symbol_addresses "$nm_path" "$symbol_name")
    [[ -n "$addresses" ]] || addresses=none
    emit "$label.$symbol_name.definition_record_count=$record_count"
    emit "$label.$symbol_name.live_address_count=$count"
    emit "$label.$symbol_name.addresses=$addresses"
    [[ "$count" == "$expected" ]] \
        || fail "$label must contain $expected live address group(s) for $symbol_name; found $count"
}

require_map_origin() {
    local label=$1
    local map_path=$2
    local symbol_name=$3
    local origin_fragment=$4
    local symbol_line
    local object_index
    local object_line
    symbol_line=$(awk -v expected="$symbol_name" '$1 ~ /^0x/ && $NF == expected { print; exit }' "$map_path")
    [[ -n "$symbol_line" ]] || fail "$label link map has no live $symbol_name entry"
    object_index=$(sed -E 's/.*\[[[:space:]]*([0-9]+)\].*/\1/' <<<"$symbol_line")
    [[ "$object_index" =~ ^[0-9]+$ ]] || fail "$label could not parse the $symbol_name object index"
    object_line=$(grep -E "^\[[[:space:]]*$object_index\]" "$map_path" | sed -n '1p')
    [[ "$object_line" == *"$origin_fragment"* ]] \
        || fail "$label $symbol_name origin is not $origin_fragment: $object_line"
    emit "$label.$symbol_name.origin=$object_line"
}

emit "audit_version=2"
emit "wireguard_binary=$wireguard_binary"
emit "wireguard_sha256=$(shasum -a 256 "$wireguard_binary" | awk '{ print $1 }')"
emit "xray_binary=$xray_binary"
emit "xray_sha256=$(shasum -a 256 "$xray_binary" | awk '{ print $1 }')"
emit "wireguard_link_map=$wireguard_link_map"
emit "xray_link_map=$xray_link_map"

wireguard_api_symbols=(
    _wgTurnOn
    _wgTurnOff
    _wgSetLogger
    _wgSetConfig
    _wgGetConfig
    _wgBumpSockets
)
for symbol_name in "${wireguard_api_symbols[@]}"; do
    require_definition_count wireguard "$audit_tmp/wireguard.nm" "$symbol_name" 1
    require_definition_count xray "$audit_tmp/xray.nm" "$symbol_name" 0
    require_map_origin wireguard "$wireguard_link_map" "$symbol_name" "libwg-go.a("
done

go_runtime_symbols=(
    __cgo_topofstack
    _runtime.load_g.abi0
    _crosscall2
    _x_cgo_init
)
for symbol_name in "${go_runtime_symbols[@]}"; do
    require_definition_count wireguard "$audit_tmp/wireguard.nm" "$symbol_name" 1
    require_definition_count xray "$audit_tmp/xray.nm" "$symbol_name" 1
done
require_map_origin wireguard "$wireguard_link_map" "_runtime.load_g.abi0" "libwg-go.a("
require_map_origin xray "$xray_link_map" "_runtime.load_g.abi0" "LibXray"

if grep -Fq 'LibXray.framework/LibXray' "$wireguard_link_map" \
    || grep -Fq 'LibXray.framework/LibXray' "$audit_tmp/wireguard.otool"; then
    fail "PacketTunnelExtension contains a LibXray library origin or dependency"
fi
if awk '$1 ~ /^[[:xdigit:]]+$/ && $(NF - 1) != "U" && $NF ~ /^_LibXray/ { found = 1 } END { exit(found ? 0 : 1) }' \
    "$audit_tmp/wireguard.nm"; then
    fail "PacketTunnelExtension contains live LibXray C exports"
fi
if grep -Eq '(^|[^[:alnum:]_])(main\.LibXray|_cgoexp_[[:xdigit:]]+_LibXray)' \
    "$audit_tmp/wireguard.strings"; then
    fail "PacketTunnelExtension contains LibXray Go-runtime implementation markers"
fi
require_definition_count wireguard "$audit_tmp/wireguard.nm" _create_os_log 0
emit "wireguard.libxray_library_present=no"
emit "wireguard.libxray_go_runtime_present=no"
emit "wireguard.create_os_log_present=no"

grep -Fq 'LibXray.framework/LibXray' "$xray_link_map" \
    || fail "PacketTunnelXrayExtension link map contains no LibXray origin"
if grep -Fq 'libwg-go' "$xray_link_map" \
    || grep -Fq 'libwg-go' "$audit_tmp/xray.otool" \
    || grep -Fq 'libwg-go' "$audit_tmp/xray.strings"; then
    fail "PacketTunnelXrayExtension contains a libwg-go reference"
fi
emit "xray.libxray_present=yes"
emit "xray.libwg_go_present=no"

emit "wireguard.go_runtime_family_count=1"
emit "xray.go_runtime_family_count=1"
emit "audit_result=pass"
emit "report_path=$report_path"
