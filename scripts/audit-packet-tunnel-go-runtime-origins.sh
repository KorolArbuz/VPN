#!/bin/bash

set -euo pipefail

usage() {
    cat >&2 <<'USAGE'
usage: audit-packet-tunnel-go-runtime-origins.sh <PacketTunnelExtension-executable>
       [--report <report-path>]
       [--link-map <link-map-path>]
       [--wireguard-archive <libwg-go.a-path>]
       [--libxray-binary <LibXray-path>]
USAGE
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
    exit 64
fi

provider_binary=$1
shift

report_path=""
link_map=""
wireguard_archive=""
xray_binary=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --report)
            [[ $# -ge 2 ]] || fail "--report requires a path"
            report_path=$2
            shift 2
            ;;
        --link-map)
            [[ $# -ge 2 ]] || fail "--link-map requires a path"
            link_map=$2
            shift 2
            ;;
        --wireguard-archive)
            [[ $# -ge 2 ]] || fail "--wireguard-archive requires a path"
            wireguard_archive=$2
            shift 2
            ;;
        --libxray-binary)
            [[ $# -ge 2 ]] || fail "--libxray-binary requires a path"
            xray_binary=$2
            shift 2
            ;;
        *)
            fail "unsupported argument: $1"
            ;;
    esac
done

[[ -f "$provider_binary" ]] || fail "extension executable does not exist: $provider_binary"
[[ -s "$provider_binary" ]] || fail "extension executable is empty: $provider_binary"

case $provider_binary in
    */Build/Products/*)
        derived_data_path=${provider_binary%%/Build/Products/*}
        products_remainder=${provider_binary#*/Build/Products/}
        products_directory_name=${products_remainder%%/*}
        ;;
    *)
        fail "extension executable is not inside an Xcode DerivedData Build/Products directory"
        ;;
esac

readonly derived_data_path
readonly products_directory_name
readonly products_path="$derived_data_path/Build/Products/$products_directory_name"
readonly extension_intermediates="$derived_data_path/Build/Intermediates.noindex/VPN.build/$products_directory_name/PacketTunnelExtension.build"

if [[ -z "$link_map" ]]; then
    link_map="$extension_intermediates/PacketTunnelExtension-LinkMap-normal-arm64.txt"
fi
if [[ -z "$wireguard_archive" ]]; then
    wireguard_archive="$products_path/libwg-go.a"
fi
if [[ -z "$xray_binary" ]]; then
    xray_binary="$products_path/LibXray.framework/LibXray"
fi

[[ -f "$link_map" ]] || fail "PacketTunnelExtension linker map does not exist: $link_map"
[[ -s "$link_map" ]] || fail "PacketTunnelExtension linker map is empty: $link_map"
[[ -f "$wireguard_archive" ]] || fail "libwg-go archive does not exist: $wireguard_archive"
[[ -s "$wireguard_archive" ]] || fail "libwg-go archive is empty: $wireguard_archive"

if [[ -n "$report_path" ]]; then
    [[ ! -e "$report_path" ]] || fail "refusing to overwrite existing report: $report_path"
    report_parent=$(dirname "$report_path")
    [[ -d "$report_parent" ]] || fail "report parent directory does not exist: $report_parent"
else
    report_path=$(mktemp "${TMPDIR:-/tmp}/packet-tunnel-go-runtime-origins.XXXXXX")
fi
readonly report_path

audit_tmp=$(mktemp -d "${TMPDIR:-/tmp}/packet-tunnel-go-runtime-audit.XXXXXX")
cleanup() {
    rm -rf "$audit_tmp"
}
trap cleanup EXIT

if ! xcrun nm -a "$provider_binary" > "$audit_tmp/provider.nm" 2> "$audit_tmp/provider.nm.stderr"; then
    cat "$audit_tmp/provider.nm.stderr" >&2
    fail "nm could not inspect the extension executable"
fi
if ! xcrun nm -A -a "$wireguard_archive" > "$audit_tmp/wireguard.nm" 2> "$audit_tmp/wireguard.nm.stderr"; then
    cat "$audit_tmp/wireguard.nm.stderr" >&2
    fail "nm could not inspect the libwg-go archive"
fi

xray_present=no
if [[ -f "$xray_binary" && -s "$xray_binary" ]]; then
    xray_present=yes
    if ! xcrun nm -A -a "$xray_binary" > "$audit_tmp/xray.nm" 2> "$audit_tmp/xray.nm.stderr"; then
        cat "$audit_tmp/xray.nm.stderr" >&2
        fail "nm could not inspect the LibXray binary"
    fi
else
    : > "$audit_tmp/xray.nm"
fi

emit() {
    printf '%s\n' "$*" | tee -a "$report_path"
}

symbol_key() {
    tr -c '[:alnum:]' '_' <<<"$1" | sed -E 's/_+$//'
}

final_addresses() {
    local symbol_name=$1
    awk -v expected="$symbol_name" \
        '$1 ~ /^[[:xdigit:]]+$/ && $NF == expected { print toupper($1) }' \
        "$audit_tmp/provider.nm" | sort -u
}

archive_definitions() {
    local nm_path=$1
    local symbol_name=$2
    awk -v expected="$symbol_name" \
        '$NF == expected && $(NF - 1) != "U" { print }' "$nm_path" | sort -u
}

map_entries() {
    local symbol_name=$1
    awk -v expected="$symbol_name" '$NF == expected { print }' "$link_map"
}

map_object_for_index() {
    local object_index=$1
    grep -E "^\[[[:space:]]*$object_index\]" "$link_map" | sed -n '1p'
}

emit "audit_version=1"
emit "provider_binary=$provider_binary"
emit "provider_sha256=$(shasum -a 256 "$provider_binary" | awk '{ print $1 }')"
emit "link_map=$link_map"
emit "wireguard_archive=$wireguard_archive"
emit "libxray_binary=$xray_binary"
emit "libxray_binary_present=$xray_present"

symbols=(
    "_cgo_topofstack|__cgo_topofstack"
    "runtime.load_g.abi0|_runtime.load_g.abi0"
    "_crosscall2|_crosscall2"
    "_x_cgo_init|_x_cgo_init"
    "create_os_log|_create_os_log"
    "wgSetLogger|_wgSetLogger"
    "wgTurnOn|_wgTurnOn"
    "wgTurnOff|_wgTurnOff"
    "wgGetConfig|_wgGetConfig"
    "wgSetConfig|_wgSetConfig"
    "wgBumpSockets|_wgBumpSockets"
)

for symbol_spec in "${symbols[@]}"; do
    display_name=${symbol_spec%%|*}
    mach_o_name=${symbol_spec#*|}
    key=$(symbol_key "$display_name")

    addresses=$(final_addresses "$mach_o_name")
    definition_count=$(grep -c . <<<"$addresses" || true)
    if [[ -z "$addresses" ]]; then
        definition_count=0
        address_csv=none
    else
        address_csv=$(paste -sd, - <<<"$addresses")
    fi

    wg_definitions=$(archive_definitions "$audit_tmp/wireguard.nm" "$mach_o_name")
    wg_definition_count=$(grep -c . <<<"$wg_definitions" || true)
    if [[ -z "$wg_definitions" ]]; then
        wg_definition_count=0
    fi

    xray_definitions=$(archive_definitions "$audit_tmp/xray.nm" "$mach_o_name")
    xray_definition_count=$(grep -c . <<<"$xray_definitions" || true)
    if [[ -z "$xray_definitions" ]]; then
        xray_definition_count=0
    fi

    emit "symbol.$key.final_definition_count=$definition_count"
    emit "symbol.$key.final_addresses=$address_csv"
    emit "symbol.$key.libwg_archive_definition_count=$wg_definition_count"
    emit "symbol.$key.libxray_archive_definition_count=$xray_definition_count"

    entries=$(map_entries "$mach_o_name")
    live_origin_count=0
    dead_origin_count=0
    if [[ -n "$entries" ]]; then
        while IFS= read -r entry; do
            object_index=$(sed -E 's/.*\[[[:space:]]*([0-9]+)\].*/\1/' <<<"$entry")
            [[ "$object_index" =~ ^[0-9]+$ ]] || fail "could not parse linker-map object index for $display_name"
            object_origin=$(map_object_for_index "$object_index")
            [[ -n "$object_origin" ]] || fail "missing linker-map object record [$object_index] for $display_name"
            if [[ "$entry" == 0x* ]]; then
                live_origin_count=$((live_origin_count + 1))
                emit "symbol.$key.live_origin.$live_origin_count=$object_origin"
            elif [[ "$entry" == '<<dead>>'* ]]; then
                dead_origin_count=$((dead_origin_count + 1))
                emit "symbol.$key.dead_origin.$dead_origin_count=$object_origin"
            fi
        done <<<"$entries"
    fi
    emit "symbol.$key.link_map_live_origin_count=$live_origin_count"
    emit "symbol.$key.link_map_dead_origin_count=$dead_origin_count"
done

wg_symbols=(wgSetLogger wgTurnOn wgTurnOff wgGetConfig wgSetConfig wgBumpSockets)
for wg_symbol in "${wg_symbols[@]}"; do
    key=$(symbol_key "$wg_symbol")
    count_line=$(grep -F "symbol.$key.final_definition_count=" "$report_path" | tail -n 1)
    definition_count=${count_line#*=}
    [[ "$definition_count" == 1 ]] \
        || fail "$wg_symbol must have exactly one definition in the final image; found $definition_count"
    if ! grep -F "symbol.$key.live_origin." "$report_path" | grep -Fq 'libwg-go.a('; then
        fail "$wg_symbol does not originate from the expected libwg-go archive"
    fi
done
emit "wg_api_symbol_origin_check=pass"

runtime_key=$(symbol_key "runtime.load_g.abi0")
runtime_count_line=$(grep -F "symbol.$runtime_key.final_definition_count=" "$report_path" | tail -n 1)
runtime_definition_count=${runtime_count_line#*=}
runtime_has_wireguard_origin=no
runtime_has_xray_origin=no
if grep -F "symbol.$runtime_key.live_origin." "$report_path" | grep -Fq 'libwg-go.a('; then
    runtime_has_wireguard_origin=yes
fi
if grep -F "symbol.$runtime_key.live_origin." "$report_path" | grep -Fq 'LibXray'; then
    runtime_has_xray_origin=yes
fi

multiple_runtime_groups=no
if (( runtime_definition_count > 1 )) \
    && [[ "$runtime_has_wireguard_origin" == yes ]] \
    && [[ "$runtime_has_xray_origin" == yes ]]; then
    multiple_runtime_groups=yes
fi

emit "runtime_load_g_has_libwg_origin=$runtime_has_wireguard_origin"
emit "runtime_load_g_has_libxray_origin=$runtime_has_xray_origin"
emit "multiple_go_runtime_address_groups=$multiple_runtime_groups"
emit "audit_result=pass"
emit "report_path=$report_path"
