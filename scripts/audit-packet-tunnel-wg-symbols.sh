#!/bin/bash

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 <PacketTunnelExtension-binary> <libwg-go.a> <LibXray-binary> <link-map>" >&2
    exit 64
fi

provider_binary=$1
wireguard_archive=$2
xray_binary=$3
link_map=$4

for input_path in "$provider_binary" "$wireguard_archive" "$xray_binary" "$link_map"; do
    if [[ ! -f "$input_path" ]]; then
        echo "missing audit input: $input_path" >&2
        exit 66
    fi
done

audit_tmp=$(mktemp -d "${TMPDIR:-/tmp}/securelink-wg-symbol-audit.XXXXXX")
cleanup() {
    rm -rf "$audit_tmp"
}
trap cleanup EXIT

symbols=(
    wgSetLogger
    wgTurnOn
    wgTurnOff
    wgGetConfig
    wgSetConfig
    wgBumpSockets
)

xcrun nm -A -gU "$wireguard_archive" 2>/dev/null > "$audit_tmp/wireguard-definitions"
xcrun nm -A -gU "$xray_binary" 2>/dev/null > "$audit_tmp/xray-definitions"
xcrun nm -gU "$provider_binary" 2>/dev/null > "$audit_tmp/provider-definitions"

definition_count=0
for symbol in "${symbols[@]}"; do
    definitions_file="$audit_tmp/$symbol.definitions"
    awk -v expected="_$symbol" '$NF == expected { print }' \
        "$audit_tmp/wireguard-definitions" "$audit_tmp/xray-definitions" \
        > "$definitions_file"
    symbol_definition_count=$(wc -l < "$definitions_file" | tr -d ' ')
    if [[ "$symbol_definition_count" -ne 1 ]]; then
        echo "$symbol: expected exactly one native definition, found $symbol_definition_count" >&2
        sed 's/^/  /' "$definitions_file" >&2
        exit 1
    fi
    definition_count=$((definition_count + symbol_definition_count))
    echo "$symbol definition: $(sed -n '1p' "$definitions_file")"

    map_symbol_line=$(awk -v expected="_$symbol" '$NF == expected { print; exit }' "$link_map")
    if [[ -z "$map_symbol_line" ]]; then
        echo "$symbol: missing from link map" >&2
        exit 1
    fi
    map_index=$(printf '%s\n' "$map_symbol_line" | sed -E 's/.*\[[[:space:]]*([0-9]+)\].*/\1/')
    map_object=$(grep -E "^\\[[[:space:]]*$map_index\\]" "$link_map" | sed -n '1p')
    echo "$symbol linked object: $map_object"
done

awk '$NF ~ /^_(crosscall|_cgo|x_cgo)/ { print $NF }' "$audit_tmp/wireguard-definitions" \
    | sort -u > "$audit_tmp/wireguard-cgo-symbols"
awk '$NF ~ /^_(crosscall|_cgo|x_cgo)/ { print $NF }' "$audit_tmp/xray-definitions" \
    | sort -u > "$audit_tmp/xray-cgo-symbols"
comm -12 "$audit_tmp/wireguard-cgo-symbols" "$audit_tmp/xray-cgo-symbols" \
    > "$audit_tmp/duplicate-cgo-symbols"

duplicate_cgo_count=$(wc -l < "$audit_tmp/duplicate-cgo-symbols" | tr -d ' ')
echo "wg symbol definitions audited: $definition_count"
echo "duplicate external cgo/runtime symbols across libwg-go and LibXray: $duplicate_cgo_count"
if [[ "$duplicate_cgo_count" -gt 0 ]]; then
    sed 's/^/  /' "$audit_tmp/duplicate-cgo-symbols"
fi

if ! awk '$NF == "_wgSetLogger" { found = 1 } END { exit found ? 0 : 1 }' \
    "$audit_tmp/provider-definitions"; then
    echo "final PacketTunnelExtension binary does not contain _wgSetLogger" >&2
    exit 1
fi

echo "PacketTunnelExtension WireGuard symbol-origin audit passed"
