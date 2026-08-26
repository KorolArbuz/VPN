#!/bin/bash

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <WireGuardAdapter.swift> <wireguard.h> <api-apple.go>" >&2
    exit 64
fi

adapter_source=$1
bridge_header=$2
go_source=$3

for input_path in "$adapter_source" "$bridge_header" "$go_source"; do
    if [[ ! -f "$input_path" ]]; then
        echo "missing source-audit input: $input_path" >&2
        exit 66
    fi
done

required_checkpoints=(
    wireGuardAdapterInitEntered
    wireGuardAdapterProviderReferenceStored
    wireGuardAdapterSwiftLogHandlerStored
    wireGuardAdapterSetupLogHandlerEntered
    wireGuardAdapterLoggerContextPreparationStarted
    wireGuardAdapterLoggerContextPrepared
    wireGuardAdapterLoggerCallbackPreparationStarted
    wireGuardAdapterLoggerCallbackPrepared
    wireGuardAdapterWGSetLoggerCallStarted
    wireGuardAdapterWGSetLoggerCallReturned
    wireGuardAdapterLoggerInstallationBypassed
    wireGuardAdapterLoggerInstallationDeferred
    wireGuardAdapterSetupLogHandlerReturned
    wireGuardAdapterInitCompleted
    wireGuardAdapterWGTurnOnCallStarted
    wireGuardAdapterWGTurnOnCallReturned
)

previous_line=0
for checkpoint in "${required_checkpoints[@]}"; do
    current_line=$(grep -n "case $checkpoint" "$adapter_source" | sed -n '1s/:.*//p')
    if [[ -z "$current_line" ]]; then
        echo "missing initializer checkpoint declaration: $checkpoint" >&2
        exit 1
    fi
    if [[ "$current_line" -le "$previous_line" ]]; then
        echo "initializer checkpoint declarations are out of order at: $checkpoint" >&2
        exit 1
    fi
    previous_line=$current_line
done

grep -Fq 'private typealias GoLoggerCallback = @convention(c)' "$adapter_source"
grep -Fq 'private static let goLoggerCallback: GoLoggerCallback' "$adapter_source"
grep -Fq 'wgSetLogger(context, callback)' "$adapter_source"
grep -Fq 'self.loggerInstallationPolicy = .enabled' "$adapter_source"
grep -Fq 'initializationObserver?(.wireGuardAdapterLoggerInstallationDeferred)' "$adapter_source"

wg_turn_on_line=$(grep -n 'let handle = wgTurnOn' "$adapter_source" | sed -n '1s/:.*//p')
setup_call_line=$(grep -n '^[[:space:]]*setupLogHandler()' "$adapter_source" | sed -n '1s/:.*//p')
if [[ -z "$wg_turn_on_line" || -z "$setup_call_line" || "$setup_call_line" -le "$wg_turn_on_line" ]]; then
    echo "logger installation is not deferred until after wgTurnOn returns" >&2
    exit 1
fi

diagnostic_initializer_line=$(grep -n 'diagnosticWith packetTunnelProvider' "$adapter_source" | sed -n '1s/:.*//p')
debug_line=$(head -n "$diagnostic_initializer_line" "$adapter_source" \
    | grep -n '^[[:space:]]*#if DEBUG' \
    | tail -n 1 \
    | sed 's/:.*//')
debug_end_line=$(awk -v start="$debug_line" 'NR > start && /^[[:space:]]*#endif/ { print NR; exit }' "$adapter_source")
if [[ -z "$debug_line" || -z "$diagnostic_initializer_line" || -z "$debug_end_line" \
    || "$diagnostic_initializer_line" -le "$debug_line" \
    || "$diagnostic_initializer_line" -ge "$debug_end_line" ]]; then
    echo "diagnostic bypass initializer is not confined to DEBUG" >&2
    exit 1
fi

grep -Eq 'typedef void\(\*logger_fn_t\)\(void \*context, int level, const char \*msg\);' "$bridge_header"
grep -Eq 'extern void wgSetLogger\(void \*context, logger_fn_t logger_fn\);' "$bridge_header"
grep -Fq '//export wgSetLogger' "$go_source"
grep -Eq '^func wgSetLogger\(context, loggerFn uintptr\)' "$go_source"
grep -Fq '((void(*)(void *, int, const char *))func)(ctx, level, msg);' "$go_source"

echo "WireGuardAdapter construction checkpoints: ${#required_checkpoints[@]}"
echo "logger bypass visibility: DEBUG-only"
echo "Swift callback convention: @convention(c)"
echo "bridge ABI source audit passed"
