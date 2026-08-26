#!/bin/bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <PacketTunnelProvider.swift> <NativeWireGuardRuntime.swift>" >&2
    exit 64
fi

provider_source=$1
runtime_source=$2

for input_path in "$provider_source" "$runtime_source"; do
    if [[ ! -f "$input_path" ]]; then
        echo "missing controller-boundary source-audit input: $input_path" >&2
        exit 66
    fi
done

provider_checkpoints=(
    nativeBackendControllerResolutionStarted
    nativeBackendControllerMakeArgumentsStarted
    nativeBackendControllerMakeArgumentsPrepared
    nativeBackendControllerMakeCallStarted
    nativeBackendControllerMakeCallReturned
    nativeBackendControllerResolved
)

previous_line=0
for checkpoint in "${provider_checkpoints[@]}"; do
    current_line=$(grep -n "\.$checkpoint" "$provider_source" | sed -n '1s/:.*//p')
    if [[ -z "$current_line" || "$current_line" -le "$previous_line" ]]; then
        echo "missing or out-of-order provider checkpoint: $checkpoint" >&2
        exit 1
    fi
    previous_line=$current_line
done

grep -Fq 'let controllerProvider = self' "$provider_source"
grep -Fq 'let controllerTelemetryStore = self.telemetryStore' "$provider_source"
grep -Fq 'let controllerAttemptID = attemptID' "$provider_source"
grep -Fq 'let controllerMode = mode' "$provider_source"
grep -Fq 'provider: controllerProvider' "$provider_source"
grep -Fq 'telemetryStore: controllerTelemetryStore' "$provider_source"
grep -Fq 'attemptID: controllerAttemptID' "$provider_source"
grep -Fq 'mode: controllerMode' "$provider_source"

grep -Fq 'nonisolated static func make(' "$runtime_source"
grep -Fq 'static func controllerConstructionCheckpoint(' "$runtime_source"
grep -Fq 'try TunnelNativeConstructionCheckpointJournal.appendToAppGroup(' "$runtime_source"

make_start=$(grep -n 'nonisolated static func make(' "$runtime_source" | sed -n '1s/:.*//p')
make_end=$(awk -v start="$make_start" 'NR > start && /^[[:space:]]*func start\(/ { print NR; exit }' "$runtime_source")
if [[ -z "$make_start" || -z "$make_end" ]]; then
    echo "unable to isolate NativeWireGuardTunnelController.make" >&2
    exit 1
fi

make_source=$(sed -n "${make_start},${make_end}p" "$runtime_source")
runtime_checkpoints=(
    nativeBackendControllerMakeEntered
    runtimeLoaderResolutionStarted
    runtimeLoaderResolved
    nativeFrameworkReferenceStarted
    nativeAdapterConstructionStarted
)

previous_line=0
for checkpoint in "${runtime_checkpoints[@]}"; do
    current_line=$(grep -n "\.$checkpoint" <<<"$make_source" | sed -n '1s/:.*//p')
    if [[ -z "$current_line" || "$current_line" -le "$previous_line" ]]; then
        echo "missing or out-of-order make checkpoint: $checkpoint" >&2
        exit 1
    fi
    previous_line=$current_line
done

if grep -A6 -F '.runtimeLoaderResolutionStarted' <<<"$make_source" | grep -Fq ').value'; then
    echo "runtime-loader checkpoint still blocks startup on diagnostics persistence" >&2
    exit 1
fi

echo "controller make caller checkpoints: ${#provider_checkpoints[@]}"
echo "controller make body checkpoints: ${#runtime_checkpoints[@]}"
echo "runtime-loader boundary does not await diagnostics persistence"
