#!/bin/bash

set -euo pipefail

readonly FORK_PACKAGE_COMMIT="bf1edba79609bb7688970ed5947ce9458a289603"
readonly UPSTREAM_BASE_COMMIT="bdaf0b337b85c815e1dc462505455155b6cdfe79"

normalize_executable_path() {
    local candidate="$1"
    local candidate_directory

    if ! candidate_directory="$(cd "$(dirname "$candidate")" 2>/dev/null && pwd -P)"; then
        return 1
    fi

    printf '%s/%s\n' "$candidate_directory" "$(basename "$candidate")"
}

select_go_binary() {
    local candidate

    candidate="$(command -v go 2>/dev/null || true)"
    if [[ -n "$candidate" && -x "$candidate" ]]; then
        normalize_executable_path "$candidate"
        return
    fi

    for candidate in \
        /usr/local/go/bin/go \
        /opt/homebrew/bin/go \
        /usr/local/bin/go; do
        if [[ -x "$candidate" ]]; then
            normalize_executable_path "$candidate"
            return
        fi
    done

    return 1
}

selected_go=""
go_version=""

configure_go() {
    local selected_go_directory
    local makefile_go

    if ! selected_go="$(select_go_binary)"; then
        echo "error: Go is required, but no executable was found via PATH or a supported installation path" >&2
        return 1
    fi

    selected_go_directory="$(dirname "$selected_go")"
    if [[ -n "${PATH:-}" ]]; then
        PATH="$selected_go_directory:$PATH"
    else
        PATH="$selected_go_directory"
    fi
    export PATH

    # The upstream Makefile invokes `go` by name. Keeping the selected
    # directory first guarantees that its recipes use this exact binary.
    makefile_go="$(command -v go 2>/dev/null || true)"
    if [[ "$makefile_go" != "$selected_go" ]]; then
        echo "error: selected Go binary is $selected_go, but the Makefile would use ${makefile_go:-none}" >&2
        return 1
    fi

    if ! go_version="$("$selected_go" version 2>&1)"; then
        echo "error: selected Go binary failed to report its version: $selected_go" >&2
        return 1
    fi

    printf 'note: selected Go binary: %s\n' "$selected_go"
    printf 'note: selected Go version: %s\n' "$go_version"
}

if [[ "${1:-}" == "--validate-go-discovery" ]]; then
    if [[ "$#" -ne 1 ]]; then
        echo "error: --validate-go-discovery does not accept additional arguments" >&2
        exit 2
    fi

    configure_go
    exit 0
fi

if [[ "$#" -ne 0 ]]; then
    echo "error: unsupported argument: $1" >&2
    exit 2
fi

if [[ -z "${BUILD_DIR:-}" || "$BUILD_DIR" != *"/Build/"* ]]; then
    echo "error: BUILD_DIR does not identify an Xcode DerivedData build directory" >&2
    exit 1
fi

readonly project_source_root="${SRCROOT:-${PROJECT_DIR:-}}"
if [[ -z "$project_source_root" ]]; then
    echo "error: SRCROOT or PROJECT_DIR is required to locate the audited bridge Makefile" >&2
    exit 1
fi

readonly derived_data_root="${BUILD_DIR%/Build/*}"
readonly checkout_root="$derived_data_root/SourcePackages/checkouts/amneziawg-apple"
readonly bridge_root="$checkout_root/Sources/WireGuardKitGo"
readonly bridge_makefile="$bridge_root/Makefile"
readonly bridge_makefile_relative_path="Sources/WireGuardKitGo/Makefile"
readonly audited_bridge_makefile="$project_source_root/scripts/patches/amneziawg-apple/WireGuardKitGo.Makefile"
readonly archive_output_root="${CONFIGURATION_BUILD_DIR:-$bridge_root/out}"
readonly output_archive="$archive_output_root/libwg-go.a"
readonly build_stamp="$archive_output_root/.kvn-amneziawg-build-stamp"

if [[ "$archive_output_root" != "$derived_data_root/"* ]]; then
    echo "error: AmneziaWG archive output must remain inside Xcode DerivedData: $archive_output_root" >&2
    exit 1
fi

if [[ ! -f "$checkout_root/Package.swift" || ! -f "$bridge_makefile" ]]; then
    echo "error: pinned amneziawg-apple package checkout is unavailable at $checkout_root" >&2
    exit 1
fi

if [[ ! -f "$audited_bridge_makefile" ]]; then
    echo "error: audited WireGuard-only bridge Makefile is unavailable: $audited_bridge_makefile" >&2
    exit 1
fi

readonly actual_package_commit="$(git -C "$checkout_root" rev-parse --verify HEAD^{commit})"
if [[ "$actual_package_commit" != "$FORK_PACKAGE_COMMIT" ]]; then
    echo "error: amneziawg-apple checkout is $actual_package_commit; expected exact fork commit $FORK_PACKAGE_COMMIT" >&2
    exit 1
fi

commit_line=()
read -r -a commit_line <<< "$(git -C "$checkout_root" rev-list --parents -n 1 "$actual_package_commit")"
if [[ "${#commit_line[@]}" -ne 2 ]]; then
    echo "error: fork commit $actual_package_commit must have exactly one parent" >&2
    exit 1
fi

readonly actual_parent_commit="${commit_line[1]}"
if [[ "$actual_parent_commit" != "$UPSTREAM_BASE_COMMIT" ]]; then
    echo "error: fork commit parent is $actual_parent_commit; expected upstream base $UPSTREAM_BASE_COMMIT" >&2
    exit 1
fi

readonly changed_from_parent="$(git -C "$checkout_root" diff --name-only "$actual_parent_commit" "$actual_package_commit")"
if [[ "$changed_from_parent" != "Package.swift" ]]; then
    echo "error: fork commit must differ from its upstream parent only in Package.swift" >&2
    printf 'error: observed changed paths: %s\n' "${changed_from_parent:-none}" >&2
    exit 1
fi

if ! cmp -s "$audited_bridge_makefile" "$bridge_makefile"; then
    readonly upstream_makefile_blob="$(git -C "$checkout_root" rev-parse "HEAD:$bridge_makefile_relative_path")"
    readonly checkout_makefile_blob="$(git -C "$checkout_root" hash-object "$bridge_makefile")"
    if [[ "$checkout_makefile_blob" != "$upstream_makefile_blob" ]]; then
        echo "error: refusing to overwrite unexpected local changes in the WireGuardKitGo Makefile" >&2
        exit 1
    fi
    install -m 0644 "$audited_bridge_makefile" "$bridge_makefile"
fi

if ! cmp -s "$audited_bridge_makefile" "$bridge_makefile"; then
    echo "error: failed to install the audited WireGuard-only bridge Makefile" >&2
    exit 1
fi

readonly audited_bridge_makefile_sha256="$(shasum -a 256 "$audited_bridge_makefile" | awk '{ print $1 }')"

configure_go
readonly selected_go
readonly go_version

readonly platform_name="${PLATFORM_NAME:-iphoneos}"
readonly build_architectures="${ARCHS:-arm64}"
readonly sdk_root="${SDKROOT:-$(xcrun --sdk "$platform_name" --show-sdk-path)}"
readonly deployment_flag_name="${DEPLOYMENT_TARGET_CLANG_FLAG_NAME:-}"
readonly deployment_environment_name="${DEPLOYMENT_TARGET_CLANG_ENV_NAME:-}"
readonly desired_stamp="fork=$actual_package_commit;upstream=$actual_parent_commit;bridgeMakefile=$audited_bridge_makefile_sha256;platform=$platform_name;archs=$build_architectures;sdk=$sdk_root;deploymentFlag=$deployment_flag_name;deploymentEnvironment=$deployment_environment_name;go=$go_version"

if [[ -f "$output_archive" && -f "$build_stamp" ]] && [[ "$(<"$build_stamp")" == "$desired_stamp" ]]; then
    exit 0
fi

make -C "$bridge_root" clean

make_arguments=(
    -C "$bridge_root"
    build
    "ARCHS=$build_architectures"
    "PLATFORM_NAME=$platform_name"
    "SDKROOT=$sdk_root"
)

if [[ "$platform_name" == "iphonesimulator" ]]; then
    make_arguments+=("GOOS_iphonesimulator=ios")
fi

make "${make_arguments[@]}"

readonly archive_symbol_audit="$archive_output_root/.kvn-libwg-go-symbols.txt"
xcrun nm -a "$output_archive" > "$archive_symbol_audit"
if ! grep -Eq '[[:space:]]_?wgTurnOn$' "$archive_symbol_audit"; then
    echo "error: WireGuard-only archive does not export wgTurnOn" >&2
    exit 1
fi
if grep -Fq 'LibXray' "$archive_symbol_audit"; then
    echo "error: WireGuard-only archive unexpectedly contains LibXray symbols" >&2
    exit 1
fi
if grep -Fq 'create_os_log' "$archive_symbol_audit"; then
    echo "error: WireGuard-only archive unexpectedly contains create_os_log" >&2
    exit 1
fi

mkdir -p "$(dirname "$build_stamp")"
printf '%s' "$desired_stamp" > "$build_stamp"
