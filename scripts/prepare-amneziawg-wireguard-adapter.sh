#!/bin/bash

set -euo pipefail

readonly fork_package_commit="bf1edba79609bb7688970ed5947ce9458a289603"
readonly upstream_base_commit="bdaf0b337b85c815e1dc462505455155b6cdfe79"
readonly adapter_relative_path="Sources/WireGuardKit/WireGuardAdapter.swift"

readonly project_source_root="${SRCROOT:-${PROJECT_DIR:-}}"
readonly build_location="${BUILD_DIR:-${OBJROOT:-${SYMROOT:-}}}"

if [[ -z "$project_source_root" || -z "$build_location" || "$build_location" != *"/Build/"* ]]; then
    echo "error: Xcode project and DerivedData build locations are required" >&2
    exit 1
fi

readonly derived_data_root="${build_location%/Build/*}"
readonly checkout_root="$derived_data_root/SourcePackages/checkouts/amneziawg-apple"
readonly checkout_adapter="$checkout_root/$adapter_relative_path"
readonly audited_adapter="$project_source_root/scripts/patches/amneziawg-apple/WireGuardAdapter.swift"

if [[ ! -f "$checkout_root/Package.swift" || ! -f "$checkout_adapter" ]]; then
    echo "error: pinned amneziawg-apple checkout is unavailable at the expected DerivedData location" >&2
    exit 1
fi

if [[ ! -f "$audited_adapter" ]]; then
    echo "error: audited SecureLink WireGuardAdapter source is unavailable" >&2
    exit 1
fi

readonly actual_package_commit="$(git -C "$checkout_root" rev-parse --verify HEAD^{commit})"
if [[ "$actual_package_commit" != "$fork_package_commit" ]]; then
    echo "error: amneziawg-apple is $actual_package_commit; expected $fork_package_commit" >&2
    exit 1
fi

commit_line=()
read -r -a commit_line <<< "$(git -C "$checkout_root" rev-list --parents -n 1 "$actual_package_commit")"
if [[ "${#commit_line[@]}" -ne 2 || "${commit_line[1]}" != "$upstream_base_commit" ]]; then
    echo "error: amneziawg-apple fork ancestry does not match the audited source" >&2
    exit 1
fi

readonly changed_from_parent="$(git -C "$checkout_root" diff --name-only "$upstream_base_commit" "$actual_package_commit")"
if [[ "$changed_from_parent" != "Package.swift" ]]; then
    echo "error: the pinned fork contains unaudited committed source changes" >&2
    exit 1
fi

if cmp -s "$audited_adapter" "$checkout_adapter"; then
    echo "note: audited SecureLink WireGuardAdapter source is already installed"
    exit 0
fi

readonly upstream_blob="$(git -C "$checkout_root" rev-parse "HEAD:$adapter_relative_path")"
readonly checkout_blob="$(git -C "$checkout_root" hash-object "$checkout_adapter")"
if [[ "$checkout_blob" != "$upstream_blob" ]]; then
    echo "error: refusing to overwrite unexpected local changes in the SwiftPM WireGuardAdapter checkout" >&2
    exit 1
fi

install -m 0644 "$audited_adapter" "$checkout_adapter"

if ! cmp -s "$audited_adapter" "$checkout_adapter"; then
    echo "error: failed to install the audited SecureLink WireGuardAdapter source" >&2
    exit 1
fi

echo "note: installed audited SecureLink WireGuardAdapter source before package compilation"
