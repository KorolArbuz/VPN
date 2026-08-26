#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
module_cache_directory=/tmp/vpn-stage0-swift-module-cache
mkdir -p "$module_cache_directory"

CLANG_MODULE_CACHE_PATH="$module_cache_directory" \
SWIFT_MODULECACHE_PATH="$module_cache_directory" \
exec xcrun swift -module-cache-path "$module_cache_directory" \
    "$script_directory/Stage0SourceContractValidator.swift"
