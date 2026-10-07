#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/nbs-fallback-test.XXXXXX")"
trap 'rm -rf "$test_dir"' EXIT
source_dir="$repo_dir/Bcore/src/main/java/top/niunaijun/blackbox/proxy"
mapfile -t stubs < <(find "$repo_dir/tests/vpn-fallback/stubs" -name '*.java' -print)
java --module jdk.compiler/com.sun.tools.javac.Main -d "$test_dir" \
    "${stubs[@]}" "$source_dir/NetworkDiagnostics.java" "$source_dir/VpnTcpDecision.java" \
    "$source_dir/SyntheticMappings.java" "$source_dir/SyntheticAddressCursor.java" "$source_dir/FallbackSocks.java" "$source_dir/FallbackTransport.java" \
    "$source_dir/VpnFlowRegistry.java" \
    "$repo_dir/tests/vpn-fallback/top/niunaijun/blackbox/proxy/FallbackTest.java"
java -cp "$test_dir" top.niunaijun.blackbox.proxy.FallbackTest
