#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/nbs-diagnostics-test.XXXXXX")"
trap 'rm -rf "$test_dir"' EXIT
source_dir="$repo_dir/Bcore/src/main/java/top/niunaijun/blackbox/proxy"
java --module jdk.compiler/com.sun.tools.javac.Main -d "$test_dir" \
    "$source_dir/NetworkDiagnostics.java" \
    "$source_dir/VpnTcpDecision.java" \
    "$repo_dir/tests/network-diagnostics/top/niunaijun/blackbox/proxy/NetworkDiagnosticsTest.java"
java -cp "$test_dir" top.niunaijun.blackbox.proxy.NetworkDiagnosticsTest
