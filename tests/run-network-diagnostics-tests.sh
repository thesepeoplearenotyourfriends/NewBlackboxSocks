#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
test_dir="$(mktemp -d "${TMPDIR:-/tmp}/nbs-diagnostics-test.XXXXXX")"
trap 'rm -rf "$test_dir"' EXIT
source_dir="$repo_dir/Bcore/src/main/java/top/niunaijun/blackbox/proxy"
java --module jdk.compiler/com.sun.tools.javac.Main -d "$test_dir" \
    "$source_dir/NetworkDiagnostics.java" \
    "$source_dir/VpnTcpDecision.java" \
    "$source_dir/VpnTcpOwnerDiagnostics.java" \
    "$repo_dir/tests/network-diagnostics/top/niunaijun/blackbox/proxy/NetworkDiagnosticsTest.java"
java -cp "$test_dir" top.niunaijun.blackbox.proxy.NetworkDiagnosticsTest

# Guard the production boundary: diagnostics run in the existing null-grant branch.
python3 - "$source_dir" <<'PYTHON'
from pathlib import Path
import sys
p = Path(sys.argv[1])
r = (p / 'VpnFlowRegistry.java').read_text()
branch = r.split('synchronized Flow authorizeTcp', 1)[1].split('TcpDrop rejection = VpnTcpDecision.validate', 1)[0]
assert 'ownerDiagnostics.observe(rejection, syn, source, key.sourcePort, key.address, key.port);\n            return null;' in branch
assert 'diagnostics.dropTcp(rejection);' in branch
relay = (p / 'VpnRelay.java').read_text()
assert 'if (grant == null) return;' in relay
assert 'android.os.Process.myUid()' in relay
android = (p / 'AndroidTcpOwnerLookup.java').read_text()
assert 'Build.VERSION.SDK_INT < Build.VERSION_CODES.Q' in android
assert 'getConnectionOwnerUid(OsConstants.IPPROTO_TCP,' in android
assert 'endpoint(source, sourcePort), endpoint(destination, destinationPort)' in android
print('Owner diagnostic production boundary guards passed.')
PYTHON
