# Repository instructions for Codex

NewBlackboxSocks is an Android virtualization project derived from NewBlackbox.
Its current development goal is transparent SOCKS5 networking for applications
running inside BlackBox guest processes.

These instructions describe durable repository and build rules.
Do not use AGENTS.md as a development diary or PR history.

## Source of truth

When repository documentation disagrees, use this priority:

1. Current source and build configuration
2. `.github/workflows/build.yml`
3. `AGENTS.md`
4. README/documentation inherited from upstream

The root README contains inherited NewBlackbox material and may describe stale
build requirements or commands. Do not assume README build instructions are
current merely because they are documented.

In particular, the current CI environment uses:
- JDK 21
- Android platform 35
- Android build-tools 35.0.0
- NDK 29.0.13846066
- Gradle wrapper from this repository
- arm64-v8a for CI validation

Do not downgrade or replace these merely to match inherited documentation.

## Work discipline

Do not run a build, test, Gradle task, or compilation command before making
the requested code changes unless the task explicitly asks for investigation
of an existing build failure.

The checked-out revision should be treated as the starting baseline.

Workflow:
1. inspect the relevant code and existing architecture;
2. make the requested changes;
3. review the resulting diff for obvious errors;
4. run the canonical build once;
5. rerun only to fix a concrete reported failure.

Do not repeatedly rebuild unchanged source "for confirmation", environment
discovery, or speculative diagnosis.

If several small implementation paths are all required by the requested final
feature, implement them together and instrument them together. Do not turn
each one into a separate prerequisite experiment unless resolving one would
make the others unnecessary or materially change the architecture.

## Canonical build

The canonical CI verification target is the performance arm64 APK:

    ./gradlew assemblePerformance -PciAbi=arm64-v8a --no-daemon

If repository policy is changed to include another flag such as
`--max-workers=4`, update both this file and the GitHub workflow so Codex and CI
use the same command.

Do not substitute:
- `assembleDebug`
- `assembleRelease`
- Android Studio builds
- arbitrary Gradle tasks
- a different JDK
- a different NDK

unless the task specifically requires doing so.

## GitHub Actions is the clean build oracle

Codex execution environments are not guaranteed to contain a usable Android
SDK/NDK installation.

If the local/Codex build cannot start because Android tooling, SDK paths,
licenses, or other environment prerequisites are unavailable:

- report that accurately;
- do not describe it as an application/source build failure;
- do not rewrite Gradle or Android build configuration merely to accommodate
  the temporary Codex environment;
- do not install random replacement toolchains or change project versions;
- let GitHub Actions perform the clean repository build.

When GitHub Actions reaches Java/C++ compilation and reports a source error,
that is a real build failure. Fix the exact reported failure.

Do not repeat a stale claim such as "the SDK was unavailable" after CI has
demonstrated that provisioning succeeded and produced a compiler error.

## CI pipeline

For pull requests, GitHub Actions:
1. checks out the repository;
2. installs Temurin JDK 21;
3. configures the Android SDK;
4. installs platform 35, build-tools 35.0.0, and NDK 29.0.13846066;
5. builds the arm64 performance APK;
6. requires exactly one APK in the performance output directory;
7. uploads that APK as a workflow artifact.

For successful pushes to `main`, CI also publishes the APK to the moving
`latest-newblackboxsocks` release.

Do not modify CI merely to conceal a source build failure.

## Done condition

Editing files is not completion.

For ordinary code changes, completion means:
- requested implementation is present;
- no knowingly false PASS diagnostics or claims remain;
- the canonical performance build succeeds in a valid build environment;
- exactly one expected APK is produced;
- PR summary distinguishes what was actually executed/tested from what was
  merely installed, inferred, or not testable in the build environment.

If device/runtime validation is required, compilation success alone is not
runtime validation. Say so explicitly.

## Architecture boundary: guest networking

NewBlackboxSocks adapts networking for BlackBox guest applications.

Keep one coherent networking policy rather than independent ad-hoc proxy
implementations at Java, Binder, and native layers.

Current architectural direction:
- guest Internet TCP goes through configured SOCKS5;
- hostname resolution uses the fake-IP/SOCKS DOMAIN mechanism rather than
  ordinary public DNS;
- guest UDP should use SOCKS5 UDP ASSOCIATE when supported by the selected
  SOCKS endpoint;
- the configured socksbridge endpoint determines whether UDP is permitted;
  BlackBox should not add a second independent UDP policy;
- AF_UNIX and ordinary local Android IPC are not Internet networking and must
  remain untouched;
- failed SOCKS operation must never silently fall back to direct Internet
  access.

The external network environment is the final fail-closed boundary, but code
inside this repository should still classify and adapt known guest networking
paths consistently.

Do not add VpnService/TUN/tun2socks, root requirements, or guest APK rewriting
unless explicitly requested.

## Hook implementation rules

Prefer a shared networking policy behind multiple interception seams over
duplicating SOCKS protocol behavior.

When adding coverage:
- native/Bionic hooks,
- libcore `Os`,
- Android Binder/network services,
- WebView/Chromium paths

should converge on shared SOCKS/fake-IP behavior.

Do not claim a path is supported merely because a hook exists or a method
eventually "should" reach another hook. Establish the actual call seam or
report it as unverified.

A self-test may report PASS only when that behavior was actually exercised.
Installed hooks, symbol availability, or architectural inference should be
reported as INSTALLED, AVAILABLE, SKIP, or NOT_TESTED as appropriate.

Never fabricate successful diagnostics.

## Existing networking behavior to preserve unless deliberately replaced

Preserve tested properties such as:
- enabled-but-invalid proxy configuration fails closed;
- authenticated SOCKS mode never downgrades to no-auth;
- failed SOCKS negotiation does not leave a usable connection to the proxy;
- fake 198.18/15 addresses must map back to a known hostname;
- unknown synthetic addresses fail closed;
- hostnames remain remote-resolved through SOCKS DOMAIN;
- AF_INET6 dual-stack sockets may reach the configured IPv4 proxy through the
  appropriate mapped-address handoff;
- sensitive values, credentials, payloads, URLs, and hostnames are not written
  to diagnostics.

If changing one of these invariants is necessary, call it out explicitly.

## Logging and diagnostics

Diagnostics are part of the implementation, not proof by assertion.

Logs should identify:
- interception layer/path;
- operation class;
- relevant errno / SOCKS reply / failure stage;
- installed versus unavailable hooks.

Do not log:
- proxy passwords;
- usernames unless explicitly necessary;
- destination hostnames;
- full URLs;
- payloads or message contents.

Keep repeated high-frequency logs bounded.

## Repository changes

Make the smallest coherent change that reaches the requested destination.

Do not:
- rewrite the project into a different Android architecture;
- replace Gradle;
- upgrade/downgrade AGP, Gradle, JDK, SDK, or NDK incidentally;
- reformat unrelated files;
- repair inherited code unrelated to the requested behavior merely because it
  looks old.

Do fix nearby inherited behavior when it directly conflicts with the subsystem
being changed, and explain why.

## Pull requests

Keep a task coherent in one PR when its pieces are all necessary parts of the
same final capability.

PR summaries must distinguish:
- implemented;
- compiled;
- runtime tested;
- inferred;
- not tested.

Never say "PASS" for an unexecuted test.

Do not create a chain of diagnostic-only PRs when the bounded final
implementation can reasonably be completed and instrumented in one pass.


Do not run any build, test, Gradle task, or compilation command before making the requested code changes. The current revision has already been validated externally. First inspect, then edit. Only after the implementation is complete should you run assemblePerformance once for validation, unless a concrete compile failure requires another run.
