# WebView INTERNET permission and cache-only loading

Raw TCP/HttpURLConnection succeeding does not establish that WebView's Java
permission check succeeds inside a guest. Chromium constructs AwSettings with
an INTERNET permission result and defaults blockNetworkLoads to the inverse of
that result. Its network loader makes blocked network loads cache-only, even
when cacheMode is LOAD_NO_CACHE. This provides a concrete possible explanation
for shouldInterceptRequest followed by CACHE_MISS without a socket attempt.
It is not yet a confirmed explanation for the reported device.

Source references:
- [Chromium AwSettings](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/android_webview/java/src/org/chromium/android_webview/AwSettings.java): permission captured at construction; clearing the block with a denied captured permission throws SecurityException.
- [Chromium network load flags](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/android_webview/browser/network_service/net_helpers.cc): ShouldBlockNetworkLoads takes precedence over cache mode and selects LOAD_ONLY_FROM_CACHE.
- [Android 15 PermissionManager](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-15.0.0_r1/core/java/android/permission/PermissionManager.java): Context's permission path reaches IActivityManager.checkPermissionForDevice.

## Implemented repair

GuestInternetPermission provides one read-only INTERNET check for the bound
current guest. It handles the full virtual UID, libcore's guest app ID, and the
real backing host UID, with current-pid/UID-only checks and guest/host user-ID
mapping. For package checks it handles only the current guest package.

A handled check grants INTERNET only if the guest manifest requests it and the
real host package already has it. Missing declarations or host denial return
denied. Unbound/host/server processes, other permissions, unrelated packages,
UIDs, PIDs and users delegate to existing behavior. No grant API or host/global
permission state is changed. Declaration/check failures do not fabricate grants.
A recursion guard lets the real host authorization read reach Android.

Hook seams:
- IActivityManager.checkPermission and checkPermissionForDevice. The latter
  ends in deviceId, so the UID is read at its actual position, not the last int.
- IPackageManager.checkPermission and checkUidPermission.
- IPermissionManager.checkPermission and checkUidPermission, including Android 15's package/UID-first argument order (older versions are permission-first).
- The current guest's INTERNET requested-permission granted flag in returned
  PackageInfo agrees with these checks; unrelated permissions/identities remain
  under existing behavior.

NetworkPermissionCompat now bypasses both UID and package-name permission
caches locally in guest processes, so a cached denial cannot bypass these Binder
checks. Older platforms without the package-cache bypass retain the available
UID-cache bypass. Host/server processes do not install the bypass. The older WebViewProxy's getWho returns null, so it does not install and
its constructor/settings hooks cannot provide the claimed network unblock.
This repair uses the real permission Binder seams and leaves that inert proxy,
WebView provider selection, guest connectivity facade and NBS transport alone.
It does not force Via's WebView settings or alter ordinary host applications.

## Probe and device acceptance

ProbeActivity now logs:
- INTERNET_PERMISSION before WebView construction, in ENV, and before top-level
  loads: PID, runtime/application UID, self/explicit/application-context/package
  permission results and declared/granted manifest flags. 0 means granted;
  -1 means denied.
- WEB_NETWORK immediately after construction, after an explicit unblock attempt,
  and before top-level/JS actions: blockNetworkLoads, blockNetworkImage, cacheMode.
- An explicit setBlockNetworkLoads(false) call after recording the original
  setting. A SecurityException is reported as an exception, not a successful
  unblock. The readback, not just the setter returning, establishes the setting.

Start fresh after installing the updated host and probe APKs: force-stop/restart
NBS, then start the guest and create a new WebView. AwSettings captures permission
at construction; an existing WebView may retain its earlier denied result.
Test both primary and :wv2 processes.

Expected readings with declared INTERNET and an authorized host are all four
permission results 0, declared=true, requestedGranted=true, and
blockNetworkLoads=false immediately after construction. Before top-level loading,
cacheMode=2 (LOAD_NO_CACHE). Probe-only unblocking cannot establish that the
production permission repair fixed Via: inspect AFTER_CREATE before the setter,
and test Via separately after a fresh start.

Then exercise top-level HTTPS GET, local harness IMG/fetch, and Via navigation.
Acceptance remains an actual socket attempt through NBS fake-DNS/connect producing
SOCKS DOMAIN CONNECT and successful transfer/rendering. If AFTER_CREATE is true
or unblock throws, the log identifies a remaining permission/provider-context
problem. If all readings are correct but CACHE_MISS persists with no socket,
the next step is Chromium load flags/provider state, rather than SOCKS changes.

Unit tests exercise identity/signature matching (including multi-user app IDs and
Android 15's device-aware layout and reordered PermissionManager signatures), declarations/host denial, delegation boundaries,
argument immutability, PackageInfo flag consistency, both local-cache bypasses and hook annotations. These
are source-level checks, not a physical WebView runtime test.

Validation executed for this change:
- `./gradlew assemblePerformance -PciAbi=arm64-v8a --no-daemon`: successful on the final source, including R8/lintVital. Exactly one main performance APK and one WebViewProbe performance APK were produced.
- `./gradlew :Bcore:testReleaseUnitTest -PciAbi=arm64-v8a --no-daemon`: 74 tests passed (10 new permission/cache/signature tests and the existing 64 connectivity cases), no failures/errors/skips. The Android 15 argument-order regression initially failed and was corrected before final validation.
- Both performance APKs verify with v1/v2 signatures; `git diff --check` passes.
- Physical-device WebView/Via behavior has not been tested here. The diagnosis remains a hypothesis until the new permission/settings logs and SOCKS CONNECT/transfer/rendering observations confirm it.
