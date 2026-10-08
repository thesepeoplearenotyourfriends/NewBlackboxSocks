# BlackSocks

<p align="center">
  <img src="assets/blacksocks-icon.svg" alt="BlackSocks: overlapping red B and S on black" width="192" />
</p>

Run cloned Android apps through a SOCKS5 proxy without root and without modifying the guest APK.

BlackSocks is a fork of the BlackBox/NewBlackbox Android virtualization engine. Apps run inside its virtual environment as independent instances; their Internet traffic is routed through the SOCKS endpoint configured in BlackSocks.

## Status

Working now:

- SOCKS5 TCP networking
- Via browser, including normal browsing and redirects
- Prime Video, including streaming
- Multiple virtual app instances
- Selective Android `VpnService` containment for BlackSocks traffic
- SOCKS5 UDP ASSOCIATE when the proxy supports it

Not working yet:

- Direct SOCKS username/password authentication. Leave **Username** and **Password** empty and use a SOCKS5 endpoint that accepts unauthenticated connections.

BlackBox virtualization is still the compatibility boundary: some Android apps simply will not run correctly inside it.

## Quick start

1. Download the current **arm64-v8a** APK from the [latest build release](https://github.com/thesepeoplearenotyourfriends/NewBlackboxSocks/releases/tag/latest-newblackboxsocks) and install it.
2. Open BlackSocks and approve Android's VPN request.
3. Open **Global Settings → SOCKS5 proxy (guest apps)**.
4. Enter the proxy's **numeric IPv4 address** and port. The default `127.0.0.1:1080` expects a SOCKS server on the Android device itself.
5. Leave **Username** and **Password** empty for now.
6. Restart BlackSocks and its guest processes after changing proxy settings.
7. Add or clone an app into BlackSocks and launch that copy.

The normally installed copy of an app is unchanged and keeps its normal network path.

## What BlackSocks does

Guest network calls are intercepted before they leave the virtualized app.

Hostname lookups are represented internally by synthetic addresses from `198.18.0.0/15`. BlackSocks maps those addresses back to the original hostname and sends a SOCKS5 DOMAIN request, so hostname resolution happens at the proxy rather than through ordinary guest DNS.

A BlackSocks-only Android VPN/TUN path catches traffic that does not travel through the usual guest hooks. That gives WebView/Chromium and other awkward networking paths a second route into the same SOCKS policy.

If the proxy configuration is invalid or SOCKS negotiation fails, networking is intended to fail closed rather than quietly fall back to direct Internet access.

### What happens to other apps?

Nothing.

The Android VPN allowlist contains the BlackSocks host package. Apps running inside BlackSocks share that host and are covered; ordinary apps outside BlackSocks are not routed through it.

Android still shows the normal VPN permission prompt and VPN indicator because BlackSocks uses `VpnService`. Android generally permits one active VPN per user/profile, so starting BlackSocks can replace another VPN in that profile.

The local VPN is a containment/forwarding mechanism, not a remote VPN provider. SOCKS5 itself does not encrypt traffic.

## Network path

At a high level:

```text
guest app
   ↓
BlackBox virtualization
   ↓
native / libcore / Android network hooks
   ↓
synthetic hostname mapping when needed
   ↓
BlackSocks VPN/TUN fallback for uncaught paths
   ↓
SOCKS5
   ↓
proxy endpoint
   ↓
Internet
```

TCP uses SOCKS5 CONNECT. Hooked UDP uses SOCKS5 UDP ASSOCIATE when available. Arbitrary unregistered UDP is dropped.

IPv6 is captured so it cannot become an escape path; the current relay itself is IPv4-oriented.

Local Android IPC such as `AF_UNIX` is left alone.

## Requirements

- Android 5.0 / API 21 minimum as configured by the project
- **arm64-v8a** for the published CI APK
- No root required
- A reachable SOCKS5 server
- UDP ASSOCIATE support on that server if an app needs UDP

The source tree also carries **armeabi-v7a** build support. x86 is not a configured APK target.

## Building

Use the repository Gradle wrapper with the same toolchain as [GitHub Actions](.github/workflows/build.yml):

- JDK **21**
- Android SDK platform **35**
- Android build-tools **35.0.0**
- Android NDK **29.0.13846066**

```bash
git clone https://github.com/thesepeoplearenotyourfriends/NewBlackboxSocks.git
cd NewBlackboxSocks
./gradlew assemblePerformance -PciAbi=arm64-v8a --no-daemon
```

The BlackSocks APK is written to:

```text
app/build/outputs/apk/performance/
```

The same build also produces **WebViewProbe**, a diagnostic companion app, under:

```text
webviewprobe/build/outputs/apk/performance/
```

Pull-request CI uploads the two APKs separately. Successful pushes to `main` update the moving release linked above.

The performance build currently uses the debug signing configuration.

## Troubleshooting

**No guest Internet:** verify the proxy IPv4 address and port, leave credentials empty, confirm the proxy is reachable, and make sure Android granted BlackSocks VPN permission.

**Changed proxy settings but nothing changed:** restart BlackSocks, its VPN service, and the guest processes. Network configuration is captured when those pieces start.

**Browser works but another app does not:** check whether the app depends on UDP, a networking path BlackSocks does not cover yet, or some unrelated BlackBox/DRM compatibility requirement.

**Need the counters:** open **Global Settings → Network Diagnostics**. For crashes or low-level networking failures, use logcat.

## Project notes

For lower-level API/background material, see [Docs.md](Docs.md) and [RELEASE_NOTES.md](RELEASE_NOTES.md). Some material there is inherited or historical; current source wins when they disagree.

Contributors should read [AGENTS.md](AGENTS.md).

## Credits

BlackSocks builds on:

- BlackBox/NewBlackbox by **ALEX502**
- VirtualApp and VirtualAPK
- Dobby and xDL
- BlackReflection and FreeReflection

## License

Copyright 2022 BlackBox. Licensed under the [Apache License, Version 2.0](LICENSE).
