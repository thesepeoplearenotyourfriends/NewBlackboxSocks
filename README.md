# BlackSocks (NewBlackboxSocks)

<p align="center">
  <img src="assets/blacksocks-icon.svg" alt="BlackSocks: overlapping red B and S on black" width="192" />
</p>

A corny-but-awesome icon for a useful idea: run Android apps inside BlackBox and send their Internet traffic through SOCKS5, without root or modifying the guest APKs.

BlackSocks is a fork of the BlackBox/NewBlackbox Android virtualization engine. It clones apps into its own virtual environment, where you launch them independently of their normally installed copies. This fork focuses on transparent SOCKS5 networking for those guest apps.

## What works today

**Unauthenticated SOCKS5 is working.** Real-world use has been confirmed with **Via browser**, **Prime Video**, and other apps. These are reported working examples, not a guarantee for every app, Android version, device, or streaming/DRM configuration.

**SOCKS username/password authentication is not functional yet.** The settings fields and protocol code exist, but authenticated connections are not currently a working feature. Use a SOCKS5 endpoint that accepts unauthenticated connections and leave both credential fields empty.

BlackBox features such as multiple app instances, fake location, and device information spoofing remain part of the underlying engine. App compatibility varies; virtualization does not guarantee that every app will run.

## How networking actually works

SOCKS networking is built into the current BlackSocks app; there is no optional direct-network mode or “Use VPN Network” switch to enable.

1. **Guest networking hooks intercept connections.** Native/Bionic, libcore, and Android network-service integration adapt guest networking to the configured SOCKS5 endpoint. TCP uses SOCKS5 CONNECT.
2. **Hostnames use synthetic addresses.** Hooked hostname lookups return fake IPv4 addresses from `198.18.0.0/15`. BlackSocks maps those addresses back to hostnames and sends SOCKS DOMAIN requests so the proxy resolves the destination remotely. Unknown synthetic addresses are rejected.
3. **An app-scoped Android VPN captures additional paths.** The local VPN/TUN relay forwards registered proxy flows and provides a SOCKS5 TCP fallback for connections that bypass the usual hooks, including some WebView/Chromium paths. Its outgoing sockets are protected from re-entering the VPN.
4. **UDP depends on the SOCKS server.** Hooked UDP uses SOCKS5 UDP ASSOCIATE and authorized relay flows. The endpoint must support it; arbitrary unregistered UDP is dropped. Do not assume every UDP/QUIC app will work.

Invalid proxy settings and failed SOCKS negotiations are intended to fail closed rather than silently use direct Internet access. The VPN captures IPv6 too, but its packet relay currently handles IPv4; IPv6 capture prevents a bypass and is not a claim of full IPv6 support. Local Android IPC (`AF_UNIX`) is left alone.

### Does the VPN affect other apps?

**BlackSocks does not route or proxy networking outside the BlackSocks app.** Android's VPN allowlist contains only the BlackSocks host package. Virtualized guests run under that host, so they are covered; apps launched normally outside BlackSocks keep their ordinary network paths, including the normally installed copy of a cloned app.

Android shows a VPN permission prompt and VPN indicator because this uses `VpnService`. Android normally allows only one active VPN per user/profile, so starting BlackSocks can replace another VPN in that profile. The SOCKS endpoint supplies the onward connection; the local VPN is not a separate remote VPN service, and SOCKS5 itself does not add encryption.

## Getting started

1. Download `NewBlackboxSocks.apk` from the [latest successful build release](https://github.com/thesepeoplearenotyourfriends/NewBlackboxSocks/releases/tag/latest-newblackboxsocks) and install it. The published CI APK is **arm64-v8a**.
2. Open BlackSocks and approve the Android VPN request.
3. In **Settings → SOCKS5 proxy (guest apps)**, enter a reachable **numeric IPv4 address** and proxy port. Defaults are `127.0.0.1:1080`; that only works if a SOCKS server is running on the Android device. Leave **Username** and **Password** empty.
4. Restart BlackSocks, including its VPN service and guest processes, after changing proxy settings so all networking layers use the new configuration.
5. Add/clone an app into BlackSocks and launch it from inside BlackSocks. Launching its normal installed copy does not use this proxy configuration.

## Requirements and compatibility

- Android 5.0 (API 21) is the configured minimum; this is not a tested compatibility promise for every version up to the latest Android release.
- The build configuration supports **arm64-v8a** and **armeabi-v7a**. Current CI validates and publishes arm64 only; x86 is not a configured APK target.
- No root is required.
- A reachable SOCKS5 server accepting unauthenticated connections is required for guest Internet access. UDP support requires UDP ASSOCIATE on that server.

## Building from source

Use the repository's Gradle wrapper with the toolchain used by [GitHub Actions](.github/workflows/build.yml):

- JDK **21**
- Android SDK platform **35** and build-tools **35.0.0**
- Android NDK **29.0.13846066**

```bash
git clone https://github.com/thesepeoplearenotyourfriends/NewBlackboxSocks.git
cd NewBlackboxSocks
./gradlew assemblePerformance -PciAbi=arm64-v8a --no-daemon
```

The BlackSocks APK is written to `app/build/outputs/apk/performance/`. The same build also produces the companion **WebViewProbe** diagnostic app under `webviewprobe/build/outputs/apk/performance/`; it is not the main BlackSocks app. Pull-request CI uploads both APKs as separate artifacts. Successful pushes to `main` also update the moving release linked above.

The current performance build uses the debug signing configuration. It is a development distribution, not a separately configured production signing setup.

For core API background, see [Docs.md](Docs.md). That document and [RELEASE_NOTES.md](RELEASE_NOTES.md) include inherited/historical material; current source and build configuration take precedence. Contributors should read [AGENTS.md](AGENTS.md).

## Troubleshooting

- **No guest Internet:** Check the proxy IPv4 address/port, server reachability, empty credential fields, and Android VPN permission. The default loopback address is not a remote proxy.
- **Settings changed but behavior did not:** Restart the VPN and all guest processes along with BlackSocks.
- **Browser works but another app does not:** Check whether the app needs UDP, unsupported networking paths, or virtualization/DRM features. Via and Prime Video working does not establish universal compatibility.
- **Need networking details:** Open **Settings → Network diagnostics** for VPN/relay state, failure stages, and aggregate rejection counters. Flow counts alone do not prove SOCKS negotiation or browsing succeeded. Use logcat for app crashes and permission/ABI problems; redact sensitive information before sharing logs.

## Credits

- BlackBox/NewBlackbox and original developer **ALEX502**
- VirtualApp and VirtualAPK
- Dobby and xDL
- BlackReflection and FreeReflection

## License

Copyright 2022 BlackBox. Licensed under the [Apache License, Version 2.0](LICENSE).
