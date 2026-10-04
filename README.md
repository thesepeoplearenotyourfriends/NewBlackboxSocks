
# NewBlackboxSocks

NewBlackboxSocks is a fork of NewBlackbox focused on running ordinary Android
applications inside the BlackBox virtual environment while transparently
adapting guest Internet networking through a configured SOCKS5 proxy.

The project is intentionally userspace-only:

- no root requirement
- no VPN/TUN requirement
- no guest APK rewriting
- no per-app source modification

The networking layer is implemented inside the BlackBox guest runtime using
the project's existing native-hook, libcore, and Binder virtualization
machinery.

## Current networking direction

The intended guest-networking model is:

```text
guest application
    |
    | TCP / UDP / hostname resolution
    v
BlackBox guest networking policy
    |
    | SOCKS5
    v
configured SOCKS endpoint
```

Current design rules:
- guest TCP is transparently routed through SOCKS5;
- hostnames use the fake-IP / SOCKS DOMAIN mechanism so destination DNS remains
  remote to the SOCKS endpoint;
- guest UDP uses SOCKS5 UDP ASSOCIATE when supported by the selected endpoint;
- the configured SOCKS endpoint determines whether UDP is available;
- AF_UNIX and ordinary local Android IPC are left alone;
- failed SOCKS operation must not silently fall back to direct Internet access.
The physical/network environment may provide an additional fail-closed boundary,
but NewBlackboxSocks should still consistently classify and adapt known guest
Internet paths itself.
Build
The canonical CI build is the arm64 performance APK:
./gradlew assemblePerformance -PciAbi=arm64-v8a --no-daemon

The GitHub Actions build environment currently uses:
- JDK 21
- Android platform 35
- Android build-tools 35.0.0
- NDK 29.0.13846066
- arm64-v8a CI target
GitHub Actions is the clean build oracle for Codex work. A temporary Codex
environment that lacks a usable Android SDK/NDK is not, by itself, evidence of
a source-code failure.
Successful pull-request builds publish the performance APK as a workflow
artifact. Successful builds on main also update the moving
latest-newblackboxsocks release. 
Repository guidance
AGENTS.md contains the current repository instructions for Codex, including
build discipline, source-of-truth rules, and networking invariants.
The historical README below is retained from the NewBlackbox base repository
for provenance and background. Its old build instructions have been removed
because they no longer describe this fork.
Historical upstream README
BlackBox - Virtual Engine
BlackBox is a virtual engine that allows you to clone and run virtual applications on Android devices without installing APKs. This project works on Android 5.0 to 14.0+ and supports multiple architectures (ARM64, ARMv7, x86).
Overview
This enhanced edition includes bug fixes, stability improvements, and Android 14+ compatibility tailored for modern devices.
Key Features
- Virtual App Cloning: Run multiple instances of applications.
- Sandboxed Environment: Isolated process execution.
- No Root Required: Runs entirely in userspace.
- Multi-Architecture: Support for 32-bit and 64-bit apps.
- Device Spoofing: Modify device information for virtual apps.
- Fake Location: Spoof GPS coordinates.
Requirements
- Android Version: Android 5.0 (API 21) or higher.
- RAM: 2GB minimum recommended.
- Architecture: ARMv7a, ARM64-v8a, x86.
Integration
To use BlackBox Core in your own project, add the AAR dependency:
dependencies {
    implementation fileTree(dir: "libs", include: ["*.aar"])
}

Refer to Docs.md for detailed API documentation.
Troubleshooting
- App Crashes: Check logcat for UID mismatches or permission errors.
- Installation Failures: Verify potential architecture mismatches or storage permissions.
- Android 15: Ensure you are using the latest build which handles stricter security policies.
Credits
- Main Developer: ALEX502
- Original Framework: VirtualApp, VirtualAPK
- Native Hooks: Dobby, xDL
- Reflection: BlackReflection, FreeReflection
License
Copyright 2022 BlackBox
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
   http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
