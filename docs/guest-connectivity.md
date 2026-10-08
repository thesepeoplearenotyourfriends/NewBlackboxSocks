# Guest-local connectivity facade

`IConnectivityManagerProxy` now delegates connectivity observations to one
`GuestConnectivityState`. Installation and invocation are restricted to
`BlackBoxCore.isBlackProcess()`; the server and main/host process do not receive
the facade. The process-local service cache and already-cached context
ConnectivityManager are replaced. The original Binder is retained exclusively
for identity/capability/link-property reads and existing unrelated operations.

The facade does not register a NetworkAgent, request a host network, bind a
process/socket, change global settings, or report validation to ConnectivityService.
Existing VPN authorization hooks and NBS transport code are unchanged.

## Identity and synchronous surfaces

The state prefers the actual active Network, otherwise retains the previously
observed real Network, otherwise selects an existing handle from getAllNetworks.
It never constructs a Network/netId. During a host default-network gap, it retains
the last real identity and its metadata. If this process has never observed any
real network, network queries return null/empty and callbacks wait for a real
identity. This is deliberate: a fabricated netId would break later network-specific
operations. Retention does not make a disappeared host netId routable.

The guest exposes one network. Queries for an unrelated handle or incompatible
legacy transport return null/false, rather than claiming both Wi-Fi and cellular.

| Binder surface | Guest result |
| --- | --- |
| getActiveNetwork, getActiveNetworkForUid, getNetworkForType | Retained real identity (legacy transport checked) |
| getAllNetworks | Singleton real identity, or empty before one is observed |
| getActiveNetworkInfo, getProvisioningOrActiveNetworkInfo, getActiveNetworkInfoForUid, getNetworkInfo, getNetworkInfoForNetwork, getNetworkInfoForUid | Connected and available NetworkInfo for the virtual network |
| getAllNetworkInfo | Singleton connected NetworkInfo |
| getNetworkCapabilities, getDefaultNetworkCapabilitiesForUser | Copied capabilities with Internet, validated, trusted and unrestricted status |
| getLinkProperties, getLinkPropertiesForType, getActiveLinkProperties | Sanitized copy of link properties |
| isNetworkValidated | True only for the virtual network |
| isActiveNetworkMetered | Derived from the same capabilities; actual metering is preserved |
| isPrivateDnsActive, getPrivateDnsServerName, getDnsServers | False, null, empty |
| getCaptivePortalServerUrl | Null |

Capability construction preserves real transport, VPN and metering metadata.
It removes captive-portal/partial-connectivity flags and adds uncongested and
not-suspended flags where the platform supports them. API 21 has no validated
capability bit; API 22 has validated but not captive portal. No unsupported
capability bit is added on those releases.

LinkProperties retain interface, routes, addresses and other real metadata,
but ordinary DNS servers, search domains and private-DNS configuration/validated
servers and captive-portal metadata are removed from the copy, including stacked links. NBS synthetic DNS
and SOCKS DOMAIN CONNECT remain responsible for guest names. Host LinkProperties
and NetworkCapabilities are never mutated.

## Callback lifecycle

Public `registerNetworkCallback`, `registerDefaultNetworkCallback`, and
`requestNetwork` reach Binder `listenForNetwork` or `requestNetwork`, rather than
Binder methods named after those public APIs. The facade intercepts those actual
entry points and returns unique process-local NetworkRequest tokens. No raw host
callback is registered or forwarded.

A worker reads the state immediately and then every two seconds while registrations
exist. Matching requests receive CM Messenger messages containing the same real
Network and copied virtual capabilities/link properties as synchronous queries.
API 21-27 receive separate initial capabilities/link-properties messages; API 28+
receive the compound available payload. Modern blocked status is false. Ordinary
host lost/unvalidated/unavailable events cannot reach the guest. A change to a new
real identity produces available(new), then lost(old); requests that no longer
match that identity get a local lost event. Transport-specific requests do not
invent another transport. Explicit unsatisfied request timeouts generate a local
unavailable event, not a forwarded host unavailable event.

`releaseNetworkRequest` removes the registration, unlinks its Binder death token,
and stops the worker after the last release. API 21-26 also receive CALLBACK_RELEASED,
which those versions require to remove the framework callback map entry. Token
death/dead Messengers clean up registrations. Repeated release is harmless.
PendingIntent requests/listeners use the corresponding local lifecycle:
one-shot requests release after delivery, listeners notify on new matching
identities, and releasePendingNetworkRequest removes them.

Guest `reportNetworkConnectivity`, `reportInetCondition`, `reportBadNetwork`,
`setAcceptUnvalidated`, `setAcceptPartialConnectivity`, and `setAvoidUnvalidated`
are consumed locally so virtual observations do not change host validation.

## Audit boundary

HookManager previously installed connectivity hooks in guest and server processes;
the proxy now guards both injection and invocation. Its duplicate annotated hooks
were keyed only by method name, so overload-specific classes overwrote one another.
They have been replaced by one dispatcher covering all signatures by their Binder
method name and argument types. The old public-API-named callback annotations did
not intercept Android's actual Messenger request lifecycle.

VpnCommonProxy remains unchanged. IDnsResolverProxy currently returns null from
getWho, so its legacy annotations are not an active connectivity observation
surface. NetworkPermissionCompat adjusts only the process-local permission cache.
INetworkManagementServiceProxy's existing policy/UID hooks are outside this
connectivity facade and are unchanged; data-activity listeners there describe
traffic activity, not validation or network availability.

## Validation and device acceptance

Robolectric tests exercise API 21, 22, 23, 25, 26, 27, 28 and 35: synchronous consistency,
connected/available status, real identity retention, no fabricated identity,
capability/DNS copy isolation, Messenger capability rewriting, unregister/death
cleanup, host-offline suppression, identity replacement, transport matching and
local request timeout. The test NetworkInfo shadow supplies the constructor and
hidden setters absent from Robolectric's stock factory-only shadow.

Source/build checks cannot prove WebView ERR_CACHE_MISS is fixed. On a device,
install the performance APK and exercise WebView top-level, image, and fetch
requests. Acceptance requires socket attempts reaching NBS fake DNS/connect and
producing SOCKS DOMAIN CONNECT after shouldInterceptRequest. Also verify callback
register/unregister churn and network switching on the device/OEM Android version,
and that host Android still reports its actual unvalidated/no-Internet state.

Local validation on this change:

- `./gradlew :Bcore:testDebugUnitTest -PciAbi=arm64-v8a --no-daemon`: 64 cases passed, no failures/skips.
- `./gradlew :Bcore:testDebugUnitTest assemblePerformance :Bcore:lintDebug -PciAbi=arm64-v8a --no-daemon`: passed; main app and WebViewProbe performance APKs built, including R8 and lintVital. The final expanded API 21/22 test matrix was run separately afterward.
- Lint: no findings in the three connectivity implementation files; existing unrelated repository findings remain.
- `apksigner verify --verbose` on both performance APKs: v1/v2 signatures verify.
- `git diff --check`: passed. Changed production files are only the connectivity proxy and its two helpers; build/test configuration, focused tests and this document are the other changes.
