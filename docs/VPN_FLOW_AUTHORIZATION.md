# Selective VPN flow authorization

The VPN contains only NBS package traffic through
`addAllowedApplication(getPackageName())`. Descriptor-backed native registrations
remain the strongest path. Otherwise-unregistered TCP initial SYNs may use
selective-TUN membership as fallback authority, subject to tuple/generation,
packet, destination and mapping validation described below. UDP still requires
explicit native registrations.

Registered native transports retain their existing SOCKS stream without another
CONNECT wrapper. Fallback transports perform SOCKS5 CONNECT in the VPN service,
using the configured endpoint/authentication and the original IPv4 destination
or a centrally allocated hostname mapping.

## Registration and lifetime

When VPN mode is enabled, the native hook binds a previously unbound transport
socket before connecting/sending, and registers it synchronously over the
filesystem Unix socket `files/nbs-flow.sock`. This name lives inside the host's
private app directory, has mode 0600, and is not Android exported IPC or an
abstract Unix socket. Both ends verify the kernel peer UID. The broker checks
SCM_RIGHTS socket descriptors to obtain the bound source port and socket type;
it does not accept a caller's claimed source port. A pre-bound wildcard source
is allowed only at the VPN's exact source address at the packet gate.

TCP registration permits only the configured numeric IPv4 SOCKS host/port. The
first SYN claims that record, and its initial sequence number distinguishes
retransmission from a new connection using the same tuple. All subsequent TUN
packets require that same live record. A protected onward socket is created only
for the corresponding local TCP listener connection. The Android kernel handles
TCP sequencing, windows, retransmission and half-close through address/port
rewriting; this routing behavior still requires Android device validation.

UDP registration includes the negotiated SOCKS relay, exact SOCKS destination
header, and the association's TCP control descriptor. Its real connected peer
must match the configured SOCKS endpoint, and its registered control flow must
belong to that same guest process and remain live. Loopback control sockets can
be local to Android without traversing the TUN; their descriptor/registration
is still required. Each send grants one ticket
for that destination header. Each matching TUN datagram consumes one ticket;
unused tickets expire after five seconds. UDP sockets using SO_REUSEADDR or
SO_REUSEPORT are rejected to avoid granting another socket the same source port.
Replies come only from the connected, authorized relay socket, and retain the
SOCKS envelope for guest native decoding. Closing/failing the TCP control relay
invalidates its dependent UDP grants.

Each guest transport retains a private capability channel. Native `close` and
`dup`/`dup2`/`dup3` tracking close that channel when the last tracked alias closes.
Process death also closes it. The gate checks kernel channel hangup directly,
so it does not depend only on the broker thread noticing EOF. The broker closes
received SCM_RIGHTS duplicates immediately; it must not keep guest sockets alive.
Records have a ten-minute maximum lifetime and a two-minute inactivity timeout.
Traffic and UDP registration can update activity, but never extend the hard
deadline. Expired connections fail closed; guests must open new sockets.

Limits are 128 broker channels/flow records, 64 outstanding UDP tickets per
record, and 256 native tracked descriptor entries. Capacity/IPC/configuration
failures deny networking. The private app/native guest processes form the trust
boundary; this mechanism is not an isolation boundary against arbitrary code
already controlling NBS's own UID/address space. Raw syscall interception,
`fcntl(F_DUPFD*)`, and descriptor transfer to another process are not newly
covered by this change; losing a tracked lease denies rather than grants traffic.

## Unsupported traffic and failure behavior

The selective VPN captures IPv4 and IPv6. This relay forwards ordinary,
unfragmented IPv4 SOCKS transports (including IPv4-mapped guest IPv6 sockets).
Native IPv6 relay addresses, IP options, IP fragments, oversized UDP replies
above the 1500-byte TUN MTU, malformed packets and unsupported protocols are
dropped. SOCKS UDP fragmentation was already unsupported by the native client.
There is no direct-network fallback. Startup/reader failure retains an
established TUN as deny-all containment until Android/user service teardown.
Changing settings requires restarting the VPN and guest processes so their
configuration snapshots agree; the broker rejects mismatched TCP endpoints.

## Diagnostics and device validation

Open **Settings → Network Diagnostics** in NBS. The screen refreshes once per
second while visible and shows the host-process VPN instance's aggregate
counters. **Copy diagnostics** puts a fresh plaintext snapshot on the clipboard;
**Reset diagnostics** clears counters and the last failure stage atomically,
without changing settings, registrations, SYN generations, tickets or sockets.
Each VPN service creation starts a fresh diagnostics instance. Stop/revoke marks
the VPN and relay inactive; the previous aggregates remain visible until reset,
service recreation or host-process restart. Late workers retain their own
instance and cannot update a newly created VPN's counters. SOCKS enabled is
explicitly the current Settings value, not a claim that running guests have
reloaded those settings.

TCP drops are classified at their existing rejection decisions:

- **No retained registration:** no exact tuple and no retained TCP registration
  with the packet's source port.
- **Tuple mismatch (registered source port):** no exact tuple, but the bounded
  current registry contains a TCP registration with that source port. This is
  diagnostic evidence only and never authorizes the different tuple.
- **Expired/revoked:** the exact retained record (or local reply's known flow)
  fails the existing lease/channel/control liveness test.
- **SYN/generation mismatch:** invalid SYN flags, a first packet without the
  required SYN, or a new SYN sequence on an active registration.
- **Malformed/unsupported:** bad lengths/checksums, IP options/fragments, or
  unsupported IP versions when the TCP protocol can be identified. IPv6 with
  an immediate TCP next-header is classified here; extension chains and packets
  too short to identify a protocol remain in other/unclassifiable drops.
- **Source/address policy:** a guest-side TCP packet has a source different from
  the VPN's required address.
- **Other policy:** unavailable registry/relay, missing local-reply connection,
  conflicting live relay generation or a stopped TUN writer.

Revoked native source ports and closed fallback generations are briefly
quarantined. After quarantine cleanup, later packets can count as **no retained
registration**; that cannot prove the socket was never registered. Diagnostics
retain no per-flow history. The screen separately counts expired/revoked registrations, once per record (including guest close and VPN
shutdown). Accepted registrations count acknowledged requests, including UDP
send tickets. Failed registrations count rejected requests/channels, including
timeout before the first accepted request. Local TCP listener rejections count
connections separately, not TUN packet drops.

Accepted first SYNs help distinguish passing the gate from reaching the onward
socket. Authorized TCP flows mean an onward socket connected; authorized UDP
flows mean the first datagram was sent. Forwarded packet counters count the
guest-to-relay direction; TCP rewrite-to-TUN success and UDP socket send success
respectively. UDP drops cover both directions, including ticket rejection,
malformed traffic, invalid/oversized replies and failed outbound sends. Expired
UDP tickets count tickets pruned at their existing expiration points. None of
these counters asserts SOCKS authentication or browsing success.

All counters saturate at `Long.MAX_VALUE`; increments, TCP category/total pairs,
failure stages, reset and snapshots are synchronized. State is process-local and
contains only fixed counters, flags and an allowlisted failure-stage enum. No
addresses, credentials, hostnames, URLs, payloads, packets or flow tuples enter
the UI, clipboard summary or this diagnostics store. `NBSVpn` keeps aggregate
logcat reporting every thirty seconds and at shutdown. `NetworkHook` continues
its existing bounded SOCKS negotiation/authentication failure reporting.

Focused host checks: `bash tests/run-network-diagnostics-tests.sh` exercises the
actual registry classification helpers, generation acceptance/rejection, reset,
immutable snapshots, concurrent category/total accounting and saturation. It
does not exercise Android kernel descriptor checks or actual packet forwarding.

For the Via reproduction, keep **NBS → socksbridge.py → 3proxy:1080**, enable VPN,
optionally reset diagnostics immediately before the attempt, launch Via, attempt
one URL, then return to Network Diagnostics. Inspect first SYNs, the TCP rejection
categories and the last relay failure stage before considering routing changes.
The fallback implementation below changes authorization for selective-TUN TCP
and adds SOCKS forwarding. The external proxy topology remains unchanged.

Device checks should exercise authenticated TCP with numeric and fake-IP
destinations, authentication refusal/downgrade rejection, UDP numeric/DOMAIN
traffic against a UDP-capable endpoint, ordinary unregistered TCP/UDP sockets,
guest close/death and source-port reuse, idle/hard expiry, and VPN stop/restart.
Verify counters and endpoint observations together. Android delegated TCP is
eligible only when it arrives through the selective NBS TUN and passes the fallback gate. Compilation or installed hooks are not runtime PASS.

### Selective-TUN TCP fallback

Descriptor-backed authorization remains first. For valid outgoing IPv4 initial
SYNs from the VPN's exact source address, only `NO_REGISTRATION` may create a
fallback. A retained native source-port registration with a different tuple,
expired/revoked registration, invalid SYN generation, malformed packet, or
address-policy rejection cannot grant fallback authority. The NBS-only
`addAllowedApplication(getPackageName())` selection supplies fallback provenance;
there is no framework connection-owner lookup.

Fallback records bind the original tuple and SYN sequence. Retransmissions reuse
the record; a different tuple or sequence is rejected. Closed/expired fallback
records and revoked native ports are quarantined for 120 seconds. Each relay
connection receives a distinct, never-recycled kernel listener source-port alias
for the service lifetime, so delayed listener packets/accepts cannot attach to a
new generation. Alias or flow capacity exhaustion fails closed. Native registrations
still carry their unchanged SOCKS byte stream to the registered endpoint.

Fallback uses the existing local kernel TCP listener and byte pumps. Its outward
socket is protected before connecting to the configured SOCKS endpoint. It then
performs SOCKS5 CONNECT: ATYP IPv4 for the exact ordinary destination, or ATYP
DOMAIN for an exact active synthetic mapping. Authentication settings offer only
RFC1929; no-auth is offered only without credentials. Connect and negotiation each
have a ten-second bound, including a total negotiation deadline. Malformed replies,
missing mappings, protect/connect failures and shutdown close the transport; there
is no direct-network retry. The external topology remains NBS -> socksbridge.py ->
3proxy:1080. UDP continues to require the existing native registration/ticket path.

In VPN/flow-broker mode, native resolver allocation and reverse-mapping validation
use `files/nbs-mapping.sock`, a mode-0600 filesystem AF_UNIX endpoint. Both ends
verify the real NBS UID. The protocol is versioned, ASCII hostname requests are
bounded to 253 bytes, labels are validated, requests time out, and concurrent
clients share one synchronized hostname allocator. Names normalize to lowercase
with an optional trailing dot removed. Repeated names get stable mappings; distinct
names get distinct addresses from 198.18/15. Unknown synthetic addresses are never
sent upstream. Broker failure does not restore per-process allocation. Without VPN
mode, the original process-local native SOCKS/fake-DNS implementation remains.

Mappings are memory-only and are cleared at shutdown. A private, numeric-only
`nbs-mapping-cursor` high-water mark is synced before issuing an address; it stores
no hostname or reverse mapping. It prevents cached guest synthetic addresses from
aliasing new names even after host/service process death. Addresses are never
recycled until app data is cleared; exhaustion or corrupt cursor storage fails
closed. Unused addresses consumed by a crash remain reserved. Filesystem socket
names and active clients are cleaned up at startup/shutdown. Diagnostics contain
only aggregate accepted/connected, IPv4/DOMAIN, mapping-miss and failure counts.

Host checks: `tests/run-network-diagnostics-tests.sh`,
`tests/run-vpn-fallback-tests.sh`, and `python3 tests/run-native-mapping-tests.py`.
The registry checks run production authorization with explicit Android boundary
stubs; they do not claim Android IPC or TUN validation. Native mapping checks
exercise extracted production IPC/allocator functions against real host AF_UNIX.
The SOCKS transport check exchanges bytes with a host mock SOCKS endpoint and
checks protection before connect; actual Android `VpnService.protect` is device-only.

Next device validation: install the performance arm64 APK, restart guests, enable
VPN, retain socksbridge.py -> 3proxy:1080, launch Via and navigate to an ordinary
HTTPS URL. Confirm previously unregistered traffic establishes fallback SOCKS
connections and the page loads/materially advances. Also check registered native
TCP, concurrent guest DNS uniqueness/DOMAIN forwarding, native-only VPN-off
operation, failure containment, guest close/port reuse and VPN stop/restart.
Compilation and host tests do not establish that device result.
