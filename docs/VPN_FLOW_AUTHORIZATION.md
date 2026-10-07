# Selective VPN flow authorization

The VPN is a second containment layer. Package membership, SYSTEM identity and
arrival at its TUN do not grant forwarding permission. No Android deputies are
exceptions. `addAllowedApplication(getPackageName())` remains the package scope.

The existing guest `NetworkHook` already translates TCP into SOCKS CONNECT and
UDP into SOCKS UDP ASSOCIATE datagrams. The VPN therefore authorizes and relays
those **SOCKS transport sockets**. It does not implement a second SOCKS client or
wrap an existing SOCKS connection in another SOCKS connection. The guest native
implementation still sends credentials, rejects authentication downgrade,
encodes fake-IP destinations as SOCKS DOMAIN, and decodes UDP replies. No guest
hostname mappings or credentials need to be copied into the VPN broker.

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

`NBSVpn` reports aggregate counters every thirty seconds and at shutdown:
authorized TCP/UDP flows, forwarded packets, TCP/UDP/other drops, registrations,
registration failures, expired records/tickets and relay failures. Flow counters
mean an onward socket connected or a UDP datagram was sent; they do not assert
SOCKS authentication success or application success. `NetworkHook` reports
bounded SOCKS negotiation/authentication failure stages. None of these logs
contains addresses, credentials, hostnames, URLs, payloads or flow tuples.

Device checks should exercise authenticated TCP with numeric and fake-IP
destinations, authentication refusal/downgrade rejection, UDP numeric/DOMAIN
traffic against a UDP-capable endpoint, ordinary unregistered TCP/UDP sockets,
guest close/death and source-port reuse, idle/hard expiry, and VPN stop/restart.
Verify counters and endpoint observations together. Android delegated networking
is deliberately denied. Compilation or installed hooks are not runtime PASS.
