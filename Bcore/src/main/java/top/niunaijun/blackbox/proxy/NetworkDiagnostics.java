package top.niunaijun.blackbox.proxy;

import java.util.Arrays;

/** Process-local aggregates only. No addresses, credentials, packets or flow history. */
public final class NetworkDiagnostics {
    public enum Counter {
        REGISTERED, REGISTRATION_FAILED, REGISTRATION_ENDED,
        TCP_FLOWS, TCP_FIRST_SYN, TCP_PACKETS, TCP_DROPPED,
        TCP_NO_REGISTRATION, TCP_TUPLE_MISMATCH, TCP_EXPIRED_REVOKED,
        TCP_SYN_GENERATION, TCP_MALFORMED, TCP_SOURCE_ADDRESS, TCP_OTHER_POLICY,
        TCP_LISTENER_REJECTED,
        FALLBACK_ACCEPTED, FALLBACK_CONNECTED, FALLBACK_IPV4, FALLBACK_DOMAIN,
        SYNTHETIC_MISS, FALLBACK_FAILED, FALLBACK_SOCKET_FAILED, FALLBACK_PROTECT_FAILED,
        FALLBACK_PROXY_CONNECT_FAILED, FALLBACK_SOCKS_FAILED,
        UDP_FLOWS, UDP_PACKETS, UDP_DROPPED, UDP_TICKET_EXPIRED,
        OTHER_DROPPED, RELAY_FAILED
    }

    enum TcpDrop {
        NO_REGISTRATION(Counter.TCP_NO_REGISTRATION),
        TUPLE_MISMATCH(Counter.TCP_TUPLE_MISMATCH),
        EXPIRED_REVOKED(Counter.TCP_EXPIRED_REVOKED),
        SYN_GENERATION(Counter.TCP_SYN_GENERATION),
        MALFORMED(Counter.TCP_MALFORMED),
        SOURCE_ADDRESS(Counter.TCP_SOURCE_ADDRESS),
        OTHER_POLICY(Counter.TCP_OTHER_POLICY);

        final Counter counter;
        TcpDrop(Counter counter) { this.counter = counter; }
    }

    // Only these internal stage names may enter the human-facing diagnostics.
    enum FailureStage {
        NONE("none"), VPN_START("vpn-start"), VPN_ESTABLISH("vpn-establish"),
        SETUP_DENY_ALL("setup-deny-all"), TUN_READ_DENY_ALL("tun-read-or-packet-handling-deny-all"),
        TCP_ACCEPT("tcp-accept"), TCP_SOCKET("tcp-socket"),
        TCP_LEASE_BEFORE_CONNECT("tcp-lease-before-connect"), TCP_PROTECT("tcp-protect"),
        TCP_CONNECT("tcp-connect"), TCP_LEASE_AFTER_CONNECT("tcp-lease-after-connect"),
        FALLBACK_SOCKET("fallback-socket-create-bind"), FALLBACK_PROTECT("fallback-protect"),
        FALLBACK_PROXY_CONNECT("fallback-proxy-connect"), FALLBACK_SOCKS("fallback-socks-negotiation"),
        TCP_IO("tcp-relay-io"), UDP_RELAY("udp-relay"), UDP_READ("udp-relay-read");

        final String label;
        FailureStage(String label) { this.label = label; }
    }

    private final long[] counters = new long[Counter.values().length];
    private boolean vpnActive, relayActive;
    private FailureStage lastFailure = FailureStage.NONE;

    private void add(Counter counter) {
        int index = counter.ordinal();
        if (counters[index] < Long.MAX_VALUE) counters[index]++;
    }

    synchronized void increment(Counter counter) { add(counter); }
    synchronized void dropTcp(TcpDrop reason) { add(Counter.TCP_DROPPED); add(reason.counter); }
    synchronized long failure(FailureStage stage) {
        add(Counter.RELAY_FAILED);
        lastFailure = stage;
        return counters[Counter.RELAY_FAILED.ordinal()];
    }
    synchronized void fallbackFailure(FailureStage stage) {
        add(Counter.FALLBACK_FAILED);
        switch (stage) {
            case FALLBACK_SOCKET: add(Counter.FALLBACK_SOCKET_FAILED); break;
            case FALLBACK_PROTECT: add(Counter.FALLBACK_PROTECT_FAILED); break;
            case FALLBACK_PROXY_CONNECT: add(Counter.FALLBACK_PROXY_CONNECT_FAILED); break;
            case FALLBACK_SOCKS: add(Counter.FALLBACK_SOCKS_FAILED); break;
            default: break;
        }
    }
    synchronized void vpnActive(boolean active) { vpnActive = active; }
    synchronized void relayActive(boolean active) { relayActive = active; }

    /** Does not touch leases, tickets, relay sockets, or networking configuration. */
    public synchronized void reset() {
        Arrays.fill(counters, 0);
        lastFailure = FailureStage.NONE;
    }

    public synchronized Snapshot snapshot() {
        return new Snapshot(counters.clone(), vpnActive, relayActive, lastFailure.label);
    }

    public static final class Snapshot {
        private final long[] counters;
        public final boolean vpnActive, relayActive;
        public final String lastFailureStage;

        private Snapshot(long[] counters, boolean vpnActive, boolean relayActive, String lastFailureStage) {
            this.counters = counters;
            this.vpnActive = vpnActive;
            this.relayActive = relayActive;
            this.lastFailureStage = lastFailureStage;
        }

        public long count(Counter counter) { return counters[counter.ordinal()]; }

        public String toPlainText(boolean socksEnabledInSettings) {
            StringBuilder out = new StringBuilder("Network Diagnostics\n");
            out.append("VPN active: ").append(vpnActive ? "yes" : "no");
            out.append("\nSOCKS enabled (Settings): ").append(socksEnabledInSettings ? "yes" : "no");
            out.append("\nVPN relay active: ").append(relayActive ? "yes" : "no");
            out.append("\n\nRegistrations\n");
            line(out, "accepted requests", Counter.REGISTERED);
            line(out, "failed requests/channels", Counter.REGISTRATION_FAILED);
            line(out, "expired/revoked records", Counter.REGISTRATION_ENDED);
            out.append("\nTCP\n");
            line(out, "authorized flows (onward connected)", Counter.TCP_FLOWS);
            line(out, "accepted first SYNs", Counter.TCP_FIRST_SYN);
            line(out, "forwarded packets (guest to relay)", Counter.TCP_PACKETS);
            line(out, "dropped packets, total", Counter.TCP_DROPPED);
            line(out, "dropped — no retained registration", Counter.TCP_NO_REGISTRATION);
            line(out, "dropped — tuple mismatch (registered source port)", Counter.TCP_TUPLE_MISMATCH);
            line(out, "dropped — expired/revoked", Counter.TCP_EXPIRED_REVOKED);
            line(out, "dropped — SYN/generation mismatch", Counter.TCP_SYN_GENERATION);
            line(out, "dropped — malformed/unsupported", Counter.TCP_MALFORMED);
            line(out, "dropped — source/address policy", Counter.TCP_SOURCE_ADDRESS);
            line(out, "dropped — other policy (including relay unavailable)", Counter.TCP_OTHER_POLICY);
            line(out, "rejected local listener connections", Counter.TCP_LISTENER_REJECTED);
            out.append("\nSelective VPN TCP fallback\n");
            line(out, "accepted flows", Counter.FALLBACK_ACCEPTED);
            line(out, "SOCKS connections established", Counter.FALLBACK_CONNECTED);
            line(out, "IPv4 CONNECTs established", Counter.FALLBACK_IPV4);
            line(out, "DOMAIN CONNECTs established", Counter.FALLBACK_DOMAIN);
            line(out, "synthetic mapping misses", Counter.SYNTHETIC_MISS);
            line(out, "SOCKS transport/negotiation failures", Counter.FALLBACK_FAILED);
            line(out, "socket creation/bind failures", Counter.FALLBACK_SOCKET_FAILED);
            line(out, "VPN protection failures", Counter.FALLBACK_PROTECT_FAILED);
            line(out, "proxy connect failures", Counter.FALLBACK_PROXY_CONNECT_FAILED);
            line(out, "SOCKS negotiation failures", Counter.FALLBACK_SOCKS_FAILED);
            out.append("\nUDP\n");
            line(out, "authorized flows (first datagram sent)", Counter.UDP_FLOWS);
            line(out, "forwarded packets (guest to relay)", Counter.UDP_PACKETS);
            line(out, "dropped packets (both directions)", Counter.UDP_DROPPED);
            line(out, "expired tickets", Counter.UDP_TICKET_EXPIRED);
            out.append("\nRelay\n");
            line(out, "failures (including VPN setup)", Counter.RELAY_FAILED);
            out.append("  last failure stage: ").append(lastFailureStage).append('\n');
            line(out, "other/unclassifiable packets dropped", Counter.OTHER_DROPPED);
            out.append("\nCounts since VPN service creation or last reset.\n")
                    .append("Removed registrations are not retained as history; later packets can count as no retained registration.\n")
                    .append("Settings changes require VPN/guest restart. Flow counts do not confirm SOCKS or browsing success.");
            return out.toString();
        }

        private void line(StringBuilder out, String label, Counter counter) {
            out.append("  ").append(label).append(": ").append(count(counter)).append('\n');
        }
    }
}
