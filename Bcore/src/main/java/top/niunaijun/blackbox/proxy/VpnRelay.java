package top.niunaijun.blackbox.proxy;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.Counter.*;
import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.TcpDrop;
import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.FailureStage;

/**
 * Relays authorized guest SOCKS transports, not arbitrary guest IP destinations.
 * NetworkHook remains the sole SOCKS5/auth/fake-IP/UDP-ASSOCIATE implementation.
 * TCP packets are redirected to a local kernel TCP listener; only its onward
 * connection is protected. Thus retransmission, windows and half-close use the
 * Android TCP stack instead of a second, incomplete userspace TCP implementation.
 */
final class VpnRelay implements AutoCloseable {
    static final byte[] LOCAL_BYTES = {10, 0, 0, 2};
    private static final int LOCAL = 0x0a000002, PEER = 0x0a000001;
    private static final int MTU = 1500;
    private final VpnService service;
    private final ParcelFileDescriptor tun;
    private final Map<Integer, Tcp> tcp = new HashMap<>();
    private final Map<VpnFlowRegistry.Key, Udp> udp = new HashMap<>();
    private final NetworkDiagnostics diagnostics;
    private VpnFlowRegistry registry;
    private ServerSocket listener;
    private int listenerPort;
    private volatile boolean running = true;
    private Thread packetThread;

    private void report() {
        NetworkDiagnostics.Snapshot snapshot = diagnostics.snapshot();
        Log.i("NBSVpn", "authorized_flows_tcp=" + snapshot.count(TCP_FLOWS)
                + " authorized_flows_udp=" + snapshot.count(UDP_FLOWS)
                + " forwarded_packets_tcp=" + snapshot.count(TCP_PACKETS)
                + " forwarded_packets_udp=" + snapshot.count(UDP_PACKETS)
                + " dropped_tcp=" + snapshot.count(TCP_DROPPED)
                + " dropped_udp=" + snapshot.count(UDP_DROPPED)
                + " dropped_other=" + snapshot.count(OTHER_DROPPED)
                + " tcp_no_retained_registration=" + snapshot.count(TCP_NO_REGISTRATION)
                + " tcp_tuple_mismatch=" + snapshot.count(TCP_TUPLE_MISMATCH)
                + " tcp_expired_revoked=" + snapshot.count(TCP_EXPIRED_REVOKED)
                + " tcp_syn_generation=" + snapshot.count(TCP_SYN_GENERATION)
                + " tcp_malformed=" + snapshot.count(TCP_MALFORMED)
                + " tcp_source_address=" + snapshot.count(TCP_SOURCE_ADDRESS)
                + " tcp_other_policy=" + snapshot.count(TCP_OTHER_POLICY)
                + " registered=" + snapshot.count(REGISTERED)
                + " registration_failures=" + snapshot.count(REGISTRATION_FAILED)
                + " expired_revoked=" + snapshot.count(REGISTRATION_ENDED)
                + " udp_ticket_expired=" + snapshot.count(UDP_TICKET_EXPIRED)
                + " relay_failures=" + snapshot.count(RELAY_FAILED)
                + " last_failure_stage=" + snapshot.lastFailureStage);
    }

    private void failure(FailureStage stage) {
        long count = diagnostics.failure(stage);
        if (count <= 4 || (count & (count - 1)) == 0)
            Log.w("NBSVpn", "relay_failure stage=" + stage.label + " count=" + count);
    }

    VpnRelay(VpnService service, ParcelFileDescriptor descriptor, File files, int proxyAddress, int proxyPort, boolean configured, NetworkDiagnostics diagnostics)
            throws IOException {
        this.service = service;
        this.diagnostics = diagnostics;
        tun = ParcelFileDescriptor.dup(descriptor.getFileDescriptor());
        try {
            if (!configured) throw new IOException("configuration");
            listener = new ServerSocket();
            listener.bind(new InetSocketAddress(InetAddress.getByAddress(LOCAL_BYTES), 0), 64);
            listenerPort = listener.getLocalPort();
            registry = new VpnFlowRegistry(files, proxyAddress, proxyPort, diagnostics,
                    new VpnTcpOwnerDiagnostics(new AndroidTcpOwnerLookup(service), android.os.Process.myUid(), diagnostics));
            new Thread(this::acceptTcp, "NBSVpnAccept").start();
        } catch (Exception failure) {
            failure(FailureStage.SETUP_DENY_ALL);
            if (registry != null) registry.close();
            registry = null;
            if (listener != null) try { listener.close(); } catch (IOException ignored) { }
        }
        packetThread = new Thread(this::packets, "NBSVpnTun");
        diagnostics.relayActive(registry != null);
        packetThread.start();
    }

    private void packets() {
        byte[] buffer = new byte[65535];
        long nextReport = SystemClock.elapsedRealtime() + 30_000;
        try {
            StructPollfd poll = new StructPollfd();
            poll.fd = tun.getFileDescriptor(); poll.events = (short) OsConstants.POLLIN;
            while (running) {
                int available = Os.poll(new StructPollfd[]{poll}, 1_000);
                if (!running) break;
                if (available > 0) {
                    if ((poll.revents & (OsConstants.POLLERR | OsConstants.POLLHUP | OsConstants.POLLNVAL)) != 0) throw new IOException("tun-poll");
                    if ((poll.revents & OsConstants.POLLIN) != 0) {
                        int count = Os.read(tun.getFileDescriptor(), buffer, 0, buffer.length);
                        if (count > 0) handle(buffer, count);
                    }
                }
                reap();
                long now = SystemClock.elapsedRealtime();
                if (now >= nextReport) { report(); nextReport = now + 30_000; }
            }
        } catch (Exception failure) {
            if (running) {
                failure(FailureStage.TUN_READ_DENY_ALL);
                running = false;
                disableForwarding();
                report();
            }
            // Keep the established TUN as containment even if its reader fails.
            // Never tear down the VPN here or restore a direct networking route.
        }
    }

    private void drop(int protocol, TcpDrop reason) {
        if (protocol == 6) diagnostics.dropTcp(reason);
        else if (protocol == 17) diagnostics.increment(UDP_DROPPED);
        else diagnostics.increment(OTHER_DROPPED);
    }

    private void handle(byte[] packet, int count) throws Exception {
        int version = count > 0 ? (packet[0] & 255) >>> 4 : 0;
        int protocol = version == 4 && count >= 20 ? packet[9] & 255
                : version == 6 && count >= 40 ? packet[6] & 255 : 0;
        // Unknown IP versions, IP options, fragments and malformed/checksum-bad
        // traffic are denied. Capture IPv6 too, rather than letting it bypass VPN.
        if (count < 20 || packet[0] != 0x45 || u16(packet, 2) != count ||
                (u16(packet, 6) & 0xbfff) != 0 || checksum(packet, 0, 20, 0) != 0) {
            drop(protocol, TcpDrop.MALFORMED); return;
        }
        if (registry == null) { drop(protocol, TcpDrop.OTHER_POLICY); return; }
        int source = i32(packet, 12), destination = i32(packet, 16);
        if (protocol == 6) handleTcp(packet, count, source, destination);
        else if (protocol == 17) handleUdp(packet, count, source, destination);
        else drop(protocol, TcpDrop.MALFORMED);
    }

    private void handleTcp(byte[] packet, int count, int source, int destination) throws Exception {
        if (count < 40 || (packet[32] & 0xf0) < 0x50 || 20 + ((packet[32] & 0xf0) >> 2) > count ||
                checksum(packet, 20, count - 20, pseudo(source, destination, 6, count - 20)) != 0) {
            diagnostics.dropTcp(TcpDrop.MALFORMED); return;
        }
        int sourcePort = u16(packet, 20), destinationPort = u16(packet, 22);
        if (source == LOCAL && destination == PEER && sourcePort == listenerPort) {
            Tcp connection;
            synchronized (this) { connection = tcp.get(destinationPort); }
            if (connection == null) { diagnostics.dropTcp(TcpDrop.OTHER_POLICY); return; }
            if (!registry.live(connection.flow)) { diagnostics.dropTcp(TcpDrop.EXPIRED_REVOKED); return; }
            registry.touch(connection.flow);
            put32(packet, 12, connection.flow.key.address); put32(packet, 16, LOCAL);
            put16(packet, 20, connection.flow.key.port);
            rewriteChecksums(packet, count, 6);
            writeTun(packet, count); return;
        }
        if (source != LOCAL) { diagnostics.dropTcp(TcpDrop.SOURCE_ADDRESS); return; }
        int flags = packet[33] & 255;
        boolean syn = (flags & 0x17) == 2;
        if ((flags & 2) != 0 && !syn) { diagnostics.dropTcp(TcpDrop.SYN_GENERATION); return; }
        VpnFlowRegistry.Key key = new VpnFlowRegistry.Key(6, sourcePort, destination, destinationPort);
        VpnFlowRegistry.Flow grant = registry.authorizeTcp(key, syn, i32(packet, 24), source);
        if (grant == null) return; // Registry recorded the exact rejection.
        synchronized (this) {
            Tcp connection = tcp.get(sourcePort);
            if (connection != null && connection.flow != grant) {
                if (registry.live(connection.flow)) { diagnostics.dropTcp(TcpDrop.OTHER_POLICY); return; }
                connection.close(); connection = null;
            }
            if (connection == null) tcp.put(sourcePort, new Tcp(grant));
        }
        put32(packet, 12, PEER); put32(packet, 16, LOCAL); put16(packet, 22, listenerPort);
        rewriteChecksums(packet, count, 6);
        if (writeTun(packet, count)) diagnostics.increment(TCP_PACKETS);
        else diagnostics.dropTcp(TcpDrop.OTHER_POLICY);
    }

    private void handleUdp(byte[] packet, int count, int source, int destination) {
        int length = count - 20;
        if (source != LOCAL || length < 8 || u16(packet, 24) != length ||
                (u16(packet, 26) != 0 && checksum(packet, 20, length, pseudo(source, destination, 17, length)) != 0)) {
            diagnostics.increment(UDP_DROPPED); return;
        }
        VpnFlowRegistry.Key key = new VpnFlowRegistry.Key(17, u16(packet, 20), destination, u16(packet, 22));
        VpnFlowRegistry.Flow grant = registry.authorizeUdp(key, packet, 28, count - 28);
        if (grant == null) return; // Registry recorded this rejection.
        try {
            Udp connection;
            synchronized (this) {
                connection = udp.get(key);
                if (connection != null && connection.flow != grant) {
                    if (registry.live(connection.flow)) { diagnostics.increment(UDP_DROPPED); return; }
                    connection.socket.close(); connection = null;
                }
                if (connection == null) {
                    connection = new Udp(grant); udp.put(key, connection);
                    new Thread(connection::receive, "NBSVpnUdp").start();
                }
            }
            if (!registry.live(grant)) { diagnostics.increment(UDP_DROPPED); return; }
            connection.socket.send(new DatagramPacket(packet, 28, count - 28));
            if (!connection.forwarded) { connection.forwarded = true; diagnostics.increment(UDP_FLOWS); }
            diagnostics.increment(UDP_PACKETS);
        } catch (Exception failure) {
            diagnostics.increment(UDP_DROPPED);
            failure(FailureStage.UDP_RELAY);
        }
    }

    private void acceptTcp() {
        while (running) {
            Socket accepted = null;
            try {
                accepted = listener.accept();
                Tcp connection;
                synchronized (this) { connection = tcp.get(accepted.getPort()); }
                if (!Arrays.equals(accepted.getInetAddress().getAddress(), bytes(PEER)) ||
                        connection == null || !registry.live(connection.flow) || !connection.attach(accepted)) {
                    accepted.close(); diagnostics.increment(TCP_LISTENER_REJECTED); continue;
                }
                new Thread(connection::connect, "NBSVpnTcp").start();
            } catch (Exception failure) {
                if (accepted != null) try { accepted.close(); } catch (IOException ignored) { }
                if (running) failure(FailureStage.TCP_ACCEPT);
                break;
            }
        }
    }

    private final class Tcp {
        final VpnFlowRegistry.Flow flow;
        private Socket local, remote;
        private boolean closed;
        private final AtomicInteger pumps = new AtomicInteger(2);
        Tcp(VpnFlowRegistry.Flow flow) { this.flow = flow; }
        synchronized boolean attach(Socket accepted) {
            if (closed || local != null) return false;
            local = accepted; return true;
        }
        void connect() {
            FailureStage stage = FailureStage.TCP_SOCKET;
            try {
                Socket outward = new Socket();
                synchronized (this) {
                    if (closed) { outward.close(); return; }
                    remote = outward;
                }
                stage = FailureStage.TCP_LEASE_BEFORE_CONNECT;
                if (!registry.live(flow)) throw new IOException("expired");
                stage = FailureStage.TCP_PROTECT;
                if (!service.protect(outward)) throw new IOException("protect");
                stage = FailureStage.TCP_CONNECT;
                outward.connect(new InetSocketAddress(InetAddress.getByAddress(bytes(flow.key.address)), flow.key.port), 10_000);
                stage = FailureStage.TCP_LEASE_AFTER_CONNECT;
                if (!registry.live(flow)) throw new IOException("expired");
                diagnostics.increment(TCP_FLOWS);
                new Thread(() -> pump(local, outward), "NBSVpnTcpUp").start();
                pump(outward, local);
            } catch (Exception failure) { if (running) failure(stage); close(); }
        }
        void pump(Socket from, Socket to) {
            try {
                byte[] buffer = new byte[16_384];
                InputStream input = from.getInputStream(); OutputStream output = to.getOutputStream();
                int length;
                while (running && (length = input.read(buffer)) != -1) {
                    if (!registry.live(flow)) throw new IOException("expired");
                    output.write(buffer, 0, length);
                }
                if (from == remote) registry.remoteClosed(flow);
                to.shutdownOutput();
            } catch (Exception failure) { if (running && registry.live(flow)) failure(FailureStage.TCP_IO); close(); }
            finally { if (pumps.decrementAndGet() == 0) close(); }
        }
        synchronized void close() {
            closed = true;
            if (registry != null) registry.remoteClosed(flow);
            if (local != null) try { local.close(); } catch (IOException ignored) { }
            if (remote != null) try { remote.close(); } catch (IOException ignored) { }
        }
    }

    private final class Udp {
        final VpnFlowRegistry.Flow flow;
        final DatagramSocket socket;
        volatile boolean forwarded;
        Udp(VpnFlowRegistry.Flow flow) throws IOException {
            this.flow = flow;
            socket = new DatagramSocket(null);
            try {
                if (!service.protect(socket)) throw new IOException("protect");
                socket.bind(new InetSocketAddress(0));
                socket.connect(InetAddress.getByAddress(bytes(flow.key.address)), flow.key.port);
                socket.setSoTimeout(1_000);
            } catch (Exception failure) { socket.close(); throw new IOException("udp-setup"); }
        }
        void receive() {
            byte[] payload = new byte[65507];
            while (running && registry.live(flow) && !socket.isClosed()) {
                try {
                    DatagramPacket reply = new DatagramPacket(payload, payload.length); socket.receive(reply);
                    if (!registry.live(flow)) { diagnostics.increment(UDP_DROPPED); break; }
                    registry.touch(flow);
                    int length = reply.getLength();
                    // Connected socket accepts only the registered SOCKS relay.
                    // Return its SOCKS envelope unchanged for native decoding.
                    if (!validSocksUdp(Arrays.copyOf(payload, length)) || length + 28 > MTU) { diagnostics.increment(UDP_DROPPED); continue; }
                    byte[] packet = new byte[28 + length];
                    packet[0] = 0x45; put16(packet, 2, packet.length); packet[8] = 64; packet[9] = 17;
                    put32(packet, 12, flow.key.address); put32(packet, 16, LOCAL);
                    put16(packet, 20, flow.key.port); put16(packet, 22, flow.key.sourcePort); put16(packet, 24, length + 8);
                    System.arraycopy(payload, 0, packet, 28, length); rewriteChecksums(packet, packet.length, 17);
                    writeTun(packet, packet.length);
                } catch (SocketTimeoutException timeout) { /* periodically recheck lease */ }
                catch (Exception failure) { if (running && registry.live(flow)) failure(FailureStage.UDP_READ); break; }
            }
            socket.close();
        }
    }

    private void reap() {
        if (registry == null) return;
        registry.expire();
        synchronized (this) {
            for (Iterator<Tcp> it = tcp.values().iterator(); it.hasNext();) {
                Tcp connection = it.next();
                if (!registry.live(connection.flow)) { connection.close(); it.remove(); }
            }
            for (Iterator<Udp> it = udp.values().iterator(); it.hasNext();) {
                Udp connection = it.next();
                if (!registry.live(connection.flow) || connection.socket.isClosed()) { connection.socket.close(); it.remove(); }
            }
        }
    }

    private synchronized boolean writeTun(byte[] packet, int count) throws Exception {
        if (!running) return false;
        if (Os.write(tun.getFileDescriptor(), packet, 0, count) != count) throw new IOException("tun-write");
        return true;
    }

    static boolean validSocksUdp(byte[] packet) {
        if (packet.length < 7 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0) return false;
        int type = packet[3] & 255;
        int header = type == 1 ? 10 : type == 4 ? 22 : type == 3 && packet[4] != 0 ? 7 + (packet[4] & 255) : -1;
        return header > 0 && packet.length >= header;
    }
    static int u16(byte[] data, int offset) { return ((data[offset] & 255) << 8) | (data[offset + 1] & 255); }
    static int i32(byte[] data, int offset) { return (u16(data, offset) << 16) | u16(data, offset + 2); }
    static void put16(byte[] data, int offset, int value) { data[offset] = (byte) (value >> 8); data[offset + 1] = (byte) value; }
    static void put32(byte[] data, int offset, int value) { put16(data, offset, value >> 16); put16(data, offset + 2, value); }
    static byte[] bytes(int address) { byte[] bytes = new byte[4]; put32(bytes, 0, address); return bytes; }
    static long pseudo(int source, int destination, int protocol, int length) {
        return (source >>> 16) + (source & 65535L) + (destination >>> 16) + (destination & 65535L) + protocol + length;
    }
    static int checksum(byte[] data, int offset, int length, long sum) {
        for (int end = offset + length; offset < end; offset += 2)
            sum += ((data[offset] & 255) << 8) | (offset + 1 < end ? data[offset + 1] & 255 : 0);
        while ((sum >>> 16) != 0) sum = (sum & 65535) + (sum >>> 16);
        return (int) (~sum & 65535);
    }
    static void rewriteChecksums(byte[] packet, int count, int protocol) {
        put16(packet, 10, 0); put16(packet, 10, checksum(packet, 0, 20, 0));
        int offset = protocol == 6 ? 36 : 26;
        put16(packet, offset, 0);
        int checksum = checksum(packet, 20, count - 20, pseudo(i32(packet, 12), i32(packet, 16), protocol, count - 20));
        put16(packet, offset, protocol == 17 && checksum == 0 ? 65535 : checksum);
    }

    @Override public void close() {
        running = false;
        disableForwarding();
        if (packetThread != null && packetThread != Thread.currentThread()) try { packetThread.join(1_500); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        try { tun.close(); } catch (IOException ignored) { }
        report();
    }

    private void disableForwarding() {
        diagnostics.relayActive(false);
        if (registry != null) registry.close();
        if (listener != null) try { listener.close(); } catch (IOException ignored) { }
        synchronized (this) {
            for (Tcp connection : tcp.values()) connection.close(); tcp.clear();
            for (Udp connection : udp.values()) connection.socket.close(); udp.clear();
        }
    }
}
