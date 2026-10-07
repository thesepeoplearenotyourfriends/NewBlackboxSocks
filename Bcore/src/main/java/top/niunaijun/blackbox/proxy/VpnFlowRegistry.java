package top.niunaijun.blackbox.proxy;

import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Process;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.EOFException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Semaphore;

/** Private capability broker. No exported Binder/service or abstract socket name. */
final class VpnFlowRegistry implements AutoCloseable {
    static final int MAX_FLOWS = 128;
    static final long MAX_LIFETIME_MS = 10 * 60_000L;
    static final long IDLE_MS = 120_000L;
    private static final long TICKET_MS = 5_000L;
    private final Map<Key, Flow> flows = new HashMap<>();
    private final Set<LocalSocket> channels = new HashSet<>();
    private final Semaphore slots = new Semaphore(MAX_FLOWS);
    private final LocalSocket listener;
    private final LocalServerSocket server;
    private final File path;
    private final int proxyAddress, proxyPort;
    private final VpnRelay.Diagnostics diagnostics;
    private volatile boolean running = true;

    static final class Key {
        final int protocol, sourcePort, address, port;
        Key(int protocol, int sourcePort, int address, int port) {
            this.protocol = protocol; this.sourcePort = sourcePort;
            this.address = address; this.port = port;
        }
        @Override public int hashCode() { return ((protocol * 31 + sourcePort) * 31 + address) * 31 + port; }
        @Override public boolean equals(Object value) {
            if (!(value instanceof Key)) return false;
            Key other = (Key) value;
            return protocol == other.protocol && sourcePort == other.sourcePort && address == other.address && port == other.port;
        }
    }
    private static final class Ticket {
        final byte[] header;
        final long expires = SystemClock.elapsedRealtime() + TICKET_MS;
        Ticket(byte[] header) { this.header = header; }
    }
    static final class Flow {
        final Key key;
        final LocalSocket owner;
        final long expires = SystemClock.elapsedRealtime() + MAX_LIFETIME_MS;
        long lastActivity = SystemClock.elapsedRealtime();
        boolean active, revoked;
        boolean remoteClosed;
        final Flow control;
        int initialSequence;
        final ArrayDeque<Ticket> tickets = new ArrayDeque<>();
        Flow(Key key, LocalSocket owner, Flow control) { this.key = key; this.owner = owner; this.control = control; }
    }

    VpnFlowRegistry(File directory, int proxyAddress, int proxyPort, VpnRelay.Diagnostics diagnostics) throws IOException {
        this.proxyAddress = proxyAddress; this.proxyPort = proxyPort; this.diagnostics = diagnostics;
        path = new File(directory, "nbs-flow.sock");
        // The service is a singleton. A stale filesystem name grants no capability.
        if (path.exists() && !path.delete()) throw new IOException("broker-path");
        listener = new LocalSocket();
        LocalServerSocket created = null;
        try {
            listener.bind(new LocalSocketAddress(path.getAbsolutePath(), LocalSocketAddress.Namespace.FILESYSTEM));
            Os.chmod(path.getAbsolutePath(), 0600);
            created = new LocalServerSocket(listener.getFileDescriptor());
        } catch (Exception failure) {
            listener.close(); path.delete();
            if (created != null) created.close();
            throw new IOException("broker-bind");
        }
        server = created;
        new Thread(this::accept, "NBSFlowBroker").start();
    }

    private void accept() {
        while (running) {
            try {
                LocalSocket channel = server.accept();
                if (!slots.tryAcquire()) { diagnostics.registrationFailure.incrementAndGet(); channel.close(); continue; }
                synchronized (this) {
                    if (!running) { slots.release(); channel.close(); break; }
                    channels.add(channel);
                }
                new Thread(() -> serve(channel), "NBSFlowLease").start();
            } catch (IOException failure) {
                if (running) diagnostics.registrationFailure.incrementAndGet();
                break;
            }
        }
    }

    private void serve(LocalSocket channel) {
        int sourcePort = 0, socketType = 0;
        Flow control = null;
        long channelExpiry = SystemClock.elapsedRealtime() + MAX_LIFETIME_MS;
        try {
            if (channel.getPeerCredentials().getUid() != Process.myUid()) throw new IOException("peer");
            channel.setSoTimeout(2_000);
            DataInputStream input = new DataInputStream(channel.getInputStream());
            boolean first = true;
            while (running) {
                // Waiting for the next command is bounded by the hard lease lifetime.
                channel.setSoTimeout(first ? 2_000 : (int) Math.max(1, channelExpiry - SystemClock.elapsedRealtime()));
                int magic = input.readInt();
                channel.setSoTimeout(2_000);
                FileDescriptor[] descriptors = channel.getAncillaryFileDescriptors();
                try {
                    if (magic != 0x4e425301) throw new IOException("version");
                    int protocol = input.readUnsignedByte();
                    int address = input.readInt(), port = input.readUnsignedShort();
                    int headerLength = input.readUnsignedShort();
                    if (headerLength > 262) throw new IOException("header-length");
                    byte[] header = new byte[headerLength]; input.readFully(header);
                    if (first) {
                        if (descriptors == null || descriptors.length != (protocol == 17 ? 2 : 1)) throw new IOException("descriptor");
                        FileDescriptor fd = descriptors[0];
                        SocketAddress local = Os.getsockname(fd);
                        if (!(local instanceof InetSocketAddress)) throw new IOException("family");
                        InetSocketAddress endpoint = (InetSocketAddress) local;
                        if (!localAddress(endpoint) || endpoint.getPort() == 0)
                            throw new IOException("source");
                        sourcePort = endpoint.getPort();
                        socketType = Os.getsockoptInt(fd, OsConstants.SOL_SOCKET, OsConstants.SO_TYPE);
                        if (socketType == OsConstants.SOCK_DGRAM &&
                                (Os.getsockoptInt(fd, OsConstants.SOL_SOCKET, OsConstants.SO_REUSEADDR) != 0 ||
                                 Os.getsockoptInt(fd, OsConstants.SOL_SOCKET, OsConstants.SO_REUSEPORT) != 0))
                            throw new IOException("shared-port");
                        if (protocol == 17) {
                            FileDescriptor parentFd = descriptors[1];
                            SocketAddress parentAddress = Os.getsockname(parentFd);
                            SocketAddress parentPeer = Os.getpeername(parentFd);
                            if (!(parentAddress instanceof InetSocketAddress) || !localAddress((InetSocketAddress) parentAddress) ||
                                    !(parentPeer instanceof InetSocketAddress) ||
                                    ((InetSocketAddress) parentPeer).getPort() != proxyPort ||
                                    !Arrays.equals(normalizedAddress((InetSocketAddress) parentPeer), VpnRelay.bytes(proxyAddress)) ||
                                    Os.getsockoptInt(parentFd, OsConstants.SOL_SOCKET, OsConstants.SO_TYPE) != OsConstants.SOCK_STREAM)
                                throw new IOException("udp-control");
                            synchronized (this) {
                                control = flows.get(new Key(6, ((InetSocketAddress) parentAddress).getPort(), proxyAddress, proxyPort));
                                // A loopback SOCKS control connection can be local
                                // to Android and never traverse the TUN. Its real
                                // connected descriptor plus NBS registration is
                                // the authority, not VPN membership/arrival.
                                if (!live(control) || control.remoteClosed ||
                                        control.owner.getPeerCredentials().getPid() != channel.getPeerCredentials().getPid())
                                    throw new IOException("udp-control-lease");
                            }
                        }
                    } else if (descriptors != null && descriptors.length != 0) throw new IOException("extra-descriptor");
                    if (SystemClock.elapsedRealtime() >= channelExpiry || port == 0) throw new IOException("expired");
                    if (protocol == 6) {
                        if (!first || socketType != OsConstants.SOCK_STREAM || headerLength != 0 ||
                                address != proxyAddress || port != proxyPort) throw new IOException("tcp-policy");
                    } else if (protocol == 17) {
                        if (socketType != OsConstants.SOCK_DGRAM || !VpnRelay.validSocksUdp(header)) throw new IOException("udp-policy");
                    } else throw new IOException("protocol");
                    register(new Key(protocol, sourcePort, address, port), channel, header, control);
                    channel.getOutputStream().write(1);
                    diagnostics.registered.incrementAndGet();
                    first = false;
                } finally {
                    // Never keep a reference to the guest socket: doing so would
                    // prolong its lifetime after guest close/death and permit reuse.
                    if (descriptors != null) for (FileDescriptor fd : descriptors) try { Os.close(fd); } catch (Exception ignored) { }
                }
            }
        } catch (EOFException closed) {
            // Normal socket closure/death revokes; it is not registration failure.
        } catch (SocketTimeoutException expired) {
            if (running) diagnostics.expired.incrementAndGet();
        } catch (Exception failure) {
            if (running) diagnostics.registrationFailure.incrementAndGet();
        } finally {
            // Also collect descriptors received with a truncated/aborted request.
            // SCM_RIGHTS must never turn malformed IPC into a descriptor leak.
            try {
                FileDescriptor[] remaining = channel.getAncillaryFileDescriptors();
                if (remaining != null) for (FileDescriptor fd : remaining) try { Os.close(fd); } catch (Exception ignored) { }
            } catch (IOException ignored) { }
            synchronized (this) {
                channels.remove(channel);
                for (Iterator<Flow> it = flows.values().iterator(); it.hasNext();) {
                    Flow flow = it.next();
                    if (flow.owner == channel) { flow.revoked = true; it.remove(); }
                }
            }
            try { channel.close(); } catch (IOException ignored) { }
            slots.release();
        }
    }

    private static boolean localAddress(InetSocketAddress endpoint) {
        byte[] address = endpoint.getAddress().getAddress();
        // A guest may bind INADDR_ANY before connect/send. The kernel descriptor
        // still establishes the exclusive source port; the gate permits that
        // port only with the VPN's exact source address, never on other routes.
        boolean wildcard = true;
        for (byte value : address) if (value != 0) { wildcard = false; break; }
        if (wildcard) return true;
        return Arrays.equals(normalizedAddress(endpoint), VpnRelay.LOCAL_BYTES);
    }

    private static byte[] normalizedAddress(InetSocketAddress endpoint) {
        byte[] address = endpoint.getAddress().getAddress();
        if (address.length == 16) {
            for (int i = 0; i < 10; i++) if (address[i] != 0) return address;
            if (address[10] != (byte) 255 || address[11] != (byte) 255) return address;
            return Arrays.copyOfRange(address, 12, 16);
        }
        return address;
    }

    private synchronized void register(Key key, LocalSocket channel, byte[] header, Flow control) throws IOException {
        expire();
        if (key.protocol == 17 && (!live(control) || control.remoteClosed)) throw new IOException("udp-control-expired");
        Flow flow = flows.get(key);
        if (flow == null) {
            if (flows.size() >= MAX_FLOWS) throw new IOException("capacity");
            flow = new Flow(key, channel, control); flows.put(key, flow);
        } else if (flow.owner != channel || key.protocol == 6) throw new IOException("collision");
        if (key.protocol == 17) {
            pruneTickets(flow);
            if (flow.tickets.size() >= 64) throw new IOException("ticket-capacity");
            flow.tickets.addLast(new Ticket(header));
        }
        flow.lastActivity = SystemClock.elapsedRealtime();
        if (control != null) control.lastActivity = flow.lastActivity;
    }

    synchronized Flow authorizeTcp(Key key, boolean syn, int sequence) {
        Flow flow = flows.get(key);
        if (!live(flow)) return null;
        if (!flow.active) {
            if (!syn) return null;
            flow.active = true; flow.initialSequence = sequence;
        } else if (syn && flow.initialSequence != sequence) return null;
        flow.lastActivity = SystemClock.elapsedRealtime();
        return flow;
    }

    synchronized Flow authorizeUdp(Key key, byte[] packet, int offset, int length) {
        Flow flow = flows.get(key);
        if (!live(flow)) return null;
        pruneTickets(flow);
        for (Iterator<Ticket> it = flow.tickets.iterator(); it.hasNext();) {
            Ticket ticket = it.next();
            if (length < ticket.header.length) continue;
            boolean match = true;
            for (int i = 0; i < ticket.header.length; i++) if (packet[offset + i] != ticket.header[i]) { match = false; break; }
            if (match) { it.remove(); flow.active = true; touch(flow); return flow; }
        }
        return null;
    }

    synchronized boolean live(Flow flow) {
        long now = SystemClock.elapsedRealtime();
        return flow != null && !flow.revoked && flows.get(flow.key) == flow &&
                now < flow.expires && now - flow.lastActivity < IDLE_MS && channelLive(flow.owner) &&
                (flow.control == null || (!flow.control.remoteClosed && live(flow.control)));
    }

    private boolean channelLive(LocalSocket channel) {
        // Observe kernel hangup at the gate itself, rather than waiting for the
        // broker thread to process EOF after guest close or source-port reuse.
        try {
            StructPollfd poll = new StructPollfd(); poll.fd = channel.getFileDescriptor();
            if (poll.fd == null) return false;
            poll.events = (short) OsConstants.POLLIN;
            Os.poll(new StructPollfd[]{poll}, 0);
            return (poll.revents & (OsConstants.POLLHUP | OsConstants.POLLERR | OsConstants.POLLNVAL)) == 0;
        } catch (Exception failure) { return false; }
    }

    synchronized void touch(Flow flow) {
        if (!live(flow)) return;
        flow.lastActivity = SystemClock.elapsedRealtime();
        if (flow.control != null) flow.control.lastActivity = flow.lastActivity;
    }

    synchronized void remoteClosed(Flow flow) { flow.remoteClosed = true; }

    private void pruneTickets(Flow flow) {
        long now = SystemClock.elapsedRealtime();
        while (!flow.tickets.isEmpty() && flow.tickets.peekFirst().expires <= now) {
            flow.tickets.removeFirst(); diagnostics.ticketExpiry.incrementAndGet();
        }
    }

    synchronized void expire() {
        for (Iterator<Flow> it = flows.values().iterator(); it.hasNext();) {
            Flow flow = it.next(); pruneTickets(flow);
            if (!live(flow)) { flow.revoked = true; it.remove(); diagnostics.expired.incrementAndGet(); }
        }
    }

    @Override public void close() {
        running = false;
        synchronized (this) {
            for (Flow flow : flows.values()) flow.revoked = true;
            flows.clear();
            for (LocalSocket channel : new ArrayList<>(channels)) try { channel.close(); } catch (IOException ignored) { }
        }
        try { server.close(); } catch (IOException ignored) { }
        try { listener.close(); } catch (IOException ignored) { }
        path.delete();
    }
}
