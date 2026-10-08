package top.niunaijun.blackbox.proxy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.NetworkInterface;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.FailureStage;

/** Local or protected proxy transport. Any failure closes the socket before returning. */
final class FallbackTransport {
    static final class Failure extends IOException {
        final FailureStage stage;
        Failure(FailureStage stage, Exception cause) {
            super(stage.label, cause);
            this.stage = stage;
        }
    }
    // Private/LAN addresses are not necessarily local: only loopback or an address
    // assigned to this device skips protection. The configured endpoint is numeric.
    static boolean localProxy(InetSocketAddress proxy) throws IOException {
        return proxy.getAddress() != null && (proxy.getAddress().isLoopbackAddress()
                || NetworkInterface.getByInetAddress(proxy.getAddress()) != null);
    }
    interface Protector { boolean protect(Socket socket); }
    static void connect(Socket socket, Protector protector, InetSocketAddress proxy,
                        ScheduledExecutorService timer, byte[] user, byte[] password,
                        int address, int port, String hostname) throws IOException {
        ScheduledFuture<?> deadline = null;
        FailureStage stage = FailureStage.FALLBACK_SOCKET;
        try {
            // Android Socket creates its kernel fd lazily. VpnService.protect(Socket)
            // reads that fd without creating it; bind forces creation before protect.
            // Bind local hops too so fd creation failures have their own stage.
            socket.bind(new InetSocketAddress(0));
            if (!localProxy(proxy)) {
                stage = FailureStage.FALLBACK_PROTECT;
                if (!protector.protect(socket)) throw new IOException("protect");
            }
            stage = FailureStage.FALLBACK_PROXY_CONNECT;
            socket.connect(proxy, 10_000);
            stage = FailureStage.FALLBACK_SOCKS;
            // Total negotiation deadline bounds trickle replies and blocked writes too.
            deadline = timer.schedule(() -> {
                try { socket.close(); } catch (IOException ignored) { }
            }, 10, TimeUnit.SECONDS);
            socket.setSoTimeout(10_000);
            FallbackSocks.negotiate(socket.getInputStream(), socket.getOutputStream(), user,
                    password, address, port, hostname);
            if (socket.isClosed()) throw new IOException("socks-timeout");
            socket.setSoTimeout(0);
        } catch (IOException | RuntimeException failure) {
            try { socket.close(); } catch (IOException ignored) { }
            throw new Failure(stage, failure);
        } finally { if (deadline != null) deadline.cancel(false); }
    }
}
