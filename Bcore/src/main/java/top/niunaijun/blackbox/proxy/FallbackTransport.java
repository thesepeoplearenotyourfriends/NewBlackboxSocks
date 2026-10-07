package top.niunaijun.blackbox.proxy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/** Protected proxy transport. Any failure closes the socket before returning. */
final class FallbackTransport {
    interface Protector { boolean protect(Socket socket); }
    static void connect(Socket socket, Protector protector, InetSocketAddress proxy,
                        ScheduledExecutorService timer, byte[] user, byte[] password,
                        int address, int port, String hostname) throws IOException {
        ScheduledFuture<?> deadline = null;
        try {
            if (!protector.protect(socket)) throw new IOException("protect");
            socket.connect(proxy, 10_000);
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
            throw failure;
        } finally { if (deadline != null) deadline.cancel(false); }
    }
}
