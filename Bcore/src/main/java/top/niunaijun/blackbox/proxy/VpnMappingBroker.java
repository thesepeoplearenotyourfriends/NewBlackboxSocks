package top.niunaijun.blackbox.proxy;

import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.Process;
import android.system.Os;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Semaphore;

/** Same-real-UID filesystem IPC; one bounded allocation request per connection. */
final class VpnMappingBroker implements AutoCloseable {
    final SyntheticMappings mappings;
    private final File path;
    private final LocalSocket listener = new LocalSocket();
    private final LocalServerSocket server;
    private final Set<LocalSocket> clients = new HashSet<>();
    private final Semaphore slots = new Semaphore(32);
    private volatile boolean running = true;
    VpnMappingBroker(File directory, int proxyAddress) throws IOException {
        mappings = new SyntheticMappings(proxyAddress, new SyntheticAddressCursor(directory));
        path = new File(directory, "nbs-mapping.sock");
        if (path.exists() && !path.delete()) throw new IOException("mapping-path");
        LocalServerSocket created = null;
        try {
            listener.bind(new LocalSocketAddress(path.getAbsolutePath(), LocalSocketAddress.Namespace.FILESYSTEM));
            Os.chmod(path.getAbsolutePath(), 0600);
            created = new LocalServerSocket(listener.getFileDescriptor());
        } catch (Exception failure) {
            listener.close(); path.delete();
            if (created != null) created.close();
            throw new IOException("mapping-bind");
        }
        server = created;
        new Thread(this::accept, "NBSMappingBroker").start();
    }
    private void accept() {
        while (running) {
            try {
                LocalSocket client = server.accept();
                synchronized (this) {
                    if (!running || !slots.tryAcquire()) { client.close(); continue; }
                    clients.add(client);
                }
                new Thread(() -> serve(client), "NBSMappingRequest").start();
            } catch (IOException failure) { break; }
        }
    }
    private void serve(LocalSocket client) {
        try {
            if (client.getPeerCredentials().getUid() != Process.myUid()) throw new IOException("mapping-peer");
            client.setSoTimeout(2000);
            DataInputStream input = new DataInputStream(client.getInputStream());
            if (input.readInt() != 0x4e424d01) throw new IOException("mapping-version");
            int size = input.readUnsignedShort();
            if (size == 0 || size > 253) throw new IOException("mapping-size");
            byte[] bytes = new byte[size]; input.readFully(bytes);
            for (byte b : bytes) if (b < 0 || b == 0) throw new IOException("mapping-ascii");
            int address = mappings.allocate(new String(bytes, StandardCharsets.US_ASCII));
            DataOutputStream output = new DataOutputStream(client.getOutputStream());
            output.writeInt(0x4e424d01); output.writeInt(address); output.flush();
        } catch (Exception failure) { /* Closing IPC is a fail-closed response; no names in logs. */ }
        finally {
            synchronized (this) { clients.remove(client); }
            try { client.close(); } catch (IOException ignored) { }
            slots.release();
        }
    }
    @Override public synchronized void close() {
        running = false; mappings.close();
        try { server.close(); } catch (IOException ignored) { }
        try { listener.close(); } catch (IOException ignored) { }
        for (LocalSocket client : clients) try { client.close(); } catch (IOException ignored) { }
        path.delete();
    }
}
