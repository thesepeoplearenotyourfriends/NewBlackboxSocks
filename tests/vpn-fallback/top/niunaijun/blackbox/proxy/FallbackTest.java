package top.niunaijun.blackbox.proxy;

import android.net.LocalSocket;
import android.os.SystemClock;
import java.io.*;
import java.lang.reflect.Method;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.Counter.*;

public final class FallbackTest {
    static final int SOURCE = 0x0a000002, DEST = 0x08080808;
    static final byte[] EMPTY = new byte[0];
    interface Checked { void run() throws Exception; }
    static void check(boolean b) { if (!b) throw new AssertionError(); }
    static void rejects(Checked f) throws Exception {
        try { f.run(); } catch (IOException expected) { return; }
        throw new AssertionError("expected fail closed");
    }
    static VpnFlowRegistry.Key key(int source, int address) { return new VpnFlowRegistry.Key(6, source, address, 443); }
    static void registry() throws Exception {
        SystemClock.now = 0;
        SyntheticMappings mappings = new SyntheticMappings();
        NetworkDiagnostics d = new NetworkDiagnostics();
        try (VpnFlowRegistry r = new VpnFlowRegistry(new File(System.getProperty("java.io.tmpdir")), DEST, 1080, d, mappings)) {
            VpnFlowRegistry.Key k = key(1234, DEST);
            check(r.authorizeTcp(k, false, 10, SOURCE) == null);
            VpnFlowRegistry.Flow flow = r.authorizeTcp(k, true, 10, SOURCE);
            check(flow != null && flow.owner == null && flow.hostname == null);
            check(r.authorizeTcp(k, true, 10, SOURCE) == flow); // retransmission, no duplicates
            check(d.snapshot().count(FALLBACK_ACCEPTED) == 1);
            check(r.authorizeTcp(k, true, 11, SOURCE) == null); // generation conflict
            check(r.authorizeTcp(key(1234, DEST + 1), true, 10, SOURCE) == null);
            check(r.authorizeTcp(k, true, 10, SOURCE + 1) == null);
            r.endFallback(flow);
            check(r.authorizeTcp(k, true, 12, SOURCE) == null); // closed port quarantine
            SystemClock.now = VpnFlowRegistry.IDLE_MS + 1; r.expire();
            VpnFlowRegistry.Flow reused = r.authorizeTcp(k, true, 12, SOURCE);
            check(reused != null && reused != flow && reused.initialSequence == 12);
            check(!r.live(flow));
            check(r.authorizeTcp(k, true, 10, SOURCE) == null); // delayed old generation
            check(r.authorizeTcp(key(2222, SyntheticMappings.BASE + 999), true, 10, SOURCE) == null);
            check(d.snapshot().count(SYNTHETIC_MISS) == 1);
            int fake = mappings.allocate("Example.COM.");
            VpnFlowRegistry.Flow domain = r.authorizeTcp(key(2223, fake), true, 10, SOURCE);
            check(domain != null && "example.com".equals(domain.hostname));
            // Exercise the actual registration and authorization code, with Android boundaries stubbed.
            Method register = VpnFlowRegistry.class.getDeclaredMethod("register", VpnFlowRegistry.Key.class,
                    LocalSocket.class, byte[].class, VpnFlowRegistry.Flow.class);
            register.setAccessible(true);
            VpnFlowRegistry.Key registered = key(3333, DEST);
            LocalSocket owner = new LocalSocket();
            register.invoke(r, registered, owner, EMPTY, null);
            long accepted = d.snapshot().count(FALLBACK_ACCEPTED);
            check(r.authorizeTcp(key(3333, DEST + 1), true, 100, SOURCE) == null);
            VpnFlowRegistry.Flow grant = r.authorizeTcp(registered, true, 100, SOURCE);
            check(grant != null && grant.owner == owner);
            check(r.authorizeTcp(registered, true, 100, SOURCE) == grant);
            check(r.authorizeTcp(registered, true, 101, SOURCE) == null);
            check(d.snapshot().count(FALLBACK_ACCEPTED) == accepted);
            SystemClock.now += VpnFlowRegistry.IDLE_MS + 1;
            check(r.authorizeTcp(registered, true, 100, SOURCE) == null);
            r.expire();
            check(r.authorizeTcp(registered, true, 102, SOURCE) == null); // revoked registration cannot fallback
            mappings.close(); check(!r.live(domain));
            r.close(); check(r.authorizeTcp(key(9999, DEST), true, 1, SOURCE) == null);
        }
    }
    static byte[] bytes(int... values) { byte[] b = new byte[values.length]; for (int i=0;i<b.length;i++) b[i]=(byte)values[i]; return b; }
    static void socks() throws Exception {
        check(Arrays.equals(FallbackSocks.request(DEST, 443, null), bytes(5,1,0,1,8,8,8,8,1,187)));
        byte[] domain = FallbackSocks.request(SyntheticMappings.BASE, 443, "EXAMPLE.com.");
        check(domain[3] == 3 && domain[4] == 11);
        check("example.com".equals(new String(domain,5,11,java.nio.charset.StandardCharsets.US_ASCII)));
        rejects(() -> FallbackSocks.request(SyntheticMappings.BASE,443,null));
        rejects(() -> FallbackSocks.request(DEST,0,null));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] reply = bytes(5,0,5,0,0,1,0,0,0,0,0,0);
        FallbackSocks.negotiate(new ByteArrayInputStream(reply),out,EMPTY,EMPTY,DEST,443,null);
        check(Arrays.equals(out.toByteArray(),bytes(5,1,0,5,1,0,1,8,8,8,8,1,187)));
        out.reset();
        FallbackSocks.negotiate(new ByteArrayInputStream(bytes(5,2,1,0,5,0,0,3,1,'x',0,1)),
                out,bytes('u'),bytes('p'),DEST,443,null);
        check(Arrays.equals(Arrays.copyOf(out.toByteArray(),8),bytes(5,1,2,1,1,'u',1,'p')));
        rejects(() -> FallbackSocks.negotiate(new ByteArrayInputStream(bytes(5,0)),out,bytes('u'),bytes('p'),DEST,443,null));
        for (byte[] bad : new byte[][] {bytes(4,0),bytes(5,255),bytes(5,2),bytes(5,0,4,0,0,1),
                bytes(5,0,5,1,0,1),bytes(5,0,5,0,1,1),bytes(5,0,5,0,0,9),
                bytes(5,0,5,0,0,3,0),bytes(5,0,5,0,0,1,0)})
            rejects(() -> FallbackSocks.negotiate(new ByteArrayInputStream(bad),out,EMPTY,EMPTY,DEST,443,null));
        rejects(() -> FallbackSocks.negotiate(new ByteArrayInputStream(bytes(5,2,1,1)),out,bytes('u'),bytes('p'),DEST,443,null));
    }
    static void transport() throws Exception {
        ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
        try (ServerSocket proxy = new ServerSocket(0,1,InetAddress.getLoopbackAddress())) {
            InetSocketAddress endpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), proxy.getLocalPort());
            Socket denied = new Socket();
            rejects(() -> FallbackTransport.connect(denied,s -> false,endpoint,timer,EMPTY,EMPTY,DEST,443,null));
            check(denied.isClosed() && !denied.isConnected());
            CompletableFuture<Void> served = CompletableFuture.runAsync(() -> {
                try (Socket s = proxy.accept()) {
                    s.setSoTimeout(2000);
                    DataInputStream in = new DataInputStream(s.getInputStream());
                    byte[] greeting = new byte[3]; in.readFully(greeting); check(Arrays.equals(greeting,bytes(5,1,0)));
                    s.getOutputStream().write(bytes(5,0));
                    byte[] connect = new byte[10]; in.readFully(connect);
                    check(Arrays.equals(connect,FallbackSocks.request(DEST,443,null)));
                    s.getOutputStream().write(bytes(5,0,0,1,0,0,0,0,0,0));
                    check(in.readUnsignedByte() == 42); s.getOutputStream().write(43);
                } catch (Exception e) { throw new CompletionException(e); }
            });
            try (Socket connected = new Socket()) {
                int[] protectedCount = {0};
                FallbackTransport.connect(connected,s -> {check(!s.isConnected()); protectedCount[0]++; return true;},
                        endpoint,timer,EMPTY,EMPTY,DEST,443,null);
                check(protectedCount[0] == 1 && connected.getPort() == proxy.getLocalPort());
                connected.getOutputStream().write(42); check(connected.getInputStream().read() == 43);
            }
            served.get(5,TimeUnit.SECONDS);
            try (ServerSocket unused = new ServerSocket(0)) {
                int port = unused.getLocalPort(); unused.close();
                Socket refused = new Socket();
                rejects(() -> FallbackTransport.connect(refused,s -> true,new InetSocketAddress("127.0.0.1",port),
                        timer,EMPTY,EMPTY,DEST,443,null)); check(refused.isClosed());
            }
        } finally { timer.shutdownNow(); }
    }
    static void mappings() throws Exception {
        SyntheticMappings m = new SyntheticMappings();
        int first = m.allocate("stable.example"); check(first == m.allocate("STABLE.EXAMPLE."));
        Set<Integer> assigned = ConcurrentHashMap.newKeySet();
        List<CompletableFuture<Void>> clients = new ArrayList<>();
        for (int client=0;client<8;client++) {
            final int id = client;
            clients.add(CompletableFuture.runAsync(() -> {
                try {
                    for (int i=0;i<100;i++) check(assigned.add(m.allocate("guest"+id+"-"+i+".example")));
                    check(first == m.allocate("stable.example"));
                } catch (Exception e) { throw new CompletionException(e); }
            }));
        }
        CompletableFuture.allOf(clients.toArray(new CompletableFuture[0])).join();
        check(assigned.size() == 800);
        for (int a : assigned) check(SyntheticMappings.synthetic(a));
        check(m.lookup(SyntheticMappings.BASE + SyntheticMappings.CAPACITY - 1) == null);
        for (String bad : new String[]{"", "bad name", "bad/host", "a..b", "-bad.test", "x".repeat(64)+".test", "é.test"})
            rejects(() -> m.allocate(bad));
        check(SyntheticMappings.synthetic(SyntheticMappings.BASE));
        check(SyntheticMappings.synthetic(SyntheticMappings.BASE+SyntheticMappings.CAPACITY-1));
        check(!SyntheticMappings.synthetic(SyntheticMappings.BASE-1));
        check(!SyntheticMappings.synthetic(SyntheticMappings.BASE+SyntheticMappings.CAPACITY));
        m.close(); check(m.lookup(first) == null); rejects(() -> m.allocate("stable.example"));
        SyntheticMappings next = new SyntheticMappings(); check(next.allocate("stable.example") != first);
        int last=0;
        try { for (int i=0;i<SyntheticMappings.CAPACITY;i++) last=next.allocate("capacity"+i+".test"); }
        catch (IOException exhausted) { check(last == SyntheticMappings.BASE+SyntheticMappings.CAPACITY-1); }
        rejects(() -> next.allocate("overflow.test"));
    }
    static void cursor() throws Exception {
        java.nio.file.Path directory = java.nio.file.Files.createTempDirectory("nbs-cursor-test");
        File state = directory.resolve("nbs-mapping-cursor").toFile();
        try {
            SyntheticAddressCursor one = new SyntheticAddressCursor(directory.toFile());
            int first = one.nextAddress();
            SyntheticAddressCursor restarted = new SyntheticAddressCursor(directory.toFile());
            check(restarted.nextAddress() == first + 1);
            try (RandomAccessFile file = new RandomAccessFile(state,"rw")) {
                file.seek(4); file.writeInt(SyntheticMappings.CAPACITY - 1);
            }
            check(restarted.nextAddress() == SyntheticMappings.BASE + SyntheticMappings.CAPACITY - 1);
            rejects(restarted::nextAddress);
            try (RandomAccessFile file = new RandomAccessFile(state,"rw")) { file.setLength(3); }
            rejects(restarted::nextAddress);
        } finally { state.delete(); java.nio.file.Files.delete(directory); }
    }
    public static void main(String[] args) throws Exception {
        registry(); socks(); transport(); mappings(); cursor();
        System.out.println("Fallback host checks passed: production registry/generations, SOCKS encodings/auth/rejections, protected proxy transport and byte exchange, concurrent global mappings/capacity.");
        System.out.println("Android TUN, AF_UNIX peer credentials and native resolver IPC require device validation.");
    }
}
