package top.niunaijun.blackbox.proxy;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.Counter.*;
import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.TcpDrop;
import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.FailureStage;

/** Host checks for the actual classifications used by the registry and the counter store. */
public final class NetworkDiagnosticsTest {
    public static void main(String[] args) throws Exception {
        classifications();
        ownerEvidence();
        resetAndSnapshots();
        concurrentAccounting();
        saturation();
        System.out.println("Network diagnostics host checks passed (classification, reset, snapshots, concurrency, saturation).");
    }

    private static void ownerEvidence() {
        NetworkDiagnostics d = new NetworkDiagnostics();
        int[] calls = {0};
        int[] uid = {12345};
        VpnTcpOwnerDiagnostics observer = new VpnTcpOwnerDiagnostics((source, sp, destination, dp) -> {
            calls[0]++;
            equal(0x0a000002, source); equal(43210, sp);
            equal(0xc6120000, destination); equal(443, dp);
            if (uid[0] == -2) throw new SecurityException();
            return uid[0];
        }, 12345, d);
        for (TcpDrop reason : TcpDrop.values()) {
            if (reason != TcpDrop.NO_REGISTRATION)
                observer.observe(reason, true, 0, 0, 0, 0);
        }
        observer.observe(TcpDrop.NO_REGISTRATION, false, 0, 0, 0, 0);
        equal(0, calls[0]); // registered/mismatched/established paths do not query
        for (int result : new int[]{12345, 99999, -1, -2}) {
            uid[0] = result;
            observer.observe(TcpDrop.NO_REGISTRATION, true, 0x0a000002, 43210, 0xc6120000, 443);
        }
        new VpnTcpOwnerDiagnostics(null, 12345, d)
                .observe(TcpDrop.NO_REGISTRATION, true, 0, 0, 0, 0);
        new VpnTcpOwnerDiagnostics((a,b,c,e) -> 12345, 12345, d)
                .observe(TcpDrop.NO_REGISTRATION, true, 0, 0, 0x08080808, 443);
        NetworkDiagnostics.Snapshot snap = d.snapshot();
        equal(2L, snap.count(TCP_OWNER_NBS)); equal(1L, snap.count(TCP_OWNER_OTHER));
        equal(1L, snap.count(TCP_OWNER_INVALID)); equal(2L, snap.count(TCP_OWNER_UNAVAILABLE));
        equal(1L, snap.count(TCP_OWNER_NBS_SYNTHETIC)); equal(1L, snap.count(TCP_OWNER_NBS_ORDINARY));
        equal(0L, snap.count(TCP_FIRST_SYN)); equal(0L, snap.count(TCP_FLOWS));
        equal(0L, snap.count(TCP_PACKETS)); // evidence cannot affect authorization/forwarding
        check(!VpnTcpOwnerDiagnostics.synthetic(0xc611ffff));
        check(VpnTcpOwnerDiagnostics.synthetic(0xc6120000));
        check(VpnTcpOwnerDiagnostics.synthetic(0xc613ffff));
        check(!VpnTcpOwnerDiagnostics.synthetic(0xc6140000));
        check(!VpnTcpOwnerDiagnostics.synthetic(0x08080808));
        check(snap.toPlainText(true).contains("diagnostic only; still dropped"));
        d.reset();
        for (NetworkDiagnostics.Counter counter : NetworkDiagnostics.Counter.values()) equal(0L, d.snapshot().count(counter));
    }

    private static void classifications() {
        equal(TcpDrop.NO_REGISTRATION, VpnTcpDecision.missingTuple(false));
        equal(TcpDrop.TUPLE_MISMATCH, VpnTcpDecision.missingTuple(true));
        equal(TcpDrop.EXPIRED_REVOKED, VpnTcpDecision.validate(false, false, true, 0, 123));
        equal(TcpDrop.EXPIRED_REVOKED, VpnTcpDecision.validate(false, true, false, 123, 124));
        equal(TcpDrop.SYN_GENERATION, VpnTcpDecision.validate(true, false, false, 0, 123));
        equal(null, VpnTcpDecision.validate(true, false, true, 0, 123));
        equal(null, VpnTcpDecision.validate(true, true, true, 123, 123)); // retransmit
        equal(TcpDrop.SYN_GENERATION, VpnTcpDecision.validate(true, true, true, 123, 124)); // reuse
        equal(null, VpnTcpDecision.validate(true, true, false, 123, 456)); // established ACK/data
        equal(null, VpnTcpDecision.validate(true, true, true, Integer.MIN_VALUE, Integer.MIN_VALUE));
    }

    private static void resetAndSnapshots() {
        NetworkDiagnostics diagnostics = new NetworkDiagnostics();
        diagnostics.vpnActive(true);
        diagnostics.relayActive(true);
        for (NetworkDiagnostics.Counter counter : NetworkDiagnostics.Counter.values()) diagnostics.increment(counter);
        for (TcpDrop reason : TcpDrop.values()) diagnostics.dropTcp(reason);
        diagnostics.failure(FailureStage.TCP_PROTECT);
        NetworkDiagnostics.Snapshot before = diagnostics.snapshot();
        equal(8L, before.count(TCP_DROPPED));
        equal("tcp-protect", before.lastFailureStage);
        check(before.toPlainText(true).contains("SOCKS enabled (Settings): yes"));
        check(before.toPlainText(false).contains("SOCKS enabled (Settings): no"));
        diagnostics.reset();
        NetworkDiagnostics.Snapshot after = diagnostics.snapshot();
        for (NetworkDiagnostics.Counter counter : NetworkDiagnostics.Counter.values()) equal(0L, after.count(counter));
        equal("none", after.lastFailureStage);
        check(after.vpnActive && after.relayActive);
        equal(8L, before.count(TCP_DROPPED)); // reset cannot mutate a captured snapshot
        diagnostics.dropTcp(TcpDrop.TUPLE_MISMATCH);
        equal(1L, diagnostics.snapshot().count(TCP_TUPLE_MISMATCH));
        equal(0L, after.count(TCP_TUPLE_MISMATCH));
    }

    private static void concurrentAccounting() throws Exception {
        NetworkDiagnostics diagnostics = new NetworkDiagnostics();
        List<Thread> workers = new ArrayList<>();
        CountDownLatch start = new CountDownLatch(1);
        for (TcpDrop reason : TcpDrop.values()) {
            Thread worker = new Thread(() -> {
                try { start.await(); }
                catch (InterruptedException failure) { throw new AssertionError(failure); }
                for (int i = 0; i < 10_000; i++) diagnostics.dropTcp(reason);
            });
            workers.add(worker); worker.start();
        }
        start.countDown();
        for (Thread worker : workers) worker.join();
        NetworkDiagnostics.Snapshot all = diagnostics.snapshot();
        equal(70_000L, all.count(TCP_DROPPED));
        for (TcpDrop reason : TcpDrop.values()) equal(10_000L, all.count(reason.counter));

        Thread writer = new Thread(() -> {
            for (int i = 0; i < 20_000; i++) diagnostics.dropTcp(TcpDrop.NO_REGISTRATION);
        });
        writer.start();
        for (int i = 0; i < 1000; i++) {
            diagnostics.reset();
            NetworkDiagnostics.Snapshot snapshot = diagnostics.snapshot();
            long total = 0;
            for (TcpDrop reason : TcpDrop.values()) total += snapshot.count(reason.counter);
            equal(total, snapshot.count(TCP_DROPPED));
        }
        writer.join();
        diagnostics.reset();
        equal(0L, diagnostics.snapshot().count(TCP_DROPPED));
    }

    private static void saturation() throws Exception {
        NetworkDiagnostics diagnostics = new NetworkDiagnostics();
        Field field = NetworkDiagnostics.class.getDeclaredField("counters");
        field.setAccessible(true);
        long[] values = (long[]) field.get(diagnostics);
        values[TCP_DROPPED.ordinal()] = Long.MAX_VALUE;
        values[TCP_NO_REGISTRATION.ordinal()] = Long.MAX_VALUE;
        values[RELAY_FAILED.ordinal()] = Long.MAX_VALUE;
        diagnostics.dropTcp(TcpDrop.NO_REGISTRATION);
        diagnostics.failure(FailureStage.TCP_CONNECT);
        equal(Long.MAX_VALUE, diagnostics.snapshot().count(TCP_DROPPED));
        equal(Long.MAX_VALUE, diagnostics.snapshot().count(TCP_NO_REGISTRATION));
        equal(Long.MAX_VALUE, diagnostics.snapshot().count(RELAY_FAILED));
        equal("tcp-connect", diagnostics.snapshot().lastFailureStage);
    }

    private static void check(boolean value) { if (!value) throw new AssertionError(); }
    private static void equal(Object expected, Object actual) {
        if (!java.util.Objects.equals(expected, actual))
            throw new AssertionError("expected " + expected + ", actual " + actual);
    }
}
