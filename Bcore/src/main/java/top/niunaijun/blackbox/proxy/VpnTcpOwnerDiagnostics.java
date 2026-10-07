package top.niunaijun.blackbox.proxy;

import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.Counter.*;
import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.TcpDrop;

/** Diagnostic only: never returns a grant or retains a packet tuple. */
final class VpnTcpOwnerDiagnostics {
    interface Lookup {
        int ownerUid(int source, int sourcePort, int destination, int destinationPort) throws Exception;
    }

    private final Lookup lookup;
    private final int processUid;
    private final NetworkDiagnostics diagnostics;

    VpnTcpOwnerDiagnostics(Lookup lookup, int processUid, NetworkDiagnostics diagnostics) {
        this.lookup = lookup;
        this.processUid = processUid;
        this.diagnostics = diagnostics;
    }

    void observe(TcpDrop rejection, boolean initialSyn, int source, int sourcePort,
                 int destination, int destinationPort) {
        if (rejection != TcpDrop.NO_REGISTRATION || !initialSyn) return;
        int owner;
        try {
            if (lookup == null) throw new UnsupportedOperationException();
            owner = lookup.ownerUid(source, sourcePort, destination, destinationPort);
        } catch (Exception | LinkageError failure) {
            diagnostics.increment(TCP_OWNER_UNAVAILABLE);
            return;
        }
        diagnostics.recordTcpOwner(owner, processUid, synthetic(destination));
    }

    static boolean synthetic(int address) {
        return (address & 0xfffe0000) == 0xc6120000; // 198.18.0.0/15
    }
}
