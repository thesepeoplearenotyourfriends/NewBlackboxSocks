package top.niunaijun.blackbox.proxy;

import static top.niunaijun.blackbox.proxy.NetworkDiagnostics.TcpDrop;

/** Pure classifications used at the registry's existing rejection decisions. */
final class VpnTcpDecision {
    private VpnTcpDecision() { }

    static TcpDrop missingTuple(boolean registeredSourcePort) {
        return registeredSourcePort ? TcpDrop.TUPLE_MISMATCH : TcpDrop.NO_REGISTRATION;
    }

    static TcpDrop validate(boolean live, boolean active, boolean syn, int initialSequence, int sequence) {
        if (!live) return TcpDrop.EXPIRED_REVOKED;
        if ((!active && !syn) || (active && syn && initialSequence != sequence)) return TcpDrop.SYN_GENERATION;
        return null;
    }
}
