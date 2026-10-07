package top.niunaijun.blackbox.proxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.os.Build;
import android.system.OsConstants;

import java.net.InetAddress;
import java.net.InetSocketAddress;

/** Uses the host framework service and the exact, unmodified outgoing VPN tuple. */
final class AndroidTcpOwnerLookup implements VpnTcpOwnerDiagnostics.Lookup {
    private final Context context;

    AndroidTcpOwnerLookup(Context context) { this.context = context; }

    @Override public int ownerUid(int source, int sourcePort, int destination, int destinationPort)
            throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) throw new UnsupportedOperationException();
        ConnectivityManager manager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) throw new UnsupportedOperationException();
        return manager.getConnectionOwnerUid(OsConstants.IPPROTO_TCP,
                endpoint(source, sourcePort), endpoint(destination, destinationPort));
    }

    private static InetSocketAddress endpoint(int address, int port) throws Exception {
        return new InetSocketAddress(InetAddress.getByAddress(new byte[] {
                (byte) (address >>> 24), (byte) (address >>> 16),
                (byte) (address >>> 8), (byte) address }), port);
    }
}
