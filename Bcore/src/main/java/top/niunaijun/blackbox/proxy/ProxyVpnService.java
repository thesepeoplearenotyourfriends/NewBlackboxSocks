package top.niunaijun.blackbox.proxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.nio.charset.StandardCharsets;

public class ProxyVpnService extends VpnService {
    private static final String TAG = "NBSVpn";
    private static final int NOTIFICATION_ID = 1001;
    private static final String CHANNEL_ID = "BlackBoxVPN";
    // Manifest keeps the VPN and Settings in the host's default process. Each
    // service owns its counters; late workers cannot contaminate a new instance.
    private static volatile NetworkDiagnostics currentDiagnostics = new NetworkDiagnostics();
    private NetworkDiagnostics diagnostics;
    private ParcelFileDescriptor mVpnInterface;
    private VpnRelay relay;
    private boolean destroyed;

    @Override public void onCreate() {
        super.onCreate();
        diagnostics = new NetworkDiagnostics();
        currentDiagnostics = diagnostics;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "BlackSocks VPN Service", NotificationManager.IMPORTANCE_LOW);
            channel.setShowBadge(false);
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(channel);
        }
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        try {
            Notification.Builder notification = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                    ? new Notification.Builder(this, CHANNEL_ID) : new Notification.Builder(this);
            Notification built = notification.setContentTitle("BlackSocks VPN Active")
                    .setContentText("Containing sandboxed network traffic")
                    .setSmallIcon(android.R.drawable.ic_dialog_info).setOngoing(true).build();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
                startForeground(NOTIFICATION_ID, built, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            else startForeground(NOTIFICATION_ID, built);
            establishVpn();
        } catch (Exception failure) {
            diagnostics.failure(NetworkDiagnostics.FailureStage.VPN_START);
            Log.e(TAG, "vpn_failure stage=start");
            return START_NOT_STICKY;
        }
        return START_STICKY;
    }

    protected synchronized void establishVpn() {
        if (destroyed || mVpnInterface != null) return;
        NetworkDiagnostics.FailureStage stage = NetworkDiagnostics.FailureStage.VPN_ESTABLISH;
        try {
            Builder builder = new Builder().setSession("BlackSocks authorized SOCKS networking").setMtu(1500);
            builder.addAddress("10.0.0.2", 32).addRoute("0.0.0.0", 0);
            // Capture unsupported IPv6 as well; it must not bypass the positive gate.
            builder.addAddress("fd00:6e62:73::2", 128).addRoute("::", 0);
            builder.addDnsServer("8.8.8.8").addDnsServer("8.8.4.4");
            builder.addAllowedApplication(getPackageName());
            builder.setBlocking(false);
            mVpnInterface = builder.establish();
            if (mVpnInterface == null) {
                diagnostics.failure(NetworkDiagnostics.FailureStage.VPN_ESTABLISH);
                Log.e(TAG, "vpn_failure stage=establish"); return;
            }
            diagnostics.vpnActive(true);
            stage = NetworkDiagnostics.FailureStage.SETUP_DENY_ALL;
            SharedPreferences settings = getSharedPreferences("AppSharedPreferenceDelegate", MODE_PRIVATE);
            int address = numericAddress(settings.getString("mSocksHost", "127.0.0.1"));
            int port;
            try { port = Integer.parseInt(settings.getString("mSocksPort", "1080")); }
            catch (NumberFormatException invalid) { port = 0; }
            // SOCKS is intrinsic; invalid configuration still leaves the relay deny-all.
            boolean configured = address != 0 && port > 0 && port <= 65535
                    && settings.getString("mSocksUser", "").getBytes(StandardCharsets.UTF_8).length <= 255
                    && settings.getString("mSocksPassword", "").getBytes(StandardCharsets.UTF_8).length <= 255;
            relay = new VpnRelay(this, mVpnInterface, getFilesDir(), address, port, configured,
                    settings.getString("mSocksUser", "").getBytes(StandardCharsets.UTF_8),
                    settings.getString("mSocksPassword", "").getBytes(StandardCharsets.UTF_8), diagnostics);
        } catch (Exception failure) {
            // Preserve any established interface on failure: a stopped relay is
            // deny-all containment, never a reason to restore a direct route.
            diagnostics.relayActive(false);
            diagnostics.failure(stage);
            Log.e(TAG, "vpn_failure stage=setup-deny-all");
        }
    }

    private static int numericAddress(String host) {
        if (host == null) return 0;
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) return 0;
        int address = 0;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || (part.length() > 1 && part.charAt(0) == '0')) return 0;
            int value = 0;
            for (int i = 0; i < part.length(); i++) {
                char digit = part.charAt(i);
                if (digit < '0' || digit > '9') return 0;
                value = value * 10 + digit - '0';
            }
            if (value > 255) return 0;
            address = (address << 8) | value;
        }
        return address;
    }

    private synchronized void stopVpn() {
        diagnostics.relayActive(false);
        if (relay != null) { relay.close(); relay = null; }
        if (mVpnInterface != null) {
            try { mVpnInterface.close(); } catch (Exception ignored) { }
            mVpnInterface = null;
        }
        diagnostics.vpnActive(false);
    }
    public static NetworkDiagnostics.Snapshot getDiagnosticsSnapshot() { return currentDiagnostics.snapshot(); }
    public static void resetDiagnostics() { currentDiagnostics.reset(); }
    public synchronized boolean isEstablished() { return mVpnInterface != null; }
    public synchronized ParcelFileDescriptor getVpnInterface() { return mVpnInterface; }
    @Override public synchronized void onDestroy() { destroyed = true; stopVpn(); super.onDestroy(); }
    @Override public void onRevoke() { stopVpn(); super.onRevoke(); }
}
