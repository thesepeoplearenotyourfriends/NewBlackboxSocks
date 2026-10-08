package top.niunaijun.blackbox.fake.service;

import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.Shadows;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = {21, 22, 23, 25, 26, 27, 28, 35}, manifest = Config.NONE, shadows = GuestConnectivityTest.RealNetworkInfo.class)
public class GuestConnectivityTest {
    // The stock shadow supports its factory, but not this framework's constructor/hidden setters.
    @org.robolectric.annotation.Implements(NetworkInfo.class)
    public static class RealNetworkInfo extends org.robolectric.shadows.ShadowNetworkInfo {
        @org.robolectric.annotation.Implementation
        protected void __constructor__(int type, int subtype, String name, String subname) {
            setConnectionType(type);
            setSubType(subtype);
        }
        @org.robolectric.annotation.Implementation
        protected void setDetailedState(NetworkInfo.DetailedState state, String reason, String extra) {
            super.setDetailedState(state);
            setConnectionStatus(state == NetworkInfo.DetailedState.CONNECTED
                    ? NetworkInfo.State.CONNECTED : NetworkInfo.State.DISCONNECTED);
        }
        @org.robolectric.annotation.Implementation
        protected void setIsAvailable(boolean available) { setAvailableStatus(available); }
    }

    static class Host implements GuestConnectivityState.Source {
        Network network;
        Network active;
        NetworkCapabilities nc;
        LinkProperties lp = new LinkProperties();
        Host() throws Exception {
            network = Network.class.getDeclaredConstructor(int.class).newInstance(123);
            active = network;
            nc = GuestConnectivityTest.capabilities(new NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build());
        }
        @Override public Network activeNetwork() { return active; }
        @Override public Network[] allNetworks() { return network == null ? new Network[0] : new Network[]{network}; }
        @Override public NetworkCapabilities capabilities(Network n) { return nc; }
        @Override public LinkProperties linkProperties(Network n) { return lp; }
    }

    private static NetworkCapabilities capabilities(NetworkRequest request) throws Exception {
        return (NetworkCapabilities) NetworkRequest.class.getDeclaredField("networkCapabilities").get(request);
    }

    private static Object query(GuestConnectivityState.View view, String name, Object... args) {
        return IConnectivityManagerProxy.query(view, name, args);
    }

    @Test public void synchronousViewIsConnectedValidatedAndKeepsRealIdentity() throws Exception {
        Host host = new Host();
        GuestConnectivityState.View view = new GuestConnectivityState(host).snapshot();
        assertSame(host.network, query(view, "getActiveNetwork"));
        assertEquals(host.network, ((Network[]) query(view, "getAllNetworks"))[0]);
        NetworkInfo info = (NetworkInfo) query(view, "getActiveNetworkInfo");
        assertTrue(info.isConnected());
        assertTrue(info.isAvailable());
        assertEquals(ConnectivityManager.TYPE_WIFI, info.getType());
        assertNull(query(view, "getNetworkInfo", ConnectivityManager.TYPE_MOBILE));
        assertTrue(((NetworkInfo) query(view, "getNetworkInfoForNetwork", host.network)).isConnected());
        assertTrue(((NetworkInfo) query(view, "getProvisioningOrActiveNetworkInfo")).isConnected());
        assertNotNull(query(view, "getLinkPropertiesForType", ConnectivityManager.TYPE_WIFI));
        assertNull(query(view, "getLinkPropertiesForType", ConnectivityManager.TYPE_MOBILE));
        assertEquals(view.capabilities, ((NetworkCapabilities[]) query(view, "getDefaultNetworkCapabilitiesForUser", 0))[0]);
        assertEquals(1, ((NetworkInfo[]) query(view, "getAllNetworkInfo")).length);
        assertEquals(Boolean.TRUE, query(view, "isNetworkValidated", host.network));
        NetworkCapabilities caps = (NetworkCapabilities) query(view, "getNetworkCapabilities", host.network);
        for (int c : new int[]{NetworkCapabilities.NET_CAPABILITY_INTERNET,
                NetworkCapabilities.NET_CAPABILITY_VALIDATED, NetworkCapabilities.NET_CAPABILITY_TRUSTED,
                NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED}) {
            if (c != NetworkCapabilities.NET_CAPABILITY_VALIDATED || Build.VERSION.SDK_INT >= 22) assertTrue(caps.hasCapability(c));
        }
        if (Build.VERSION.SDK_INT >= 28) assertTrue(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED));
        assertTrue(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI));
        assertFalse(caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
        assertFalse(host.nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED));
        assertEquals(!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED), query(view, "isActiveNetworkMetered"));
        Network other = Network.class.getDeclaredConstructor(int.class).newInstance(999);
        assertNull(query(view, "getNetworkCapabilities", other));
        assertEquals(Boolean.FALSE, query(view, "isNetworkValidated", other));
    }

    @Test public void dnsIsRemovedFromCopiesWithoutMutatingHost() throws Exception {
        Host host = new Host();
        host.lp.setDnsServers(Collections.singletonList(java.net.InetAddress.getByAddress(new byte[]{8,8,8,8})));
        if (Build.VERSION.SDK_INT >= 28) {
            LinkProperties.class.getDeclaredMethod("setUsePrivateDns", boolean.class).invoke(host.lp, true);
            LinkProperties.class.getDeclaredMethod("setPrivateDnsServerName", String.class).invoke(host.lp, "dns.host.test");
        }
        if (Build.VERSION.SDK_INT >= 30) {
            LinkProperties.class.getDeclaredMethod("setCaptivePortalApiUrl", android.net.Uri.class)
                    .invoke(host.lp, android.net.Uri.parse("https://portal.host.test/"));
            Class<?> builderClass = Class.forName("android.net.CaptivePortalData$Builder");
            Object builder = builderClass.getDeclaredConstructor().newInstance();
            builderClass.getDeclaredMethod("setCaptive", boolean.class).invoke(builder, true);
            LinkProperties.class.getDeclaredMethod("setCaptivePortalData", Class.forName("android.net.CaptivePortalData"))
                    .invoke(host.lp, builderClass.getDeclaredMethod("build").invoke(builder));
        }
        GuestConnectivityState.View view = new GuestConnectivityState(host).snapshot();
        LinkProperties lp = (LinkProperties) query(view, "getLinkProperties", host.network);
        assertTrue(lp.getDnsServers().isEmpty());
        assertEquals(1, host.lp.getDnsServers().size());
        if (Build.VERSION.SDK_INT >= 28) {
            assertFalse(lp.isPrivateDnsActive());
            assertNull(lp.getPrivateDnsServerName());
            assertTrue(host.lp.isPrivateDnsActive());
        }
        if (Build.VERSION.SDK_INT >= 30) {
            assertNull(LinkProperties.class.getDeclaredMethod("getCaptivePortalApiUrl").invoke(lp));
            assertNull(LinkProperties.class.getDeclaredMethod("getCaptivePortalData").invoke(lp));
            assertNotNull(LinkProperties.class.getDeclaredMethod("getCaptivePortalData").invoke(host.lp));
        }
        lp.setDnsServers(host.lp.getDnsServers());
        assertTrue(view.linkProperties.getDnsServers().isEmpty());
    }

    @Test public void defaultGapsKeepIdentityAndNoIdentityIsInvented() throws Exception {
        Host host = new Host();
        GuestConnectivityState state = new GuestConnectivityState(host);
        Network identity = state.snapshot().network;
        host.active = null;
        host.network = null;
        host.nc = null;
        assertSame(identity, state.snapshot().network);
        assertNull(new GuestConnectivityState(host).snapshot());
        assertEquals(0, ((Network[]) query(null, "getAllNetworks")).length);
    }

    @Test public void callbacksUseSameViewAndUnregisterStopsDelivery() throws Exception {
        Host host = new Host();
        GuestConnectivityState state = new GuestConnectivityState(host);
        List<Message> messages = new ArrayList<>();
        Handler recipient = new Handler(Looper.getMainLooper()) {
            @Override public void handleMessage(Message message) { messages.add(Message.obtain(message)); }
        };
        GuestNetworkCallbacks callbacks = new GuestNetworkCallbacks(state, new Handler(Looper.getMainLooper()));
        NetworkRequest request = callbacks.register("requestNetwork", new Object[]{null, new Messenger(recipient), 0, new Binder(), -1});
        Shadows.shadowOf(Looper.getMainLooper()).idle();
        assertFalse(messages.isEmpty());
        Message available = messages.get(0);
        assertEquals(host.network, available.getData().getParcelable("Network"));
        assertEquals(request, available.getData().getParcelable("NetworkRequest"));
        NetworkCapabilities caps = available.getData().getParcelable("NetworkCapabilities");
        assertEquals(state.snapshot().capabilities, caps);
        if (Build.VERSION.SDK_INT >= 22) assertTrue(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED));
        assertFalse(host.nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED));
        callbacks.release(request);
        callbacks.release(request); // idempotent
        assertEquals(0, callbacks.size());
        Shadows.shadowOf(Looper.getMainLooper()).idle();
        int afterRelease = messages.size();
        Shadows.shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(10));
        assertEquals(afterRelease, messages.size());
        if (Build.VERSION.SDK_INT < 27) {
            assertEquals(ConnectivityManager.class.getDeclaredField("CALLBACK_RELEASED").getInt(null), messages.get(messages.size()-1).what);
        }
    }

    @Test public void callbackDeathUnlinksTokenAndCleansRegistration() throws Exception {
        class Token extends Binder {
            android.os.IBinder.DeathRecipient recipient;
            int unlinks;
            @Override public void linkToDeath(android.os.IBinder.DeathRecipient recipient, int flags) { this.recipient = recipient; }
            @Override public boolean unlinkToDeath(android.os.IBinder.DeathRecipient recipient, int flags) {
                assertSame(this.recipient, recipient);
                unlinks++;
                return true;
            }
        }
        Token token = new Token();
        GuestNetworkCallbacks callbacks = new GuestNetworkCallbacks(new GuestConnectivityState(new Host()), new Handler(Looper.getMainLooper()));
        callbacks.register("listenForNetwork", new Object[]{null, new Messenger(new Handler(Looper.getMainLooper())), token});
        assertEquals(1, callbacks.size());
        token.recipient.binderDied();
        assertEquals(0, callbacks.size());
        assertEquals(1, token.unlinks);
        Shadows.shadowOf(Looper.getMainLooper()).idle();
    }

    @Test public void hostOfflineDoesNotDeliverLostButIdentityReplacementDoes() throws Exception {
        Host host = new Host();
        GuestConnectivityState state = new GuestConnectivityState(host);
        List<Message> messages = new ArrayList<>();
        Handler recipient = new Handler(Looper.getMainLooper()) {
            @Override public void handleMessage(Message message) { messages.add(Message.obtain(message)); }
        };
        GuestNetworkCallbacks callbacks = new GuestNetworkCallbacks(state, new Handler(Looper.getMainLooper()));
        NetworkRequest request = callbacks.register("requestNetwork", new Object[]{null, new Messenger(recipient), 0, new Binder(), -1});
        Shadows.shadowOf(Looper.getMainLooper()).idle();
        int initial = messages.size();
        host.active = null;
        host.network = null;
        host.nc = null;
        Shadows.shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(2));
        assertEquals(initial, messages.size());
        host.network = Network.class.getDeclaredConstructor(int.class).newInstance(456);
        host.active = host.network;
        host.nc = capabilities(new NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build());
        Shadows.shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(2));
        assertEquals(host.network, messages.get(initial).getData().getParcelable("Network"));
        assertEquals(ConnectivityManager.class.getDeclaredField("CALLBACK_LOST").getInt(null), messages.get(messages.size()-1).what);
        callbacks.release(request);
        Shadows.shadowOf(Looper.getMainLooper()).idle();
    }

    @Test public void unsatisfiedRequestTimeoutIsLocalAndReleasesRegistration() throws Exception {
        Host host = new Host();
        List<Message> messages = new ArrayList<>();
        Handler recipient = new Handler(Looper.getMainLooper()) {
            @Override public void handleMessage(Message message) { messages.add(Message.obtain(message)); }
        };
        GuestNetworkCallbacks callbacks = new GuestNetworkCallbacks(new GuestConnectivityState(host), new Handler(Looper.getMainLooper()));
        NetworkCapabilities need = capabilities(new NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR).build());
        callbacks.register("requestNetwork", new Object[]{need, new Messenger(recipient), 1000, new Binder(), -1});
        Shadows.shadowOf(Looper.getMainLooper()).idleFor(java.time.Duration.ofSeconds(2));
        assertEquals(0, callbacks.size());
        assertEquals(ConnectivityManager.class.getDeclaredField("CALLBACK_UNAVAIL").getInt(null), messages.get(0).what);
        assertFalse(host.nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED));
    }

    @Test public void transportSpecificRequestsDoNotInventAnotherTransport() throws Exception {
        Host host = new Host();
        NetworkCapabilities need = capabilities(new NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR).build());
        assertFalse(GuestNetworkCallbacks.matches(need, new GuestConnectivityState(host).snapshot().capabilities));
    }
}
