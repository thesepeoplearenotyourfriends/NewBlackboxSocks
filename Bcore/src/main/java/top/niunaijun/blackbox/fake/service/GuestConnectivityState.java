package top.niunaijun.blackbox.fake.service;

import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.os.Build;

import java.lang.reflect.Method;
import java.util.Collections;

/** Process-local facade. Never writes to ConnectivityService or creates a routable netId. */
final class GuestConnectivityState {
    interface Source {
        Network activeNetwork();
        Network[] allNetworks();
        NetworkCapabilities capabilities(Network network);
        LinkProperties linkProperties(Network network);
    }

    static final class View {
        final Network network;
        final NetworkCapabilities capabilities;
        final LinkProperties linkProperties;

        View(Network network, NetworkCapabilities capabilities, LinkProperties linkProperties) {
            this.network = network;
            this.capabilities = capabilities;
            this.linkProperties = linkProperties;
        }

        NetworkInfo networkInfo() {
            int type = ConnectivityManager.TYPE_DUMMY;
            String name = "UNKNOWN";
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                type = ConnectivityManager.TYPE_WIFI;
                name = "WIFI";
            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                type = ConnectivityManager.TYPE_MOBILE;
                name = "MOBILE";
            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                type = ConnectivityManager.TYPE_VPN;
                name = "VPN";
            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                type = ConnectivityManager.TYPE_ETHERNET;
                name = "ETHERNET";
            } else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) {
                type = ConnectivityManager.TYPE_BLUETOOTH;
                name = "BLUETOOTH";
            }
            // These APIs exist on API 21 but were hidden from the public SDK until API 30.
            try {
                java.lang.reflect.Constructor<NetworkInfo> constructor = NetworkInfo.class.getDeclaredConstructor(
                        int.class, int.class, String.class, String.class);
                constructor.setAccessible(true);
                NetworkInfo info = constructor.newInstance(type, 0, name, "");
                NetworkInfo.class.getMethod("setDetailedState", NetworkInfo.DetailedState.class, String.class, String.class)
                        .invoke(info, NetworkInfo.DetailedState.CONNECTED, null, null);
                NetworkInfo.class.getMethod("setIsAvailable", boolean.class).invoke(info, true);
                return info;
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("Cannot construct connected guest network", e);
            }
        }
    }

    private final Source source;
    private View last;

    GuestConnectivityState(Source source) {
        this.source = source;
    }

    synchronized View snapshot() {
        Network network = source.activeNetwork();
        if (network == null) {
            Network[] networks = source.allNetworks();
            // Retain an existing real identity during host validation/default-network gaps.
            if (last != null) network = last.network;
            else if (networks != null && networks.length != 0) network = networks[0];
        }
        if (network == null) return null; // No invented Network(1) when no real identity exists.
        NetworkCapabilities nc = source.capabilities(network);
        LinkProperties lp = source.linkProperties(network);
        if (last != null && network.equals(last.network)) {
            if (nc == null) nc = last.capabilities;
            if (lp == null) lp = last.linkProperties;
        }
        last = new View(network, virtualCapabilities(nc), virtualLinkProperties(lp));
        return last;
    }

    static NetworkCapabilities virtualCapabilities(NetworkCapabilities real) {
        NetworkCapabilities nc = real == null ? emptyCapabilities() : new NetworkCapabilities(real);
        capability(nc, "addCapability", NetworkCapabilities.NET_CAPABILITY_INTERNET);
        if (Build.VERSION.SDK_INT >= 22) capability(nc, "addCapability", 16 /* VALIDATED existed hidden on API 22 */);
        capability(nc, "addCapability", NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED);
        capability(nc, "addCapability", NetworkCapabilities.NET_CAPABILITY_TRUSTED);
        if (Build.VERSION.SDK_INT >= 23) capability(nc, "removeCapability", NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL);
        if (Build.VERSION.SDK_INT >= 28) {
            capability(nc, "addCapability", NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED);
            capability(nc, "addCapability", NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED);
        }
        if (Build.VERSION.SDK_INT >= 29) capability(nc, "removeCapability", 24 /* NET_CAPABILITY_PARTIAL_CONNECTIVITY, hidden on API 29 */);
        // Preserve transports, metering and VPN status; NOT_VPN would contradict a VPN transport.
        return nc;
    }

    static LinkProperties virtualLinkProperties(LinkProperties real) {
        LinkProperties lp = real == null ? emptyLinkProperties() : copyLinkProperties(real);
        call(lp, "setDnsServers", java.util.Collection.class, Collections.emptyList());
        call(lp, "setDomains", String.class, null);
        if (Build.VERSION.SDK_INT >= 28) {
            set(lp, "setUsePrivateDns", boolean.class, false);
            set(lp, "setPrivateDnsServerName", String.class, null);
            set(lp, "setValidatedPrivateDnsServers", java.util.Collection.class, Collections.emptyList());
        }
        if (Build.VERSION.SDK_INT >= 30) {
            call(lp, "setCaptivePortalApiUrl", android.net.Uri.class, null);
            try {
                call(lp, "setCaptivePortalData", Class.forName("android.net.CaptivePortalData"), null);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("Missing platform captive portal data", e);
            }
        }
        // Stacked links (e.g. CLAT) must not leak ordinary DNS either.
        @SuppressWarnings("unchecked")
        java.util.List<LinkProperties> stackedLinks = (java.util.List<LinkProperties>) call(lp, "getStackedLinks", null, null);
        for (LinkProperties stacked : stackedLinks) {
            call(lp, "removeStackedLink", String.class, stacked.getInterfaceName());
            call(lp, "addStackedLink", LinkProperties.class, virtualLinkProperties(stacked));
        }
        return lp;
    }

    // Framework constructors below predate their public-SDK exposure (API 29/30).
    static NetworkCapabilities emptyCapabilities() {
        return construct(NetworkCapabilities.class);
    }

    private static LinkProperties emptyLinkProperties() {
        return construct(LinkProperties.class);
    }

    private static <T> T construct(Class<T> type) {
        try {
            java.lang.reflect.Constructor<T> constructor = type.getDeclaredConstructor();
            constructor.setAccessible(true);
            return constructor.newInstance();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot construct " + type.getSimpleName(), e);
        }
    }

    static LinkProperties copyLinkProperties(LinkProperties real) {
        android.os.Parcel parcel = android.os.Parcel.obtain();
        try {
            real.writeToParcel(parcel, 0);
            parcel.setDataPosition(0);
            return LinkProperties.CREATOR.createFromParcel(parcel);
        } finally { parcel.recycle(); }
    }

    private static void capability(NetworkCapabilities nc, String name, int capability) {
        call(nc, name, int.class, capability);
    }

    private static Object call(Object object, String name, Class<?> type, Object value) {
        try {
            Method method = type == null ? object.getClass().getDeclaredMethod(name)
                    : object.getClass().getDeclaredMethod(name, type);
            method.setAccessible(true);
            return type == null ? method.invoke(object) : method.invoke(object, value);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot virtualize " + name, e);
        }
    }

    private static void set(LinkProperties lp, String name, Class<?> type, Object value) {
        try {
            Method setter = LinkProperties.class.getDeclaredMethod(name, type);
            setter.setAccessible(true);
            setter.invoke(lp, value);
        } catch (ReflectiveOperationException e) {
            // Failing closed is preferable to exposing the host's private-DNS configuration.
            throw new IllegalStateException("Cannot sanitize " + name, e);
        }
    }
}
