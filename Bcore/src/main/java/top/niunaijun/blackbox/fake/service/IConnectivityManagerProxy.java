package top.niunaijun.blackbox.fake.service;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.LinkProperties;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collections;

import black.android.net.BRIConnectivityManagerStub;
import black.android.os.BRServiceManager;
import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.fake.hook.BinderInvocationStub;
import top.niunaijun.blackbox.fake.hook.ScanClass;
import top.niunaijun.blackbox.utils.Slog;

/** ConnectivityManager's Binder facade, installed only in a guest process. */
@ScanClass(VpnCommonProxy.class)
public class IConnectivityManagerProxy extends BinderInvocationStub {
    private final GuestConnectivityState state = new GuestConnectivityState(new GuestConnectivityState.Source() {
        @Override public Network activeNetwork() { return (Network) read("getActiveNetwork"); }
        @Override public Network[] allNetworks() { return (Network[]) read("getAllNetworks"); }
        @Override public NetworkCapabilities capabilities(Network n) {
            return (NetworkCapabilities) read("getNetworkCapabilities", n);
        }
        @Override public LinkProperties linkProperties(Network n) {
            return (LinkProperties) read("getLinkProperties", n);
        }
    });
    private GuestNetworkCallbacks callbacks;

    public IConnectivityManagerProxy() {
        super(BRServiceManager.get().getService(Context.CONNECTIVITY_SERVICE));
    }

    @Override protected Object getWho() {
        return BRIConnectivityManagerStub.get().asInterface(BRServiceManager.get().getService(Context.CONNECTIVITY_SERVICE));
    }

    @Override public void injectHook() {
        if (BlackBoxCore.get().isBlackProcess()) super.injectHook();
    }

    @Override protected void inject(Object base, Object proxy) {
        replaceSystemService(Context.CONNECTIVITY_SERVICE);
        // Context may already have cached a ConnectivityManager before the Binder cache replacement.
        ConnectivityManager cm = (ConnectivityManager) BlackBoxCore.getContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        try {
            Field service = ConnectivityManager.class.getDeclaredField("mService");
            service.setAccessible(true);
            service.set(cm, proxy);
            try {
                Field instance = ConnectivityManager.class.getDeclaredField("sInstance");
                instance.setAccessible(true);
                Object cached = instance.get(null);
                if (cached != null && cached != cm) service.set(cached, proxy);
            } catch (NoSuchFieldException ignored) {
                // API 21 has no process-wide ConnectivityManager singleton.
            }
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot replace cached guest ConnectivityManager", e);
        }
        callbacks = new GuestNetworkCallbacks(state);
    }

    @Override public boolean isBadEnv() { return false; }

    /** Read the original Binder directly; never recurse through the virtual facade. */
    private Object read(String name, Object... prefix) {
        for (Method method : getBase().getClass().getMethods()) {
            if (!method.getName().equals(name)) continue;
            Class<?>[] types = method.getParameterTypes();
            if (types.length < prefix.length) continue;
            Object[] args = new Object[types.length];
            boolean compatible = true;
            for (int i = 0; i < prefix.length; i++) {
                if (!types[i].isInstance(prefix[i])) { compatible = false; break; }
                args[i] = prefix[i];
            }
            if (!compatible) continue;
            boolean packageSet = false;
            for (int i = prefix.length; i < types.length; i++) {
                if (types[i] == String.class) {
                    // AOSP's first String is callingPackage; later Strings are attribution tags.
                    args[i] = packageSet ? null : BlackBoxCore.getHostPkg();
                    packageSet = true;
                }
                else if (types[i] == int.class) args[i] = android.os.Process.myUid();
                else if (types[i] == boolean.class) args[i] = false;
            }
            try {
                method.setAccessible(true);
                return method.invoke(getBase(), args);
            } catch (ReflectiveOperationException e) {
                Slog.w("GuestConnectivity", "Identity read failed: " + name + ": " + e.getClass().getSimpleName());
            }
        }
        return null;
    }

    @Override public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (!BlackBoxCore.get().isBlackProcess()) return super.invoke(proxy, method, args);
        String name = method.getName();
        switch (name) {
            // These are the actual IConnectivityManager entry points used by public callback APIs.
            case "requestNetwork":
            case "listenForNetwork":
                return callbacks.register(name, args);
            case "releaseNetworkRequest":
                callbacks.release(args[0]);
                return null;
            case "pendingRequestForNetwork":
            case "pendingListenForNetwork":
                return callbacks.registerPending(name, args, method.getReturnType());
            case "releasePendingNetworkRequest":
                callbacks.releasePending(args);
                return null;
            // A virtual observation must never feed validation results back into host Android.
            case "reportNetworkConnectivity":
            case "reportInetCondition":
            case "reportBadNetwork":
            case "setAcceptUnvalidated":
            case "setAcceptPartialConnectivity":
            case "setAvoidUnvalidated":
                return null;
            case "isPrivateDnsActive": return false;
            case "getPrivateDnsServerName": return null;
            case "getDnsServers": return Collections.emptyList();
            default: break;
        }
        switch (name) {
            case "getActiveNetwork":
            case "getActiveNetworkForUid":
            case "getNetworkForType":
            case "getAllNetworks":
            case "getActiveNetworkInfo":
            case "getProvisioningOrActiveNetworkInfo":
            case "getActiveNetworkInfoForUid":
            case "getNetworkInfo":
            case "getNetworkInfoForNetwork":
            case "getNetworkInfoForUid":
            case "getAllNetworkInfo":
            case "getDefaultNetworkCapabilitiesForUser":
            case "getNetworkCapabilities":
            case "getLinkPropertiesForType":
            case "getLinkProperties":
            case "getActiveLinkProperties":
            case "isNetworkValidated":
            case "isActiveNetworkMetered":
            case "getCaptivePortalServerUrl":
                return query(state.snapshot(), name, args);
            default: return super.invoke(proxy, method, args);
        }
    }

    static Object query(GuestConnectivityState.View view, String name, Object[] args) {
        if (name.equals("getLinkPropertiesForType")) name = "getLinkProperties";
        boolean matches = view != null;
        if (args != null && view != null) {
            for (Object arg : args) if (arg instanceof Network && !view.network.equals(arg)) matches = false;
            // A legacy type query must not claim two simultaneous transports.
            if ((name.equals("getNetworkInfo") || name.equals("getLinkProperties") || name.equals("getNetworkForType"))
                    && args.length > 0 && args[0] instanceof Integer) {
                matches = ((Integer) args[0]) == view.networkInfo().getType();
            }
        }
        switch (name) {
            case "getAllNetworks": return view == null ? new Network[0] : new Network[]{view.network};
            case "getAllNetworkInfo": return view == null ? new NetworkInfo[0] : new NetworkInfo[]{view.networkInfo()};
            case "getDefaultNetworkCapabilitiesForUser": return view == null ? new NetworkCapabilities[0]
                    : new NetworkCapabilities[]{new NetworkCapabilities(view.capabilities)};
            case "getNetworkCapabilities": return matches ? new NetworkCapabilities(view.capabilities) : null;
            case "getLinkPropertiesForType":
            case "getLinkProperties":
            case "getActiveLinkProperties": return matches ? GuestConnectivityState.copyLinkProperties(view.linkProperties) : null;
            case "isNetworkValidated": return matches;
            case "isActiveNetworkMetered": return view != null && !view.capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
            case "getCaptivePortalServerUrl": return null;
            case "getActiveNetworkInfo":
            case "getProvisioningOrActiveNetworkInfo":
            case "getActiveNetworkInfoForUid":
            case "getNetworkInfo":
            case "getNetworkInfoForNetwork":
            case "getNetworkInfoForUid": return matches ? view.networkInfo() : null;
            default: return matches ? view.network : null;
        }
    }
}
