package top.niunaijun.blackbox.fake.service;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Synthetic CM Messenger lifecycle. No request or callback is registered with host Android. */
final class GuestNetworkCallbacks {
    private static final AtomicInteger NEXT_ID = new AtomicInteger(0x40000000);
    private final GuestConnectivityState state;
    private final Map<NetworkRequest, Registration> registrations = new HashMap<>();
    private HandlerThread thread;
    private Handler handler;

    private final class Registration implements IBinder.DeathRecipient {
        final NetworkRequest request;
        final NetworkCapabilities need;
        final Messenger messenger;
        final PendingIntent pending;
        final IBinder token;
        GuestConnectivityState.View delivered;
        final boolean listen;
        long deadline;

        Registration(NetworkRequest request, NetworkCapabilities need, Messenger messenger,
                     PendingIntent pending, IBinder token, boolean listen) {
            this.request = request;
            this.need = need;
            this.messenger = messenger;
            this.pending = pending;
            this.token = token;
            this.listen = listen;
        }

        @Override public void binderDied() { release(request); }
    }

    GuestNetworkCallbacks(GuestConnectivityState state) { this.state = state; }

    GuestNetworkCallbacks(GuestConnectivityState state, Handler handler) {
        this.state = state;
        this.handler = handler;
    }

    synchronized NetworkRequest register(String name, Object[] args) throws ReflectiveOperationException, RemoteException {
        Messenger messenger = find(args, Messenger.class);
        if (messenger == null) throw new IllegalArgumentException("Network callback requires a Messenger");
        IBinder token = find(args, IBinder.class);
        if (token == null) token = messenger.getBinder();
        NetworkRequest request = add(name, find(args, NetworkCapabilities.class), messenger, null, token);
        // On supported AOSP signatures the timeout immediately follows the Messenger.
        for (int i = 0; i + 1 < args.length; i++) {
            if (args[i] instanceof Messenger && args[i + 1] instanceof Integer) {
                int timeout = (Integer) args[i + 1];
                if (timeout > 0) registrations.get(request).deadline = android.os.SystemClock.uptimeMillis() + timeout;
            }
        }
        return request;
    }

    synchronized Object registerPending(String name, Object[] args, Class<?> returnType) throws ReflectiveOperationException, RemoteException {
        PendingIntent pending = find(args, PendingIntent.class);
        if (pending == null) throw new IllegalArgumentException("Missing network PendingIntent");
        releasePending(args);
        NetworkRequest request = add(name, find(args, NetworkCapabilities.class), null, pending, null);
        return returnType == void.class ? null : request;
    }

    private NetworkRequest add(String name, NetworkCapabilities need, Messenger messenger,
                               PendingIntent pending, IBinder token) throws ReflectiveOperationException, RemoteException {
        NetworkCapabilities copy = need == null ? null : new NetworkCapabilities(need);
        NetworkRequest request = newRequest(copy, name.contains("Listen") || name.equals("listenForNetwork"));
        Registration registration = new Registration(request, copy, messenger, pending, token, name.contains("Listen") || name.equals("listenForNetwork"));
        if (token != null) token.linkToDeath(registration, 0);
        registrations.put(request, registration);
        if (handler == null) {
            thread = new HandlerThread("NBS-guest-connectivity");
            thread.start();
            handler = new Handler(thread.getLooper());
        }
        handler.removeCallbacks(tick);
        handler.post(tick);
        return request;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    static NetworkRequest newRequest(NetworkCapabilities need, boolean listen) throws ReflectiveOperationException {
        NetworkCapabilities nc = need == null ? GuestConnectivityState.emptyCapabilities() : new NetworkCapabilities(need);
        int id = NEXT_ID.getAndIncrement();
        for (Constructor<?> constructor : NetworkRequest.class.getDeclaredConstructors()) {
            Class<?>[] types = constructor.getParameterTypes();
            if (types.length >= 3 && types[0] == NetworkCapabilities.class && types[1] == int.class && types[2] == int.class) {
                Object[] args = new Object[types.length];
                args[0] = nc;
                args[1] = -1 /* TYPE_NONE */;
                args[2] = id;
                for (int i = 3; i < types.length; i++) {
                    if (!types[i].isEnum()) throw new IllegalStateException("Unknown NetworkRequest constructor");
                    args[i] = Enum.valueOf((Class) types[i], listen ? "LISTEN" : need == null ? "TRACK_DEFAULT" : "REQUEST");
                }
                constructor.setAccessible(true);
                return (NetworkRequest) constructor.newInstance(args);
            }
        }
        throw new NoSuchMethodException("NetworkRequest token constructor");
    }

    synchronized void release(Object request) {
        Registration registration = registrations.remove(request);
        if (registration == null) return;
        if (registration.token != null) registration.token.unlinkToDeath(registration, 0);
        // API 21-26 CM removes its map entry/refcount only upon this service acknowledgement.
        if (Build.VERSION.SDK_INT < 27 && registration.messenger != null) {
            try { send(registration, "CALLBACK_RELEASED", null); } catch (RemoteException ignored) { }
        }
        if (registrations.isEmpty() && handler != null) {
            handler.removeCallbacksAndMessages(null);
            if (thread != null) {
                thread.quitSafely();
                handler = null;
                thread = null;
            }
        }
    }

    synchronized void releasePending(Object[] args) {
        PendingIntent pending = find(args, PendingIntent.class);
        for (Registration registration : new ArrayList<>(registrations.values())) {
            if (pending != null && pending.equals(registration.pending)) release(registration.request);
        }
    }

    synchronized int size() { return registrations.size(); }

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            synchronized (GuestNetworkCallbacks.this) {
                if (handler == null) return;
                GuestConnectivityState.View view = state.snapshot();
                for (Registration registration : new ArrayList<>(registrations.values())) {
                    try {
                        deliver(registration, view);
                    } catch (RemoteException | PendingIntent.CanceledException e) {
                        release(registration.request);
                    }
                }
                if (handler != null) handler.postDelayed(this, 2000);
            }
        }
    };

    private void deliver(Registration registration, GuestConnectivityState.View view) throws RemoteException, PendingIntent.CanceledException {
        if (view == null || !matches(registration.need, view.capabilities)) {
            if (registration.delivered != null && registration.messenger != null) {
                send(registration, "CALLBACK_LOST", registration.delivered);
                registration.delivered = null;
            }
            if (registration.deadline != 0 && android.os.SystemClock.uptimeMillis() >= registration.deadline) {
                send(registration, "CALLBACK_UNAVAIL", null);
                release(registration.request);
            }
            return;
        }
        registration.deadline = 0;
        if (registration.pending != null) {
            if (registration.delivered == null || !registration.delivered.network.equals(view.network)) {
                Intent intent = new Intent();
                intent.putExtra("android.net.extra.NETWORK", view.network);
                intent.putExtra("android.net.extra.NETWORK_REQUEST", registration.request);
                registration.pending.send(top.niunaijun.blackbox.BlackBoxCore.getContext(), 0, intent);
                registration.delivered = view;
                if (!registration.listen) release(registration.request);
            }
            return;
        }
        GuestConnectivityState.View old = registration.delivered;
        if (old == null || !old.network.equals(view.network)) {
            send(registration, "CALLBACK_AVAILABLE", view);
            if (Build.VERSION.SDK_INT < 28) {
                send(registration, "CALLBACK_CAP_CHANGED", view);
                send(registration, "CALLBACK_IP_CHANGED", view);
            }
            // This is a virtual identity replacement, never a raw host lost/unavailable event.
            if (old != null) send(registration, "CALLBACK_LOST", old);
        } else {
            if (!old.capabilities.equals(view.capabilities)) send(registration, "CALLBACK_CAP_CHANGED", view);
            if (!old.linkProperties.equals(view.linkProperties)) send(registration, "CALLBACK_IP_CHANGED", view);
        }
        registration.delivered = view;
    }

    static boolean matches(NetworkCapabilities need, NetworkCapabilities available) {
        if (need == null) return true;
        try {
            Method method = NetworkCapabilities.class.getDeclaredMethod("satisfiedByNetworkCapabilities", NetworkCapabilities.class);
            method.setAccessible(true);
            return (Boolean) method.invoke(need, available);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Cannot evaluate guest network request", e);
        }
    }

    static Message event(NetworkRequest request, String name, GuestConnectivityState.View view) {
        Message message = Message.obtain();
        try {
            java.lang.reflect.Field field = ConnectivityManager.class.getDeclaredField(name);
            field.setAccessible(true);
            message.what = field.getInt(null);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Unsupported CM callback protocol: " + name, e);
        }
        Bundle data = new Bundle();
        data.putParcelable("NetworkRequest", request);
        if (view != null) {
            data.putParcelable("Network", view.network);
            data.putParcelable("NetworkCapabilities", new NetworkCapabilities(view.capabilities));
            data.putParcelable("LinkProperties", GuestConnectivityState.copyLinkProperties(view.linkProperties));
        }
        message.setData(data);
        message.arg1 = 0; // Usable, unblocked virtual network.
        return message;
    }

    private static void send(Registration registration, String name, GuestConnectivityState.View view) throws RemoteException {
        registration.messenger.send(event(registration.request, name, view));
    }

    private static <T> T find(Object[] args, Class<T> type) {
        if (args != null) for (Object arg : args) if (type.isInstance(arg)) return type.cast(arg);
        return null;
    }
}
