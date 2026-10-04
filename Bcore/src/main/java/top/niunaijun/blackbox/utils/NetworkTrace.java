package top.niunaijun.blackbox.utils;

import android.os.Process;
import android.os.SystemClock;

import java.io.File;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.atomic.AtomicLong;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.app.BActivityThread;

/** A single, machine-greppable event format for observed guest network boundaries. */
public final class NetworkTrace {
    public static final String TAG = "BBNET";
    private static final AtomicLong NEXT_ID = new AtomicLong();
    private static volatile String sProcessName;

    private NetworkTrace() { }

    public static long enter(String layer, String api, String details) {
        long id = nextId();
        emit(id, layer, api, "ENTER", details, null);
        return id;
    }

    public static void exit(long id, String layer, String api, String details) {
        emit(id, layer, api, "EXIT", details, null);
    }

    public static void fail(long id, String layer, String api, String details, Throwable error) {
        emit(id, layer, api, "FAIL", details, error);
    }

    public static void event(String layer, String api, String state, String details) {
        emit(nextId(), layer, api, state, details, null);
    }

    private static long nextId() {
        for (;;) {
            long previous = NEXT_ID.get();
            long candidate = Math.max(previous + 1, SystemClock.elapsedRealtimeNanos());
            if (NEXT_ID.compareAndSet(previous, candidate)) return candidate;
        }
    }

    public static String describe(Object value) {
        if (value == null) return "null";
        if (value instanceof InetSocketAddress) {
            InetSocketAddress address = (InetSocketAddress) value;
            InetAddress inet = address.getAddress();
            return "host=" + address.getHostString() + " ip=" +
                    (inet == null ? "unresolved" : inet.getHostAddress()) + " port=" + address.getPort();
        }
        if (value instanceof InetAddress) {
            InetAddress address = (InetAddress) value;
            // getHostName() may perform a reverse lookup; observability must not create traffic.
            return "ip=" + address.getHostAddress();
        }
        if (value instanceof SocketAddress) return "address=" + value;
        if (value instanceof File) return "fd=" + value;
        return String.valueOf(value);
    }

    public static String caller() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        StringBuilder result = new StringBuilder();
        int included = 0;
        for (StackTraceElement frame : stack) {
            String name = frame.getClassName();
            if (name.equals(Thread.class.getName()) || name.equals(NetworkTrace.class.getName()) ||
                    name.startsWith("java.lang.reflect.") || name.startsWith("top.niunaijun.blackbox.fake.hook.")) continue;
            if (included++ > 0) result.append(" <- ");
            result.append(name).append('.').append(frame.getMethodName()).append(':').append(frame.getLineNumber());
            if (included == 3) break;
        }
        return result.toString();
    }

    private static void emit(long id, String layer, String api, String state,
                             String details, Throwable error) {
        StringBuilder line = new StringBuilder(256)
                .append("event=").append(id)
                .append(" ts=").append(System.currentTimeMillis())
                .append(" pid=").append(Process.myPid())
                .append(" tid=").append(Process.myTid())
                .append(" process=").append(processName())
                .append(" guest_pkg=").append(guestPackage())
                .append(" layer=").append(layer)
                .append(" api=").append(api)
                .append(" state=").append(state);
        if (details != null && !details.isEmpty()) line.append(' ').append(details);
        if (error != null) {
            line.append(" exception=").append(error.getClass().getName())
                    .append(" message=").append(String.valueOf(error.getMessage()));
        }
        Slog.d(TAG, line.toString());
    }

    private static String guestPackage() {
        try {
            String value = BActivityThread.getAppPackageName();
            return value == null ? "unknown" : value;
        } catch (Throwable ignored) {
            return "unknown";
        }
    }

    private static String processName() {
        String cached = sProcessName;
        if (cached != null) return cached;
        try (FileInputStream input = new FileInputStream("/proc/self/cmdline")) {
            byte[] bytes = new byte[256];
            int count = input.read(bytes);
            int end = 0;
            while (end < count && bytes[end] != 0) end++;
            cached = new String(bytes, 0, end);
        } catch (Throwable ignored) {
            cached = "unknown";
        }
        sProcessName = cached;
        return cached;
    }
}
