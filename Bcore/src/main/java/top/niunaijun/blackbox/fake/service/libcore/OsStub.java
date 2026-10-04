package top.niunaijun.blackbox.fake.service.libcore;

import android.os.Process;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import black.libcore.io.BRLibcore;
import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.app.BActivityThread;
import top.niunaijun.blackbox.core.IOCore;
import top.niunaijun.blackbox.fake.hook.ClassInvocationStub;
import top.niunaijun.blackbox.fake.hook.MethodHook;
import top.niunaijun.blackbox.fake.hook.ProxyMethod;
import top.niunaijun.blackbox.utils.Reflector;


public class OsStub extends ClassInvocationStub {
    public static final String TAG = "OsStub";
    private Object mBase;
    private static final Set<String> sLoggedNetworkMethods =
            Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());

    public OsStub() {
        mBase = BRLibcore.get().os();
    }

    @Override
    protected Object getWho() {
        return mBase;
    }

    @Override
    protected void inject(Object baseInvocation, Object proxyInvocation) {
        BRLibcore.get()._set_os(proxyInvocation);
    }

    @Override
    protected void onBindMethod() {
    }

    @Override
    public boolean isBadEnv() {
        return BRLibcore.get().os() != getProxyInvocation();
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        String name = method.getName();
        if (isNetworkMethod(name) && sLoggedNetworkMethods.add(name)) {
            // libcore.io.Posix implements these methods with the correspondingly named
            // Bionic calls (android_getaddrinfo uses android_getaddrinfofornet). The
            // startup-fatal native hook set covers each data-plane entry point; methods
            // that only configure/listen on local sockets remain ordinary kernel calls.
            android.util.Log.d(TAG, "NetworkPolicy: libcore Os path=" + name +
                    " native=" + nativeEntryPoint(name));
        }
        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                if (args[i] == null)
                    continue;
                if (args[i] instanceof String && ((String) args[i]).startsWith("/")) {
                    String orig = (String) args[i];
                    args[i] = IOCore.get().redirectPath(orig);



                }
            }
        }
        return super.invoke(proxy, method, args);
    }

    private static boolean isNetworkMethod(String name) {
        return name.equals("socket") || name.equals("connect") || name.equals("sendto") ||
                name.equals("sendmsg") || name.equals("recvfrom") || name.equals("recvmsg") ||
                name.equals("poll") || name.equals("getsockoptInt") || name.equals("setsockoptInt") ||
                name.equals("android_getaddrinfo") || name.equals("getaddrinfo") ||
                name.equals("bind") || name.equals("listen") || name.equals("accept");
    }

    private static String nativeEntryPoint(String name) {
        if (name.equals("android_getaddrinfo") || name.equals("getaddrinfo")) {
            return "android_getaddrinfofornet/getaddrinfo";
        }
        if (name.equals("socket") || name.equals("connect") || name.equals("sendto") ||
                name.equals("sendmsg") || name.equals("recvfrom") || name.equals("recvmsg")) {
            return name;
        }
        if (name.equals("poll") || name.startsWith("getsockopt") ||
                name.startsWith("setsockopt") || name.equals("bind") || name.equals("listen") ||
                name.equals("accept")) {
            return "kernel-control";
        }
        return "unhandled";
    }

    @ProxyMethod("getuid")
    public static class getuid extends MethodHook {

        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            int callUid = (int) method.invoke(who, args);
            return getFakeUid(callUid);
        }
    }

    @ProxyMethod("stat")
    public static class stat extends MethodHook {

        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            Object invoke = null;
            try {
                invoke = method.invoke(who, args);
            } catch (Throwable e) {
                throw e.getCause();
            }
            Reflector.with(invoke).field("st_uid").set(getFakeUid(-1));
            return invoke;
        }
    }

    private static int getFakeUid(int callUid) {
        if (callUid > 0 && callUid <= Process.FIRST_APPLICATION_UID)
            return callUid;

        if (BActivityThread.isThreadInit() && BActivityThread.currentActivityThread().isInit()) {
            return BActivityThread.getBAppId();
        } else {
            return BlackBoxCore.getHostUid();
        }
    }
}
