package top.niunaijun.blackbox.fake.service;

import java.lang.reflect.Method;

import top.niunaijun.blackbox.fake.hook.IInjectHook;
import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.utils.Slog;

public class NetworkPermissionCompat implements IInjectHook {
    private static final String TAG = "NetworkPermissionCompat";

    private static volatile boolean sInstalled;

    @Override
    public void injectHook() {
        install();
    }

    @Override
    public boolean isBadEnv() {
        return BlackBoxCore.get().isBlackProcess() && !sInstalled;
    }

    public static void install() {
        if (!BlackBoxCore.get().isBlackProcess() || sInstalled) {
            return;
        }
        synchronized (NetworkPermissionCompat.class) {
            if (sInstalled) {
                return;
            }
            try {
                Class<?> permissionManager = Class.forName("android.permission.PermissionManager");
                boolean packageCache = disableCaches(permissionManager);
                sInstalled = true;
                Slog.d(TAG, "uid permission cache=DISABLED package permission cache="
                        + (packageCache ? "DISABLED" : "UNAVAILABLE"));
            } catch (Throwable e) {
                Slog.w(TAG, "install failed: " + e.getMessage(), e);
            }
        }
    }
    // Both caches are process-local; do not invalidate the system-wide permission cache property.
    static boolean disableCaches(Class<?> permissionManager) throws ReflectiveOperationException {
        Method uid = permissionManager.getDeclaredMethod("disablePermissionCache");
        uid.setAccessible(true);
        uid.invoke(null);
        try {
            Method pkg = permissionManager.getDeclaredMethod("disablePackageNamePermissionCache");
            pkg.setAccessible(true);
            pkg.invoke(null);
            return true;
        } catch (NoSuchMethodException unavailable) {
            return false;
        }
    }

}
