package top.niunaijun.blackbox.fake.service;

import android.Manifest;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Process;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.app.BActivityThread;
import top.niunaijun.blackbox.entity.AppConfig;
import top.niunaijun.blackbox.utils.Slog;

/** Read-only INTERNET permission view for the current bound guest, not a host grant. */
final class GuestInternetPermission {
    private static final ThreadLocal<Boolean> RESOLVING = new ThreadLocal<>();
    private static final Set<String> LOGGED = Collections.newSetFromMap(new ConcurrentHashMap<>());

    interface Declaration {
        boolean guestRequestsInternet();
        boolean hostHasInternet();
    }

    static final class Self {
        final String packageName;
        final int virtualUid, appId, hostUid, pid, virtualUserId, hostUserId;

        Self(String packageName, int virtualUid, int appId, int hostUid, int pid, int virtualUserId, int hostUserId) {
            this.packageName = packageName;
            this.virtualUid = virtualUid;
            this.appId = appId;
            this.hostUid = hostUid;
            this.pid = pid;
            this.virtualUserId = virtualUserId;
            this.hostUserId = hostUserId;
        }

        boolean ownsUid(int uid) {
            return uid >= Process.FIRST_APPLICATION_UID
                    && (uid == virtualUid || uid == appId || uid == hostUid);
        }
    }

    /** null means delegate unchanged; no other permission/identity is handled here. */
    static Integer evaluate(String method, Object[] args, Self self, Declaration declaration) {
        if (self == null || self.packageName == null || args == null || args.length < 2) return null;
        // PermissionManager changed from permission-first to package/uid-first. Normalize a copy,
        // never the original Binder arguments (which must remain intact when delegated).
        if (!Manifest.permission.INTERNET.equals(args[0])) {
            if (!Manifest.permission.INTERNET.equals(args[1])) return null;
            args = args.clone();
            Object target = args[0];
            args[0] = args[1];
            args[1] = target;
        }
        boolean own;
        switch (method) {
            case "checkPermissionForDevice":
            case "checkPermission":
                if (args[1] instanceof String) {
                    // IPackageManager/IPermissionManager: permission, package, [device], userId.
                    Object user = args[args.length - 1];
                    own = self.packageName.equals(args[1]) && user instanceof Integer
                            && ((Integer) user == self.virtualUserId || (Integer) user == self.hostUserId);
                } else {
                    // IActivityManager: permission, pid, uid, [deviceId]. UID is NOT the last int.
                    if (args.length < 3 || !(args[1] instanceof Integer) || !(args[2] instanceof Integer)) return null;
                    int pid = (Integer) args[1];
                    own = (pid == self.pid || pid == -1) && self.ownsUid((Integer) args[2]);
                }
                break;
            case "checkUidPermission":
                own = args[1] instanceof Integer && self.ownsUid((Integer) args[1]);
                break;
            default: return null;
        }
        if (!own) return null;
        return declaration.guestRequestsInternet() && declaration.hostHasInternet()
                ? PackageManager.PERMISSION_GRANTED : PackageManager.PERMISSION_DENIED;
    }

    static void applyRequestedPermissionFlag(PackageInfo info, int index, Integer result) {
        if (result == null || info == null || info.requestedPermissions == null || info.requestedPermissionsFlags == null
                || index < 0 || index >= info.requestedPermissions.length || index >= info.requestedPermissionsFlags.length
                || !Manifest.permission.INTERNET.equals(info.requestedPermissions[index])) return;
        if (result == PackageManager.PERMISSION_GRANTED) info.requestedPermissionsFlags[index] |= PackageInfo.REQUESTED_PERMISSION_GRANTED;
        else info.requestedPermissionsFlags[index] &= ~PackageInfo.REQUESTED_PERMISSION_GRANTED;
    }

    static Integer check(String method, Object[] args) {
        if (args == null || args.length < 2
                || (!Manifest.permission.INTERNET.equals(args[0]) && !Manifest.permission.INTERNET.equals(args[1]))
                || Boolean.TRUE.equals(RESOLVING.get()) || !BlackBoxCore.get().isBlackProcess()) return null;
        AppConfig config = BActivityThread.getAppConfig();
        if (config == null) return null;
        Self self = new Self(config.packageName, config.buid, BActivityThread.getBAppId(),
                BlackBoxCore.getHostUid(), Process.myPid(), config.userId, BlackBoxCore.getHostUserId());
        RESOLVING.set(true);
        try {
            Integer result = evaluate(method, args, self, new Declaration() {
                @Override public boolean guestRequestsInternet() {
                    PackageInfo info = BlackBoxCore.getBPackageManager().getPackageInfo(
                            config.packageName, PackageManager.GET_PERMISSIONS, config.userId);
                    if (info == null || info.requestedPermissions == null) return false;
                    for (String permission : info.requestedPermissions) {
                        if (Manifest.permission.INTERNET.equals(permission)) return true;
                    }
                    return false;
                }

                @Override public boolean hostHasInternet() {
                    // Package check deliberately targets the real host package. The recursion guard
                    // ensures this read delegates to Android even if the host itself is a guest.
                    return BlackBoxCore.getContext().getPackageManager().checkPermission(
                            Manifest.permission.INTERNET, BlackBoxCore.getHostPkg()) == PackageManager.PERMISSION_GRANTED;
                }
            });
            String surface = method.equals("checkUidPermission") ? "uid"
                    : args[1] instanceof String ? "package" : "pid_uid";
            if (result != null && LOGGED.add(method + ":" + surface + ":" + result)) {
                Slog.d("GuestInternetPermission", "path=" + method + " surface=" + surface + " result=" + result
                        + " guestUid=" + self.virtualUid + " appId=" + self.appId + " hostUid=" + self.hostUid);
            }
            return result;
        } catch (RuntimeException e) {
            if (LOGGED.add(method + ":unavailable")) Slog.w("GuestInternetPermission",
                    "path=" + method + " declaration/host check unavailable=" + e.getClass().getSimpleName());
            return PackageManager.PERMISSION_DENIED;
        } finally {
            RESOLVING.remove();
        }
    }
}
