package top.niunaijun.blackbox.fake.service;

import android.Manifest;
import android.content.pm.PackageManager;

import org.junit.Test;

import top.niunaijun.blackbox.fake.hook.ProxyMethod;
import top.niunaijun.blackbox.fake.hook.ProxyMethods;

import static org.junit.Assert.*;

public class GuestInternetPermissionTest {
    private final GuestInternetPermission.Self self = new GuestInternetPermission.Self(
            "guest.browser", 110123, 10123, 10234, 567, 1, 0);

    private static final class Declaration implements GuestInternetPermission.Declaration {
        boolean declared = true, hostAllowed = true;
        int guestReads, hostReads;
        @Override public boolean guestRequestsInternet() { guestReads++; return declared; }
        @Override public boolean hostHasInternet() { hostReads++; return hostAllowed; }
    }

    @Test public void activityManagerHandlesVirtualAppIdAndRealUidWithoutChangingArguments() {
        for (String method : new String[]{"checkPermission", "checkPermissionForDevice"}) {
            for (int uid : new int[]{110123, 10123, 10234}) {
                Object[] args = {Manifest.permission.INTERNET, 567, uid, 0};
                Object[] before = args.clone();
                assertEquals(Integer.valueOf(PackageManager.PERMISSION_GRANTED),
                        GuestInternetPermission.evaluate(method, args, self, new Declaration()));
                assertArrayEquals(before, args);
            }
        }
    }

    @Test public void deviceIdIsNeverMistakenForUid() {
        Object[] args = {Manifest.permission.INTERNET, 567, 55555, 110123};
        Declaration declaration = new Declaration();
        assertNull(GuestInternetPermission.evaluate("checkPermissionForDevice", args, self, declaration));
        assertEquals(0, declaration.guestReads);
        assertEquals(110123, args[3]);
    }

    @Test public void packageAndUidChecksAgreeForCurrentGuest() {
        for (int user : new int[]{0, 1}) {
            assertEquals(Integer.valueOf(PackageManager.PERMISSION_GRANTED), GuestInternetPermission.evaluate(
                    "checkPermission", new Object[]{Manifest.permission.INTERNET, "guest.browser", user}, self, new Declaration()));
            assertEquals(Integer.valueOf(PackageManager.PERMISSION_GRANTED), GuestInternetPermission.evaluate(
                    "checkPermission", new Object[]{Manifest.permission.INTERNET, "guest.browser", "default:0", user}, self, new Declaration()));
        }
        assertEquals(Integer.valueOf(PackageManager.PERMISSION_GRANTED), GuestInternetPermission.evaluate(
                "checkUidPermission", new Object[]{Manifest.permission.INTERNET, 10123}, self, new Declaration()));
    }

    @Test public void android15PermissionManagerUsesPackageOrUidBeforePermission() {
        Object[] packageArgs = {"guest.browser", Manifest.permission.INTERNET, "default:0", 0};
        Object[] uidArgs = {10123, Manifest.permission.INTERNET, 0};
        Object[] beforePackage = packageArgs.clone(), beforeUid = uidArgs.clone();
        assertEquals(Integer.valueOf(PackageManager.PERMISSION_GRANTED), GuestInternetPermission.evaluate(
                "checkPermission", packageArgs, self, new Declaration()));
        assertEquals(Integer.valueOf(PackageManager.PERMISSION_GRANTED), GuestInternetPermission.evaluate(
                "checkUidPermission", uidArgs, self, new Declaration()));
        assertArrayEquals(beforePackage, packageArgs);
        assertArrayEquals(beforeUid, uidArgs);
        Declaration declaration = new Declaration();
        assertNull(GuestInternetPermission.evaluate("checkPermission", new Object[]{"other.browser", Manifest.permission.INTERNET, "default:0", 0}, self, declaration));
        assertNull(GuestInternetPermission.evaluate("checkUidPermission", new Object[]{99999, Manifest.permission.INTERNET, 0}, self, declaration));
        assertEquals(0, declaration.guestReads);
    }

    @Test public void missingManifestPermissionAndHostDenialRemainDenied() {
        Declaration declaration = new Declaration();
        declaration.declared = false;
        Object[] args = {Manifest.permission.INTERNET, 567, 10123};
        assertEquals(Integer.valueOf(PackageManager.PERMISSION_DENIED), GuestInternetPermission.evaluate("checkPermission", args, self, declaration));
        assertEquals(0, declaration.hostReads);
        declaration.declared = true;
        declaration.hostAllowed = false;
        assertEquals(Integer.valueOf(PackageManager.PERMISSION_DENIED), GuestInternetPermission.evaluate("checkPermission", args, self, declaration));
    }

    @Test public void unrelatedPermissionPackageUidPidUserAndUnboundProcessDelegate() {
        Object[][] args = {
                {Manifest.permission.CAMERA, 567, 10123},
                {Manifest.permission.INTERNET, "other.browser", 0},
                {Manifest.permission.INTERNET, "guest.browser", 2},
                {Manifest.permission.INTERNET, 567, 99999},
                {Manifest.permission.INTERNET, 999, 10123},
                {Manifest.permission.INTERNET, 567, 1000},
                {Manifest.permission.INTERNET, 567, -1}
        };
        Declaration declaration = new Declaration();
        for (Object[] call : args) assertNull(GuestInternetPermission.evaluate("checkPermission", call, self, declaration));
        assertNull(GuestInternetPermission.evaluate("checkPermission", args[0], null, declaration));
        assertNull(GuestInternetPermission.evaluate("grantRuntimePermission", new Object[]{Manifest.permission.INTERNET, "guest.browser", 0}, self, declaration));
        assertEquals(0, declaration.guestReads);
        assertEquals(0, declaration.hostReads);
    }

    @Test public void malformedArgumentsDelegateAndUidOnlyCheckAcceptsSelf() {
        Declaration declaration = new Declaration();
        assertNull(GuestInternetPermission.evaluate("checkPermission", null, self, declaration));
        assertNull(GuestInternetPermission.evaluate("checkPermission", new Object[]{Manifest.permission.INTERNET}, self, declaration));
        assertNull(GuestInternetPermission.evaluate("checkPermission", new Object[]{Manifest.permission.INTERNET, 567, "bad"}, self, declaration));
        assertEquals(Integer.valueOf(PackageManager.PERMISSION_GRANTED), GuestInternetPermission.evaluate(
                "checkPermission", new Object[]{Manifest.permission.INTERNET, -1, 10123}, self, declaration));
    }

    @Test public void packagePermissionFlagAgreesWithoutChangingOtherPermissionsOrDelegatedResults() {
        android.content.pm.PackageInfo info = new android.content.pm.PackageInfo();
        info.requestedPermissions = new String[]{Manifest.permission.INTERNET, Manifest.permission.CAMERA};
        info.requestedPermissionsFlags = new int[]{0, 7};
        GuestInternetPermission.applyRequestedPermissionFlag(info, 0, PackageManager.PERMISSION_GRANTED);
        assertTrue((info.requestedPermissionsFlags[0] & android.content.pm.PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0);
        GuestInternetPermission.applyRequestedPermissionFlag(info, 1, PackageManager.PERMISSION_DENIED);
        assertEquals(7, info.requestedPermissionsFlags[1]);
        int before = info.requestedPermissionsFlags[0];
        GuestInternetPermission.applyRequestedPermissionFlag(info, 0, null);
        assertEquals(before, info.requestedPermissionsFlags[0]);
        GuestInternetPermission.applyRequestedPermissionFlag(info, 0, PackageManager.PERMISSION_DENIED);
        assertEquals(0, info.requestedPermissionsFlags[0]);
    }

    public static class PermissionCaches {
        static boolean uidDisabled, packageDisabled;
        public static void disablePermissionCache() { uidDisabled = true; }
        public static void disablePackageNamePermissionCache() { packageDisabled = true; }
    }

    public static class UidCacheOnly {
        public static void disablePermissionCache() { }
    }

    @Test public void bothLocalPermissionCachesAreDisabledAndOlderCacheApiIsSupported() throws Exception {
        PermissionCaches.uidDisabled = false;
        PermissionCaches.packageDisabled = false;
        assertTrue(NetworkPermissionCompat.disableCaches(PermissionCaches.class));
        assertTrue(PermissionCaches.uidDisabled);
        assertTrue(PermissionCaches.packageDisabled);
        assertFalse(NetworkPermissionCompat.disableCaches(UidCacheOnly.class));
    }

    @Test public void hooksCoverActualFrameworkBinderEntryPoints() {
        assertArrayEquals(new String[]{"checkPermission", "checkPermissionForDevice"},
                IActivityManagerProxy.checkPermission.class.getAnnotation(ProxyMethods.class).value());
        assertEquals("checkPermission", IPackageManagerProxy.SimpleAudioPermissionHook.class.getAnnotation(ProxyMethod.class).value());
        assertEquals("checkUidPermission", IPackageManagerProxy.CheckUidPermission.class.getAnnotation(ProxyMethod.class).value());
        assertArrayEquals(new String[]{"checkPermission", "checkUidPermission"},
                IPermissionManagerProxy.CheckInternetPermission.class.getAnnotation(ProxyMethods.class).value());
    }
}
