package top.niunaijun.blackbox.proxy;
// Host-only Android boundary stub; no Android IPC behavior is asserted.
public class VpnRelay  { public static final byte[] LOCAL_BYTES={10,0,0,2}; public static byte[] bytes(int a) { return new byte[]{(byte)(a>>>24),(byte)(a>>>16),(byte)(a>>>8),(byte)a}; } public static boolean validSocksUdp(byte[] b) { return true; } }
