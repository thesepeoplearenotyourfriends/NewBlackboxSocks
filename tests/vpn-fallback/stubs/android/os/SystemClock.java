package android.os;
// Host-only Android boundary stub; no Android IPC behavior is asserted.
public class SystemClock  { public static long now; public static long elapsedRealtime() { return now; } }
