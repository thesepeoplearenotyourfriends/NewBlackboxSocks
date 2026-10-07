package android.os;
// Host-only Android boundary stub; no Android IPC behavior is asserted.
public class ParcelFileDescriptor implements AutoCloseable { public static ParcelFileDescriptor dup(java.io.FileDescriptor fd) { return new ParcelFileDescriptor(); } public int getFd() { return 1; } public void close() {} }
