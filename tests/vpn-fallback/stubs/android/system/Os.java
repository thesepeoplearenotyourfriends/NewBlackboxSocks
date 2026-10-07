package android.system;
// Host-only Android boundary stub; no Android IPC behavior is asserted.
public class Os  { public static void chmod(String p,int m) {} public static void close(java.io.FileDescriptor fd) {} public static java.net.SocketAddress getsockname(java.io.FileDescriptor fd) { return null; } public static java.net.SocketAddress getpeername(java.io.FileDescriptor fd) { return null; } public static int poll(StructPollfd[] f,int timeout) { return 0; } }
