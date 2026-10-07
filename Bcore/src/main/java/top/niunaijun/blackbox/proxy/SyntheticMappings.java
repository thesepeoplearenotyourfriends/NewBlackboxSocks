package top.niunaijun.blackbox.proxy;

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** Service-owned, memory-only allocation. Addresses are never recycled in a process. */
final class SyntheticMappings {
    static final int BASE = 0xc6120000, CAPACITY = 1 << 17;
    private static int nextOffset;
    interface Allocator { int nextAddress() throws IOException; }
    private final Allocator allocator;
    private final Map<String, Integer> addresses = new HashMap<>();
    private final Map<Integer, String> names = new HashMap<>();
    private boolean active = true;
    private final int reservedAddress;
    SyntheticMappings() { this(0); }
    SyntheticMappings(int reservedAddress) {
        this(reservedAddress, () -> {
            synchronized (SyntheticMappings.class) {
                if (nextOffset >= CAPACITY) throw new IOException("mapping-capacity");
                return BASE + nextOffset++;
            }
        });
    }
    SyntheticMappings(int reservedAddress, Allocator allocator) {
        this.reservedAddress = reservedAddress; this.allocator = allocator;
    }
    static boolean synthetic(int address) { return (address & 0xfffe0000) == BASE; }
    static String normalize(String value) throws IOException {
        String name = value.toLowerCase(Locale.ROOT);
        if (name.endsWith(".")) name = name.substring(0, name.length() - 1);
        if (name.isEmpty() || name.length() > 253) throw new IOException("hostname-length");
        for (String label : name.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-"))
                throw new IOException("hostname-label");
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-')
                    throw new IOException("hostname-format");
            }
        }
        return name;
    }
    synchronized int allocate(String value) throws IOException {
        if (!active) throw new IOException("mapping-stopped");
        String name = normalize(value);
        Integer old = addresses.get(name);
        if (old != null) return old;
        int address = allocator.nextAddress();
        if (address == reservedAddress) address = allocator.nextAddress();
        if (!synthetic(address) || names.containsKey(address)) throw new IOException("mapping-allocator");
        addresses.put(name, address); names.put(address, name);
        return address;
    }
    synchronized String lookup(int address) { return active ? names.get(address) : null; }
    synchronized void close() { active = false; addresses.clear(); names.clear(); }
}
