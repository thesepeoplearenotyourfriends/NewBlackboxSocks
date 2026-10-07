package top.niunaijun.blackbox.proxy;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;

/** Only a monotonic numeric high-water mark is durable; hostname mappings never are.
 * A synced reservation before issuance prevents old guest caches aliasing new names
 * after host/service death. Corrupt or exhausted storage fails closed.
 */
final class SyntheticAddressCursor implements SyntheticMappings.Allocator {
    private final File file;
    SyntheticAddressCursor(File directory) { file = new File(directory, "nbs-mapping-cursor"); }
    @Override public int nextAddress() throws IOException {
        synchronized (SyntheticAddressCursor.class) {
            try (RandomAccessFile state = new RandomAccessFile(file, "rw");
                 FileLock lock = state.getChannel().lock()) {
                int next = 0;
                if (state.length() != 0) {
                    if (state.length() != 8 || state.readInt() != 0x4e424d01) throw new IOException("cursor-format");
                    next = state.readInt();
                }
                if (next < 0 || next >= SyntheticMappings.CAPACITY) throw new IOException("cursor-capacity");
                state.seek(0); state.writeInt(0x4e424d01); state.writeInt(next + 1); state.getFD().sync();
                return SyntheticMappings.BASE + next;
            }
        }
    }
}
