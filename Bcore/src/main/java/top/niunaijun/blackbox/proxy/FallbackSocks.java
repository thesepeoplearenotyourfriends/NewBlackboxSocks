package top.niunaijun.blackbox.proxy;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** SOCKS5 only. Authenticated settings offer only RFC1929, never no-auth. */
final class FallbackSocks {
    static byte[] request(int address, int port, String hostname) throws IOException {
        if (port < 1 || port > 65535) throw new IOException("socks-port");
        byte[] name = hostname == null ? null : SyntheticMappings.normalize(hostname).getBytes(StandardCharsets.US_ASCII);
        if (name == null && SyntheticMappings.synthetic(address)) throw new IOException("socks-unmapped");
        byte[] request = new byte[name == null ? 10 : 7 + name.length];
        request[0] = 5; request[1] = 1; request[3] = (byte) (name == null ? 1 : 3);
        if (name == null) {
            for (int i = 0; i < 4; i++) request[4 + i] = (byte) (address >>> (24 - i * 8));
        } else { request[4] = (byte) name.length; System.arraycopy(name, 0, request, 5, name.length); }
        request[request.length - 2] = (byte) (port >>> 8); request[request.length - 1] = (byte) port;
        return request;
    }
    static void negotiate(InputStream stream, OutputStream output, byte[] user, byte[] password,
                          int address, int port, String hostname) throws IOException {
        if (user.length > 255 || password.length > 255) throw new IOException("socks-credentials");
        boolean auth = user.length != 0 || password.length != 0;
        int method = auth ? 2 : 0;
        DataInputStream input = new DataInputStream(stream);
        output.write(new byte[]{5, 1, (byte) method}); output.flush();
        if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != method) throw new IOException("socks-method");
        if (auth) {
            output.write(1); output.write(user.length); output.write(user);
            output.write(password.length); output.write(password); output.flush();
            if (input.readUnsignedByte() != 1 || input.readUnsignedByte() != 0) throw new IOException("socks-auth");
        }
        output.write(request(address, port, hostname)); output.flush();
        if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != 0 || input.readUnsignedByte() != 0)
            throw new IOException("socks-reply");
        int type = input.readUnsignedByte();
        int size = type == 1 ? 4 : type == 4 ? 16 : type == 3 ? input.readUnsignedByte() : -1;
        if (size <= 0) throw new IOException("socks-reply-address");
        byte[] bound = new byte[size + 2]; input.readFully(bound);
    }
}
