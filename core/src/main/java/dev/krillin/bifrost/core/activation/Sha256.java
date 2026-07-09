package dev.krillin.bifrost.core.activation;
import java.security.MessageDigest;
/** Lowercase-hex SHA-256 — the one content-hash discipline shared by the activation resolver and the edge check. */
public final class Sha256 {
    private Sha256() {}
    public static String hex(byte[] bytes) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder s = new StringBuilder(d.length * 2);
            for (byte x : d) s.append(String.format("%02x", x));
            return s.toString();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
}
