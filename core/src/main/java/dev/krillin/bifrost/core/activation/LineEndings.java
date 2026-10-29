package dev.krillin.bifrost.core.activation;

import java.io.ByteArrayOutputStream;

/** Tells a line-ending conversion apart from a real edit when a file's SHA-256 no longer matches the sealed one.
 *  A registry kept in git under core.autocrlf (or any text-mode copy) rewrites LF as CRLF or back, and every
 *  sealed byte then fails verification. The file is still refused; this only names the cause so the fix is
 *  "keep the registry -text" rather than a hunt for a tamperer. */
public final class LineEndings {
    private LineEndings() {}

    /** True when {@code bytes} do not hash to {@code sealedSha256} but their CRLF-to-LF or LF-to-CRLF form does. */
    public static boolean explainMismatch(byte[] bytes, String sealedSha256) {
        if (Sha256.hex(bytes).equals(sealedSha256)) return false;
        return Sha256.hex(toLf(bytes)).equals(sealedSha256) || Sha256.hex(toCrlf(bytes)).equals(sealedSha256);
    }

    static byte[] toLf(byte[] b) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(b.length);
        for (int i = 0; i < b.length; i++) if (!(b[i] == '\r' && i + 1 < b.length && b[i + 1] == '\n')) out.write(b[i]);
        return out.toByteArray();
    }

    static byte[] toCrlf(byte[] b) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(b.length + b.length / 16);
        for (int i = 0; i < b.length; i++) {
            if (b[i] == '\n' && (i == 0 || b[i - 1] != '\r')) out.write('\r');
            out.write(b[i]);
        }
        return out.toByteArray();
    }
}
