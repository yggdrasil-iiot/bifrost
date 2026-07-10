package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.identity.Ed25519Keys;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.*;

/** Identity gate. Subcommands:
 *   keygen <principal> --out <dir>   generate an Ed25519 keypair; write <principal>.key (PKCS8 b64) and
 *                                    <principal>.pub (X.509 b64); print the authorized-keys.jsonl line.
 *   verify-signed <reg> <target>     full authenticated verification (0 intact / 1 broken / 2 usage).  (Task 11)
 */
public final class IdentityGate {
    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length == 0) { usage(); return 2; }
        try {
            switch (args[0]) {
                case "keygen": return keygen(Arrays.copyOfRange(args, 1, args.length));
                default: usage(); return 2;
            }
        } catch (Exception e) { System.err.println("[GATE] error: " + e.getMessage()); return 2; }
    }

    private static int keygen(String[] a) throws Exception {
        String principal = null, out = null;
        for (int i = 0; i < a.length; i++) {
            if ("--out".equals(a[i])) out = (++i < a.length) ? a[i] : null;
            else if (principal == null) principal = a[i];
        }
        if (principal == null || out == null) {
            System.err.println("Usage: identity keygen <principal> --out <dir>"); return 2;
        }
        KeyPair kp = Ed25519Keys.generate();
        Path dir = Path.of(out);
        Files.createDirectories(dir);
        Files.writeString(dir.resolve(principal + ".key"), Ed25519Keys.privateKeyB64(kp.getPrivate()));
        Files.writeString(dir.resolve(principal + ".pub"), Ed25519Keys.publicKeyB64(kp.getPublic()));
        System.out.println("{\"principal\":\"" + principal + "\",\"publicKey\":\""
                + Ed25519Keys.publicKeyB64(kp.getPublic()) + "\"}");
        System.err.println("[GATE] keygen principal=" + principal + " -> " + dir.resolve(principal + ".key")
                + " , " + dir.resolve(principal + ".pub"));
        return 0;
    }

    private static void usage() { System.err.println("Usage: identity <keygen|verify-signed> ..."); }
}
