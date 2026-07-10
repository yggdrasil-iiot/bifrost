package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.activation.ActivationLedger;
import dev.krillin.bifrost.core.identity.Ed25519Keys;
import dev.krillin.bifrost.core.identity.SignedLedgerVerifier;
import dev.krillin.bifrost.core.identity.SignedVerdict;
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
                case "verify-signed": return verifySigned(Arrays.copyOfRange(args, 1, args.length));
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

    private static int verifySigned(String[] a) throws Exception {
        if (a.length < 2) { System.err.println("Usage: identity verify-signed <reg> <target>"); return 2; }
        Path reg = Path.of(a[0]);
        String target = a[1];
        ActivationLedger ledger = new ActivationLedger(reg);
        if (ledger.history(target).isEmpty()) {
            System.err.println("[GATE] verify-signed: no such target ledger: " + target); return 2;
        }
        SignedVerdict v = SignedLedgerVerifier.forRegistry(reg).verify(target);
        if (v.intact()) {
            System.out.println("[GATE] verify-signed target=" + target + " => INTACT (signed)");
            return 0;
        }
        System.out.println("[GATE] verify-signed target=" + target + " => BROKEN at index="
                + v.brokenIndex() + " rule=" + v.rule());
        return 1;
    }

    private static void usage() { System.err.println("Usage: identity <keygen|verify-signed> ..."); }
}
