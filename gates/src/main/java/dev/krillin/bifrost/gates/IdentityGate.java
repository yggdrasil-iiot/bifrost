package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.activation.ActivationLedger;
import dev.krillin.bifrost.core.activation.AnchorStore;
import dev.krillin.bifrost.core.activation.FileAnchorStore;
import dev.krillin.bifrost.core.identity.Ed25519Keys;
import dev.krillin.bifrost.core.identity.GitAnchorStore;
import dev.krillin.bifrost.core.identity.SignedLedgerVerifier;
import dev.krillin.bifrost.core.identity.SignedVerdict;
import dev.krillin.bifrost.core.identity.TrustLevel;
import java.io.File;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.util.*;

/** Identity gate. Subcommands:
 *   keygen <principal> --out <dir>   generate an Ed25519 keypair; write <principal>.key (PKCS8 b64) and
 *                                    <principal>.pub (X.509 b64); print the authorized-keys.jsonl line.
 *   verify-signed <reg> <target>     full authenticated verification (0 intact / 1 broken / 2 usage).  (Task 11)
 *   verify-anchored <reg> <target> [--anchor-store file|git] [--anchor-dir <dir>]
 *                                    TrustLevel.ANCHORED: verify-signed + external-anchor cross-check
 *                                    (0 intact / 1 broken / 2 usage).  (T7)
 */
public final class IdentityGate {
    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length == 0) { usage(); return 2; }
        try {
            switch (args[0]) {
                case "keygen": return keygen(Arrays.copyOfRange(args, 1, args.length));
                case "verify-signed": return verifySigned(Arrays.copyOfRange(args, 1, args.length));
                case "verify-anchored": return verifyAnchored(Arrays.copyOfRange(args, 1, args.length));
                case "authorize": return authorize(Arrays.copyOfRange(args, 1, args.length));
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
        if (!isSafePrincipal(principal)) {
            System.err.println("[GATE] keygen: invalid principal (allowed [A-Za-z0-9_.-], 1-64): " + principal);
            return 2;
        }
        Path dir = Path.of(out);
        String pub = writeKeyPair(principal, dir);
        System.out.println(authorizedKeysLine(principal, pub));
        System.err.println("[GATE] keygen principal=" + principal + " -> " + dir.resolve(principal + ".key")
                + " , " + dir.resolve(principal + ".pub"));
        return 0;
    }

    /** A principal names a file — deny path escape / odd chars. */
    static boolean isSafePrincipal(String principal) {
        return principal.matches("[A-Za-z0-9_.-]{1,64}");
    }

    /** Generate an Ed25519 keypair into {@code dir} as {@code <principal>.key} (PKCS8 b64) and
     *  {@code <principal>.pub} (X.509 b64); returns the base64 public key. Shared with
     *  {@code activation duty-key-mint} so a duty key is written under exactly the same custody rules. */
    static String writeKeyPair(String principal, Path dir) throws Exception {
        KeyPair kp = Ed25519Keys.generate();
        Files.createDirectories(dir);
        Path keyFile = dir.resolve(principal + ".key");
        Files.deleteIfExists(keyFile);                      // avoid inheriting a pre-existing file's permissions
        createOwnerOnly(keyFile);                           // 0600-intent BEFORE any secret bytes land
        Files.writeString(keyFile, Ed25519Keys.privateKeyB64(kp.getPrivate()));
        String pub = Ed25519Keys.publicKeyB64(kp.getPublic());
        Files.writeString(dir.resolve(principal + ".pub"), pub);
        return pub;
    }

    /** The one line an operator appends to {@code identity/authorized-keys.jsonl}. */
    static String authorizedKeysLine(String principal, String publicKeyB64) {
        return "{\"principal\":\"" + principal + "\",\"publicKey\":\"" + publicKeyB64 + "\"}";
    }

    /** Create an empty file readable/writable by the owner only. POSIX: rw-------; non-POSIX (Windows):
     *  best-effort strip other/group read via File.setReadable. The private key bytes are written AFTER. */
    private static void createOwnerOnly(Path f) throws Exception {
        try {
            Files.createFile(f, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException nonPosix) {  // Windows / non-POSIX filesystem
            Files.createFile(f);
            File jf = f.toFile();
            jf.setReadable(false, false);                   // strip all read
            jf.setReadable(true, true);                     // owner read
            jf.setWritable(false, false);
            jf.setWritable(true, true);                     // owner write
        }
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

    private static int verifyAnchored(String[] a) throws Exception {
        if (a.length < 2) {
            System.err.println("Usage: identity verify-anchored <reg> <target> [--anchor-store file|git] [--anchor-dir <dir>]");
            return 2;
        }
        Path reg = Path.of(a[0]);
        String target = a[1];
        String storeKind = "file"; String anchorDir = null;
        for (int i = 2; i < a.length; i++) {
            if ("--anchor-store".equals(a[i])) storeKind = (++i < a.length) ? a[i] : storeKind;
            else if ("--anchor-dir".equals(a[i])) anchorDir = (++i < a.length) ? a[i] : null;
        }
        AnchorStore anchors = "git".equals(storeKind)
                ? new GitAnchorStore(Path.of(anchorDir != null ? anchorDir : reg.toString()))
                : new FileAnchorStore(anchorDir != null ? Path.of(anchorDir) : reg);
        // IMPORTANT: do NOT short-circuit on an empty ledger the way verify-signed does — an emptied ledger
        // with a present anchor IS a detectable rollback (AN7). Only "no such target" when BOTH are absent.
        boolean ledgerEmpty = new ActivationLedger(reg).history(target).isEmpty();
        if (ledgerEmpty && anchors.latest(target).isEmpty()) {
            System.err.println("[GATE] verify-anchored: no such target ledger: " + target); return 2;
        }
        SignedVerdict v = SignedLedgerVerifier.forRegistry(reg).verify(target, TrustLevel.ANCHORED, anchors);
        if (v.intact()) {
            System.out.println("[GATE] verify-anchored target=" + target + " => INTACT (anchored)");
            return 0;
        }
        System.out.println("[GATE] verify-anchored target=" + target + " => BROKEN at index="
                + v.brokenIndex() + " rule=" + v.rule());
        return 1;
    }

    private static int authorize(String[] a) throws Exception {
        if (a.length < 6) { System.err.println("Usage: identity authorize <reg> <principal> <activate|approve> <target> <kind> <ref>"); return 2; }
        dev.krillin.bifrost.core.activation.ActivationAction action;
        try { action = dev.krillin.bifrost.core.activation.ActivationAction.from(a[2]); }
        catch (Exception e) { System.err.println("[GATE] authorize: action must be activate|approve, got: " + a[2]); return 2; }
        var policy = dev.krillin.bifrost.core.activation.ActivationPolicyStore.load(Path.of(a[0]));
        var d = new dev.krillin.bifrost.core.activation.ActivationAuthorizer()
                .authorize(policy, a[1], action, a[3], a[4], a[5]);
        if (d.allowed()) {
            System.out.println("[GATE] authorize " + a[1] + " " + action.json() + " " + a[3] + "/" + a[4] + "/" + a[5]
                    + " => ALLOW rule=" + d.ruleId());
            return 0;
        }
        System.out.println("[GATE] authorize " + a[1] + " " + action.json() + " " + a[3] + "/" + a[4] + "/" + a[5]
                + " => DENY (" + d.reason() + ")");
        return 1;
    }

    private static void usage() { System.err.println("Usage: identity <keygen|verify-signed|verify-anchored|authorize> ..."); }
}
