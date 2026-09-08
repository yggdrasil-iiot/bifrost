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
 *   rotate-key <reg> <principal> --out <dir> [--retire-at <instant>]
 *                                    mint a successor key and print the replacement block for that
 *                                    principal: every existing line retired, plus the successor.
 *   verify-signed <reg> <target>     full authenticated verification (0 intact / 1 broken / 2 usage).  (Task 11)
 *   verify-anchored <reg> <target> [--anchor-store file|git] [--anchor-dir <dir>]
 *                                    TrustLevel.ANCHORED: verify-signed + external-anchor cross-check
 *                                    (0 intact / 1 broken / 2 usage).  (T7)
 */
public final class IdentityGate {
    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        return run(args, java.time.Clock.systemUTC());
    }

    /** Clock-injected: a retirement stamp that could only be tested by sleeping would not be tested. */
    public static int run(String[] args, java.time.Clock clock) {
        if (args.length == 0) { usage(); return 2; }
        try {
            switch (args[0]) {
                case "keygen": return keygen(Arrays.copyOfRange(args, 1, args.length));
                case "rotate-key": return rotateKey(Arrays.copyOfRange(args, 1, args.length), clock);
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

    private static final String ROTATE_USAGE =
            "Usage: identity rotate-key <reg> <principal> --out <dir> [--retire-at <instant>]";

    /**
     * Mint a successor signing key for a principal and print the replacement block for it.
     *
     * <p>It PRINTS rather than edits, like {@code activation duty-key-mint}: the trust anchor is the
     * one file whose change control is deliberately out-of-band, and a CLI that rewrites it silently
     * is the wrong tool. What it prints is the WHOLE principal -- every existing line re-emitted with
     * a retirement stamp, plus the successor -- so the operator replaces a contiguous region instead
     * of hand-editing JSON under time pressure, and cannot end up with the predecessor still live or,
     * far worse, deleted.
     *
     * <p>Deleting a predecessor is the landmine {@code ADOPTION.md} names: SignedLedgerVerifier
     * resolves every historical entry against this file, so a removed line turns entries that key
     * signed years ago into identity.key.unregistered, permanently, on an append-only ledger.
     */
    private static int rotateKey(String[] a, java.time.Clock clock) throws Exception {
        String out = null, retireAt = null;
        java.util.List<String> pos = new java.util.ArrayList<>();
        for (int i = 0; i < a.length; i++) {
            switch (a[i]) {
                case "--out" -> out = (++i < a.length) ? a[i] : null;
                case "--retire-at" -> retireAt = (++i < a.length) ? a[i] : null;
                default -> pos.add(a[i]);
            }
        }
        if (pos.size() < 2 || out == null) { System.err.println(ROTATE_USAGE); return 2; }
        Path reg = Path.of(pos.get(0));
        String principal = pos.get(1);
        if (!isSafePrincipal(principal)) {
            System.err.println("[GATE] rotate-key: invalid principal (allowed [A-Za-z0-9_.-], 1-64): " + principal);
            return 2;
        }
        java.time.Instant at;
        try {
            at = retireAt == null ? clock.instant() : java.time.Instant.parse(retireAt);
        } catch (java.time.format.DateTimeParseException bad) {
            System.err.println("[GATE] rotate-key: --retire-at must be an ISO-8601 instant"
                    + " (e.g. 2026-12-25T00:00:00Z), got: " + retireAt);
            return 2;
        }
        var authorized = dev.krillin.bifrost.core.identity.AuthorizedKeys.load(reg);
        java.util.List<dev.krillin.bifrost.core.identity.AuthorizedKey> existing =
                authorized.declaredFor(principal);
        // Rotation REPLACES a key; it does not enrol a principal. Minting for an unregistered name here
        // would print a block retiring nothing, which reads like a rotation and is an enrolment.
        if (existing.isEmpty()) {
            System.out.println("[GATE] REFUSED:");
            System.out.println("  - [identity.principal.not-registered] '" + principal
                    + "' has no key line to rotate; use 'identity keygen' to enrol a new principal");
            return 1;
        }
        Path dir = Path.of(out);
        String pub = writeKeyPair(principal, dir);
        System.err.println("[GATE] rotate-key principal=" + principal + " retire-at=" + at
                + " -> " + dir.resolve(principal + ".key") + " , " + dir.resolve(principal + ".pub"));

        System.out.println("[GATE] rotate-key principal=" + principal + " => MINTED (retire-at " + at + ")");
        System.out.println("Replace every line for '" + principal + "' in "
                + reg.resolve("identity").resolve("authorized-keys.jsonl") + " with exactly these:");
        com.fasterxml.jackson.databind.ObjectMapper mapper =
                dev.krillin.bifrost.core.schema.JsonMapperFactory.create();
        for (dev.krillin.bifrost.core.identity.AuthorizedKey k : existing) {
            // An earlier retirement stamp is history and is NOT rewritten; only a still-open key closes now.
            java.time.Instant close = k.notAfter() != null ? k.notAfter() : at;
            System.out.println(mapper.writeValueAsString(
                    new dev.krillin.bifrost.core.identity.AuthorizedKey(
                            k.principal(), k.publicKey(), k.notBefore(), close)));
        }
        System.out.println(mapper.writeValueAsString(
                new dev.krillin.bifrost.core.identity.AuthorizedKey(principal, pub, at, null)));
        System.out.println("Do NOT delete the retired lines. They still verify every entry they signed,"
                + " and the ledger is append-only: removing one breaks that target permanently and the"
                + " edge bound to it refuses to start.");
        System.out.println("Retiring a key is not revoking it. The predecessor can no longer SIGN after "
                + at + "; it can still authenticate what it already signed, which is the point.");
        return 0;
    }

    private static void usage() {
        System.err.println("Usage: identity <keygen|rotate-key|verify-signed|verify-anchored|authorize> ...");
        System.err.println("       " + ROTATE_USAGE);
    }
}
