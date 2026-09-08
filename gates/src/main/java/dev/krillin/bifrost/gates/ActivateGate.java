package dev.krillin.bifrost.gates;
import java.nio.file.Path;
import java.time.Clock;
import java.util.*;
import dev.krillin.bifrost.core.activation.*;
import dev.krillin.bifrost.core.schema.Violation;

/** Activation gate. Subcommands:
 *   activate <reg> <target> <kind> <ref> <version> --by <p> --approved-by <p> [--by-key <f> --approved-by-key <f>]
 *            [--anchor-store file|git] [--anchor-dir <dir>] [--rollback]                    (0 ok / 1 refused / 2 usage)
 *   active   <reg> <target> <kind> <ref>                                                    (prints active version+sha or none)
 *   activation-log <reg> <target>                                                           (prints the audit trail)
 *   activation verify-chain <reg> <target>                                                  (0 intact / 1 tampered / 2 no such target)
 *   activation duty-key-mint <reg> <principal> --out <dir> --by <p> --by-key <f> --approved-by <p> --approved-by-key <f>
 *            two registered people mint a break-glass duty key                              (0 minted / 1 refused / 2 usage) */
public final class ActivateGate {
    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length == 0) { usage(); return 2; }
        String sub = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        try {
            switch (sub) {
                case "activate": return activate(rest);
                case "active": return active(rest);
                case "activation-log": return log(rest);
                case "activation": return activation(rest);
                default: usage(); return 2;
            }
        } catch (Exception e) { System.err.println("[GATE] error: " + e.getMessage()); return 2; }
    }

    private static int activate(String[] a) throws Exception {
        String by = null, approvedBy = null, byKey = null, approvedByKey = null; boolean rollback = false;
        String anchorStoreKind = "file", anchorDir = null;
        List<String> pos = new ArrayList<>();
        for (int i = 0; i < a.length; i++) {
            switch (a[i]) {
                case "--by" -> by = (++i < a.length) ? a[i] : null;
                case "--approved-by" -> approvedBy = (++i < a.length) ? a[i] : null;
                case "--by-key" -> byKey = (++i < a.length) ? a[i] : null;
                case "--approved-by-key" -> approvedByKey = (++i < a.length) ? a[i] : null;
                case "--anchor-store" -> anchorStoreKind = (++i < a.length) ? a[i] : anchorStoreKind;
                case "--anchor-dir" -> anchorDir = (++i < a.length) ? a[i] : null;
                case "--rollback" -> rollback = true;
                default -> pos.add(a[i]);
            }
        }
        if (pos.size() < 5) { System.err.println("Usage: activate <reg> <target> <kind> <ref> <version> --by <p> --approved-by <p> [--by-key <f> --approved-by-key <f>] [--anchor-store file|git] [--anchor-dir <dir>] [--rollback]"); return 2; }
        if ((byKey == null) != (approvedByKey == null)) {
            System.err.println("Usage: --by-key and --approved-by-key must be supplied together"); return 2;
        }
        Path reg = Path.of(pos.get(0));
        // The ledger carries an AnchorStore ONLY on the signed path; unsigned stays exact T5 (anchorStore == null).
        dev.krillin.bifrost.core.activation.AnchorStore anchorStore = null;
        if (byKey != null) {
            if ("git".equals(anchorStoreKind)) {
                Path anchorRepo = Path.of(anchorDir != null ? anchorDir : reg.toString());
                if (dev.krillin.bifrost.core.identity.GitAnchorStore.isColocatedWith(anchorRepo, reg))
                    System.err.println("[GATE] WARN: git anchor repo " + anchorRepo + " is inside the registry "
                            + reg + " - an insider who rolls back the registry rolls back this witness too."
                            + " Point --anchor-dir at a separate, off-box, protected repo to actually close co-rollback.");
                anchorStore = new dev.krillin.bifrost.core.identity.GitAnchorStore(anchorRepo);
            } else {
                anchorStore = new dev.krillin.bifrost.core.activation.FileAnchorStore(anchorDir != null ? Path.of(anchorDir) : reg);
            }
        }
        ActivationService svc = new ActivationService(new RecipeArtifactResolver(reg),
                new ActivationLedger(reg, anchorStore), Clock.systemUTC());
        ActivationRequest req = new ActivationRequest(pos.get(1), pos.get(2), pos.get(3), pos.get(4), by, approvedBy, rollback);
        ActivationVerdict v;
        if (byKey != null) {
            dev.krillin.bifrost.core.activation.LedgerSigner signer =
                    dev.krillin.bifrost.core.identity.KeyFileLedgerSigner.create(
                            by, Path.of(byKey), approvedBy, Path.of(approvedByKey),
                            dev.krillin.bifrost.core.identity.AuthorizedKeys.load(reg));
            dev.krillin.bifrost.core.activation.ActivationPolicy policy =
                    dev.krillin.bifrost.core.activation.ActivationPolicyStore.load(reg);
            v = svc.activate(req, signer, policy);
        } else {
            v = svc.activate(req);   // unsigned: no authZ
        }
        if (v.ok()) {
            ActivationEvent e = v.event();
            System.out.println("[GATE] activated target=" + e.target() + " kind=" + e.kind() + " ref=" + e.ref()
                + " version=" + e.version() + " action=" + e.action() + " by=" + e.activatedBy()
                + " approvedBy=" + e.approvedBy() + " sha256=" + e.contentSha256()
                + (byKey != null ? " signed=true" : ""));
            return 0;
        }
        System.out.println("[GATE] REFUSED:");
        for (Violation viol : v.violations()) System.out.println("  - [" + viol.rule() + "] " + viol.detail());
        return 1;
    }

    private static int active(String[] a) throws Exception {
        if (a.length < 4) { System.err.println("Usage: active <reg> <target> <kind> <ref>"); return 2; }
        Path reg = Path.of(a[0]);
        Optional<ActivationEvent> e = new ActivationLedger(reg).active(a[1], a[2], a[3]);
        if (e.isEmpty()) { System.out.println("[GATE] active target=" + a[1] + " " + a[2] + "/" + a[3] + " => none"); return 0; }
        System.out.println("[GATE] active target=" + a[1] + " " + a[2] + "/" + a[3] + " => version=" + e.get().version()
            + " sha256=" + e.get().contentSha256() + " (by " + e.get().activatedBy() + ", approvedBy " + e.get().approvedBy() + ")");
        return 0;
    }

    private static int log(String[] a) throws Exception {
        if (a.length < 2) { System.err.println("Usage: activation-log <reg> <target>"); return 2; }
        List<LedgerEntry> hist = new ActivationLedger(Path.of(a[0])).history(a[1]);
        System.out.println("[GATE] activation-log target=" + a[1] + " events=" + hist.size());
        for (LedgerEntry en : hist) {
            ActivationEvent e = en.event();
            System.out.println("  " + e.action() + " " + e.kind() + "/" + e.ref() + "@" + e.version()
                + " by=" + e.activatedBy() + " approvedBy=" + e.approvedBy() + " prior=" + e.priorVersion()
                + " sha256=" + e.contentSha256() + " entryHash=" + en.entryHash());
        }
        return 0;
    }

    private static int activation(String[] a) throws Exception {
        if (a.length == 0) { usage(); return 2; }
        switch (a[0]) {
            case "verify-chain": return verifyChain(a);
            case "duty-key-mint": return dutyKeyMint(Arrays.copyOfRange(a, 1, a.length));
            default:
                System.err.println("Usage: activation <verify-chain|duty-key-mint> ...");
                return 2;
        }
    }

    private static final String MINT_USAGE = "Usage: activation duty-key-mint <reg> <principal> --out <dir>"
            + " --by <p> --by-key <f> --approved-by <p> --approved-by-key <f>";

    /**
     * Mint a break-glass duty key: an Ed25519 keypair whose principal is granted BREAK_GLASS_APPROVE and
     * never APPROVE, so one person holding it can activate in an emergency and the record is marked as one.
     *
     * <p>The four-eyes of that later emergency happens HERE, ahead of it: two registered people must each
     * present a key file bound to their own registered public key. That is the same preflight an activation
     * runs, so a duty key cannot be conjured by one person. The mint writes no ledger entry -- the two-person
     * rule is enforced by demanding two bound keys, not by an audit trail -- and the command says so.
     */
    private static int dutyKeyMint(String[] a) throws Exception {
        String out = null, by = null, byKey = null, approvedBy = null, approvedByKey = null;
        List<String> pos = new ArrayList<>();
        for (int i = 0; i < a.length; i++) {
            switch (a[i]) {
                case "--out" -> out = (++i < a.length) ? a[i] : null;
                case "--by" -> by = (++i < a.length) ? a[i] : null;
                case "--by-key" -> byKey = (++i < a.length) ? a[i] : null;
                case "--approved-by" -> approvedBy = (++i < a.length) ? a[i] : null;
                case "--approved-by-key" -> approvedByKey = (++i < a.length) ? a[i] : null;
                default -> pos.add(a[i]);
            }
        }
        if (pos.size() < 2 || out == null || by == null || byKey == null
                || approvedBy == null || approvedByKey == null) {
            System.err.println(MINT_USAGE);
            return 2;
        }
        Path reg = Path.of(pos.get(0));
        String principal = pos.get(1);
        if (!IdentityGate.isSafePrincipal(principal)) {
            System.err.println("[GATE] duty-key-mint: invalid principal (allowed [A-Za-z0-9_.-], 1-64): " + principal);
            return 2;
        }
        dev.krillin.bifrost.core.identity.AuthorizedKeys authorized =
                dev.krillin.bifrost.core.identity.AuthorizedKeys.load(reg);
        // Refuse BEFORE minting. A second key for a principal is a ROTATION, which has its own command
        // and prints the retirement of the predecessor along with the successor; minting one here would
        // leave two live duty keys with nothing recording that the first was meant to be replaced.
        if (!authorized.allForPrincipal(principal).isEmpty()) {
            return refusedMint(List.of(new Violation("identity.principal.already-registered",
                    "'" + principal + "' already has a key line; mint a new duty principal, or run"
                    + " 'identity rotate-key' to replace this one's key")));
        }
        // Four-eyes at mint time: each key file must bind to its claimed principal's REGISTERED key, and the
        // two must resolve to different keys. Identical discipline to a signed activation, reused verbatim.
        List<Violation> pf = dev.krillin.bifrost.core.identity.KeyFileLedgerSigner.create(
                by, Path.of(byKey), approvedBy, Path.of(approvedByKey), authorized).preflight();
        if (!pf.isEmpty()) return refusedMint(pf);

        String pub = IdentityGate.writeKeyPair(principal, Path.of(out));
        Path dir = Path.of(out);
        System.err.println("[GATE] duty-key-mint principal=" + principal + " minted-by=" + by
                + " approved-by=" + approvedBy + " -> " + dir.resolve(principal + ".key")
                + " , " + dir.resolve(principal + ".pub"));
        System.out.println("[GATE] duty-key-mint principal=" + principal + " => MINTED");
        System.out.println("Append this line to " + reg.resolve("identity").resolve("authorized-keys.jsonl") + ":");
        System.out.println(IdentityGate.authorizedKeysLine(principal, pub));
        System.out.println("Then grant it BREAK_GLASS_APPROVE -- and never APPROVE -- in "
                + reg.resolve("identity").resolve("activation-policy.json")
                + ", one rule per target it may cover:");
        System.out.println("  {\"id\":\"r-bg-" + principal + "\",\"principal\":\"" + principal
                + "\",\"action\":\"break_glass_approve\",\"target\":\"<target>\",\"kind\":\"<kind>\",\"ref\":\"<ref>\"}");
        System.out.println("A principal holding both roles over overlapping resources is refused at policy load,"
                + " because it could approve normally and the emergency would never be recorded as one.");
        System.out.println("This mint is NOT recorded in the ledger. Its two-person rule is enforced by requiring"
                + " two registered, bound keys here -- there is no audit entry to point at afterwards.");
        System.out.println("Retire this key by REMOVING ITS POLICY GRANTS. Deleting its authorized-keys line"
                + " retroactively breaks every ledger entry it signed and the edge stops.");
        return 0;
    }

    private static int refusedMint(List<Violation> violations) {
        System.out.println("[GATE] REFUSED:");
        for (Violation v : violations) System.out.println("  - [" + v.rule() + "] " + v.detail());
        return 1;
    }

    private static int verifyChain(String[] a) throws Exception {
        if (a.length < 3) {
            System.err.println("Usage: activation verify-chain <reg> <target>");
            return 2;
        }
        Path reg = Path.of(a[1]);
        String target = a[2];
        ActivationLedger ledger = new ActivationLedger(reg);
        java.util.List<LedgerEntry> hist = ledger.history(target);
        if (hist.isEmpty()) { System.err.println("[GATE] verify-chain: no such target ledger: " + target); return 2; }
        ChainVerdict v = LedgerChain.verify(hist);   // verify the already-read history (avoid a 2nd file read)
        if (v.intact()) {
            System.out.println("[GATE] verify-chain target=" + target + " entries=" + hist.size() + " => INTACT");
            return 0;
        }
        System.out.println("[GATE] verify-chain target=" + target + " entries=" + hist.size()
                + " => BROKEN at index=" + v.brokenIndex() + " rule=" + v.rule());
        return 1;
    }

    private static void usage() {
        System.err.println("Usage: <activate|active|activation-log|activation> ...");
        System.err.println("       activation <verify-chain|duty-key-mint> ...");
    }
}
