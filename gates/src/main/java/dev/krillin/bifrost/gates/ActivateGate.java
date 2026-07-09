package dev.krillin.bifrost.gates;
import java.nio.file.Path;
import java.time.Clock;
import java.util.*;
import dev.krillin.bifrost.core.activation.*;
import dev.krillin.bifrost.core.schema.Violation;

/** Activation gate. Subcommands:
 *   activate <reg> <target> <kind> <ref> <version> --by <p> --approved-by <p> [--rollback]  (0 ok / 1 refused / 2 usage)
 *   active   <reg> <target> <kind> <ref>                                                    (prints active version+sha or none)
 *   activation-log <reg> <target>                                                           (prints the audit trail) */
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
                default: usage(); return 2;
            }
        } catch (Exception e) { System.err.println("[GATE] error: " + e.getMessage()); return 2; }
    }

    private static int activate(String[] a) throws Exception {
        String by = null, approvedBy = null; boolean rollback = false;
        List<String> pos = new ArrayList<>();
        for (int i = 0; i < a.length; i++) {
            switch (a[i]) {
                case "--by" -> by = (++i < a.length) ? a[i] : null;
                case "--approved-by" -> approvedBy = (++i < a.length) ? a[i] : null;
                case "--rollback" -> rollback = true;
                default -> pos.add(a[i]);
            }
        }
        if (pos.size() < 5) { System.err.println("Usage: activate <reg> <target> <kind> <ref> <version> --by <p> --approved-by <p> [--rollback]"); return 2; }
        Path reg = Path.of(pos.get(0));
        ActivationService svc = new ActivationService(new RecipeArtifactResolver(reg), new ActivationLedger(reg), Clock.systemUTC());
        ActivationVerdict v = svc.activate(new ActivationRequest(pos.get(1), pos.get(2), pos.get(3), pos.get(4), by, approvedBy, rollback));
        if (v.ok()) {
            ActivationEvent e = v.event();
            System.out.println("[GATE] activated target=" + e.target() + " kind=" + e.kind() + " ref=" + e.ref()
                + " version=" + e.version() + " action=" + e.action() + " by=" + e.activatedBy()
                + " approvedBy=" + e.approvedBy() + " sha256=" + e.contentSha256());
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
        List<ActivationEvent> hist = new ActivationLedger(Path.of(a[0])).history(a[1]);
        System.out.println("[GATE] activation-log target=" + a[1] + " events=" + hist.size());
        for (ActivationEvent e : hist)
            System.out.println("  " + e.action() + " " + e.kind() + "/" + e.ref() + "@" + e.version()
                + " by=" + e.activatedBy() + " approvedBy=" + e.approvedBy() + " prior=" + e.priorVersion() + " sha256=" + e.contentSha256());
        return 0;
    }

    private static void usage() { System.err.println("Usage: <activate|active|activation-log> ..."); }
}
