package dev.krillin.bifrost.gates;

import java.nio.file.Path;
import java.util.*;
import dev.krillin.bifrost.core.activation.ActivationLedger;
import dev.krillin.bifrost.core.activation.LedgerEntry;

/** Federation gate. Subcommand:
 *   audit &lt;target&gt; --site &lt;name&gt;=&lt;registryDir&gt; [--site ...]   (0 printed / 2 usage)
 * Read-only: aggregates each site's activation ledger for the target into one cross-site view (F6). */
public final class FederationGate {

    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length == 0 || !"audit".equals(args[0])) {
            System.err.println("Usage: federation audit <target> --site <name>=<registryDir> [--site ...]");
            return 2;
        }
        String target = null;
        LinkedHashMap<String, Path> sites = new LinkedHashMap<>();
        for (int i = 1; i < args.length; i++) {
            if ("--site".equals(args[i])) {
                String spec = (++i < args.length) ? args[i] : null;
                if (spec == null || !spec.contains("=")) {
                    System.err.println("[GATE] error: --site expects <name>=<registryDir>");
                    return 2;
                }
                String[] nv = spec.split("=", 2);
                sites.put(nv[0], Path.of(nv[1]));
            } else if (target == null) {
                target = args[i];
            } else {
                System.err.println("[GATE] error: unexpected arg: " + args[i]);
                return 2;
            }
        }
        if (target == null || sites.isEmpty()) {
            System.err.println("Usage: federation audit <target> --site <name>=<registryDir> [--site ...]");
            return 2;
        }
        try {
            Map<String, List<LedgerEntry>> perSite = new LinkedHashMap<>();
            for (Map.Entry<String, Path> s : sites.entrySet()) {
                perSite.put(s.getKey(), new ActivationLedger(s.getValue()).history(target));
            }
            FederationAudit.CrossSiteView v = FederationAudit.merge(target, perSite);
            System.out.println("[GATE] federation-audit target=" + v.target()
                    + " sites=" + v.sites().size() + " totalEvents=" + v.totalEvents());
            for (FederationAudit.SiteView sv : v.sites().values()) {
                System.out.println("  site=" + sv.site()
                        + " active=" + (sv.activeVersion() == null ? "none" : sv.activeVersion())
                        + " events=" + sv.eventCount());
            }
            return 0;
        } catch (Exception e) {
            System.err.println("[GATE] error: " + e.getMessage());
            return 2;
        }
    }
}
