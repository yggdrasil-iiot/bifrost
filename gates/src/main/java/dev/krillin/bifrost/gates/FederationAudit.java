package dev.krillin.bifrost.gates;

import java.util.*;
import dev.krillin.bifrost.core.activation.LedgerEntry;

/** Pure cross-site aggregation of per-site activation ledgers into one federated audit view (F6).
 *  No IO — {@link FederationGate} reads the ledgers and calls {@link #merge}. */
public final class FederationAudit {

    /** One site's rolled-up view: its currently-active version (null if the ledger is empty) and event count. */
    public record SiteView(String site, String activeVersion, int eventCount) {}

    /** The federated view across all sites for one target. */
    public record CrossSiteView(String target, Map<String, SiteView> sites, int totalEvents) {}

    private FederationAudit() {}

    /** @param perSite insertion-ordered site-name -> that site's ledger history for {@code target}. */
    public static CrossSiteView merge(String target, Map<String, List<LedgerEntry>> perSite) {
        Map<String, SiteView> views = new LinkedHashMap<>();
        int total = 0;
        for (Map.Entry<String, List<LedgerEntry>> e : perSite.entrySet()) {
            List<LedgerEntry> hist = e.getValue();
            total += hist.size();
            String active = hist.isEmpty() ? null : hist.get(hist.size() - 1).event().version();
            views.put(e.getKey(), new SiteView(e.getKey(), active, hist.size()));
        }
        return new CrossSiteView(target, views, total);
    }
}
