package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import dev.krillin.bifrost.core.activation.ActivationEvent;
import dev.krillin.bifrost.core.activation.LedgerEntry;
import org.junit.jupiter.api.Test;

class FederationAuditTest {

    private static LedgerEntry ev(String site, String version, String by, long at, String action) {
        ActivationEvent e = new ActivationEvent("Line1", "recipe", "mix-recipe", version,
                "sha-" + version, by, "bob", at, null, action);
        return LedgerEntry.unsigned(e, "PREV", "HASH-" + site + "-" + version);
    }

    @Test void merge_producesPerSiteActiveVersion_andTotalEvents() {
        Map<String, List<LedgerEntry>> perSite = new LinkedHashMap<>();
        perSite.put("busan", List.of(ev("busan", "1.0.0", "alice", 100, "ACTIVATE"),
                                     ev("busan", "1.1.0", "alice", 200, "ACTIVATE")));
        perSite.put("ulsan", List.of(ev("ulsan", "1.0.0", "carol", 150, "ACTIVATE")));

        FederationAudit.CrossSiteView v = FederationAudit.merge("Line1", perSite);

        assertEquals(2, v.sites().size());
        assertEquals("1.1.0", v.sites().get("busan").activeVersion());  // last ACTIVATE wins
        assertEquals("1.0.0", v.sites().get("ulsan").activeVersion());
        assertEquals(3, v.totalEvents());
    }

    @Test void merge_rollbackTailMakesActiveVersionThePriorTarget() {
        Map<String, List<LedgerEntry>> perSite = new LinkedHashMap<>();
        perSite.put("busan", List.of(ev("busan", "1.0.0", "alice", 100, "ACTIVATE"),
                                     ev("busan", "1.1.0", "alice", 200, "ACTIVATE"),
                                     ev("busan", "1.0.0", "alice", 300, "ROLLBACK")));
        FederationAudit.CrossSiteView v = FederationAudit.merge("Line1", perSite);
        assertEquals("1.0.0", v.sites().get("busan").activeVersion());  // rollback tail => version field of last entry
        assertEquals(3, v.sites().get("busan").eventCount());
    }

    @Test void merge_emptySiteReportsNoneActive() {
        Map<String, List<LedgerEntry>> perSite = new LinkedHashMap<>();
        perSite.put("busan", List.of());
        FederationAudit.CrossSiteView v = FederationAudit.merge("Line1", perSite);
        assertNull(v.sites().get("busan").activeVersion());
        assertEquals(0, v.totalEvents());
    }
}
