package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FederationGateTest {

    @Test void noArgs_returnsTwo() {
        assertEquals(2, FederationGate.run(new String[]{}));
    }

    @Test void unknownSubcommand_returnsTwo() {
        assertEquals(2, FederationGate.run(new String[]{"bogus", "Line1"}));
    }

    @Test void auditWithoutSites_returnsTwo() {
        assertEquals(2, FederationGate.run(new String[]{"audit", "Line1"}));
    }

    @Test void auditWithMalformedSite_returnsTwo() {
        assertEquals(2, FederationGate.run(new String[]{"audit", "Line1", "--site", "noequalssign"}));
    }

    @Test void auditEmptyRegistry_printsNoneActive_returnsZero(@TempDir Path d) throws Exception {
        // an empty registry has no ledger for the target -> history() is empty -> active=none, exit 0.
        Files.createDirectories(d.resolve("busan"));
        int rc = FederationGate.run(new String[]{"audit", "Line1", "--site", "busan=" + d.resolve("busan")});
        assertEquals(0, rc);
    }
}
