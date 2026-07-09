package dev.krillin.bifrost.core.activation;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ActivationLedgerTest {
    static ActivationEvent ev(String ref,String ver,String action){
        return new ActivationEvent("Line1","recipe",ref,ver,"sha","alice","bob",1L,null,action);
    }
    @Test void appendActiveHistory(@TempDir Path reg) throws Exception {
        ActivationLedger led = new ActivationLedger(reg);
        assertTrue(led.active("Line1","recipe","mix-recipe").isEmpty());
        led.append(ev("mix-recipe","1.0.0","ACTIVATE"));
        led.append(ev("other","5.0.0","ACTIVATE"));
        led.append(ev("mix-recipe","1.1.0","ACTIVATE"));
        assertEquals("1.1.0", led.active("Line1","recipe","mix-recipe").orElseThrow().version());
        assertEquals("5.0.0", led.active("Line1","recipe","other").orElseThrow().version());
        assertEquals(3, led.history("Line1").size());
        assertEquals("1.0.0", led.history("Line1").get(0).event().version());
    }
    @Test void missingTargetIsEmpty(@TempDir Path reg) throws Exception {
        assertTrue(new ActivationLedger(reg).history("Nope").isEmpty());
    }

    @Test void append_chains_entries(@TempDir java.nio.file.Path reg) throws Exception {
        ActivationLedger ledger = new ActivationLedger(reg);
        ledger.append(new ActivationEvent("Line1","recipe","mix","1.0.0","shaA","alice","bob",1L,null,"ACTIVATE"));
        ledger.append(new ActivationEvent("Line1","recipe","mix","1.1.0","shaB","alice","bob",2L,"1.0.0","ACTIVATE"));
        java.util.List<LedgerEntry> h = ledger.history("Line1");
        assertEquals(2, h.size());
        assertEquals(LedgerChain.GENESIS, h.get(0).prevHash());
        assertEquals(h.get(0).entryHash(), h.get(1).prevHash(), "2nd entry links to 1st");
        assertTrue(ledger.verifyChain("Line1").intact());
    }

    @Test void verifyChain_detects_out_of_band_edit(@TempDir java.nio.file.Path reg) throws Exception {
        ActivationLedger ledger = new ActivationLedger(reg);
        ledger.append(new ActivationEvent("Line1","recipe","mix","1.0.0","shaA","alice","bob",1L,null,"ACTIVATE"));
        ledger.append(new ActivationEvent("Line1","recipe","mix","1.1.0","shaB","alice","bob",2L,"1.0.0","ACTIVATE"));
        java.nio.file.Path f = reg.resolve("activation").resolve("Line1.jsonl");
        java.util.List<String> lines = java.nio.file.Files.readAllLines(f);
        lines.set(0, lines.get(0).replace("\"bob\"", "\"eve\""));
        java.nio.file.Files.write(f, lines);
        ChainVerdict v = ledger.verifyChain("Line1");
        assertFalse(v.intact());
        assertEquals(0, v.brokenIndex());
        assertEquals("ledger.chain.entry-hash-mismatch", v.rule());
    }

    @Test void active_still_returns_last_match_projected_to_event(@TempDir java.nio.file.Path reg) throws Exception {
        ActivationLedger ledger = new ActivationLedger(reg);
        ledger.append(new ActivationEvent("Line1","recipe","mix","1.0.0","shaA","alice","bob",1L,null,"ACTIVATE"));
        ledger.append(new ActivationEvent("Line1","recipe","mix","1.1.0","shaB","alice","bob",2L,"1.0.0","ACTIVATE"));
        assertEquals("1.1.0", ledger.active("Line1","recipe","mix").orElseThrow().version());
    }
}
