package dev.krillin.bifrost.gates;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.List;
import dev.krillin.bifrost.core.conformance.MasterSpecStore;
import dev.krillin.bifrost.core.schema.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class ActivateGateTest {
    Path reg;
    @BeforeEach void setup(@TempDir Path dir) throws Exception {
        reg = dir;
        MasterSpec s = new MasterSpec("mix-recipe","1.0.0","Line1","Line1-Mixer","1.0.0",
            List.of(new Setpoint("Rpm","Double",1500)));
        Path f = new MasterSpecStore().file(reg,"mix-recipe","1.0.0"); Files.createDirectories(f.getParent());
        JsonMapperFactory.create().writeValue(f.toFile(), s);
    }
    int run(String... a){ return ActivateGate.run(a); }

    @Test void activateThenActive() {
        assertEquals(0, run("activate", reg.toString(), "Line1","recipe","mix-recipe","1.0.0","--by","alice","--approved-by","bob"));
        assertEquals(0, run("active", reg.toString(), "Line1","recipe","mix-recipe"));
    }
    @Test void selfApprovalRefused() {
        assertEquals(1, run("activate", reg.toString(), "Line1","recipe","mix-recipe","1.0.0","--by","alice","--approved-by","alice"));
    }
    @Test void missingApprovalRefused() {
        assertEquals(1, run("activate", reg.toString(), "Line1","recipe","mix-recipe","1.0.0","--by","alice"));
    }
    @Test void unresolvedRefused() {
        assertEquals(1, run("activate", reg.toString(), "Line1","recipe","mix-recipe","9.9.9","--by","alice","--approved-by","bob"));
    }
    @Test void usageErrors() {
        assertEquals(2, run("activate", reg.toString(), "Line1"));
        assertEquals(2, run());
    }
    @Test void logListsHistory() {
        run("activate", reg.toString(), "Line1","recipe","mix-recipe","1.0.0","--by","alice","--approved-by","bob");
        assertEquals(0, run("activation-log", reg.toString(), "Line1"));
    }

    @Test void verify_chain_intact_exit0(@TempDir java.nio.file.Path reg) throws Exception {
        var ledger = new dev.krillin.bifrost.core.activation.ActivationLedger(reg);
        ledger.append(new dev.krillin.bifrost.core.activation.ActivationEvent("Line1","recipe","mix","1.0.0","shaA","alice","bob",1L,null,"ACTIVATE"));
        ledger.append(new dev.krillin.bifrost.core.activation.ActivationEvent("Line1","recipe","mix","1.1.0","shaB","alice","bob",2L,"1.0.0","ACTIVATE"));
        assertEquals(0, ActivateGate.run(new String[]{"activation","verify-chain", reg.toString(), "Line1"}));
        assertEquals(0, GatesCli.run(new String[]{"activation","verify-chain", reg.toString(), "Line1"}));
    }

    @Test void verify_chain_tampered_exit1(@TempDir java.nio.file.Path reg) throws Exception {
        var ledger = new dev.krillin.bifrost.core.activation.ActivationLedger(reg);
        ledger.append(new dev.krillin.bifrost.core.activation.ActivationEvent("Line1","recipe","mix","1.0.0","shaA","alice","bob",1L,null,"ACTIVATE"));
        java.nio.file.Path f = reg.resolve("activation").resolve("Line1.jsonl");
        java.util.List<String> lines = java.nio.file.Files.readAllLines(f);
        lines.set(0, lines.get(0).replace("\"bob\"","\"eve\""));
        java.nio.file.Files.write(f, lines);
        assertEquals(1, ActivateGate.run(new String[]{"activation","verify-chain", reg.toString(), "Line1"}));
    }

    @Test void verify_chain_no_such_target_exit2(@TempDir java.nio.file.Path reg) throws Exception {
        assertEquals(2, ActivateGate.run(new String[]{"activation","verify-chain", reg.toString(), "Nope"}));
    }
}
