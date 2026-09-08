package dev.krillin.bifrost.heimdall;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.List;
import dev.krillin.bifrost.core.activation.*;
import dev.krillin.bifrost.core.conformance.*;
import dev.krillin.bifrost.core.schema.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class LoadConformanceActivationTest {
    Path reg, confFile;
    @BeforeEach void setup(@TempDir Path dir) throws Exception {
        reg = dir.resolve("registry"); Files.createDirectories(reg);
        Path udt = reg.resolve("udt").resolve("Line1-Mixer").resolve("1.0.0.json"); Files.createDirectories(udt.getParent());
        JsonMapperFactory.create().writeValue(udt.toFile(),
            new UdtDefinition("Line1-Mixer", SemVer.parse("1.0.0"),
                List.of(new Member("Rpm","Double","corp:rpm", new Range(0,3000))), List.of(), null));
        writeSpec("mix-recipe","1.0.0",1500);
        writeSpec("mix-recipe","1.1.0",1600);
        ConformancePolicy cp = new ConformancePolicy("Line1-pol","1.0.0","Line1-Mixer","1.0.0",
            new ConformancePolicy.Dial("recipe","mix-recipe","0.0.0",0.0), List.of(), List.of());
        confFile = dir.resolve("conformance.json");
        JsonMapperFactory.create().writeValue(confFile.toFile(), cp);
    }
    void writeSpec(String ref,String ver,double rpm) throws Exception {
        MasterSpec s = new MasterSpec(ref,ver,"Line1","Line1-Mixer","1.0.0",List.of(new Setpoint("Rpm","Double",rpm)));
        Path f = new MasterSpecStore().file(reg,ref,ver); Files.createDirectories(f.getParent());
        JsonMapperFactory.create().writeValue(f.toFile(), s);
    }
    void activate(String ver) throws Exception {
        new ActivationService(new RecipeArtifactResolver(reg), new ActivationLedger(reg), Clock.systemUTC())
            .activate(new ActivationRequest("Line1","recipe","mix-recipe",ver,"alice","bob",false));
    }
    NcmdOpcUaBridgeMain.Config cfg() {
        return new NcmdOpcUaBridgeMain.Config("tcp://x","opc.tcp://x","g","e","p",
            reg.toString(), confFile.toString(), reg.toString(), "Line1", false, false, "file", null, false,
            0, 4, null, false, 1024);
    }

    @Test void bindsLedgerActiveVersionNotDial() throws Exception {
        activate("1.1.0");
        var conf = NcmdOpcUaBridgeMain.loadConformance(cfg());
        assertEquals(1600.0, conf.recipe().setpoints().get(0).value());
    }
    @Test void noActivePointerFailsClosed() {
        var ex = assertThrows(Exception.class, () -> NcmdOpcUaBridgeMain.loadConformance(cfg()));
        assertTrue(ex.getMessage().contains("activation.edge.no-active-pointer"));
    }
    @Test void tamperedBytesFailClosed() throws Exception {
        activate("1.0.0");
        Path f = new MasterSpecStore().file(reg,"mix-recipe","1.0.0");
        Files.writeString(f, Files.readString(f) + " ");
        var ex = assertThrows(Exception.class, () -> NcmdOpcUaBridgeMain.loadConformance(cfg()));
        assertTrue(ex.getMessage().contains("activation.edge.content-mismatch"));
    }
    @Test void brokenLedgerChainFailsClosed() throws Exception {
        activate("1.0.0");
        // out-of-band tamper: editing approvedBy on entry-0's raw JSONL line breaks its self-hash
        // (approvedBy "bob" occurs once), so verifyChain fails BEFORE the active pointer is read.
        Path f = reg.resolve("activation").resolve("Line1.jsonl");
        List<String> lines = Files.readAllLines(f);
        lines.set(0, lines.get(0).replace("\"bob\"", "\"eve\""));
        Files.write(f, lines);
        var ex = assertThrows(Exception.class, () -> NcmdOpcUaBridgeMain.loadConformance(cfg()));
        assertTrue(ex.getMessage().contains("activation.edge.ledger-chain-broken"), ex.getMessage());
    }
}
