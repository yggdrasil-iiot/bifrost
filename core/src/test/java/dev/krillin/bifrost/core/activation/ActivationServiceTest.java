package dev.krillin.bifrost.core.activation;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.*;
import java.util.List;
import dev.krillin.bifrost.core.conformance.MasterSpecStore;
import dev.krillin.bifrost.core.schema.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class ActivationServiceTest {
    Path reg;
    ActivationService svc;
    ActivationLedger led;
    @BeforeEach void setup(@TempDir Path dir) throws Exception {
        reg = dir;
        writeSpec("mix-recipe","1.0.0",1500);
        writeSpec("mix-recipe","1.1.0",1600);
        led = new ActivationLedger(reg);
        svc = new ActivationService(new RecipeArtifactResolver(reg), led,
                Clock.fixed(Instant.ofEpochMilli(42L), ZoneOffset.UTC));
    }
    void writeSpec(String ref,String ver,double rpm) throws Exception {
        MasterSpec s = new MasterSpec(ref,ver,"Line1","Line1-Mixer","1.0.0",List.of(new Setpoint("Rpm","Double",rpm)));
        Path f = new MasterSpecStore().file(reg,ref,ver); Files.createDirectories(f.getParent());
        JsonMapperFactory.create().writeValue(f.toFile(), s);
    }
    ActivationRequest req(String ver,String by,String appr,boolean rb){
        return new ActivationRequest("Line1","recipe","mix-recipe",ver,by,appr,rb);
    }
    @Test void happyPathAppendsSealedEvent() throws Exception {
        var v = svc.activate(req("1.0.0","alice","bob",false));
        assertTrue(v.ok());
        assertEquals("ACTIVATE", v.event().action());
        assertEquals(42L, v.event().activatedAt());
        assertNull(v.event().priorVersion());
        assertEquals(new RecipeArtifactResolver(reg).resolve("recipe","mix-recipe","1.0.0").orElseThrow().sha256(),
                     v.event().contentSha256());
        assertEquals("1.0.0", led.active("Line1","recipe","mix-recipe").orElseThrow().version());
    }
    @Test void priorVersionComputed() throws Exception {
        svc.activate(req("1.0.0","alice","bob",false));
        var v = svc.activate(req("1.1.0","alice","bob",false));
        assertEquals("1.0.0", v.event().priorVersion());
    }
    @Test void unresolvedArtifactRefused() throws Exception {
        var v = svc.activate(req("9.9.9","alice","bob",false));
        assertFalse(v.ok());
        assertTrue(hasRule(v,"activation.artifact.unresolved"));
        assertTrue(led.history("Line1").isEmpty());
    }
    @Test void missingApprovalRefused() throws Exception {
        assertTrue(hasRule(svc.activate(req("1.0.0","alice","  ",false)),"activation.approval.missing"));
    }
    @Test void selfApprovalRefused() throws Exception {
        assertTrue(hasRule(svc.activate(req("1.0.0","alice","alice",false)),"activation.approval.self"));
    }
    @Test void rollbackToUnknownVersionRefused() throws Exception {
        svc.activate(req("1.0.0","alice","bob",false));
        assertTrue(hasRule(svc.activate(req("1.1.0","alice","bob",true)),"activation.rollback.unknown-version"));
    }
    @Test void rollbackToKnownVersionRecordsReversal() throws Exception {
        svc.activate(req("1.0.0","alice","bob",false));
        svc.activate(req("1.1.0","alice","bob",false));
        var v = svc.activate(req("1.0.0","alice","bob",true));
        assertTrue(v.ok());
        assertEquals("ROLLBACK", v.event().action());
        assertEquals("1.0.0", led.active("Line1","recipe","mix-recipe").orElseThrow().version());
    }
    static boolean hasRule(ActivationVerdict v,String rule){
        return !v.ok() && v.violations().stream().anyMatch(x -> x.rule().equals(rule));
    }
}
