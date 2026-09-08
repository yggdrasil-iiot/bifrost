package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.krillin.bifrost.core.conformance.ConformancePolicy;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import dev.krillin.bifrost.core.schema.MasterSpec;
import dev.krillin.bifrost.core.schema.Member;
import dev.krillin.bifrost.core.schema.Range;
import dev.krillin.bifrost.core.schema.SemVer;
import dev.krillin.bifrost.core.schema.Setpoint;
import dev.krillin.bifrost.core.schema.UdtDefinition;

/**
 * Pure-logic test of {@link NcmdOpcUaBridgeMain#resolve} — the env-lookup seam extracted so the
 * daemon's defaults can be verified without touching a broker, an OPC-UA server, or the filesystem.
 */
class NcmdOpcUaBridgeMainDefaultsTest {

    @Test
    void neutralDefaultsWhenEnvAbsent() {
        NcmdOpcUaBridgeMain.Config config = NcmdOpcUaBridgeMain.resolve(key -> null);

        assertEquals("tcp://localhost:1883", config.broker());
        assertEquals("opc.tcp://localhost:48400", config.opcua());
        assertEquals("Bifrost:Line1", config.group());
        assertEquals("recipe-edge", config.edge());
        assertEquals("registry/policy.json", config.policyPath());
        assertEquals("registry", config.registryPath());
        assertNull(config.conformancePath());
    }

    @Test
    void envOverridesWinWhenPresent() {
        Map<String, String> env = Map.of(
                "MQTT_URL", "tcp://broker.example:1884",
                "OPCUA_URL", "opc.tcp://opcua.example:4840",
                "SPB_GROUP", "Custom:Group",
                "SPB_EDGE", "custom-edge",
                "POLICY_PATH", "custom/policy.json",
                "REGISTRY_PATH", "custom/registry",
                "CONFORMANCE_PATH", "custom/conformance.json");

        NcmdOpcUaBridgeMain.Config config = NcmdOpcUaBridgeMain.resolve(env::get);

        assertEquals("tcp://broker.example:1884", config.broker());
        assertEquals("opc.tcp://opcua.example:4840", config.opcua());
        assertEquals("Custom:Group", config.group());
        assertEquals("custom-edge", config.edge());
        assertEquals("custom/policy.json", config.policyPath());
        assertEquals("custom/registry", config.registryPath());
        assertEquals("custom/conformance.json", config.conformancePath());
    }

    @Test
    void loadConformance_nullPath_returnsOff() throws Exception {
        NcmdOpcUaBridgeMain.Config config = new NcmdOpcUaBridgeMain.Config(
                "tcp://localhost:1883", "opc.tcp://localhost:48400", "Bifrost:Line1", "recipe-edge",
                "registry/policy.json", "registry", null, null, null, false, false, "file", null, false, 0, 4, null, false, 1024, null, false, 30);

        NcmdOpcUaBridgeMain.Conformance c = NcmdOpcUaBridgeMain.loadConformance(config);

        assertNull(c.def());
        assertNull(c.policy());
        assertNull(c.recipe());
    }

    @Test
    void loadConformance_recipeMode_returnsTrio(@TempDir Path tmp) throws Exception {
        ObjectMapper mapper = JsonMapperFactory.create();
        Path registryDir = tmp.resolve("registry");

        // equipment def at registry/udt/Line1-Mixer/1.0.0.json
        UdtDefinition mixer = new UdtDefinition("Line1-Mixer", SemVer.parse("1.0.0"),
                List.of(new Member("Rpm", "Double", null, new Range(0, 3000))), List.of(), null);
        Path udtDir = registryDir.resolve("udt").resolve("Line1-Mixer");
        Files.createDirectories(udtDir);
        mapper.writeValue(udtDir.resolve("1.0.0.json").toFile(), mixer);

        // active recipe at registry/spec/Mix-Recipe/1.0.0.json
        MasterSpec recipe = new MasterSpec("Mix-Recipe", "1.0.0", "Busan", "Line1-Mixer", "1.0.0",
                List.of(new Setpoint("Rpm", "Double", 1500)));
        Path specDir = registryDir.resolve("spec").resolve("Mix-Recipe");
        Files.createDirectories(specDir);
        mapper.writeValue(specDir.resolve("1.0.0.json").toFile(), recipe);

        // conformance policy file (recipe-mode), outside the registry
        ConformancePolicy cp = new ConformancePolicy("MixPolicy", "1.0.0", "Line1-Mixer", "1.0.0",
                new ConformancePolicy.Dial("recipe", "Mix-Recipe", "1.0.0", 0.05),
                List.of(), List.of());
        Path cpFile = tmp.resolve("conformance.json");
        mapper.writeValue(cpFile.toFile(), cp);

        NcmdOpcUaBridgeMain.Config config = new NcmdOpcUaBridgeMain.Config(
                "tcp://localhost:1883", "opc.tcp://localhost:48400", "Bifrost:Line1", "recipe-edge",
                "registry/policy.json", registryDir.toString(), cpFile.toString(), null, null, false, false, "file", null, false, 0, 4, null, false, 1024, null, false, 30);

        NcmdOpcUaBridgeMain.Conformance c = NcmdOpcUaBridgeMain.loadConformance(config);

        assertNotNull(c.policy());
        assertEquals("Line1-Mixer", c.policy().equipmentRef());
        assertNotNull(c.def());
        assertEquals("Line1-Mixer", c.def().templateRef());
        assertNotNull(c.recipe());
        assertEquals("Mix-Recipe", c.recipe().specRef());
    }

    // ----- R5: certificate lifetime -----

    @Test void cert_warn_days_defaults_to_thirty_and_parses() {
        assertEquals(30, NcmdOpcUaBridgeMain.resolve(k -> null).certWarnDays());
        assertEquals(7, NcmdOpcUaBridgeMain.resolve(
                k -> "HEIMDALL_CERT_WARN_DAYS".equals(k) ? "7" : null).certWarnDays());
        assertEquals(30, NcmdOpcUaBridgeMain.resolve(
                k -> "HEIMDALL_CERT_WARN_DAYS".equals(k) ? "soon" : null).certWarnDays(),
                "an unparseable value falls back loudly rather than becoming something else");
    }

    @Test void health_omits_the_cert_metric_when_no_identity_is_configured() {
        assertFalse(new EdgeHealth().report().contains("cert_days_remaining"),
                "reporting a zero here would read as 'expires today'");
    }

    @Test void health_reports_days_remaining_when_an_identity_is_configured() {
        EdgeHealth h = new EdgeHealth();
        h.certDaysRemaining(412);
        assertTrue(h.report().contains("cert_days_remaining 412"), h.report());
        h.certDaysRemaining(-3);
        assertTrue(h.report().contains("cert_days_remaining -3"), h.report());
    }

    /** An expired certificate is a transport fault, and health already reports its consequence. */
    @Test void an_expired_certificate_does_not_by_itself_flip_health(@org.junit.jupiter.api.io.TempDir
            java.nio.file.Path dir) throws Exception {
        EdgeHealth h = new EdgeHealth();
        h.brokerConnected();
        h.plantReachable();
        EdgeIdentity id = EdgeIdentity.loadOrCreate(dir, "urn:bifrost:heimdall:t:e");
        NcmdOpcUaBridgeMain.reportCertificateLifetime(id, h, 30,
                java.time.Clock.fixed(id.notAfter().plusSeconds(86400), java.time.ZoneOffset.UTC));
        assertTrue(h.healthy(), "expiry is diagnosed by the days metric, not by hiding it in one boolean");
        assertTrue(h.report().contains("cert_days_remaining -1"), h.report());
    }
}
