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
                "registry/policy.json", "registry", null, null, null);

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
                "registry/policy.json", registryDir.toString(), cpFile.toString(), null, null);

        NcmdOpcUaBridgeMain.Conformance c = NcmdOpcUaBridgeMain.loadConformance(config);

        assertNotNull(c.policy());
        assertEquals("Line1-Mixer", c.policy().equipmentRef());
        assertNotNull(c.def());
        assertEquals("Line1-Mixer", c.def().templateRef());
        assertNotNull(c.recipe());
        assertEquals("Mix-Recipe", c.recipe().specRef());
    }
}
