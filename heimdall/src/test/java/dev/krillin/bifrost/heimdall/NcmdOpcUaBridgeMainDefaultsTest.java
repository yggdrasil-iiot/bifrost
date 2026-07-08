package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;

import org.junit.jupiter.api.Test;

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
    }

    @Test
    void envOverridesWinWhenPresent() {
        Map<String, String> env = Map.of(
                "MQTT_URL", "tcp://broker.example:1884",
                "OPCUA_URL", "opc.tcp://opcua.example:4840",
                "SPB_GROUP", "Custom:Group",
                "SPB_EDGE", "custom-edge",
                "POLICY_PATH", "custom/policy.json");

        NcmdOpcUaBridgeMain.Config config = NcmdOpcUaBridgeMain.resolve(env::get);

        assertEquals("tcp://broker.example:1884", config.broker());
        assertEquals("opc.tcp://opcua.example:4840", config.opcua());
        assertEquals("Custom:Group", config.group());
        assertEquals("custom-edge", config.edge());
        assertEquals("custom/policy.json", config.policyPath());
    }
}
