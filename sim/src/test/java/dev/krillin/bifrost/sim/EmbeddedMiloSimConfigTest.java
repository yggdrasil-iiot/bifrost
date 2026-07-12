package dev.krillin.bifrost.sim;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import org.junit.jupiter.api.Test;

class EmbeddedMiloSimConfigTest {

    @Test void defaultCtor_keepsLegacyEndpoint() {
        EmbeddedMiloSim sim = new EmbeddedMiloSim();
        assertEquals(48400, sim.bindPort());
        assertEquals("localhost", sim.bindHost());
    }

    @Test void paramCtor_overridesEndpoint() {
        EmbeddedMiloSim sim = new EmbeddedMiloSim(48401, "localhost");
        assertEquals(48401, sim.bindPort());
        assertEquals("localhost", sim.bindHost());
    }

    @Test void simMain_resolvesPortFromEnv_defaulting48400() {
        assertEquals(EmbeddedMiloSim.BIND_PORT, SimMain.resolvePort(Map.of()));  // 48400
        assertEquals(48401, SimMain.resolvePort(Map.of("SIM_BIND_PORT", "48401")));
    }

    @Test void simMain_resolvesHostFromEnv_defaultingLocalhost() {
        assertEquals("localhost", SimMain.resolveHost(Map.of()));
        assertEquals("127.0.0.1", SimMain.resolveHost(Map.of("SIM_BIND_HOST", "127.0.0.1")));
    }
}
