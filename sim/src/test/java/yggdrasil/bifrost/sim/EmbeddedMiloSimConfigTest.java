package yggdrasil.bifrost.sim;

import static org.junit.jupiter.api.Assertions.*;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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

    // ----- R3: the two security toggles, which must not be the only untested ones -----

    @Test void simMain_requireIdentity_defaultsOff() {
        assertFalse(SimMain.resolveRequireIdentity(Map.of()));
        assertTrue(SimMain.resolveRequireIdentity(Map.of("SIM_REQUIRE_IDENTITY", "on")));
        assertTrue(SimMain.resolveRequireIdentity(Map.of("SIM_REQUIRE_IDENTITY", "true")));
        assertTrue(SimMain.resolveRequireIdentity(Map.of("SIM_REQUIRE_IDENTITY", "1")));
        assertFalse(SimMain.resolveRequireIdentity(Map.of("SIM_REQUIRE_IDENTITY", "off")));
    }

    /** A typo must not silently mean "off" without saying so — same rule as heimdall's flag(). */
    @Test void simMain_requireIdentity_unrecognisedFallsOff() {
        assertFalse(SimMain.resolveRequireIdentity(Map.of("SIM_REQUIRE_IDENTITY", "yes-please")));
    }

    @Test void simMain_resolvesGovernedThumbprint() {
        assertNull(SimMain.resolveGovernedThumbprint(Map.of()));
        assertNull(SimMain.resolveGovernedThumbprint(Map.of("SIM_GOVERNED_THUMBPRINT", "   ")));
        assertEquals("aabb", SimMain.resolveGovernedThumbprint(Map.of("SIM_GOVERNED_THUMBPRINT", " aabb ")));
    }

    /**
     * The secured endpoint's certificate is minted fresh on every start, so the only way an edge can
     * trust exactly this server is for the sim to hand the certificate out. It is the certificate
     * the endpoint presents, byte for byte.
     */
    @Test void theSecuredSimExportsTheCertificateItPresents(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("sim-server.der");
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim(EmbeddedMiloSim.BIND_PORT, EmbeddedMiloSim.DEFAULT_BIND_HOST,
                true, null).start()) {
            SimMain.exportServerCertificate(sim, out.toString());
            X509Certificate written = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(out)));
            assertArrayEquals(sim.serverCertificate().getEncoded(), written.getEncoded());
            assertTrue(written.getSubjectAlternativeNames().toString().contains("urn:bifrost:opcua:sim-server"));
        }
    }

    /** The anonymous sim presents no certificate; asking for one is a gate wiring error, said so. */
    @Test void theAnonymousSimHasNoCertificateToExport(@TempDir Path tmp) throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            assertNull(sim.serverCertificate());
            var e = assertThrows(IllegalStateException.class,
                    () -> SimMain.exportServerCertificate(sim, tmp.resolve("x.der").toString()));
            assertTrue(e.getMessage().contains("SIM_REQUIRE_IDENTITY"), e.getMessage());
        }
    }

    // ----- bifrost.sim.scanMs: the one scan period, resolved before startup, no silent fallback -----

    @Test void scanMs_absentDefaultsTo1000() {
        assertEquals(1000L, SimMain.resolveScanMs(null));
        assertEquals(EmbeddedMiloSim.SimNamespace.SCAN_MS, SimMain.resolveScanMs(null));
    }

    @Test void scanMs_acceptsTheWholeRange() {
        assertEquals(250L, SimMain.resolveScanMs("250"));
        assertEquals(1L, SimMain.resolveScanMs("1"));
        assertEquals(86_400_000L, SimMain.resolveScanMs("86400000"));
    }

    /** Blank, malformed, overflowing and out-of-range values fail the start, naming the property. */
    @Test void scanMs_rejectsEveryBadValueWithAMessage() {
        for (String bad : new String[] {"", "   ", "abc", "1.5", "10ms", "0", "-5", "86400001",
                "99999999999999999999"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> SimMain.resolveScanMs(bad), "'" + bad + "' must be refused");
            assertTrue(e.getMessage().contains("bifrost.sim.scanMs"), e.getMessage());
        }
    }

    @Test void scanMs_defaultCtorKeepsTheLegacyPeriod() {
        assertEquals(1000L, new EmbeddedMiloSim().scanMs());
        assertEquals(1000L, new EmbeddedMiloSim(48401, "localhost").scanMs());
        assertEquals(1000L, new EmbeddedMiloSim(48401, "localhost", false, null).scanMs());
        assertEquals(40L, new EmbeddedMiloSim(48401, "localhost", false, null, 40).scanMs());
    }

    @Test void scanMs_ctorRefusesAnOutOfRangePeriod() {
        assertThrows(IllegalArgumentException.class,
                () -> new EmbeddedMiloSim(48401, "localhost", false, null, 0));
        assertThrows(IllegalArgumentException.class,
                () -> new EmbeddedMiloSim(48401, "localhost", false, null, 86_400_001L));
    }

    /**
     * The configured period drives the shared scheduler: at 20 ms, Mixer1's member is re-stamped
     * several times within a window in which the 1000 ms default could not re-stamp it once.
     */
    @Test void scanMs_smallPeriodIsHonouredByTheScheduler() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim(EmbeddedMiloSim.BIND_PORT, EmbeddedMiloSim.DEFAULT_BIND_HOST,
                false, null, 20).start()) {
            var client = SimStatusControlTest.connect();
            try {
                long last = SimStatusControlTest.read(client, SimStatusControlTest.TEMP).getSourceTime().getUtcTime();
                int restamps = 0;
                long deadline = System.currentTimeMillis() + 800;
                while (restamps < 3 && System.currentTimeMillis() < deadline) {
                    Thread.sleep(5);
                    long t = SimStatusControlTest.read(client, SimStatusControlTest.TEMP).getSourceTime().getUtcTime();
                    if (t > last) {
                        restamps++;
                        last = t;
                    }
                }
                assertTrue(restamps >= 3, "re-stamped " + restamps + " times in 800 ms at a 20 ms period");
            } finally {
                client.disconnect();
            }
        }
    }
}
