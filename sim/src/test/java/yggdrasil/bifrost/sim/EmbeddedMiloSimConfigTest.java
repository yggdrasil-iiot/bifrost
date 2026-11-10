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
}
