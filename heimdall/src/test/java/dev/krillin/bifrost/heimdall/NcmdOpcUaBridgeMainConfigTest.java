package dev.krillin.bifrost.heimdall;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import org.junit.jupiter.api.Test;

class NcmdOpcUaBridgeMainConfigTest {

    // ----- R3: OPC-UA identity -----

    @Test
    void identityDirDefaultsToUnset() {
        assertNull(NcmdOpcUaBridgeMain.resolve(k -> null).identityDir());
    }

    @Test
    void identityDirIsReadFromTheEnvironment() {
        assertEquals("/etc/heimdall/pki", NcmdOpcUaBridgeMain.resolve(
                k -> "HEIMDALL_IDENTITY_DIR".equals(k) ? "/etc/heimdall/pki" : null).identityDir());
    }

    /**
     * Derived, and per-edge: two edges must be two principals to the server, or a per-edge write
     * permission cannot mean anything.
     */
    @Test
    void applicationUriIsDerivedFromGroupAndEdge() {
        assertEquals("urn:bifrost:heimdall:Bifrost-Line1:recipe-edge",
                NcmdOpcUaBridgeMain.applicationUri("Bifrost:Line1", "recipe-edge"));
        assertNotEquals(NcmdOpcUaBridgeMain.applicationUri("Bifrost:Line1", "recipe-edge"),
                        NcmdOpcUaBridgeMain.applicationUri("Bifrost:Line1", "mixer-edge"));
    }

    // ----- R0: health endpoint + apply stripes -----

    @Test
    void healthPortDefaultsTo9090AndZeroDisables() {
        assertEquals(9090, NcmdOpcUaBridgeMain.resolve(k -> null).healthPort());
        assertEquals(0, NcmdOpcUaBridgeMain.resolve(k -> "HEALTH_PORT".equals(k) ? "0" : null).healthPort());
    }

    @Test
    void healthPortIsReadFromTheEnvironment() {
        assertEquals(9091, NcmdOpcUaBridgeMain.resolve(k -> "HEALTH_PORT".equals(k) ? "9091" : null).healthPort());
    }

    /** A garbled port must not silently pick a different one — fall to the default and say so. */
    @Test
    void anUnparseableHealthPortFallsToTheDefault() {
        assertEquals(9090, NcmdOpcUaBridgeMain.resolve(k -> "HEALTH_PORT".equals(k) ? "banana" : null).healthPort());
    }

    @Test
    void applyThreadsDefaultToFour() {
        assertEquals(4, NcmdOpcUaBridgeMain.resolve(k -> null).applyThreads());
    }

    /** The default alone is satisfied by a hard-coded 4 — prove the variable is actually read. */
    @Test
    void applyThreadsAreReadFromTheEnvironment() {
        assertEquals(8, NcmdOpcUaBridgeMain.resolve(
                k -> "HEIMDALL_APPLY_THREADS".equals(k) ? "8" : null).applyThreads());
    }
    @Test void activationEnvResolved() {
        var cfg = NcmdOpcUaBridgeMain.resolve(Map.of(
            "ACTIVATION_TARGET","Line1", "ACTIVATION_PATH","/reg")::get);
        assertEquals("Line1", cfg.activationTarget());
        assertEquals("/reg", cfg.activationPath());
    }
    @Test void activationDefaultsNull() {
        var cfg = NcmdOpcUaBridgeMain.resolve(Map.<String,String>of()::get);
        assertNull(cfg.activationTarget());
        assertNull(cfg.activationPath());
    }

    // ENFORCEMENT_LOG_ONLY — the one flag whose OFF is the STRICT setting, so an absent or
    // unparseable value must land on full enforcement rather than on the permissive side.
    @Test void logOnlyDefaultsOff() {
        assertFalse(NcmdOpcUaBridgeMain.resolve(Map.<String,String>of()::get).enforcementLogOnly());
    }

    @Test void logOnlyAcceptsTrueOnOne() {
        for (String v : new String[]{"true", "TRUE", "on", "1"}) {
            assertTrue(NcmdOpcUaBridgeMain.resolve(Map.of("ENFORCEMENT_LOG_ONLY", v)::get).enforcementLogOnly(), v);
        }
    }

    @Test void logOnlyUnrecognizedFallsToEnforcing() {
        for (String v : new String[]{"yes", "shadow", "0.5"}) {
            assertFalse(NcmdOpcUaBridgeMain.resolve(Map.of("ENFORCEMENT_LOG_ONLY", v)::get).enforcementLogOnly(), v);
        }
    }

    // The shared flag parser must not have changed how the REQUIRE_* bars resolve.
    @Test void requireFlagsStillParseOnAndAnchoredImpliesSigned() {
        var signed = NcmdOpcUaBridgeMain.resolve(Map.of("REQUIRE_SIGNED_ACTIVATION", "on")::get);
        assertTrue(signed.requireSignedActivation());
        assertFalse(signed.requireAnchoredActivation());
        var anchored = NcmdOpcUaBridgeMain.resolve(Map.of("REQUIRE_ANCHORED_ACTIVATION", "1")::get);
        assertTrue(anchored.requireAnchoredActivation());
        assertTrue(anchored.requireSignedActivation(), "anchored presupposes authN");
        var garbage = NcmdOpcUaBridgeMain.resolve(Map.of("REQUIRE_SIGNED_ACTIVATION", "maybe")::get);
        assertFalse(garbage.requireSignedActivation());
    }
}
