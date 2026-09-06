package dev.krillin.bifrost.heimdall;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import org.junit.jupiter.api.Test;

class NcmdOpcUaBridgeMainConfigTest {
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
