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
}
