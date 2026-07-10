package dev.krillin.bifrost.gates;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class ActivateGateSignedTest {

    @Test void only_one_key_flag_is_usage_error(@TempDir Path root) throws Exception {
        int code = ActivateGate.run(new String[]{"activate", root.toString(), "Line1","recipe","mix","1.0.0",
                "--by","alice","--approved-by","bob","--by-key","/no/such.key"});
        assertEquals(2, code, "one key flag without the other => usage error");
    }
}
