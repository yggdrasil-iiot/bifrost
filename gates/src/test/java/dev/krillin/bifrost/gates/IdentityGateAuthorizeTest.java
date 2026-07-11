package dev.krillin.bifrost.gates;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class IdentityGateAuthorizeTest {

    private void writePolicy(Path root) throws Exception {
        Path f = root.resolve("identity").resolve("activation-policy.json");
        Files.createDirectories(f.getParent());
        Files.writeString(f, "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
                + "{\"id\":\"r-act\",\"principal\":\"alice\",\"action\":\"activate\",\"target\":\"Line1\",\"kind\":\"recipe\",\"ref\":\"mix\"}]}");
    }

    @Test void allow_case_exits_0(@TempDir Path root) throws Exception {
        writePolicy(root);
        assertEquals(0, IdentityGate.run(new String[]{"authorize", root.toString(), "alice", "activate", "Line1", "recipe", "mix"}));
    }

    @Test void deny_case_exits_1(@TempDir Path root) throws Exception {
        writePolicy(root);
        assertEquals(1, IdentityGate.run(new String[]{"authorize", root.toString(), "alice", "approve", "Line1", "recipe", "mix"}));
        assertEquals(1, IdentityGate.run(new String[]{"authorize", root.toString(), "carol", "activate", "Line1", "recipe", "mix"}));
    }

    @Test void absent_policy_denies(@TempDir Path root) {
        assertEquals(1, IdentityGate.run(new String[]{"authorize", root.toString(), "alice", "activate", "Line1", "recipe", "mix"}));
    }

    @Test void usage_error_exits_2(@TempDir Path root) {
        assertEquals(2, IdentityGate.run(new String[]{"authorize", root.toString(), "alice", "activate"}));
        assertEquals(2, IdentityGate.run(new String[]{"authorize", root.toString(), "alice", "bogus-action", "Line1", "recipe", "mix"}));
    }
}
