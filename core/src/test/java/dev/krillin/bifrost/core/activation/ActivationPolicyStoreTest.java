package dev.krillin.bifrost.core.activation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class ActivationPolicyStoreTest {

    private static void writePolicy(Path root, String json) throws Exception {
        Path f = root.resolve("identity").resolve("activation-policy.json");
        Files.createDirectories(f.getParent());
        Files.writeString(f, json);
    }

    @Test void absent_file_is_deny_all(@TempDir Path root) {
        ActivationPolicy p = ActivationPolicyStore.load(root);
        assertTrue(p.rules().isEmpty());
        assertEquals("deny", p.defaultEffect());
    }

    @Test void loads_rules(@TempDir Path root) throws Exception {
        writePolicy(root, "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
                + "{\"id\":\"r1\",\"principal\":\"alice\",\"action\":\"activate\",\"target\":\"Line1\",\"kind\":\"recipe\",\"ref\":\"mix\"}]}");
        ActivationPolicy p = ActivationPolicyStore.load(root);
        assertEquals(1, p.rules().size());
        assertEquals("alice", p.rules().get(0).principal());
    }

    @Test void default_not_deny_is_a_coded_error(@TempDir Path root) throws Exception {
        writePolicy(root, "{\"version\":\"1\",\"default\":\"allow\",\"rules\":[]}");
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> ActivationPolicyStore.load(root));
        assertTrue(ex.getMessage().startsWith("activation.authz.policy.default-not-deny"), ex.getMessage());
    }

    @Test void malformed_json_is_a_coded_error(@TempDir Path root) throws Exception {
        writePolicy(root, "this is not json");
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> ActivationPolicyStore.load(root));
        assertTrue(ex.getMessage().startsWith("activation.authz.policy.read-error"), ex.getMessage());
    }

    @Test void policy_omitting_rules_key_loads_as_deny_all_not_npe(@TempDir Path root) throws Exception {
        writePolicy(root, "{\"version\":\"1\",\"default\":\"deny\"}");   // no "rules" key
        ActivationPolicy p = ActivationPolicyStore.load(root);
        assertTrue(p.rules().isEmpty(), "absent rules normalizes to empty (deny everything), not null");
        // and the authorizer denies cleanly rather than NPE-ing
        assertFalse(new ActivationAuthorizer().authorize(p, "alice", ActivationAction.ACTIVATE, "L", "recipe", "mix").allowed());
    }

    @Test void rule_missing_action_is_a_coded_error(@TempDir Path root) throws Exception {
        writePolicy(root, "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
                + "{\"id\":\"r1\",\"principal\":\"alice\",\"target\":\"L\",\"kind\":\"recipe\",\"ref\":\"mix\"}]}");   // no action
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> ActivationPolicyStore.load(root));
        assertTrue(ex.getMessage().startsWith("activation.authz.policy.malformed-rule"), ex.getMessage());
    }
}
