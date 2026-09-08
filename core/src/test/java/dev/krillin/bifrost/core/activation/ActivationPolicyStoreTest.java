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

    // ----- R4: a duty principal must not also hold APPROVE -----

    private static String rule(String id, String p, String action, String target) {
        return "{\"id\":\"" + id + "\",\"principal\":\"" + p + "\",\"action\":\"" + action
                + "\",\"target\":\"" + target + "\",\"kind\":\"recipe\",\"ref\":\"mix\"}";
    }

    /**
     * Holding both defeats the derived marking: the principal could approve normally and the
     * emergency would never be recorded as one. It is one JSON line away, and nothing caught it.
     */
    @Test void a_principal_holding_both_approve_roles_is_refused(@TempDir Path root) throws Exception {
        writePolicy(root, "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
                + rule("r1", "duty", "approve", "Line1") + ","
                + rule("r2", "duty", "break_glass_approve", "Line1") + "]}");
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> ActivationPolicyStore.load(root));
        assertTrue(e.getMessage().contains("activation.authz.policy.dual-approve-role"), e.getMessage());
    }

    /** A wildcard on either side still overlaps - the check must not be fooled by "*". */
    @Test void the_overlap_check_sees_through_a_wildcard(@TempDir Path root) throws Exception {
        writePolicy(root, "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
                + rule("r1", "duty", "approve", "*") + ","
                + rule("r2", "duty", "break_glass_approve", "Line1") + "]}");
        assertThrows(IllegalStateException.class, () -> ActivationPolicyStore.load(root));
    }

    /** Disjoint resources are legitimate: ordinary approver on one line, duty key on another. */
    @Test void the_two_roles_on_disjoint_resources_are_allowed(@TempDir Path root) throws Exception {
        writePolicy(root, "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
                + rule("r1", "duty", "approve", "Line1") + ","
                + rule("r2", "duty", "break_glass_approve", "Line2") + "]}");
        assertEquals(2, ActivationPolicyStore.load(root).rules().size());
    }

    /** Different principals holding the two roles is the normal shape, not a finding. */
    @Test void different_principals_may_hold_the_two_roles(@TempDir Path root) throws Exception {
        writePolicy(root, "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
                + rule("r1", "bob", "approve", "Line1") + ","
                + rule("r2", "duty", "break_glass_approve", "Line1") + "]}");
        assertEquals(2, ActivationPolicyStore.load(root).rules().size());
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
