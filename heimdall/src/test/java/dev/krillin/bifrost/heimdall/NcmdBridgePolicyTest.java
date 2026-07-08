package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import dev.krillin.bifrost.core.acl.AclMapperFactory;
import dev.krillin.bifrost.core.acl.CommandAuthorizer;
import dev.krillin.bifrost.core.acl.CommandPolicy;
import dev.krillin.bifrost.core.acl.CommandRequest;
import dev.krillin.bifrost.core.acl.Target;

/**
 * The koshei-line1 edge policy is deny-by-default: only the three declared nodes
 * (Rpm 0-3000, Temp 0-450, ApplyRecipe trigger-only) may be commanded, and only
 * within their value domain. Everything else is denied at the edge, independently
 * of koshei's own D4 authorization.
 */
class NcmdBridgePolicyTest {

    private static final Path POLICY = Path.of("registry/koshei-line1-policy.json");

    private CommandPolicy load() throws Exception {
        return AclMapperFactory.create().readValue(POLICY.toFile(), CommandPolicy.class);
    }

    private static final Target T = new Target("Koshei:Line1", "recipe-edge", null);

    @Test void rpm_within_range_allowed() throws Exception {
        CommandAuthorizer a = new CommandAuthorizer();
        assertTrue(a.authorize(load(), new CommandRequest(T, "ns=2;s=Recipe/Rpm", 1500.0, "Double")).allowed());
    }

    @Test void rpm_above_max_denied() throws Exception {
        CommandAuthorizer a = new CommandAuthorizer();
        assertFalse(a.authorize(load(), new CommandRequest(T, "ns=2;s=Recipe/Rpm", 9999.0, "Double")).allowed());
    }

    @Test void temp_within_range_allowed() throws Exception {
        CommandAuthorizer a = new CommandAuthorizer();
        assertTrue(a.authorize(load(), new CommandRequest(T, "ns=2;s=Recipe/Temp", 200.0, "Double")).allowed());
    }

    @Test void activate_trigger_true_allowed() throws Exception {
        CommandAuthorizer a = new CommandAuthorizer();
        assertTrue(a.authorize(load(), new CommandRequest(T, "ns=2;s=Recipe/ApplyRecipe", true, "Boolean")).allowed());
    }

    @Test void unknown_node_denied_by_default() throws Exception {
        CommandAuthorizer a = new CommandAuthorizer();
        assertFalse(a.authorize(load(), new CommandRequest(T, "ns=2;s=Recipe/Secret", 1.0, "Double")).allowed());
    }
}
