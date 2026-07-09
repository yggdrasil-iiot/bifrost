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
 * The Bifrost:Line1 edge AUTHZ policy is deny-by-default: only the three declared nodes
 * (Rpm, Temp, ApplyRecipe trigger-only) may be commanded, and only with the declared TYPE.
 * NOTE: authz enforces WHO/WHAT + type only. Value-RANGE conformance (Rpm∈[0,3000]) was
 * migrated OUT of policy.json into the governed model and is now enforced by ② conformance
 * (see NcmdOpcUaBridgeTest's ② tests + run-ncmd-runtime-gate.sh T3), not by this authorizer.
 */
class NcmdBridgePolicyTest {

    private static final Path POLICY = Path.of("registry/policy.json");

    private CommandPolicy load() throws Exception {
        return AclMapperFactory.create().readValue(POLICY.toFile(), CommandPolicy.class);
    }

    private static final Target T = new Target("Bifrost:Line1", "recipe-edge", null);

    @Test void rpm_within_range_allowed() throws Exception {
        CommandAuthorizer a = new CommandAuthorizer();
        assertTrue(a.authorize(load(), new CommandRequest(T, "ns=2;s=Recipe/Rpm", 1500.0, "Double")).allowed());
    }

    @Test void rpm_above_max_allowed_by_authz_range_governed_by_conformance() throws Exception {
        // Range moved from policy.json to the governed model: authz now ALLOWS a type-ok Rpm=9999
        // (WHO/WHAT + type pass); the above-max DENY comes from ② conformance, proven in
        // NcmdOpcUaBridgeTest.above_max_denied_by_conformance_not_applied + run-ncmd-runtime-gate.sh T3.
        CommandAuthorizer a = new CommandAuthorizer();
        assertTrue(a.authorize(load(), new CommandRequest(T, "ns=2;s=Recipe/Rpm", 9999.0, "Double")).allowed());
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
