package dev.krillin.bifrost.core.activation;

import org.junit.jupiter.api.Test;
import java.util.List;
import static dev.krillin.bifrost.core.activation.ActivationAction.*;
import static org.junit.jupiter.api.Assertions.*;

class ActivationAuthorizerTest {
    private final ActivationAuthorizer authz = new ActivationAuthorizer();

    private static ActivationPolicy policy(ActivationRule... rules) {
        return new ActivationPolicy("1", List.of(rules), "deny");
    }
    private static ActivationRule rule(String id, String p, ActivationAction a, String t, String k, String r) {
        return new ActivationRule(id, p, a, t, k, r);
    }

    @Test void first_matching_rule_allows_with_ruleId() {
        ActivationPolicy p = policy(rule("r-act", "alice", ACTIVATE, "Line1", "recipe", "mix"));
        AuthzDecision d = authz.authorize(p, "alice", ACTIVATE, "Line1", "recipe", "mix");
        assertTrue(d.allowed());
        assertEquals("r-act", d.ruleId());
    }

    @Test void no_matching_rule_denies_by_default() {
        ActivationPolicy p = policy(rule("r-act", "alice", ACTIVATE, "Line1", "recipe", "mix"));
        // wrong action (alice has ACTIVATE not APPROVE)
        assertFalse(authz.authorize(p, "alice", APPROVE, "Line1", "recipe", "mix").allowed());
        // wrong principal
        assertFalse(authz.authorize(p, "carol", ACTIVATE, "Line1", "recipe", "mix").allowed());
        // wrong resource
        assertFalse(authz.authorize(p, "alice", ACTIVATE, "Line2", "recipe", "mix").allowed());
    }

    @Test void empty_policy_denies_everything() {
        AuthzDecision d = authz.authorize(ActivationPolicy.denyAll(), "alice", ACTIVATE, "Line1", "recipe", "mix");
        assertFalse(d.allowed());
        assertTrue(d.reason().contains("deny-by-default"));
    }

    @Test void activate_and_approve_are_isolated() {
        ActivationPolicy p = policy(
                rule("r-act", "alice", ACTIVATE, "Line1", "recipe", "mix"),
                rule("r-app", "bob",   APPROVE,  "Line1", "recipe", "mix"));
        assertTrue(authz.authorize(p, "alice", ACTIVATE, "Line1", "recipe", "mix").allowed());
        assertTrue(authz.authorize(p, "bob",   APPROVE,  "Line1", "recipe", "mix").allowed());
        assertFalse(authz.authorize(p, "alice", APPROVE,  "Line1", "recipe", "mix").allowed(), "alice cannot approve");
        assertFalse(authz.authorize(p, "bob",   ACTIVATE, "Line1", "recipe", "mix").allowed(), "bob cannot activate");
    }

    @Test void wildcard_rule_matches_any_resource() {
        ActivationPolicy p = policy(rule("r-star", "alice", ACTIVATE, "*", "*", "*"));
        assertTrue(authz.authorize(p, "alice", ACTIVATE, "AnyLine", "recipe", "anyRef").allowed());
    }
}
