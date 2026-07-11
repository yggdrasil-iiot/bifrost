package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ActivationPolicyTest {
    private final ObjectMapper mapper = JsonMapperFactory.create();

    @Test void rule_wildcard_and_exact_matching() {
        // exact rule
        ActivationRule exact = new ActivationRule("r1", "alice", ActivationAction.ACTIVATE, "Line1", "recipe", "mix");
        assertTrue(exact.matches("alice", ActivationAction.ACTIVATE, "Line1", "recipe", "mix"));
        assertFalse(exact.matches("bob",   ActivationAction.ACTIVATE, "Line1", "recipe", "mix"), "principal differs");
        assertFalse(exact.matches("alice", ActivationAction.APPROVE,  "Line1", "recipe", "mix"), "action differs");
        assertFalse(exact.matches("alice", ActivationAction.ACTIVATE, "Line2", "recipe", "mix"), "target differs");
        // wildcard rule (null and "*" both match any)
        ActivationRule wild = new ActivationRule("r2", "alice", ActivationAction.ACTIVATE, "*", null, "*");
        assertTrue(wild.matches("alice", ActivationAction.ACTIVATE, "AnyLine", "anyKind", "anyRef"));
        assertFalse(wild.matches("carol", ActivationAction.ACTIVATE, "AnyLine", "anyKind", "anyRef"), "principal not wild");
    }

    @Test void action_serializes_lowercase() throws Exception {
        assertEquals("\"activate\"", mapper.writeValueAsString(ActivationAction.ACTIVATE));
        assertEquals("\"approve\"",  mapper.writeValueAsString(ActivationAction.APPROVE));
        assertEquals(ActivationAction.APPROVE, mapper.readValue("\"approve\"", ActivationAction.class));
    }

    @Test void policy_round_trips_with_default_deny_key() throws Exception {
        String json = "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
                + "{\"id\":\"r1\",\"principal\":\"alice\",\"action\":\"activate\",\"target\":\"Line1\",\"kind\":\"recipe\",\"ref\":\"mix\"}]}";
        ActivationPolicy p = mapper.readValue(json, ActivationPolicy.class);
        assertEquals("deny", p.defaultEffect());
        assertEquals(1, p.rules().size());
        assertEquals(ActivationAction.ACTIVATE, p.rules().get(0).action());
    }

    @Test void deny_all_factory_has_no_rules() {
        assertTrue(ActivationPolicy.denyAll().rules().isEmpty());
        assertEquals("deny", ActivationPolicy.denyAll().defaultEffect());
    }

    @Test void decision_factories() {
        assertTrue(AuthzDecision.allow("r1").allowed());
        assertEquals("r1", AuthzDecision.allow("r1").ruleId());
        assertFalse(AuthzDecision.deny("nope").allowed());
        assertNull(AuthzDecision.deny("nope").ruleId());
    }
}
