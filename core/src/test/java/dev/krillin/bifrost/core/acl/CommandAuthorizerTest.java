package dev.krillin.bifrost.core.acl;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import org.junit.jupiter.api.Test;

class CommandAuthorizerTest {

    private final CommandAuthorizer auth = new CommandAuthorizer();
    private final Target gw3 = new Target("Acme:Busan:Press", "L1:GW3", null);

    private CommandPolicy policy(Rule... rules) {
        return new CommandPolicy("1.0.0", List.of(rules), "deny");
    }
    private CommandRequest req(String command, Object value, String type) {
        return new CommandRequest(gw3, command, value, type);
    }

    // trigger-only commands (no constraint)
    @Test void noConstraint_trueValue_allows() {
        CommandPolicy p = policy(new Rule("r", "ops", gw3, "Node Control/Rebirth", null));
        assertTrue(auth.authorize(p, req("Node Control/Rebirth", true, "Boolean")).allowed());
    }
    @Test void noConstraint_falseValue_denies() {
        CommandPolicy p = policy(new Rule("r", "ops", gw3, "Node Control/Rebirth", null));
        assertFalse(auth.authorize(p, req("Node Control/Rebirth", false, "Boolean")).allowed());
    }

    // deny-by-default: no matching rule
    @Test void noMatchingRule_denies() {
        CommandPolicy p = policy(new Rule("r", "ops", gw3, "Node Control/Rebirth", null));
        assertFalse(auth.authorize(p, req("Node Control/Reboot", true, "Boolean")).allowed());
    }
    @Test void emptyPolicy_denies() {
        assertFalse(auth.authorize(policy(), req("Anything", true, "Boolean")).allowed());
    }

    // numeric constraint boundaries (inclusive)
    @Test void inRange_allows() {
        CommandPolicy p = policy(new Rule("r","eng",gw3,"Setpoint/Rpm", new Constraint("Double",0.0,3000.0)));
        assertTrue(auth.authorize(p, req("Setpoint/Rpm", 1500.0, "Double")).allowed());
    }
    @Test void atMinBoundary_allows() {
        CommandPolicy p = policy(new Rule("r","eng",gw3,"Setpoint/Rpm", new Constraint("Double",0.0,3000.0)));
        assertTrue(auth.authorize(p, req("Setpoint/Rpm", 0.0, "Double")).allowed());
    }
    @Test void atMaxBoundary_allows() {
        CommandPolicy p = policy(new Rule("r","eng",gw3,"Setpoint/Rpm", new Constraint("Double",0.0,3000.0)));
        assertTrue(auth.authorize(p, req("Setpoint/Rpm", 3000.0, "Double")).allowed());
    }
    @Test void belowMin_denies() {
        CommandPolicy p = policy(new Rule("r","eng",gw3,"Setpoint/Rpm", new Constraint("Double",0.0,3000.0)));
        assertFalse(auth.authorize(p, req("Setpoint/Rpm", -1.0, "Double")).allowed());
    }
    @Test void aboveMax_denies() {  // case that broker topic ACL cannot block (payload value not visible to broker)
        CommandPolicy p = policy(new Rule("r","eng",gw3,"Setpoint/Rpm", new Constraint("Double",0.0,3000.0)));
        assertFalse(auth.authorize(p, req("Setpoint/Rpm", 99999.0, "Double")).allowed());
    }

    // single-sided bounds
    @Test void maxOnly_belowAllowed() {
        CommandPolicy p = policy(new Rule("r","eng",gw3,"Setpoint/Rpm", new Constraint("Double", null, 3000.0)));
        assertTrue(auth.authorize(p, req("Setpoint/Rpm", -9999.0, "Double")).allowed());
    }
    @Test void minOnly_aboveAllowed() {
        CommandPolicy p = policy(new Rule("r","eng",gw3,"Setpoint/Rpm", new Constraint("Double", 0.0, null)));
        assertTrue(auth.authorize(p, req("Setpoint/Rpm", 1e9, "Double")).allowed());
    }

    // type mismatch
    @Test void typeMismatch_denies() {
        CommandPolicy p = policy(new Rule("r","eng",gw3,"Setpoint/Rpm", new Constraint("Double",0.0,3000.0)));
        assertFalse(auth.authorize(p, req("Setpoint/Rpm", "1500", "String")).allowed());
    }

    // fail-closed: null or non-Number value against a constrained rule -> DENY, not crash
    @Test void nullValueWithConstraint_deniesNotCrashes() {
        CommandPolicy p = policy(new Rule("r","eng",gw3,"Setpoint/Rpm", new Constraint("Double",0.0,3000.0)));
        assertFalse(auth.authorize(p, req("Setpoint/Rpm", null, "Double")).allowed());
    }

    // wildcard target
    @Test void wildcardTarget_matches() {
        Target any = new Target("*", "*", null);
        CommandPolicy p = policy(new Rule("r","ops", any, "Node Control/Rebirth", null));
        assertTrue(auth.authorize(p, req("Node Control/Rebirth", true, "Boolean")).allowed());
    }
    @Test void edgeMismatch_denies() {
        CommandPolicy p = policy(new Rule("r","ops",
                new Target("Acme:Busan:Press", "L9:OTHER", null), "Node Control/Rebirth", null));
        assertFalse(auth.authorize(p, req("Node Control/Rebirth", true, "Boolean")).allowed());
    }

    // first-match: when multiple rules match, only the first applies
    @Test void firstMatch_wins() {
        CommandPolicy p = policy(
                new Rule("first","eng",gw3,"Setpoint/Rpm", new Constraint("Double",0.0,10.0)),
                new Rule("second","eng",gw3,"Setpoint/Rpm", new Constraint("Double",0.0,3000.0)));
        // 1500 is blocked by the first rule (max=10) -> DENY, proving the second rule is never reached
        assertFalse(auth.authorize(p, req("Setpoint/Rpm", 1500.0, "Double")).allowed());
    }
}
