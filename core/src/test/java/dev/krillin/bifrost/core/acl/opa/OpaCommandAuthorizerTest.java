package dev.krillin.bifrost.core.acl.opa;

import dev.krillin.bifrost.core.acl.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class OpaCommandAuthorizerTest {
    private final OpaCommandAuthorizer opa = new OpaCommandAuthorizer();
    private final CommandAuthorizer hand = new CommandAuthorizer();
    private Target line1() { return new Target("line1", "*", "*"); }
    private CommandRequest write(double v) { return new CommandRequest(line1(), "write", v, "Double"); }
    private CommandRequest safeHold() { return new CommandRequest(line1(), "SafeHold", Boolean.TRUE, "Boolean"); }

    @Test void denyByDefault_unknownCommand() {
        assertFalse(opa.authorize(new CommandRequest(line1(), "reboot", 1, "Int"),
                                  new Context("Execute", 14)).allowed());
    }
    @Test void subsumption_normalRange_allowedAnyContext() {
        assertTrue(opa.authorize(write(800), new Context("Idle", 2)).allowed());
    }
    @Test void extension_highRpm_dayExecute_allow() {
        assertTrue(opa.authorize(write(1500), new Context("Execute", 14)).allowed());
    }
    @Test void extension_highRpm_night_deny() {
        assertFalse(opa.authorize(write(1500), new Context("Execute", 2)).allowed());
    }
    @Test void extension_highRpm_nonExecute_deny() {
        assertFalse(opa.authorize(write(1500), new Context("Idle", 14)).allowed());
    }
    @Test void extension_safeHold_execute_allow_held_deny() {
        assertTrue(opa.authorize(safeHold(), new Context("Execute", 14)).allowed());
        assertFalse(opa.authorize(safeHold(), new Context("Held", 14)).allowed());
    }
    @Test void contrast_handRolledIsContextBlind_allows1500_soDenialIsContextOnly() {
        // Hand-rolled engine, given a rpm rule bounded max 3000, ALLOWS 1500 (it cannot see hour/state).
        // So OPA's night-deny of the same request is a context-only capability the flat engine lacks.
        CommandPolicy p = new CommandPolicy("1", java.util.List.of(
            new Rule("rpm", "*", line1(), "write", new Constraint("Double", 0.0, 3000.0))), "deny");
        assertTrue(hand.authorize(p, write(1500)).allowed(), "hand-rolled allows 1500 (context-blind)");
        assertFalse(opa.authorize(write(1500), new Context("Execute", 2)).allowed(), "OPA denies at night");
    }
}
