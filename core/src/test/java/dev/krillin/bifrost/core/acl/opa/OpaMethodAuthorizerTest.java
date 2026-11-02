package dev.krillin.bifrost.core.acl.opa;

import dev.krillin.bifrost.core.acl.*;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.List;
import java.util.function.UnaryOperator;
import static org.junit.jupiter.api.Assertions.*;

/** command_method.wasm through the Chicory host: the compiled module, not only the Rego source, decides. The
 *  full decision table runs as `opa test` in scripts/build-opa-wasm.sh; these rows prove the module agrees. */
class OpaMethodAuthorizerTest {
    static final String METHOD = "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1.SetTemperature";
    static final Instant T0 = Instant.parse("2026-11-02T00:00:00Z");
    private final OpaMethodAuthorizer opa = new OpaMethodAuthorizer();

    static OpaMethodAuthorizer.MethodFacts valid() {
        return new OpaMethodAuthorizer.MethodFacts("agent", List.of("propose_command"), "operator", List.of("approve_command"), true,
            T0, T0.plusSeconds(900), T0, true, true, new Target("Bifrost:Line1", "heimdall-edge", "Line1/Mixer1"), METHOD,
            "targetTemperature", "Double", 42.0);
    }
    static OpaMethodAuthorizer.MethodFacts with(UnaryOperator<Object[]> edit) {
        var f = valid();
        Object[] c = {f.proposer(), f.proposerGrants(), f.approver(), f.approverGrants(), f.distinctKeys(), f.notBefore(), f.notAfter(),
            f.now(), f.headMatch(), f.evidenceUsable(), f.target(), f.methodNodeId(), f.inputName(), f.inputType(), f.value()};
        c = edit.apply(c);
        @SuppressWarnings("unchecked") var r = new OpaMethodAuthorizer.MethodFacts((String) c[0], (List<String>) c[1], (String) c[2], (List<String>) c[3],
            (boolean) c[4], (Instant) c[5], (Instant) c[6], (Instant) c[7], (boolean) c[8], (boolean) c[9], (Target) c[10], (String) c[11],
            (String) c[12], (String) c[13], (double) c[14]);
        return r;
    }
    static UnaryOperator<Object[]> set(int i, Object v) { return c -> { c[i] = v; return c; }; }
    String denied(OpaMethodAuthorizer.MethodFacts f) {
        Decision d = opa.authorize(f);
        assertFalse(d.allowed(), d.reason());
        return d.reason();
    }

    @Test void validCallIsAllowed() {
        Decision d = opa.authorize(valid());
        assertTrue(d.allowed(), d.reason());
        assertEquals("command_method", d.ruleId());
        assertTrue(opa.authorize(with(set(14, 0.0))).allowed());
        assertTrue(opa.authorize(with(set(14, 100.0))).allowed());
        assertTrue(opa.authorize(with(set(7, T0.plusSeconds(899)))).allowed());
    }

    @Test void eachFactIsChecked() {
        assertEquals("opa: principal", denied(with(set(2, "agent"))));
        assertEquals("opa: grant.propose", denied(with(set(1, List.of("activate")))));
        assertEquals("opa: grant.approve", denied(with(set(3, List.of("approve")))));
        assertEquals("opa: distinct-keys", denied(with(set(4, false))));
        assertEquals("opa: window", denied(with(set(7, T0.plusSeconds(900)))));
        assertEquals("opa: window", denied(with(set(7, T0.minusSeconds(1)))));
        assertEquals("opa: window", denied(with(set(6, T0.plusSeconds(901)))));
        assertEquals("opa: head", denied(with(set(8, false))));
        assertEquals("opa: evidence", denied(with(set(9, false))));
        assertEquals("opa: argument", denied(with(set(14, 100.000001))));
        assertEquals("opa: argument", denied(with(set(14, -0.5))));
        assertEquals("opa: argument", denied(with(set(12, "rpm"))));
        assertEquals("opa: argument,method", denied(with(set(11, "ns=2;s=Line1/Mixer1.SetTemperature"))));
    }

    @Test void violationsAreAllListed() {
        assertEquals("opa: distinct-keys,evidence,head", denied(with(c -> { c[4] = false; c[8] = false; c[9] = false; return c; })));
    }

    @Test void anotherPolicyModuleDenies() {
        Decision d = new OpaMethodAuthorizer(OpaPolicy.fromResource("/opa/spike.wasm")).authorize(valid());
        assertFalse(d.allowed());
    }
}
