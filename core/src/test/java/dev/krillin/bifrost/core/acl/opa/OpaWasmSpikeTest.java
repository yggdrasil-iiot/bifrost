package dev.krillin.bifrost.core.acl.opa;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OpaWasmSpikeTest {
    @Test void trivialPolicyRoundTrips() {
        OpaPolicy p = OpaPolicy.fromResource("/opa/spike.wasm");
        assertTrue(p.eval("{\"x\": 9}").contains("\"ok\":true"), "9>5 true");
        assertTrue(p.eval("{\"x\": 1}").contains("\"ok\":false"), "1>5 false");
    }
}
