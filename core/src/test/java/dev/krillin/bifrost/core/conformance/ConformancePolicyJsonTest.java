package dev.krillin.bifrost.core.conformance;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import org.junit.jupiter.api.Test;

class ConformancePolicyJsonTest {
    @Test void roundTrip() throws Exception {
        String json = """
          {"policyRef":"WeldPolicy","version":"1.0.0","equipmentRef":"Weld-Controller","equipmentVersion":"1.0.0",
           "dial":{"mode":"envelope"},
           "crossConstraints":[{"id":"weld-lobe","ifMember":"ElectrodeForce","ifOp":"lt","ifValue":3.0,
                                "thenMember":"WeldCurrent","thenOp":"le","thenValue":8.0}],
           "nodeBindings":[{"opcNodeId":"ns=2;s=Weld/WeldCurrent","readNodeId":"ns=2;s=BodyShop/Weld1.WeldCurrent","member":"WeldCurrent"}]}
          """;
        ObjectMapper m = JsonMapperFactory.create();
        ConformancePolicy p = m.readValue(json, ConformancePolicy.class);
        assertEquals("WeldPolicy", p.policyRef());
        assertEquals("envelope", p.dial().mode());
        assertEquals(1, p.crossConstraints().size());
        assertEquals("weld-lobe", p.crossConstraints().get(0).id());
        assertEquals("WeldCurrent", p.nodeBindings().get(0).member());
    }
}
