package dev.krillin.bifrost.core.acl;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

class CommandPolicyJsonTest {

    @Test void roundTrip_preservesFields() throws Exception {
        ObjectMapper m = AclMapperFactory.create();
        CommandPolicy p = new CommandPolicy("1.0.0", List.of(
                new Rule("rebirth", "ops", new Target("Acme:Busan:Press", "L1:GW3", null),
                        "Node Control/Rebirth", null),
                new Rule("rpm", "engineer", new Target("Acme:Busan:Press", "L1:GW3", null),
                        "Setpoint/Rpm", new Constraint("Double", 0.0, 3000.0))
        ), "deny");

        String json = m.writeValueAsString(p);
        assertTrue(json.contains("\"default\":\"deny\""), json);

        CommandPolicy back = m.readValue(json, CommandPolicy.class);
        assertEquals(p, back);
    }

    @Test void unknownField_isRejected() {
        ObjectMapper m = AclMapperFactory.create();
        String bad = "{\"version\":\"1.0.0\",\"rules\":[],\"default\":\"deny\",\"bogus\":1}";
        assertThrows(Exception.class, () -> m.readValue(bad, CommandPolicy.class));
    }
}
