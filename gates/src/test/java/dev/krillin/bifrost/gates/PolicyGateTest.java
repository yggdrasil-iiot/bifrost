package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PolicyGateTest {

    private Path write(Path dir, String name, String json) throws Exception {
        Path f = dir.resolve(name);
        Files.writeString(f, json);
        return f;
    }

    private static final String GOOD = """
        {"version":"1.0.0","rules":[
          {"id":"rebirth","principal":"ops","target":{"group":"Acme:Busan:Press","edge":"L1:GW3"},
           "command":"Node Control/Rebirth"},
          {"id":"rpm","principal":"engineer","target":{"group":"Acme:Busan:Press","edge":"L1:GW3"},
           "command":"Setpoint/Rpm","constraint":{"type":"Double","min":0,"max":3000}}
        ],"default":"deny"}""";

    @Test void goodPolicy_returnsZero(@TempDir Path d) throws Exception {
        assertEquals(0, PolicyGate.run(new String[]{ write(d,"p.json",GOOD).toString() }));
    }

    @Test void defaultNotDeny_returnsOne(@TempDir Path d) throws Exception {  // lint rule: default must be "deny"
        String bad = GOOD.replace("\"default\":\"deny\"", "\"default\":\"allow\"");
        assertEquals(1, PolicyGate.run(new String[]{ write(d,"p.json",bad).toString() }));
    }

    @Test void duplicateId_returnsOne(@TempDir Path d) throws Exception {  // lint rule: duplicate rule ids
        String bad = GOOD.replace("\"id\":\"rpm\"", "\"id\":\"rebirth\"");
        assertEquals(1, PolicyGate.run(new String[]{ write(d,"p.json",bad).toString() }));
    }

    @Test void constraintWithoutBounds_returnsOne(@TempDir Path d) throws Exception {  // lint rule: constraint with no min or max
        String bad = """
            {"version":"1.0.0","rules":[
              {"id":"x","principal":"e","target":{"group":"G","edge":"E"},
               "command":"Setpoint/Rpm","constraint":{"type":"Double"}}
            ],"default":"deny"}""";
        assertEquals(1, PolicyGate.run(new String[]{ write(d,"p.json",bad).toString() }));
    }

    @Test void overGrantWildcard_returnsOne(@TempDir Path d) throws Exception {  // lint rule: over-grant (group=* edge=* with no constraint)
        String bad = """
            {"version":"1.0.0","rules":[
              {"id":"x","principal":"admin","target":{"group":"*","edge":"*"},
               "command":"Node Control/Rebirth"}
            ],"default":"deny"}""";
        assertEquals(1, PolicyGate.run(new String[]{ write(d,"p.json",bad).toString() }));
    }

    @Test void unknownField_returnsTwo(@TempDir Path d) throws Exception {  // lint rule: unknown JSON field (parse error)
        String bad = GOOD.substring(0, GOOD.length()-1) + ",\"bogus\":1}";
        assertEquals(2, PolicyGate.run(new String[]{ write(d,"p.json",bad).toString() }));
    }

    @Test void noArgs_returnsTwo() {
        assertEquals(2, PolicyGate.run(new String[]{}));
    }
}
