package dev.krillin.bifrost.core.acl;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import org.junit.jupiter.api.Test;

class BrokerAclProjectorTest {

    private final BrokerAclProjector proj = new BrokerAclProjector();

    private CommandPolicy policy(Rule... rules) {
        return new CommandPolicy("1.0.0", List.of(rules), "deny");
    }

    @Test void mapsPrincipalToNcmdTopic() {
        CommandPolicy p = policy(new Rule("r","ops",
                new Target("Acme:Busan:Press","L1:GW3",null), "Node Control/Rebirth", null));
        List<AclEntry> acl = proj.project(p);
        assertEquals(1, acl.size());
        AclEntry e = acl.get(0);
        assertEquals("ops", e.principal());
        assertEquals("spBv1.0/Acme:Busan:Press/NCMD/L1:GW3", e.topicFilter());
        assertEquals("PUBLISH", e.permission());
    }

    @Test void dedupesIdenticalEntries() {
        Target gw3 = new Target("Acme:Busan:Press","L1:GW3",null);
        CommandPolicy p = policy(  // same principal+node, different commands -> deduped to 1 ACL entry
                new Rule("a","ops",gw3,"Node Control/Rebirth", null),
                new Rule("b","ops",gw3,"Setpoint/Rpm", new Constraint("Double",0.0,3000.0)));
        assertEquals(1, proj.project(p).size());
    }

    @Test void distinctEdges_distinctEntries() {
        CommandPolicy p = policy(
                new Rule("a","ops",new Target("Acme:Busan:Press","L1:GW3",null),"Node Control/Rebirth",null),
                new Rule("b","ops",new Target("Acme:Busan:Press","L2:GW4",null),"Node Control/Rebirth",null));
        assertEquals(2, proj.project(p).size());
    }

    @Test void wildcardRendersToMqttPlus() {
        CommandPolicy p = policy(new Rule("r","admin",
                new Target("*","*",null), "Node Control/Rebirth", null));
        assertEquals("spBv1.0/+/NCMD/+", proj.project(p).get(0).topicFilter());
    }
}
