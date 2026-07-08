package dev.krillin.bifrost.core.acl;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Projects a command policy to broker ACL entries (principal → NCMD topic PUBLISH).
 * The device field is omitted from NCMD topics and is ignored here.
 * A target wildcard "*" is rendered as the MQTT single-level wildcard "+".
 * This produces a static artifact only — it does not enforce live RBAC on the broker.
 */
public final class BrokerAclProjector {

    public List<AclEntry> project(CommandPolicy policy) {
        LinkedHashSet<AclEntry> out = new LinkedHashSet<>();
        for (Rule r : policy.rules()) {
            String topic = "spBv1.0/" + wild(r.target().group()) + "/NCMD/" + wild(r.target().edge());
            out.add(new AclEntry(r.principal(), topic, "PUBLISH"));
        }
        return new ArrayList<>(out);
    }

    private String wild(String s) { return "*".equals(s) ? "+" : s; }
}
