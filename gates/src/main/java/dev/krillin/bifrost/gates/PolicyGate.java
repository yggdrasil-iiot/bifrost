package dev.krillin.bifrost.gates;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.acl.AclMapperFactory;
import dev.krillin.bifrost.core.acl.CommandPolicy;
import dev.krillin.bifrost.core.acl.Constraint;
import dev.krillin.bifrost.core.acl.Rule;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Pre-deployment command policy gate for CI. Exit codes: 0=pass, 1=semantic lint violation, 2=error/parse/usage.
 * Usage: PolicyGate &lt;policyJson&gt;
 */
public final class PolicyGate {

    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: PolicyGate <policyJson>");
            return 2;
        }
        CommandPolicy policy;
        try {
            ObjectMapper m = AclMapperFactory.create();  // FAIL_ON_UNKNOWN_PROPERTIES
            policy = m.readValue(Path.of(args[0]).toFile(), CommandPolicy.class);
        } catch (Exception e) {
            System.err.println("[ACL-GATE] ERROR (parse/IO): " + e.getMessage());
            return 2;  // covers unknown-field rejection and malformed JSON
        }
        List<String> v = lint(policy);
        if (v.isEmpty()) {
            System.out.println("[ACL-GATE] PASS ✅ (rules=" + policy.rules().size() + ")");
            return 0;
        }
        System.out.println("[ACL-GATE] FAIL ❌ — violations:");
        for (String s : v) System.out.println("  - " + s);
        return 1;
    }

    private static List<String> lint(CommandPolicy p) {
        List<String> v = new ArrayList<>();
        // default must be "deny" — deny-by-default is mandatory
        if (!"deny".equals(p.defaultEffect())) v.add("[lint-1] default must be \"deny\" (got " + p.defaultEffect() + ")");
        // duplicate rule ids produce ambiguous first-match ordering
        Set<String> seen = new HashSet<>();
        for (Rule r : p.rules()) {
            if (!seen.add(r.id())) v.add("[lint-2] duplicate rule id: " + r.id());
        }
        for (Rule r : p.rules()) {
            Constraint c = r.constraint();
            // a constraint with neither min nor max is meaningless and likely a mistake
            if (c != null && c.min() == null && c.max() == null) {
                v.add("[lint-3] constraint without min/max: rule " + r.id());
            }
            // over-grant: group=* and edge=* with no value constraint allows any payload value
            if (c == null && "*".equals(r.target().group()) && "*".equals(r.target().edge())) {
                v.add("[lint-4] over-grant (group=* edge=* with no constraint): rule " + r.id());
            }
        }
        return v;
    }
}
