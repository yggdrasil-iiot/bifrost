package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import java.io.IOException;
import java.nio.file.*;

/** Loads registry/identity/activation-policy.json (co-located with the T5 identity trust anchor). Fail-closed:
 *  an ABSENT file is deny-all (a policy with no rules), a malformed file or a default other than "deny" is a
 *  coded IllegalStateException. Whole-file read per load, not cached (small policy; matches T4/T5 reads).
 *  Bootstrap/change-control of the policy are out-of-band (spec §7). */
public final class ActivationPolicyStore {
    private ActivationPolicyStore() {}

    public static ActivationPolicy load(Path registryRoot) {
        Path f = registryRoot.resolve("identity").resolve("activation-policy.json");
        if (!Files.isRegularFile(f)) return ActivationPolicy.denyAll();
        ObjectMapper mapper = JsonMapperFactory.create();
        ActivationPolicy p;
        try {
            p = mapper.readValue(Files.readString(f), ActivationPolicy.class);
        } catch (IOException e) {
            throw new IllegalStateException("activation.authz.policy.read-error: " + f, e);
        }
        if (!"deny".equals(p.defaultEffect()))
            throw new IllegalStateException("activation.authz.policy.default-not-deny: " + f
                    + " (default must be \"deny\")");
        for (ActivationRule r : p.rules())      // a rule missing action/id/principal would silently never match — refuse loudly
            if (r.action() == null || r.id() == null || r.principal() == null)
                throw new IllegalStateException("activation.authz.policy.malformed-rule: " + f
                        + " (rule id/principal/action must all be present; got id=" + r.id()
                        + " principal=" + r.principal() + " action=" + r.action() + ")");
        return p;
    }
}
