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
        rejectDualApproveRole(p, f);
        return p;
    }

    /**
     * A principal holding BOTH {@code APPROVE} and {@code BREAK_GLASS_APPROVE} over resources that can
     * overlap defeats the whole point of a duty key.
     *
     * <p>The emergency marking is derived from which role authorized the approval, so a principal that
     * holds both can simply approve normally and the emergency is never recorded as one. That is one
     * JSON line away from a policy that looks correct, and nothing else in the system would notice --
     * the activation succeeds, the ledger verifies, and the record says ACTIVATE.
     */
    private static void rejectDualApproveRole(ActivationPolicy p, Path f) {
        for (ActivationRule a : p.rules()) {
            if (a.action() != ActivationAction.APPROVE) continue;
            for (ActivationRule b : p.rules()) {
                if (b.action() != ActivationAction.BREAK_GLASS_APPROVE) continue;
                if (!a.principal().equals(b.principal())) continue;
                if (overlaps(a.target(), b.target()) && overlaps(a.kind(), b.kind()) && overlaps(a.ref(), b.ref()))
                    throw new IllegalStateException("activation.authz.policy.dual-approve-role: " + f
                            + " (principal '" + a.principal() + "' holds both approve [" + a.id()
                            + "] and break_glass_approve [" + b.id() + "] over overlapping resources;"
                            + " a duty principal must not be able to approve normally)");
            }
        }
    }

    /** Two resource selectors can match the same thing when either is a wildcard or they are equal. */
    private static boolean overlaps(String x, String y) {
        return x == null || y == null || "*".equals(x) || "*".equals(y) || x.equals(y);
    }
}
