package dev.krillin.bifrost.core.activation;

/** Design-time & edge decision engine for the activation act. First-match, deny-by-default (fail-closed),
 *  pure (no I/O) — the exact discipline of core.acl.CommandAuthorizer, over the activation resource shape. */
public final class ActivationAuthorizer {

    public AuthzDecision authorize(ActivationPolicy policy, String principal, ActivationAction action,
                                   String target, String kind, String ref) {
        for (ActivationRule r : policy.rules()) {
            if (r.matches(principal, action, target, kind, ref)) return AuthzDecision.allow(r.id());
        }
        return AuthzDecision.deny("no-matching-rule (deny-by-default)");
    }
}
