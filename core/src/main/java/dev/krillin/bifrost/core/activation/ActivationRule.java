package dev.krillin.bifrost.core.activation;

/** One deny-by-default authorization rule (implicit allow candidate): principal P may perform ACTION on
 *  resource (target,kind,ref). A null or "*" field matches any value; otherwise an exact match is required
 *  (identical to core.acl.Rule.fieldMatches). */
public record ActivationRule(String id, String principal, ActivationAction action,
                             String target, String kind, String ref) {

    public boolean matches(String principal, ActivationAction action, String target, String kind, String ref) {
        return this.action == action
                && field(this.principal, principal)
                && field(this.target, target)
                && field(this.kind, kind)
                && field(this.ref, ref);
    }

    private static boolean field(String rule, String actual) {
        return rule == null || "*".equals(rule) || rule.equals(actual);
    }
}
