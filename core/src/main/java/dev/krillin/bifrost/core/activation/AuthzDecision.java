package dev.krillin.bifrost.core.activation;

/** Authorization result. {@code allowed} => {@code ruleId} identifies the matching rule; on deny, ruleId is
 *  null and {@code reason} explains. Mirrors core.acl.Decision. */
public record AuthzDecision(boolean allowed, String ruleId, String reason) {
    public static AuthzDecision allow(String ruleId) { return new AuthzDecision(true, ruleId, "allow"); }
    public static AuthzDecision deny(String reason)  { return new AuthzDecision(false, null, reason); }
}
