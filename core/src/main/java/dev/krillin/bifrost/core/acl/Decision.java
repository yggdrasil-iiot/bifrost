package dev.krillin.bifrost.core.acl;
/** Authorization result. {@code allowed} indicates whether the command is permitted; {@code ruleId} identifies the matching rule (set only on allow); {@code reason} is a human-readable explanation. */
public record Decision(boolean allowed, String ruleId, String reason) {
    public static Decision allow(String ruleId) { return new Decision(true, ruleId, "allow"); }
    public static Decision deny(String reason)  { return new Decision(false, null, reason); }
}
