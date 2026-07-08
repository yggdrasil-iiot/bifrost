package dev.krillin.bifrost.core.acl;

/** Edge-side payload-aware decision engine. Evaluation order: first-match, deny-by-default (fail-closed). */
public final class CommandAuthorizer {

    public Decision authorize(CommandPolicy policy, CommandRequest req) {
        for (Rule r : policy.rules()) {
            if (!targetMatches(r.target(), req.target())) continue;
            if (!r.command().equals(req.command())) continue;
            // first-match: this rule is the final verdict
            Constraint c = r.constraint();
            if (c == null) {
                return Boolean.TRUE.equals(req.value())
                        ? Decision.allow(r.id())
                        : Decision.deny("trigger-only: value!=true [" + r.id() + "]");
            }
            if (!c.type().equals(req.type())) {
                return Decision.deny("type-mismatch: expected " + c.type() + " got " + req.type());
            }
            // fail-closed: if a value constraint exists but the value is null or not a Number, DENY rather than crash
            if (!(req.value() instanceof Number)) {
                return Decision.deny("invalid-value (not a number): " + req.value());
            }
            double v = ((Number) req.value()).doubleValue();
            if (c.min() != null && v < c.min()) return Decision.deny("below-min: " + v + "<" + c.min());
            if (c.max() != null && v > c.max()) return Decision.deny("above-max: " + v + ">" + c.max());
            return Decision.allow(r.id());
        }
        return Decision.deny("no-matching-rule (deny-by-default)");
    }

    private boolean targetMatches(Target rule, Target req) {
        return fieldMatches(rule.group(), req.group())
                && fieldMatches(rule.edge(), req.edge())
                && fieldMatches(rule.device(), req.device());
    }
    /** A rule field of null or "*" matches any value; otherwise an exact match is required. */
    private boolean fieldMatches(String rule, String actual) {
        return rule == null || "*".equals(rule) || rule.equals(actual);
    }
}
