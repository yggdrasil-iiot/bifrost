package dev.krillin.bifrost.core.acl;

/**
 * Edge-side payload-aware decision engine. Evaluation order: first-match, deny-by-default
 * (fail-closed).
 *
 * <p><b>First-match plus deny-on-principal-mismatch means one principal per (target, command).</b>
 * A second rule granting the same node to a different principal is unreachable, because the first
 * matching rule returns. That follows the documented first-match semantics rather than contradicting
 * them, but it is a real constraint on the policy language and is chosen, not stumbled into.
 */
public final class CommandAuthorizer {

    public Decision authorize(CommandPolicy policy, CommandRequest req) {
        for (Rule r : policy.rules()) {
            if (!targetMatches(r.target(), req.target())) continue;
            if (!r.command().equals(req.command())) continue;
            // Checked ONLY when the caller asserted a subject. A null subject is "not asserted",
            // not "anonymous is fine": the edge's REQUIRE_SIGNED_COMMAND bar is what makes an
            // unasserted subject impossible, and it refuses the command outright rather than
            // through the bridge's refuse() -- which log-only would turn into a shadowed
            // would-deny and then apply. This method is weaker in isolation than the system it
            // sits in, and that is the reason.
            //
            // The reason string carries the RULE ID and never the expected principal: it travels
            // to the NDATA response as well as the log, on a broker this design's own premise says
            // authenticates nobody.
            if (req.subject() != null && !principalMatches(r.principal(), req.subject())) {
                return Decision.deny("principal-mismatch [" + r.id() + "]");
            }
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

    /**
     * Same shape as {@link #fieldMatches}: a null or {@code "*"} rule principal admits any subject.
     *
     * <p>That is a real fail-open, and it is linted rather than prevented here — {@code PolicyGate}
     * rejects a rule with no principal, because otherwise this enforcement is one missing JSON key
     * away from admitting every signed principal.
     */
    private boolean principalMatches(String rulePrincipal, String subject) {
        return rulePrincipal == null || "*".equals(rulePrincipal) || rulePrincipal.equals(subject);
    }
}
