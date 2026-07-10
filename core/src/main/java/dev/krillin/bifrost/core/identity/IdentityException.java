package dev.krillin.bifrost.core.identity;

/** A fail-closed identity fault carrying a reason-code rule slug (identity.*). */
public final class IdentityException extends RuntimeException {
    private final String rule;
    public IdentityException(String rule, String detail) { super(detail); this.rule = rule; }
    public String rule() { return rule; }
}
