package dev.krillin.bifrost.core.conduit;

/** A coded refusal projecting the governed conduits, in the reason-code style the ladder uses. */
public class ConduitException extends RuntimeException {
    private final String rule;

    public ConduitException(String rule, String detail) {
        super(rule + ": " + detail);
        this.rule = rule;
    }

    public String rule() {
        return rule;
    }
}
