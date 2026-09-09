package dev.krillin.bifrost.core.vendor;

/** A coded failure reading a vendor's model, in the reason-code style the rest of the ladder uses. */
public class VendorException extends RuntimeException {
    private final String rule;

    public VendorException(String rule, String detail) {
        super(rule + ": " + detail);
        this.rule = rule;
    }

    public String rule() {
        return rule;
    }
}
