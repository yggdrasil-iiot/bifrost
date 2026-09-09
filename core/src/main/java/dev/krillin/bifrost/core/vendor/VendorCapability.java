package dev.krillin.bifrost.core.vendor;

/**
 * What a vendor product can actually do with its own model, as measured rather than assumed.
 *
 * <p>{@code product} is a label for the report, not a discriminator: nothing in {@code core}
 * branches on it, exactly as nothing in {@code core} knows an Ignition type on the inbound side.
 */
public record VendorCapability(String product, Granularity granularity,
                               boolean canRead, boolean canWrite) {

    /** Read-only, per-object: the posture every product supports and the one this round uses. */
    public static VendorCapability readOnly(String product, Granularity granularity) {
        return new VendorCapability(product, granularity, true, false);
    }
}
