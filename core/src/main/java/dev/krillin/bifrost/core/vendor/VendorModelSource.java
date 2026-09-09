package dev.krillin.bifrost.core.vendor;

import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * The outbound port: where a vendor's copy of a governed model is read FROM.
 *
 * <p>It returns a foreign {@link JsonNode}, not a vendor type, for the same reason
 * {@code TemplateAdapter} takes one inbound: {@code core} must have no compile-time knowledge that
 * Ignition or Kepware exists. Normalizing that tree is the adapter's job, and comparing the result
 * is {@link ModelReconciler}'s.
 *
 * <p>An empty result means <b>the vendor has no copy of this ref</b>, which is a finding an
 * operator needs to see. It is deliberately distinct from a {@link VendorException}, which means
 * the copy could not be read -- collapsing the two would let a truncated download read as an empty
 * vendor model and report every governed member as missing.
 */
public interface VendorModelSource {

    VendorCapability capability();

    /** The vendor's current configuration for {@code ref}, or empty if it holds none. */
    Optional<JsonNode> read(String ref);
}
