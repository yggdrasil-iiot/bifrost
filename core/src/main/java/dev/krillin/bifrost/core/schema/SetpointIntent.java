package dev.krillin.bifrost.core.schema;

/**
 * A setpoint intent in a {@link GeneralSpec} (ISA-88 general recipe): a logical, equipment-independent
 * {@code key} bound to a value, with its type. Resolved to a concrete equipment {@link Setpoint} when
 * a general spec is bound to a site's equipment as a master recipe.
 */
public record SetpointIntent(String key, String type, double value) {}
