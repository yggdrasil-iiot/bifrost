package dev.krillin.bifrost.core.schema;

/**
 * A concrete setpoint in a {@link MasterSpec} (ISA-88 master recipe): binds a value to a specific
 * equipment {@code member} name (an equipment definition's member), with its type. The
 * equipment-dependent counterpart of a {@link SetpointIntent}.
 */
public record Setpoint(String member, String type, double value) {}
