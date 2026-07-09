package dev.krillin.bifrost.core.schema;
/**
 * Schema of a UDT member (Sparkplug Template metric): name + type name as returned by
 * MetricDataType.toString(). AAS-aligned — a member ≈ AAS {@code Property}, carrying a
 * {@code semanticId} (concept-dictionary reference) and an optional numeric {@code range}
 * (null for non-numeric members).
 */
public record Member(String name, String type, String semanticId, Range range) {}
