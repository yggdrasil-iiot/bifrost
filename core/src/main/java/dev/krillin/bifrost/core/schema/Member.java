package dev.krillin.bifrost.core.schema;
/** Schema of a UDT member (Sparkplug Template metric): name + type name as returned by MetricDataType.toString(). */
public record Member(String name, String type) {}
