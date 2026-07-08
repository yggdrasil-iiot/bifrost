package dev.krillin.bifrost.core.acl;
/** Value domain constraint. {@code type} is MetricDataType.toString() (e.g. "Double"). {@code min}/{@code max} are each optional; null means unbounded. Bounds are inclusive. */
public record Constraint(String type, Double min, Double max) {}
