package dev.krillin.bifrost.core.schema;

/** Numeric operating range of a member (AAS {@code Property} value bounds): inclusive low/high. */
public record Range(double low, double high) {}
