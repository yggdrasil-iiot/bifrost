package yggdrasil.bifrost.core.schema;
/** A single compatibility violation: rule id + human-readable explanation. */
public record Violation(String rule, String detail) {}
