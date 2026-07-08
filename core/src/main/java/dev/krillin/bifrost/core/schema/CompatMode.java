package dev.krillin.bifrost.core.schema;

/**
 * Compatibility policy mode (Confluent vocabulary).
 * FORWARD = old consumers read new data (add OK, remove/type-change = violation) — default for UNS.
 * BACKWARD = new consumers read old data (remove OK, add/type-change = violation).
 * FULL     = both directions (add, remove, and type-change all violate).
 * NONE     = no checks.
 */
public enum CompatMode { FORWARD, BACKWARD, FULL, NONE }
