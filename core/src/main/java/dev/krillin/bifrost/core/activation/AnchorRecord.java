package dev.krillin.bifrost.core.activation;

/** The minimal external-anchor witness datum: the highest ledger seq reached for a target and the
 *  entryHash it anchored. Persisted as one JSON line per record by an {@link AnchorStore}. */
public record AnchorRecord(String target, long seq, String tailEntryHash) {}
