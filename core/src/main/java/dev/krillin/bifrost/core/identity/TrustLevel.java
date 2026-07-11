package dev.krillin.bifrost.core.identity;

/** Activation-ledger trust depth. STRUCTURAL = T4 hash chain; SIGNED = T5 dual-sig entries + signed
 *  head; ANCHORED = T7 four-eyes head + monotonic external anchor cross-check. Each tier is opt-in. */
public enum TrustLevel { STRUCTURAL, SIGNED, ANCHORED }
