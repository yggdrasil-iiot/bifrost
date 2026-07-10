package dev.krillin.bifrost.core.activation;

/** The two Ed25519 signatures over a LedgerEntry's entryHash (base64). */
public record Signatures(String activatorSig, String approverSig) {}
