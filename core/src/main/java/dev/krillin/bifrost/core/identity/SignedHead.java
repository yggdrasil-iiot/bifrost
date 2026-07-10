package dev.krillin.bifrost.core.identity;

/** The signed anchor for a target's ledger tail. seq is monotonic per target and MUST equal
 *  (entryCount - 1) at verify time — this is what makes tail-truncation detectable. sig is the approver's
 *  Ed25519 signature over {@link SignedHeadStore#preimage}. Persisted as one JSON line at
 *  registry/identity/<target>.head. */
public record SignedHead(String target, long seq, String tailEntryHash, String signedBy, String sig) {}
