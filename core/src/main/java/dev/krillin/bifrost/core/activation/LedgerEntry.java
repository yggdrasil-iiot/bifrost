package dev.krillin.bifrost.core.activation;

/** The persisted unit: a T3 ActivationEvent plus its hash-chain links, plus (T5) two Ed25519 signatures
 *  over entryHash. Serialized as one JSONL line
 *  {"event":{…},"prevHash":"…","entryHash":"…","activatorSig":"…","approverSig":"…"}.
 *  prevHash = the prior entry's entryHash (GENESIS for the first). entryHash = LedgerChain.entryHash(event,
 *  prevHash) — signatures are NOT in the hash, so T4 structural verification is unaffected and legacy
 *  (unsigned) lines still verify. activatorSig/approverSig are NULL on a legacy T4 line (fields absent). */
public record LedgerEntry(ActivationEvent event, String prevHash, String entryHash,
                          String activatorSig, String approverSig) {

    /** T4-compatibility factory for unsigned entries (both signatures null). */
    public static LedgerEntry unsigned(ActivationEvent event, String prevHash, String entryHash) {
        return new LedgerEntry(event, prevHash, entryHash, null, null);
    }
}
