package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.annotation.JsonInclude;

/** The persisted unit: a T3 ActivationEvent plus its hash-chain links, plus (T5) two Ed25519 signatures
 *  over entryHash. Serialized as one JSONL line
 *  {"event":{…},"prevHash":"…","entryHash":"…","activatorSig":"…","approverSig":"…"}.
 *  prevHash = the prior entry's entryHash (GENESIS for the first). entryHash = LedgerChain.entryHash(event,
 *  prevHash) — signatures are NOT in the hash, so T4 structural verification is unaffected and legacy
 *  (unsigned) lines still verify. activatorSig/approverSig are NULL on a legacy T4 line; the NON_NULL
 *  inclusion omits them entirely for an unsigned entry, so its on-disk line is byte-identical to a T4 line. */
public record LedgerEntry(ActivationEvent event, String prevHash, String entryHash,
                          @JsonInclude(JsonInclude.Include.NON_NULL) String activatorSig,
                          @JsonInclude(JsonInclude.Include.NON_NULL) String approverSig) {

    /** T4-compatibility factory for unsigned entries (both signatures null). */
    public static LedgerEntry unsigned(ActivationEvent event, String prevHash, String entryHash) {
        return new LedgerEntry(event, prevHash, entryHash, null, null);
    }
}
