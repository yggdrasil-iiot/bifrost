package dev.krillin.bifrost.core.activation;

/** The persisted unit: a T3 ActivationEvent plus its hash-chain links. Serialized as one JSONL line
 *  {"event":{…},"prevHash":"…","entryHash":"…"}. prevHash = the prior entry's entryHash (GENESIS for the
 *  first entry). entryHash = LedgerChain.entryHash(event, prevHash) — this entry's identity. */
public record LedgerEntry(ActivationEvent event, String prevHash, String entryHash) {}
