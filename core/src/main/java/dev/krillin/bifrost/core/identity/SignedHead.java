package dev.krillin.bifrost.core.identity;

import com.fasterxml.jackson.annotation.JsonInclude;

/** The signed anchor for a target's ledger tail. seq is monotonic per target and MUST equal
 *  (entryCount - 1) at verify time. sig is the approver's Ed25519 signature over
 *  {@link SignedHeadStore#preimage}; coSig is the four-eyes co-signature by a SECOND distinct
 *  registered principal (coSignedBy) over the SAME preimage (T7). coSignedBy/coSig are nullable so
 *  T5-era single-sig heads still parse; T7 `anchored` verification requires them. Persisted as one
 *  JSON line at registry/identity/<target>.head. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record SignedHead(String target, long seq, String tailEntryHash,
                         String signedBy, String sig, String coSignedBy, String coSig) {
    /** T5-compatible single-sig head (co-pair null). */
    public SignedHead(String target, long seq, String tailEntryHash, String signedBy, String sig) {
        this(target, seq, tailEntryHash, signedBy, sig, null, null);
    }
}
