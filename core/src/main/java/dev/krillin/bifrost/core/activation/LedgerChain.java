package dev.krillin.bifrost.core.activation;

import java.nio.charset.StandardCharsets;
import java.util.List;

/** The single hash-chain implementation shared by the ledger writer and every verifier (gate CLI,
 *  Heimdall edge). Pure, no I/O. An entry's hash commits to the event's business fields AND the prior
 *  entry's hash, so any retroactive edit/delete/reorder of history breaks the chain. The canonical
 *  preimage is an explicit, ordered, delimiter-joined field concatenation (NOT JSON) so the writer and
 *  every verifier hash byte-for-byte identical input regardless of serialization stability.
 *  If a field is ever added to ActivationEvent, it MUST be added to preimage() below (spec §4.2) or new
 *  events would be left un-chained on that field.
 *  LIMITATION (spec §9): the preimage assumes field values never contain the SEP (0x1F) delimiter or the
 *  NULL_SENTINEL sequence; this is not enforced. A malicious *writer* injecting a delimiter to force a
 *  preimage collision is outside T4's threat model (tamper-evidence of the recorded history against
 *  retroactive edits) — that authenticity gap is closed by T5 signed/authenticated writes. */
public final class LedgerChain {
    private LedgerChain() {}

    /** The genesis predecessor — the first entry's prevHash. 64 hex zeros. */
    public static final String GENESIS = "0".repeat(64);

    private static final char SEP = '\u001F';                       // ASCII Unit Separator -- cannot occur in field values
    private static final String NULL_SENTINEL = "\u0000null\u0000"; // distinct from a literal "null" string value

    /** Deterministic, serialization-independent hash preimage: event fields in fixed order, then prevHash. */
    static String preimage(ActivationEvent e, String prevHash) {
        return f(e.target()) + SEP + f(e.kind()) + SEP + f(e.ref()) + SEP + f(e.version()) + SEP
             + f(e.contentSha256()) + SEP + f(e.activatedBy()) + SEP + f(e.approvedBy()) + SEP
             + e.activatedAt() + SEP + f(e.priorVersion()) + SEP + f(e.action()) + SEP + f(prevHash);
    }

    private static String f(String v) { return v == null ? NULL_SENTINEL : v; }

    /** This entry's identity hash over (event fields + prevHash), UTF-8 encoded. */
    public static String entryHash(ActivationEvent e, String prevHash) {
        return Sha256.hex(preimage(e, prevHash).getBytes(StandardCharsets.UTF_8));
    }

    /** Walk the entries in append order; return the FIRST break, or intact. Check order: genesis (i==0)
     *  → entry self-hash → prev-link (i>0). */
    public static ChainVerdict verify(List<LedgerEntry> entries) {
        for (int i = 0; i < entries.size(); i++) {
            LedgerEntry en = entries.get(i);
            if (i == 0 && !GENESIS.equals(en.prevHash()))
                return ChainVerdict.broken(0, "ledger.chain.genesis-broken");
            if (!entryHash(en.event(), en.prevHash()).equals(en.entryHash()))
                return ChainVerdict.broken(i, "ledger.chain.entry-hash-mismatch");
            if (i > 0 && !entries.get(i - 1).entryHash().equals(en.prevHash()))
                return ChainVerdict.broken(i, "ledger.chain.prev-link-broken");
        }
        return ChainVerdict.whole();
    }
}
