package dev.krillin.bifrost.core.identity;

import dev.krillin.bifrost.core.activation.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

/** The full authenticated check, layered on T4's structural chain. verify(target):
 *  1. LedgerChain.verify (structural — reused verbatim; a structural break returns first);
 *  2. per entry: both sigs present, valid vs AuthorizedKeys for the claimed activatedBy/approvedBy, and
 *     the two resolved keys distinct;
 *  3. head: present, tailEntryHash == last.entryHash, seq == size-1, sig valid vs the head's signer.
 *  Fail-closed throughout. A fully-unsigned legacy ledger yields identity.sig.missing at index 0. */
public final class SignedLedgerVerifier {
    private final ActivationLedger ledger;
    private final AuthorizedKeys authorized;
    private final SignedHeadStore heads;

    public SignedLedgerVerifier(ActivationLedger ledger, AuthorizedKeys authorized, SignedHeadStore heads) {
        this.ledger = ledger; this.authorized = authorized; this.heads = heads;
    }

    /** Convenience: build all three collaborators from one registry root (gate + Heimdall use this). */
    public static SignedLedgerVerifier forRegistry(Path registryRoot) {
        return new SignedLedgerVerifier(new ActivationLedger(registryRoot),
                AuthorizedKeys.load(registryRoot), new SignedHeadStore(registryRoot));
    }

    public SignedVerdict verify(String target) throws IOException {
        return verify(target, TrustLevel.SIGNED, null);
    }

    /** T7 depth-selectable verification. STRUCTURAL=chain only; SIGNED=today's verify(target);
     *  ANCHORED=structure + per-entry sigs + anchor cross-check + four-eyes head. The anchor check runs
     *  BEFORE the signed-head check, and the signed-head check always runs in ANCHORED, so ANCHORED is a
     *  strict superset of SIGNED (an emptied ledger with an orphan head is still caught). */
    public SignedVerdict verify(String target, TrustLevel level, AnchorStore anchors) throws IOException {
        List<LedgerEntry> hist = ledger.history(target);
        ChainVerdict structural = LedgerChain.verify(hist);
        if (!structural.intact()) return SignedVerdict.broken(structural.brokenIndex(), structural.rule());
        if (level == TrustLevel.STRUCTURAL) return SignedVerdict.whole();

        SignedVerdict entries = verifyEntries(hist);
        if (!entries.intact()) return entries;

        if (level == TrustLevel.SIGNED) return verifySignedHead(target, hist);

        // ANCHORED. A null store here is a wiring error, not a ledger property — fail closed with a coded
        // verdict (never an opaque NPE) so a mis-wired caller gets the same disciplined failure as a tamper.
        if (anchors == null) return SignedVerdict.broken(-1, "identity.anchor.store-required");
        SignedVerdict anchorV = verifyAnchor(target, hist, anchors);
        if (!anchorV.intact()) return anchorV;
        SignedVerdict headV = verifySignedHead(target, hist);
        if (!headV.intact()) return headV;
        if (hist.isEmpty()) return SignedVerdict.whole();
        return verifyFourEyesCoPair(target);
    }

    /** Per-entry: both sigs present, valid vs AuthorizedKeys for the claimed activatedBy/approvedBy, and
     *  the two resolved keys distinct. Returns broken(i, code) on the first bad entry, else whole(). */
    private SignedVerdict verifyEntries(List<LedgerEntry> hist) {
        for (int i = 0; i < hist.size(); i++) {
            LedgerEntry en = hist.get(i);
            ActivationEvent e = en.event();
            if (en.activatorSig() == null || en.approverSig() == null)
                return SignedVerdict.broken(i, "identity.sig.missing");
            // A principal may hold several keys once rotation exists, and an entry carries no key id,
            // so the question is which of its registered keys signed this -- not "its key".
            if (authorized.allForPrincipal(e.activatedBy()).isEmpty()
                    || authorized.allForPrincipal(e.approvedBy()).isEmpty())
                return SignedVerdict.broken(i, "identity.key.unregistered");
            byte[] msg = en.entryHash().getBytes(StandardCharsets.UTF_8);
            Optional<PublicKey> aKey = authorized.verifying(e.activatedBy(), msg, en.activatorSig());
            Optional<PublicKey> pKey = authorized.verifying(e.approvedBy(), msg, en.approverSig());
            if (aKey.isEmpty() || pKey.isEmpty())
                return SignedVerdict.broken(i, "identity.sig.invalid");
            // Four-eyes has always been enforced on KEYS, but what it means is two PEOPLE. Once a
            // principal may hold several keys, key-distinctness stops implying person-distinctness:
            // one person could sign both legs with two keys of their own and pass a key-only check.
            // So both must hold, and the principal check is named separately -- an operator reading
            // "same-key" for what is actually one person signing twice would look for the wrong fault.
            if (e.activatedBy() != null && e.activatedBy().equals(e.approvedBy()))
                return SignedVerdict.broken(i, "identity.four-eyes.same-principal");
            if (java.util.Arrays.equals(aKey.get().getEncoded(), pKey.get().getEncoded()))
                return SignedVerdict.broken(i, "identity.four-eyes.same-key");
        }
        return SignedVerdict.whole();
    }

    /** Head block (T5): present, tailEntryHash == last.entryHash, seq == size-1, sig valid vs the head's
     *  signer. An empty ledger with an ORPHAN signed head is itself a fault (the head anchors entries that
     *  no longer exist — a full-truncation trace), not a vacuously-intact ledger. */
    private SignedVerdict verifySignedHead(String target, List<LedgerEntry> hist) throws IOException {
        if (hist.isEmpty()) {
            if (heads.read(target).isPresent()) return SignedVerdict.broken(-1, "identity.head.tail-mismatch");
            return SignedVerdict.whole();
        }
        Optional<SignedHead> maybe = heads.read(target);
        if (maybe.isEmpty()) return SignedVerdict.broken(-1, "identity.head.missing");
        SignedHead head = maybe.get();
        LedgerEntry last = hist.get(hist.size() - 1);
        if (!last.entryHash().equals(head.tailEntryHash()))
            return SignedVerdict.broken(-1, "identity.head.tail-mismatch");
        if (head.seq() != hist.size() - 1)
            return SignedVerdict.broken(-1, "identity.head.seq-mismatch");
        // head.signedBy need NOT equal the tail approver (spec §4.7) — only must be registered
        byte[] hp = SignedHeadStore.preimage(head.target(), head.seq(), head.tailEntryHash())
                .getBytes(StandardCharsets.UTF_8);
        if (authorized.verifying(head.signedBy(), hp, head.sig()).isEmpty())
            return SignedVerdict.broken(-1, "identity.head.sig-invalid");
        return SignedVerdict.whole();
    }

    /** Anchor faults only. Returns whole() when the anchor is simply not applicable (empty ledger AND no
     *  witness) — the signed-head check that follows handles the orphan-head corner. */
    private SignedVerdict verifyAnchor(String target, List<LedgerEntry> hist, AnchorStore anchors)
            throws IOException {
        Optional<AnchorRecord> latest = anchors.latest(target);
        Optional<SignedHead> head = heads.read(target);
        if (hist.isEmpty() || head.isEmpty())
            return latest.isPresent()
                    ? SignedVerdict.broken(-1, "identity.anchor.rollback")
                    : SignedVerdict.whole();
        if (latest.isEmpty()) return SignedVerdict.broken(-1, "identity.anchor.missing");
        long headSeq = head.get().seq();
        AnchorRecord a = latest.get();
        if (headSeq < a.seq()) return SignedVerdict.broken(-1, "identity.anchor.rollback");
        if (headSeq > a.seq()) return SignedVerdict.broken(-1, "identity.anchor.behind");
        if (!head.get().tailEntryHash().equals(a.tailEntryHash()))
            return SignedVerdict.broken(-1, "identity.anchor.tail-mismatch");
        return SignedVerdict.whole();
    }

    /** ONLY the four-eyes co-pair (verifySignedHead already validated tail/seq/approver-sig). */
    private SignedVerdict verifyFourEyesCoPair(String target) throws IOException {
        // head presence is guaranteed here: reached only for a non-empty ledger after verifySignedHead passed.
        SignedHead head = heads.read(target).orElseThrow();
        if (head.coSignedBy() == null || head.coSig() == null)
            return SignedVerdict.broken(-1, "identity.head.four-eyes.missing");
        byte[] hp = SignedHeadStore.preimage(head.target(), head.seq(), head.tailEntryHash())
                .getBytes(StandardCharsets.UTF_8);
        Optional<PublicKey> coKey = authorized.verifying(head.coSignedBy(), hp, head.coSig());
        if (coKey.isEmpty())
            return SignedVerdict.broken(-1, "identity.head.four-eyes.invalid");
        // Same reasoning as the per-entry check above: two keys held by one person are not two people.
        if (head.signedBy() != null && head.signedBy().equals(head.coSignedBy()))
            return SignedVerdict.broken(-1, "identity.head.four-eyes.same-principal");
        Optional<PublicKey> primary = authorized.verifying(head.signedBy(), hp, head.sig());
        if (primary.isPresent() && java.util.Arrays.equals(primary.get().getEncoded(), coKey.get().getEncoded()))
            return SignedVerdict.broken(-1, "identity.head.four-eyes.same-key");
        return SignedVerdict.whole();
    }
}
