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
        List<LedgerEntry> hist = ledger.history(target);

        // 1. structural (T4)
        ChainVerdict structural = LedgerChain.verify(hist);
        if (!structural.intact())
            return SignedVerdict.broken(structural.brokenIndex(), structural.rule());

        // 2. per-entry signatures
        for (int i = 0; i < hist.size(); i++) {
            LedgerEntry en = hist.get(i);
            ActivationEvent e = en.event();
            if (en.activatorSig() == null || en.approverSig() == null)
                return SignedVerdict.broken(i, "identity.sig.missing");
            Optional<PublicKey> aKey = authorized.forPrincipal(e.activatedBy());
            Optional<PublicKey> pKey = authorized.forPrincipal(e.approvedBy());
            if (aKey.isEmpty() || pKey.isEmpty())
                return SignedVerdict.broken(i, "identity.key.unregistered");
            byte[] msg = en.entryHash().getBytes(StandardCharsets.UTF_8);
            if (!Ed25519Keys.verify(msg, en.activatorSig(), aKey.get())
                    || !Ed25519Keys.verify(msg, en.approverSig(), pKey.get()))
                return SignedVerdict.broken(i, "identity.sig.invalid");
            if (java.util.Arrays.equals(aKey.get().getEncoded(), pKey.get().getEncoded()))
                return SignedVerdict.broken(i, "identity.four-eyes.same-key");
        }

        // 3. head (only meaningful for a non-empty ledger)
        if (!hist.isEmpty()) {
            Optional<SignedHead> maybe = heads.read(target);
            if (maybe.isEmpty()) return SignedVerdict.broken(-1, "identity.head.missing");
            SignedHead head = maybe.get();
            LedgerEntry last = hist.get(hist.size() - 1);
            if (!last.entryHash().equals(head.tailEntryHash()))
                return SignedVerdict.broken(-1, "identity.head.tail-mismatch");
            if (head.seq() != hist.size() - 1)
                return SignedVerdict.broken(-1, "identity.head.seq-mismatch");
            Optional<PublicKey> hKey = authorized.forPrincipal(head.signedBy());
            // head.signedBy need NOT equal the tail approver (spec §4.7) — only must be registered
            byte[] hp = SignedHeadStore.preimage(head.target(), head.seq(), head.tailEntryHash())
                    .getBytes(StandardCharsets.UTF_8);
            if (hKey.isEmpty() || !Ed25519Keys.verify(hp, head.sig(), hKey.get()))
                return SignedVerdict.broken(-1, "identity.head.sig-invalid");
        }
        return SignedVerdict.whole();
    }
}
