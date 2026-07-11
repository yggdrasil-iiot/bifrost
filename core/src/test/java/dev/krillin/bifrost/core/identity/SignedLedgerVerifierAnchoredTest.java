package dev.krillin.bifrost.core.identity;

import dev.krillin.bifrost.core.activation.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import static org.junit.jupiter.api.Assertions.*;

/** T7 ANCHORED depth: four-eyes head + monotonic external-anchor cross-check. Each test asserts the
 *  EXACT identity.* rule string. Proves ANCHORED is a strict superset of SIGNED (test 10). */
class SignedLedgerVerifierAnchoredTest {

    private final KeyPair alice = Ed25519Keys.generate();   // activator -> head.coSignedBy/coSig
    private final KeyPair bob   = Ed25519Keys.generate();   // approver  -> head.signedBy/sig

    private static ActivationEvent ev(String v, String prior) {
        return new ActivationEvent("Line1", "recipe", "mix", v, "sha-" + v, "alice", "bob", 1000L, prior, "ACTIVATE");
    }

    /** Seed authorized-keys + private key files; return a dual-signer over alice(activator)/bob(approver). */
    private LedgerSigner signer(Path root, Path keys) throws Exception {
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.writeString(akf,
            "{\"principal\":\"alice\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(alice.getPublic()) + "\"}\n"
          + "{\"principal\":\"bob\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(bob.getPublic()) + "\"}\n");
        Path a = keys.resolve("a"), b = keys.resolve("b");
        Files.writeString(a, Ed25519Keys.privateKeyB64(alice.getPrivate()));
        Files.writeString(b, Ed25519Keys.privateKeyB64(bob.getPrivate()));
        return KeyFileLedgerSigner.create("alice", a, "bob", b, AuthorizedKeys.load(root));
    }

    private SignedVerdict verifyAnchored(Path root, AnchorStore anchor) throws Exception {
        return new SignedLedgerVerifier(new ActivationLedger(root), AuthorizedKeys.load(root),
                new SignedHeadStore(root)).verify("Line1", TrustLevel.ANCHORED, anchor);
    }

    private Path ledgerFile(Path root) { return root.resolve("activation").resolve("Line1.jsonl"); }
    private Path headFile(Path root)   { return root.resolve("identity").resolve("Line1.head"); }
    private SignedHead readHead(Path root) throws Exception { return new SignedHeadStore(root).read("Line1").orElseThrow(); }
    private void writeHead(Path root, SignedHead h) throws Exception { new SignedHeadStore(root).write(h); }

    @Test void happy_path_whole(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        AnchorStore anchor = new FileAnchorStore(root);
        new ActivationLedger(root, anchor).append(ev("1.0.0", null), s);
        SignedVerdict v = verifyAnchored(root, anchor);
        assertTrue(v.intact(), v.rule());
    }

    @Test void anchor_missing(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        new ActivationLedger(root).append(ev("1.0.0", null), s);   // head written, NO anchor recorded
        SignedVerdict v = verifyAnchored(root, new FileAnchorStore(root));
        assertFalse(v.intact());
        assertEquals("identity.anchor.missing", v.rule());
    }

    @Test void anchor_rollback_head_seq_below_latest(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        AnchorStore anchor = new FileAnchorStore(root);
        ActivationLedger ledger = new ActivationLedger(root, anchor);
        ledger.append(ev("1.0.0", null), s);
        ledger.append(ev("1.1.0", "1.0.0"), s);                    // anchor latest seq=1, head seq=1
        SignedHead h = readHead(root);
        writeHead(root, new SignedHead(h.target(), 0, h.tailEntryHash(), h.signedBy(), h.sig(), h.coSignedBy(), h.coSig()));
        SignedVerdict v = verifyAnchored(root, anchor);
        assertFalse(v.intact());
        assertEquals("identity.anchor.rollback", v.rule());
    }

    @Test void anchor_rollback_emptied_ledger_and_head_deleted(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        AnchorStore anchor = new FileAnchorStore(root);
        new ActivationLedger(root, anchor).append(ev("1.0.0", null), s);
        Files.delete(ledgerFile(root));   // emptied ledger
        Files.delete(headFile(root));     // head deleted, but the anchor witness remains
        SignedVerdict v = verifyAnchored(root, anchor);
        assertFalse(v.intact());
        assertEquals("identity.anchor.rollback", v.rule());
    }

    @Test void anchor_tail_mismatch_same_seq(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        AnchorStore anchor = new FileAnchorStore(root);
        new ActivationLedger(root, anchor).append(ev("1.0.0", null), s);
        SignedHead h = readHead(root);    // seq stays 0, only the tail hash diverges from the anchor's
        writeHead(root, new SignedHead(h.target(), h.seq(), "deadbeefdeadbeef", h.signedBy(), h.sig(), h.coSignedBy(), h.coSig()));
        SignedVerdict v = verifyAnchored(root, anchor);
        assertFalse(v.intact());
        assertEquals("identity.anchor.tail-mismatch", v.rule());
    }

    @Test void anchor_behind_head_seq_above_latest(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        AnchorStore anchor = new FileAnchorStore(root);
        new ActivationLedger(root, anchor).append(ev("1.0.0", null), s);      // anchor seq 0, head seq 0
        new ActivationLedger(root).append(ev("1.1.0", "1.0.0"), s);           // head -> seq 1, anchor still 0
        SignedVerdict v = verifyAnchored(root, anchor);
        assertFalse(v.intact());
        assertEquals("identity.anchor.behind", v.rule());
    }

    @Test void head_four_eyes_missing(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        AnchorStore anchor = new FileAnchorStore(root);
        new ActivationLedger(root, anchor).append(ev("1.0.0", null), s);
        SignedHead h = readHead(root);
        writeHead(root, new SignedHead(h.target(), h.seq(), h.tailEntryHash(), h.signedBy(), h.sig()));  // 5-arg: co-pair null
        SignedVerdict v = verifyAnchored(root, anchor);
        assertFalse(v.intact());
        assertEquals("identity.head.four-eyes.missing", v.rule());
    }

    @Test void head_four_eyes_same_key(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        AnchorStore anchor = new FileAnchorStore(root);
        new ActivationLedger(root, anchor).append(ev("1.0.0", null), s);
        SignedHead h = readHead(root);   // signedBy == "bob"; make the co-signer bob too, with a VALID bob co-sig
        byte[] pre = SignedHeadStore.preimage("Line1", h.seq(), h.tailEntryHash()).getBytes(StandardCharsets.UTF_8);
        String bobCoSig = Ed25519Keys.sign(pre, bob.getPrivate());
        writeHead(root, new SignedHead(h.target(), h.seq(), h.tailEntryHash(), "bob", h.sig(), "bob", bobCoSig));
        SignedVerdict v = verifyAnchored(root, anchor);
        assertFalse(v.intact());
        assertEquals("identity.head.four-eyes.same-key", v.rule());
    }

    @Test void head_four_eyes_invalid(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        AnchorStore anchor = new FileAnchorStore(root);
        new ActivationLedger(root, anchor).append(ev("1.0.0", null), s);
        SignedHead h = readHead(root);   // coSignedBy stays alice, but coSig no longer verifies under alice's key
        String badCoSig = Ed25519Keys.sign("not-the-head-preimage".getBytes(StandardCharsets.UTF_8), alice.getPrivate());
        writeHead(root, new SignedHead(h.target(), h.seq(), h.tailEntryHash(), h.signedBy(), h.sig(), h.coSignedBy(), badCoSig));
        SignedVerdict v = verifyAnchored(root, anchor);
        assertFalse(v.intact());
        assertEquals("identity.head.four-eyes.invalid", v.rule());
    }

    @Test void emptied_ledger_with_orphan_head_and_no_anchor_is_tail_mismatch(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        new ActivationLedger(root).append(ev("1.0.0", null), s);   // head written, NO anchor store
        Files.delete(ledgerFile(root));                            // orphan head over an emptied ledger
        SignedVerdict v = verifyAnchored(root, new FileAnchorStore(root));   // empty anchor witness
        assertFalse(v.intact());
        assertEquals("identity.head.tail-mismatch", v.rule());     // ANCHORED >= SIGNED: signed-head fault still caught
    }
}
