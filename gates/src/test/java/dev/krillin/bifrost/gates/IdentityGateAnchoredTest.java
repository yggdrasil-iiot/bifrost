package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.activation.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.KeyPair;
import static org.junit.jupiter.api.Assertions.*;

/** T7 Chunk 5.1: the `identity verify-anchored` CLI (TrustLevel.ANCHORED). 0 intact / 1 broken / 2 usage.
 *  Unlike verify-signed, an emptied ledger with a live anchor must NOT be masked as "no such target"
 *  (that is a detectable rollback) — see the no-such-target-only-when-both-absent guard. */
class IdentityGateAnchoredTest {

    /** Seed authorized-keys + private key files; return a dual-signer over alice(activator)/bob(approver). */
    private LedgerSigner signer(Path root, Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate();
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.writeString(akf,
            "{\"principal\":\"alice\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(alice.getPublic())+"\"}\n"
          + "{\"principal\":\"bob\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(bob.getPublic())+"\"}\n");
        Path a = keys.resolve("a"), b = keys.resolve("b");
        Files.writeString(a, Ed25519Keys.privateKeyB64(alice.getPrivate()));
        Files.writeString(b, Ed25519Keys.privateKeyB64(bob.getPrivate()));
        return KeyFileLedgerSigner.create("alice", a, "bob", b, AuthorizedKeys.load(root));
    }

    private static ActivationEvent ev(String v, String prior) {
        return new ActivationEvent("Line1", "recipe", "mix", v, "sha-" + v, "alice", "bob", 1000L, prior, "ACTIVATE");
    }

    @Test void verify_anchored_intact_exits_0(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        new ActivationLedger(root, new FileAnchorStore(root)).append(ev("1.0.0", null), s);
        assertEquals(0, IdentityGate.run(new String[]{"verify-anchored", root.toString(), "Line1"}));
    }

    @Test void verify_anchored_rolled_back_head_exits_1(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = signer(root, keys);
        AnchorStore anchor = new FileAnchorStore(root);
        ActivationLedger ledger = new ActivationLedger(root, anchor);
        ledger.append(ev("1.0.0", null), s);
        ledger.append(ev("1.1.0", "1.0.0"), s);        // anchor latest seq=1, head seq=1
        SignedHeadStore heads = new SignedHeadStore(root);
        SignedHead h = heads.read("Line1").orElseThrow();
        heads.write(new SignedHead(h.target(), 0, h.tailEntryHash(), h.signedBy(), h.sig(), h.coSignedBy(), h.coSig()));
        assertEquals(1, IdentityGate.run(new String[]{"verify-anchored", root.toString(), "Line1"}));
    }

    @Test void verify_anchored_usage_exits_2(@TempDir Path root) {
        assertEquals(2, IdentityGate.run(new String[]{"verify-anchored", root.toString()}));
    }

    @Test void verify_anchored_no_such_target_exits_2(@TempDir Path root) {
        assertEquals(2, IdentityGate.run(new String[]{"verify-anchored", root.toString(), "Nope"}));
    }
}
