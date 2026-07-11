package dev.krillin.bifrost.heimdall;

import dev.krillin.bifrost.core.activation.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Chunk 6: the ANCHORED edge tier ({@code REQUIRE_ANCHORED_ACTIVATION}). Mirrors
 * {@link RequireSignedActivationTest}'s fixture — seed keys + authorized-keys, then drive
 * {@link NcmdOpcUaBridgeMain#assertLedgerTrustworthy} directly at trust level ANCHORED.
 */
class RequireAnchoredActivationTest {

    /** Seed keys + authorized-keys + a dual-head ANCHORED ledger (with the anchor witness recorded). Returns
     *  the signer so a follow-up append can advance the head PAST the anchor (rollback/behind simulation). */
    private LedgerSigner seedAnchored(Path root, Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate();
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.writeString(akf,
            "{\"principal\":\"alice\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(alice.getPublic())+"\"}\n"
          + "{\"principal\":\"bob\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(bob.getPublic())+"\"}\n");
        Path a=keys.resolve("a"), b=keys.resolve("b");
        Files.writeString(a, Ed25519Keys.privateKeyB64(alice.getPrivate()));
        Files.writeString(b, Ed25519Keys.privateKeyB64(bob.getPrivate()));
        LedgerSigner s = KeyFileLedgerSigner.create("alice", a, "bob", b, AuthorizedKeys.load(root));
        new ActivationLedger(root, new FileAnchorStore(root)).append(
            new ActivationEvent("Line1","recipe","mix","1.0.0","sha","alice","bob",1000L,null,"ACTIVATE"), s);
        return s;
    }

    @Test void require_anchored_on_passes_for_intact_anchored_ledger(@TempDir Path root, @TempDir Path keys) throws Exception {
        seedAnchored(root, keys);
        assertDoesNotThrow(() -> NcmdOpcUaBridgeMain.assertLedgerTrustworthy(root, "Line1", true, true, "file", null));
    }

    @Test void require_anchored_on_throws_anchor_denied_when_head_outpaces_anchor(@TempDir Path root, @TempDir Path keys) throws Exception {
        LedgerSigner s = seedAnchored(root, keys);
        // advance the head PAST the witness WITHOUT recording an anchor (plain ActivationLedger, no store) ->
        // head.seq(1) > anchor.seq(0): the anchor is stale, an anchor.* fault that must fail-close at the edge.
        new ActivationLedger(root).append(
            new ActivationEvent("Line1","recipe","mix","1.0.1","sha2","alice","bob",2000L,null,"ACTIVATE"), s);
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> NcmdOpcUaBridgeMain.assertLedgerTrustworthy(root, "Line1", true, true, "file", null));
        assertTrue(ex.getMessage().contains("activation.edge.anchor-denied"), ex.getMessage());
        assertTrue(ex.getMessage().contains("reason=identity.anchor."), ex.getMessage());
    }

    @Test void resolve_default_off_is_neither_anchored_nor_signed() {
        var cfg = NcmdOpcUaBridgeMain.resolve(key -> null);
        assertFalse(cfg.requireAnchoredActivation());
        assertFalse(cfg.requireSignedActivation());
    }

    @Test void resolve_anchored_on_implies_signed() {
        var cfg = NcmdOpcUaBridgeMain.resolve(Map.of("REQUIRE_ANCHORED_ACTIVATION","on")::get);
        assertTrue(cfg.requireAnchoredActivation());
        assertTrue(cfg.requireSignedActivation());   // anchored presupposes authN
    }
}
