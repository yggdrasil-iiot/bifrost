package dev.krillin.bifrost.core.activation;

import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ActivationLedgerSignedTest {

    private static ActivationEvent ev(String v, String prior) {
        return new ActivationEvent("Line1","recipe","mix",v,"sha-"+v,"alice","bob",1000L,prior,"ACTIVATE");
    }

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

    @Test void null_signer_writes_unsigned_entry_and_no_head(@TempDir Path root) throws Exception {
        ActivationLedger ledger = new ActivationLedger(root);
        ledger.append(ev("1.0.0", null), null);
        List<LedgerEntry> h = ledger.history("Line1");
        assertEquals(1, h.size());
        assertNull(h.get(0).activatorSig());
        assertTrue(new SignedHeadStore(root).read("Line1").isEmpty(), "no head on the unsigned path");
    }

    @Test void t4_append_still_works(@TempDir Path root) throws Exception {
        ActivationLedger ledger = new ActivationLedger(root);
        ledger.append(ev("1.0.0", null));   // legacy single-arg
        assertEquals(1, ledger.history("Line1").size());
    }

    @Test void signed_append_writes_two_sigs_and_advances_head(@TempDir Path root, @TempDir Path keys) throws Exception {
        ActivationLedger ledger = new ActivationLedger(root);
        LedgerSigner s = signer(root, keys);
        ledger.append(ev("1.0.0", null), s);
        ledger.append(ev("1.1.0", "1.0.0"), s);
        List<LedgerEntry> h = ledger.history("Line1");
        assertEquals(2, h.size());
        assertNotNull(h.get(1).activatorSig());
        assertNotNull(h.get(1).approverSig());
        SignedHead head = new SignedHeadStore(root).read("Line1").orElseThrow();
        assertEquals(1L, head.seq(), "seq == entryCount-1");
        assertEquals(h.get(1).entryHash(), head.tailEntryHash());
        assertEquals("bob", head.signedBy());
    }
}
