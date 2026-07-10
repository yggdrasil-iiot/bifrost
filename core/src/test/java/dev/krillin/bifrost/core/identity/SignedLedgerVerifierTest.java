package dev.krillin.bifrost.core.identity;

import dev.krillin.bifrost.core.activation.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class SignedLedgerVerifierTest {

    private static ActivationEvent ev(String v, String prior) {
        return new ActivationEvent("Line1","recipe","mix",v,"sha-"+v,"alice","bob",1000L,prior,"ACTIVATE");
    }

    /** Deterministically flip the first activatorSig base64 char to a DIFFERENT fixed char
     *  (the plan's plain replaceFirst is a no-op ~1/64 when that char is already 'A'). */
    private static String flipActivatorSig(String line) {
        String marker = "\"activatorSig\":\"";
        int start = line.indexOf(marker) + marker.length();
        char c0 = line.charAt(start);
        char repl = (c0 == 'A') ? 'B' : 'A';
        return line.substring(0, start) + repl + line.substring(start + 1);
    }

    /** Seed a 2-entry signed ledger; returns the verifier over the registry root. */
    private SignedLedgerVerifier seed(Path root, Path keys, KeyPair alice, KeyPair bob) throws Exception {
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.writeString(akf,
            "{\"principal\":\"alice\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(alice.getPublic())+"\"}\n"
          + "{\"principal\":\"bob\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(bob.getPublic())+"\"}\n");
        Path a = keys.resolve("a"), b = keys.resolve("b");
        Files.writeString(a, Ed25519Keys.privateKeyB64(alice.getPrivate()));
        Files.writeString(b, Ed25519Keys.privateKeyB64(bob.getPrivate()));
        LedgerSigner s = KeyFileLedgerSigner.create("alice", a, "bob", b, AuthorizedKeys.load(root));
        ActivationLedger ledger = new ActivationLedger(root);
        ledger.append(ev("1.0.0", null), s);
        ledger.append(ev("1.1.0", "1.0.0"), s);
        return SignedLedgerVerifier.forRegistry(root);
    }

    private Path ledgerFile(Path root) { return root.resolve("activation").resolve("Line1.jsonl"); }

    @Test void intact_signed_ledger_verifies(@TempDir Path root, @TempDir Path keys) throws Exception {
        SignedVerdict v = seed(root, keys, Ed25519Keys.generate(), Ed25519Keys.generate()).verify("Line1");
        assertTrue(v.intact(), v.rule());
    }

    @Test void tampered_signature_is_invalid(@TempDir Path root, @TempDir Path keys) throws Exception {
        SignedLedgerVerifier ver = seed(root, keys, Ed25519Keys.generate(), Ed25519Keys.generate());
        List<String> lines = Files.readAllLines(ledgerFile(root));
        lines.set(0, flipActivatorSig(lines.get(0)));
        Files.write(ledgerFile(root), lines);
        SignedVerdict v = ver.verify("Line1");
        assertFalse(v.intact());
        assertEquals("identity.sig.invalid", v.rule());
    }

    @Test void unregistered_signer_is_rejected(@TempDir Path root, @TempDir Path keys) throws Exception {
        SignedLedgerVerifier ver = seed(root, keys, Ed25519Keys.generate(), Ed25519Keys.generate());
        // drop alice from authorized-keys after the fact
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        List<String> keep = new ArrayList<>();
        for (String l : Files.readAllLines(akf)) if (!l.contains("\"alice\"")) keep.add(l);
        Files.write(akf, keep);
        SignedVerdict v = SignedLedgerVerifier.forRegistry(root).verify("Line1");
        assertFalse(v.intact());
        assertEquals("identity.key.unregistered", v.rule());
    }

    @Test void tail_truncation_is_detected_by_head(@TempDir Path root, @TempDir Path keys) throws Exception {
        SignedLedgerVerifier ver = seed(root, keys, Ed25519Keys.generate(), Ed25519Keys.generate());
        List<String> lines = Files.readAllLines(ledgerFile(root));
        Files.write(ledgerFile(root), lines.subList(0, 1)); // drop the last entry, leave the head
        SignedVerdict v = ver.verify("Line1");
        assertFalse(v.intact());
        // seq (1) != size-1 (0) OR head.tailEntryHash != last.entryHash — both are head faults
        assertTrue(v.rule().equals("identity.head.seq-mismatch") || v.rule().equals("identity.head.tail-mismatch"), v.rule());
    }

    @Test void full_rechain_of_a_past_event_fails_signature(@TempDir Path root, @TempDir Path keys) throws Exception {
        SignedLedgerVerifier ver = seed(root, keys, Ed25519Keys.generate(), Ed25519Keys.generate());
        // Rewrite entry#0's event AND recompute all entryHash/prevHash so LedgerChain.verify passes,
        // but WITHOUT re-signing (attacker has no registered key). Rebuild via the same chain math.
        List<LedgerEntry> h = new ActivationLedger(root).history("Line1");
        ActivationEvent edited = ev("9.9.9", null);                 // forged past event
        String h0 = LedgerChain.entryHash(edited, LedgerChain.GENESIS);
        LedgerEntry e0 = new LedgerEntry(edited, LedgerChain.GENESIS, h0, h.get(0).activatorSig(), h.get(0).approverSig());
        ActivationEvent e1ev = h.get(1).event();
        String h1 = LedgerChain.entryHash(e1ev, h0);
        LedgerEntry e1 = new LedgerEntry(e1ev, h0, h1, h.get(1).activatorSig(), h.get(1).approverSig());
        com.fasterxml.jackson.databind.ObjectMapper m = dev.krillin.bifrost.core.schema.JsonMapperFactory.create();
        Files.write(ledgerFile(root), List.of(m.writeValueAsString(e0), m.writeValueAsString(e1)));
        SignedVerdict v = ver.verify("Line1");
        assertFalse(v.intact());
        assertEquals("identity.sig.invalid", v.rule(), "structural chain re-validates but the sig over the new hash fails");
    }
}
