package dev.krillin.bifrost.heimdall;

import dev.krillin.bifrost.core.activation.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class RequireSignedActivationTest {

    private void seedSigned(Path root, Path keys) throws Exception {
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
        new ActivationLedger(root).append(
            new ActivationEvent("Line1","recipe","mix","1.0.0","sha","alice","bob",1000L,null,"ACTIVATE"), s);
    }

    /** Deterministic sig-byte flip: capture the first activatorSig char and replace it with a DIFFERENT
     *  fixed char, so the tamper is never a no-op (the ~1/64 case where the char was already 'A'). */
    private void tamperFirstSigByte(Path ledgerFile) throws Exception {
        List<String> lines = Files.readAllLines(ledgerFile);
        String line = lines.get(0);
        int idx = line.indexOf("\"activatorSig\":\"") + "\"activatorSig\":\"".length();
        char c0 = line.charAt(idx);
        char repl = (c0 == 'A') ? 'B' : 'A';
        lines.set(0, line.substring(0, idx) + repl + line.substring(idx + 1));
        Files.write(ledgerFile, lines);
    }

    @Test void require_signed_on_passes_for_intact_signed_ledger(@TempDir Path root, @TempDir Path keys) throws Exception {
        seedSigned(root, keys);
        assertDoesNotThrow(() -> NcmdOpcUaBridgeMain.assertLedgerTrustworthy(root, "Line1", true));
    }

    @Test void require_signed_on_throws_signed_code_on_broken(@TempDir Path root, @TempDir Path keys) throws Exception {
        seedSigned(root, keys);
        tamperFirstSigByte(root.resolve("activation").resolve("Line1.jsonl"));
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> NcmdOpcUaBridgeMain.assertLedgerTrustworthy(root, "Line1", true));
        assertTrue(ex.getMessage().contains("activation.edge.signed-ledger-broken"), ex.getMessage());
    }

    @Test void require_signed_off_uses_structural_only(@TempDir Path root) throws Exception {
        // an UNSIGNED T4 ledger: intact structurally, no sigs -> must PASS when flag is off
        new ActivationLedger(root).append(
            new ActivationEvent("Line1","recipe","mix","1.0.0","sha","alice","bob",1000L,null,"ACTIVATE"));
        assertDoesNotThrow(() -> NcmdOpcUaBridgeMain.assertLedgerTrustworthy(root, "Line1", false));
    }
}
