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
        assertDoesNotThrow(() -> NcmdOpcUaBridgeMain.assertLedgerTrustworthy(root, "Line1", true, false, "file", null));
    }

    @Test void require_signed_on_throws_signed_code_on_broken(@TempDir Path root, @TempDir Path keys) throws Exception {
        seedSigned(root, keys);
        tamperFirstSigByte(root.resolve("activation").resolve("Line1.jsonl"));
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> NcmdOpcUaBridgeMain.assertLedgerTrustworthy(root, "Line1", true, false, "file", null));
        assertTrue(ex.getMessage().contains("activation.edge.signed-ledger-broken"), ex.getMessage());
    }

    @Test void require_signed_off_uses_structural_only(@TempDir Path root) throws Exception {
        // an UNSIGNED T4 ledger: intact structurally, no sigs -> must PASS when flag is off
        new ActivationLedger(root).append(
            new ActivationEvent("Line1","recipe","mix","1.0.0","sha","alice","bob",1000L,null,"ACTIVATE"));
        assertDoesNotThrow(() -> NcmdOpcUaBridgeMain.assertLedgerTrustworthy(root, "Line1", false, false, "file", null));
    }

    private void writePolicy(Path root, boolean grantAlice) throws Exception {
        Path f = root.resolve("identity").resolve("activation-policy.json");
        Files.createDirectories(f.getParent());
        String rules = "{\"id\":\"r-app\",\"principal\":\"bob\",\"action\":\"approve\",\"target\":\"Line1\",\"kind\":\"recipe\",\"ref\":\"mix\"}"
                + (grantAlice ? ",{\"id\":\"r-act\",\"principal\":\"alice\",\"action\":\"activate\",\"target\":\"Line1\",\"kind\":\"recipe\",\"ref\":\"mix\"}" : "");
        Files.writeString(f, "{\"version\":\"1\",\"default\":\"deny\",\"rules\":[" + rules + "]}");
    }

    @Test void edge_authz_allows_when_both_permitted(@TempDir Path root) throws Exception {
        writePolicy(root, true);
        assertDoesNotThrow(() -> NcmdOpcUaBridgeMain.assertActivationAuthorized(root, "Line1","recipe","mix","alice","bob", true));
    }

    @Test void edge_authz_denies_when_activator_revoked(@TempDir Path root) throws Exception {
        writePolicy(root, false);   // alice's ACTIVATE removed
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> NcmdOpcUaBridgeMain.assertActivationAuthorized(root, "Line1","recipe","mix","alice","bob", true));
        assertTrue(ex.getMessage().contains("activation.edge.authz-denied"), ex.getMessage());
    }

    /**
     * A break-glass activation must RESTORE the line, not take it down. Its approver holds
     * BREAK_GLASS_APPROVE and -- by the dual-role rule in ActivationPolicyStore -- never APPROVE, so an
     * edge that only ever asks for APPROVE fail-closes on exactly the entry written during an emergency.
     */
    @Test void edge_authz_accepts_a_break_glass_approver(@TempDir Path root) throws Exception {
        writeBreakGlassPolicy(root);
        assertDoesNotThrow(() -> NcmdOpcUaBridgeMain.assertActivationAuthorized(
                root, "Line1", "recipe", "mix", "alice", "breakglass-duty", true));
    }

    /** The fallback is a second grant, not a hole: a principal holding neither role is still denied. */
    @Test void edge_authz_still_denies_an_approver_holding_neither_role(@TempDir Path root) throws Exception {
        writeBreakGlassPolicy(root);
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> NcmdOpcUaBridgeMain.assertActivationAuthorized(
                        root, "Line1", "recipe", "mix", "alice", "stranger", true));
        assertTrue(ex.getMessage().contains("activation.edge.authz-denied"), ex.getMessage());
    }

    /** Scope still binds: a duty grant on one target does not admit an entry on another. */
    @Test void edge_authz_denies_a_break_glass_approver_out_of_scope(@TempDir Path root) throws Exception {
        writeBreakGlassPolicy(root);
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> NcmdOpcUaBridgeMain.assertActivationAuthorized(
                        root, "Line1", "recipe", "other", "alice", "breakglass-duty", true));
        assertTrue(ex.getMessage().contains("activation.edge.authz-denied"), ex.getMessage());
    }

    /** alice ACTIVATE + breakglass-duty BREAK_GLASS_APPROVE; nobody holds APPROVE. */
    private void writeBreakGlassPolicy(Path root) throws Exception {
        Path f = root.resolve("identity").resolve("activation-policy.json");
        Files.createDirectories(f.getParent());
        Files.writeString(f, "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
                + "{\"id\":\"r-act\",\"principal\":\"alice\",\"action\":\"activate\","
                + "\"target\":\"Line1\",\"kind\":\"recipe\",\"ref\":\"mix\"},"
                + "{\"id\":\"r-bg\",\"principal\":\"breakglass-duty\",\"action\":\"break_glass_approve\","
                + "\"target\":\"Line1\",\"kind\":\"recipe\",\"ref\":\"mix\"}]}");
    }

    @Test void edge_authz_is_noop_when_require_signed_off(@TempDir Path root) throws Exception {
        // no policy at all; require-signed off => skip (authZ presupposes authN)
        assertDoesNotThrow(() -> NcmdOpcUaBridgeMain.assertActivationAuthorized(root, "Line1","recipe","mix","alice","bob", false));
    }
}
