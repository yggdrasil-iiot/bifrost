package dev.krillin.bifrost.core.activation;

import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.KeyPair;
import java.time.Clock;
import java.util.List;
import static dev.krillin.bifrost.core.activation.ActivationAction.*;
import static org.junit.jupiter.api.Assertions.*;

class ActivationServiceAuthzTest {

    private ArtifactResolver okResolver() {
        return (kind, ref, version) -> java.util.Optional.of(
                new ArtifactResolver.ResolvedArtifact(Path.of("x"), "shaX"));
    }

    /** Registers alice+bob and returns a signer that names them. */
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

    private static ActivationPolicy policy(ActivationRule... rules) {
        return new ActivationPolicy("1", List.of(rules), "deny");
    }
    private ActivationRule r(String id, String p, ActivationAction a) {
        return new ActivationRule(id, p, a, "Line1", "recipe", "mix");
    }
    private ActivationRequest req() { return new ActivationRequest("Line1","recipe","mix","1.0.0","alice","bob",false); }

    @Test void authorized_activator_and_approver_are_admitted(@TempDir Path root, @TempDir Path keys) throws Exception {
        ActivationLedger ledger = new ActivationLedger(root);
        ActivationPolicy p = policy(r("r-act","alice",ACTIVATE), r("r-app","bob",APPROVE));
        ActivationVerdict v = new ActivationService(okResolver(), ledger, Clock.systemUTC())
                .activate(req(), signer(root, keys), p);
        assertTrue(v.ok(), v.violations().toString());
        assertEquals(1, ledger.history("Line1").size());
    }

    @Test void unauthorized_activator_is_denied_ledger_untouched(@TempDir Path root, @TempDir Path keys) throws Exception {
        ActivationLedger ledger = new ActivationLedger(root);
        // only bob→APPROVE; alice has no ACTIVATE rule
        ActivationPolicy p = policy(r("r-app","bob",APPROVE));
        ActivationVerdict v = new ActivationService(okResolver(), ledger, Clock.systemUTC())
                .activate(req(), signer(root, keys), p);
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("activation.authz.denied")), v.violations().toString());
        assertTrue(ledger.history("Line1").isEmpty(), "refused => ledger untouched");
    }

    @Test void unauthorized_approver_is_denied(@TempDir Path root, @TempDir Path keys) throws Exception {
        ActivationLedger ledger = new ActivationLedger(root);
        // only alice→ACTIVATE; bob has no APPROVE rule
        ActivationPolicy p = policy(r("r-act","alice",ACTIVATE));
        ActivationVerdict v = new ActivationService(okResolver(), ledger, Clock.systemUTC())
                .activate(req(), signer(root, keys), p);
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("activation.authz.denied")));
    }

    @Test void deny_all_policy_denies_signed_activation(@TempDir Path root, @TempDir Path keys) throws Exception {
        ActivationLedger ledger = new ActivationLedger(root);
        ActivationVerdict v = new ActivationService(okResolver(), ledger, Clock.systemUTC())
                .activate(req(), signer(root, keys), ActivationPolicy.denyAll());
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("activation.authz.denied")));
    }

    @Test void unsigned_activate_has_no_authz(@TempDir Path root) throws Exception {
        // 1-arg path: no signer, no authZ — succeeds even with no policy
        ActivationLedger ledger = new ActivationLedger(root);
        ActivationVerdict v = new ActivationService(okResolver(), ledger, Clock.systemUTC()).activate(req());
        assertTrue(v.ok());
        assertNull(ledger.history("Line1").get(0).activatorSig());
    }
}
