package dev.krillin.bifrost.core.activation;

import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.KeyPair;
import java.time.Clock;
import static org.junit.jupiter.api.Assertions.*;

class ActivationServiceSignedTest {

    private static final ActivationPolicy ALLOW_ALL = new ActivationPolicy("t", java.util.List.of(
            new ActivationRule("a","*", ActivationAction.ACTIVATE, "*","*","*"),
            new ActivationRule("b","*", ActivationAction.APPROVE,  "*","*","*")), "deny");

    /** Minimal resolver: any (kind,ref,version) resolves. NOTE the REAL interface is
     *  ArtifactResolver.ResolvedArtifact(Path path, String sha256) — NOT Resolved(byte[],String). */
    private ArtifactResolver okResolver() {
        return (kind, ref, version) ->
                java.util.Optional.of(new ArtifactResolver.ResolvedArtifact(java.nio.file.Path.of("x"), "shaX"));
    }

    private KeyFileLedgerSigner signer(Path root, Path keys, String aP, KeyPair a, String pP, KeyPair p) throws Exception {
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.writeString(akf,
            "{\"principal\":\""+aP+"\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(a.getPublic())+"\"}\n"
          + "{\"principal\":\""+pP+"\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(p.getPublic())+"\"}\n");
        Path af = keys.resolve("a"), pf = keys.resolve("p");
        Files.writeString(af, Ed25519Keys.privateKeyB64(a.getPrivate()));
        Files.writeString(pf, Ed25519Keys.privateKeyB64(p.getPrivate()));
        return KeyFileLedgerSigner.create(aP, af, pP, pf, AuthorizedKeys.load(root));
    }

    @Test void signed_activation_writes_a_signed_ledger(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate();
        ActivationLedger ledger = new ActivationLedger(root);
        ActivationService svc = new ActivationService(okResolver(), ledger, Clock.systemUTC());
        ActivationVerdict v = svc.activate(
                new ActivationRequest("Line1","recipe","mix","1.0.0","alice","bob",false),
                signer(root, keys, "alice", alice, "bob", bob), ALLOW_ALL);
        assertTrue(v.ok(), v.violations().toString());
        assertNotNull(ledger.history("Line1").get(0).activatorSig());
    }

    @Test void principal_mismatch_refuses_and_leaves_ledger_untouched(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate();
        // approver claims "bob" but the key file is alice's
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.writeString(akf,
            "{\"principal\":\"alice\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(alice.getPublic())+"\"}\n"
          + "{\"principal\":\"bob\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(bob.getPublic())+"\"}\n");
        Path af = keys.resolve("a"), pf = keys.resolve("p");
        Files.writeString(af, Ed25519Keys.privateKeyB64(alice.getPrivate()));
        Files.writeString(pf, Ed25519Keys.privateKeyB64(alice.getPrivate())); // wrong: alice's key as bob
        LedgerSigner bad = KeyFileLedgerSigner.create("alice", af, "bob", pf, AuthorizedKeys.load(root));

        ActivationLedger ledger = new ActivationLedger(root);
        ActivationVerdict v = new ActivationService(okResolver(), ledger, Clock.systemUTC())
                .activate(new ActivationRequest("Line1","recipe","mix","1.0.0","alice","bob",false), bad, ALLOW_ALL);
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("identity.key.principal-mismatch")));
        assertTrue(ledger.history("Line1").isEmpty(), "refused => ledger untouched");
    }

    @Test void signer_identity_must_match_named_principals(@TempDir Path root, @TempDir Path keys) throws Exception {
        // signer legitimately holds carol+bob keys, but the request NAMES alice as activator -> refuse at write time
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate(), carol = Ed25519Keys.generate();
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.writeString(akf,
            "{\"principal\":\"alice\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(alice.getPublic())+"\"}\n"
          + "{\"principal\":\"bob\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(bob.getPublic())+"\"}\n"
          + "{\"principal\":\"carol\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(carol.getPublic())+"\"}\n");
        Path cf = keys.resolve("c"), bf = keys.resolve("b");
        Files.writeString(cf, Ed25519Keys.privateKeyB64(carol.getPrivate()));
        Files.writeString(bf, Ed25519Keys.privateKeyB64(bob.getPrivate()));
        LedgerSigner carolSigner = KeyFileLedgerSigner.create("carol", cf, "bob", bf, AuthorizedKeys.load(root));

        ActivationLedger ledger = new ActivationLedger(root);
        ActivationVerdict v = new ActivationService(okResolver(), ledger, Clock.systemUTC())
                .activate(new ActivationRequest("Line1","recipe","mix","1.0.0","alice","bob",false), carolSigner, ALLOW_ALL);
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("identity.signer.principal-mismatch")),
                v.violations().toString());
        assertTrue(ledger.history("Line1").isEmpty(), "refused => ledger untouched (no signed-but-unverifiable record)");
    }

    @Test void null_signer_is_unchanged_t3_behavior(@TempDir Path root) throws Exception {
        ActivationLedger ledger = new ActivationLedger(root);
        ActivationVerdict v = new ActivationService(okResolver(), ledger, Clock.systemUTC())
                .activate(new ActivationRequest("Line1","recipe","mix","1.0.0","alice","bob",false));
        assertTrue(v.ok());
        assertNull(ledger.history("Line1").get(0).activatorSig());
    }
}
