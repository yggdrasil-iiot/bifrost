package dev.krillin.bifrost.core.identity;

import dev.krillin.bifrost.core.activation.LedgerSigner;
import dev.krillin.bifrost.core.activation.Signatures;
import dev.krillin.bifrost.core.schema.Violation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class KeyFileLedgerSignerTest {

    private Path writeKey(Path dir, String name, java.security.PrivateKey k) throws Exception {
        Path f = dir.resolve(name);
        Files.writeString(f, Ed25519Keys.privateKeyB64(k));
        return f;
    }

    private void authorize(Path root, String principal, KeyPair kp) throws Exception {
        Path f = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(f.getParent());
        String line = "{\"principal\":\"" + principal + "\",\"publicKey\":\""
                + Ed25519Keys.publicKeyB64(kp.getPublic()) + "\"}\n";
        Files.writeString(f, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    @Test void preflight_clean_for_two_distinct_registered_principals(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate();
        authorize(root, "alice", alice); authorize(root, "bob", bob);
        LedgerSigner s = KeyFileLedgerSigner.create("alice", writeKey(keys,"a",alice.getPrivate()),
                "bob", writeKey(keys,"b",bob.getPrivate()), AuthorizedKeys.load(root));
        assertTrue(s.preflight().isEmpty());
        // sigs verify under the registered keys
        Signatures sig = s.sign("hash1");
        assertTrue(Ed25519Keys.verify("hash1".getBytes(StandardCharsets.UTF_8), sig.activatorSig(), alice.getPublic()));
        assertTrue(Ed25519Keys.verify("hash1".getBytes(StandardCharsets.UTF_8), sig.approverSig(), bob.getPublic()));
    }

    @Test void preflight_flags_key_file_not_matching_its_principal(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate();
        authorize(root, "alice", alice); authorize(root, "bob", bob);
        // approver claims "bob" but hands alice's key file -> principal-mismatch
        LedgerSigner s = KeyFileLedgerSigner.create("alice", writeKey(keys,"a",alice.getPrivate()),
                "bob", writeKey(keys,"b2",alice.getPrivate()), AuthorizedKeys.load(root));
        List<Violation> v = s.preflight();
        assertFalse(v.isEmpty());
        assertTrue(v.stream().anyMatch(x -> x.rule().equals("identity.key.principal-mismatch")));
    }

    @Test void preflight_flags_unregistered_principal(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate();
        authorize(root, "alice", alice); // bob NOT authorized
        LedgerSigner s = KeyFileLedgerSigner.create("alice", writeKey(keys,"a",alice.getPrivate()),
                "bob", writeKey(keys,"b",bob.getPrivate()), AuthorizedKeys.load(root));
        // an UNREGISTERED principal folds into principal-mismatch at WRITE time (spec 4.5);
        // identity.key.unregistered is the VERIFIER-side code, exercised in Chunk 3.
        assertTrue(s.preflight().stream().anyMatch(x -> x.rule().equals("identity.key.principal-mismatch")));
    }

    @Test void preflight_flags_two_principals_sharing_one_pubkey(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair shared = Ed25519Keys.generate();
        authorize(root, "alice", shared); authorize(root, "bob", shared);
        LedgerSigner s = KeyFileLedgerSigner.create("alice", writeKey(keys,"a",shared.getPrivate()),
                "bob", writeKey(keys,"b",shared.getPrivate()), AuthorizedKeys.load(root));
        assertTrue(s.preflight().stream().anyMatch(x -> x.rule().equals("identity.four-eyes.same-key")));
    }

    @Test void signHead_is_verifiable_by_approver_key(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate();
        authorize(root, "alice", alice); authorize(root, "bob", bob);
        LedgerSigner s = KeyFileLedgerSigner.create("alice", writeKey(keys,"a",alice.getPrivate()),
                "bob", writeKey(keys,"b",bob.getPrivate()), AuthorizedKeys.load(root));
        String preimage = "Line1\u001F0\u001Fhash1";
        assertEquals("bob", s.approverPrincipal());
        assertTrue(Ed25519Keys.verify(preimage.getBytes(StandardCharsets.UTF_8), s.signHead(preimage), bob.getPublic()));
    }
}
