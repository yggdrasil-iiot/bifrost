package dev.krillin.bifrost.core.identity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class AuthorizedKeysTest {

    private static void writeKeys(Path root, String... lines) throws Exception {
        Path f = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(f.getParent());
        Files.write(f, List.of(lines));
    }

    private static String line(String principal, KeyPair kp) {
        return "{\"principal\":\"" + principal + "\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(kp.getPublic()) + "\"}";
    }

    @Test void absent_file_authorizes_nobody(@TempDir Path root) throws Exception {
        AuthorizedKeys ak = AuthorizedKeys.load(root);
        assertTrue(ak.forPrincipal("alice").isEmpty());
    }

    @Test void registered_principal_resolves_to_its_pubkey(@TempDir Path root) throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        writeKeys(root, line("alice", alice));
        AuthorizedKeys ak = AuthorizedKeys.load(root);
        assertTrue(ak.forPrincipal("alice").isPresent());
        assertTrue(ak.forPrincipal("bob").isEmpty());
        // resolved key verifies a sig made by alice's private key
        String sig = Ed25519Keys.sign("m".getBytes(), alice.getPrivate());
        assertTrue(Ed25519Keys.verify("m".getBytes(), sig, ak.forPrincipal("alice").get()));
    }

    @Test void duplicate_principal_same_key_is_tolerated(@TempDir Path root) throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        writeKeys(root, line("alice", alice), line("alice", alice));
        assertTrue(AuthorizedKeys.load(root).forPrincipal("alice").isPresent());
    }

    @Test void duplicate_principal_different_key_is_a_load_error(@TempDir Path root) throws Exception {
        writeKeys(root, line("alice", Ed25519Keys.generate()), line("alice", Ed25519Keys.generate()));
        assertThrows(IllegalStateException.class, () -> AuthorizedKeys.load(root));
    }

    @Test void blank_lines_are_ignored(@TempDir Path root) throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        writeKeys(root, line("alice", alice), "", "  ");
        assertTrue(AuthorizedKeys.load(root).forPrincipal("alice").isPresent());
    }

    @Test void malformed_public_key_value_is_a_coded_load_error(@TempDir Path root) throws Exception {
        writeKeys(root, "{\"principal\":\"alice\",\"publicKey\":\"not-a-valid-key!!!\"}");
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> AuthorizedKeys.load(root));
        assertTrue(ex.getMessage().startsWith("identity.authorized-keys.bad-public-key"), ex.getMessage());
    }

    @Test void unparseable_json_line_is_a_coded_load_error(@TempDir Path root) throws Exception {
        writeKeys(root, "this is not json");
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> AuthorizedKeys.load(root));
        assertTrue(ex.getMessage().startsWith("identity.authorized-keys.read-error"), ex.getMessage());
    }
}
