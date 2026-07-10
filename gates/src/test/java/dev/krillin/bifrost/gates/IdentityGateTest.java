package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class IdentityGateTest {

    @Test void keygen_writes_key_and_pub_files(@TempDir Path out) {
        int code = IdentityGate.run(new String[]{"keygen", "alice", "--out", out.toString()});
        assertEquals(0, code);
        assertTrue(Files.isRegularFile(out.resolve("alice.key")));
        assertTrue(Files.isRegularFile(out.resolve("alice.pub")));
    }

    @Test void keygen_key_and_pub_are_a_valid_pair(@TempDir Path out) throws Exception {
        IdentityGate.run(new String[]{"keygen", "alice", "--out", out.toString()});
        var priv = Ed25519Keys.privateKey(Files.readString(out.resolve("alice.key")).strip());
        var pub  = Ed25519Keys.publicKey(Files.readString(out.resolve("alice.pub")).strip());
        String sig = Ed25519Keys.sign("m".getBytes(), priv);
        assertTrue(Ed25519Keys.verify("m".getBytes(), sig, pub));
    }

    @Test void keygen_missing_args_is_usage_error(@TempDir Path out) {
        assertEquals(2, IdentityGate.run(new String[]{"keygen"}));
        assertEquals(2, IdentityGate.run(new String[]{"keygen", "alice"})); // no --out
    }

    @Test void keygen_rejects_path_traversal_principal(@TempDir Path out) {
        int code = IdentityGate.run(new String[]{"keygen", "../../evil", "--out", out.toString()});
        assertEquals(2, code, "a principal that escapes the out dir must be refused");
        assertTrue(Files.notExists(out.getParent().getParent().resolve("evil.key")), "no key written outside out dir");
    }

    @Test void keygen_private_key_not_world_readable(@TempDir Path out) throws Exception {
        IdentityGate.run(new String[]{"keygen", "alice", "--out", out.toString()});
        Path key = out.resolve("alice.key");
        var view = Files.getFileAttributeView(key, java.nio.file.attribute.PosixFileAttributeView.class);
        if (view != null) {   // POSIX only; on Windows this check is skipped (best-effort setReadable applied)
            var perms = view.readAttributes().permissions();
            assertFalse(perms.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_READ), "world-readable key");
            assertFalse(perms.contains(java.nio.file.attribute.PosixFilePermission.GROUP_READ), "group-readable key");
        }
    }
}
