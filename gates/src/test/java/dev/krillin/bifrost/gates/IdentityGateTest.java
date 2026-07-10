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
}
