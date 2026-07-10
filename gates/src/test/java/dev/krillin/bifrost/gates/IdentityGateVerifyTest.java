package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.activation.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.KeyPair;
import static org.junit.jupiter.api.Assertions.*;

class IdentityGateVerifyTest {

    /** Deterministically flip the first activatorSig base64 char to a DIFFERENT fixed char
     *  (a plain replaceFirst-with-'A' is a no-op ~1/64 when that char is already 'A'). */
    private static String flipActivatorSig(String line) {
        String marker = "\"activatorSig\":\"";
        int start = line.indexOf(marker) + marker.length();
        char c0 = line.charAt(start);
        char repl = (c0 == 'A') ? 'B' : 'A';
        return line.substring(0, start) + repl + line.substring(start + 1);
    }

    private void seedSigned(Path root, Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate();
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
        ledger.append(new ActivationEvent("Line1","recipe","mix","1.0.0","sha","alice","bob",1000L,null,"ACTIVATE"), s);
    }

    @Test void verify_signed_intact_exits_0(@TempDir Path root, @TempDir Path keys) throws Exception {
        seedSigned(root, keys);
        assertEquals(0, IdentityGate.run(new String[]{"verify-signed", root.toString(), "Line1"}));
    }

    @Test void verify_signed_broken_exits_1(@TempDir Path root, @TempDir Path keys) throws Exception {
        seedSigned(root, keys);
        Path lf = root.resolve("activation").resolve("Line1.jsonl");
        java.util.List<String> lines = Files.readAllLines(lf);
        lines.set(0, flipActivatorSig(lines.get(0)));
        Files.write(lf, lines);
        assertEquals(1, IdentityGate.run(new String[]{"verify-signed", root.toString(), "Line1"}));
    }

    @Test void verify_signed_no_such_target_exits_2(@TempDir Path root) {
        assertEquals(2, IdentityGate.run(new String[]{"verify-signed", root.toString(), "Nope"}));
    }

    @Test void verify_signed_usage_exits_2(@TempDir Path root) {
        assertEquals(2, IdentityGate.run(new String[]{"verify-signed", root.toString()}));
    }
}
