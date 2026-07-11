package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.activation.FileAnchorStore;
import dev.krillin.bifrost.core.identity.Ed25519Keys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

class ActivateGateSignedTest {

    @Test void only_one_key_flag_is_usage_error(@TempDir Path root) throws Exception {
        int code = ActivateGate.run(new String[]{"activate", root.toString(), "Line1","recipe","mix","1.0.0",
                "--by","alice","--approved-by","bob","--by-key","/no/such.key"});
        assertEquals(2, code, "one key flag without the other => usage error");
    }

    /** Seed authorized-keys + private key files + a deny-by-default policy that allows alice/bob on the
     *  target; write the recipe MasterSpec the resolver seals. Returns {aliceKeyFile, bobKeyFile}. */
    private Path[] seedIdentity(Path root, Path keys, String target, String ref, String version)
            throws Exception {
        KeyPair alice = Ed25519Keys.generate(), bob = Ed25519Keys.generate();
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.writeString(akf,
            "{\"principal\":\"alice\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(alice.getPublic())+"\"}\n"
          + "{\"principal\":\"bob\",\"publicKey\":\""+Ed25519Keys.publicKeyB64(bob.getPublic())+"\"}\n");
        Path a = keys.resolve("a"), b = keys.resolve("b");
        Files.writeString(a, Ed25519Keys.privateKeyB64(alice.getPrivate()));
        Files.writeString(b, Ed25519Keys.privateKeyB64(bob.getPrivate()));
        // deny-by-default activation policy: alice may ACTIVATE, bob may APPROVE on (target, recipe, ref)
        Path pol = root.resolve("identity").resolve("activation-policy.json");
        Files.writeString(pol,
            "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
          + "{\"id\":\"r-act\",\"principal\":\"alice\",\"action\":\"activate\",\"target\":\""+target+"\",\"kind\":\"recipe\",\"ref\":\""+ref+"\"},"
          + "{\"id\":\"r-app\",\"principal\":\"bob\",\"action\":\"approve\",\"target\":\""+target+"\",\"kind\":\"recipe\",\"ref\":\""+ref+"\"}"
          + "]}");
        // recipe MasterSpec the resolver seals: spec/<ref>/<version>.json
        Path art = root.resolve("spec").resolve(ref).resolve(version + ".json");
        Files.createDirectories(art.getParent());
        Files.writeString(art,
            "{\"specRef\":\""+ref+"\",\"version\":\""+version+"\",\"site\":\""+target+"\","
          + "\"equipmentRef\":\""+target+"-Mixer\",\"equipmentVersion\":\"1.0.0\","
          + "\"setpoints\":[{\"member\":\"Rpm\",\"type\":\"Double\",\"value\":1500.0}]}");
        return new Path[]{a, b};
    }

    @Test void signed_activate_records_anchor(@TempDir Path root, @TempDir Path keys) throws Exception {
        Path[] kf = seedIdentity(root, keys, "Line1", "mix-recipe", "1.0.0");
        int code = ActivateGate.run(new String[]{"activate", root.toString(), "Line1","recipe","mix-recipe","1.0.0",
                "--by","alice","--approved-by","bob",
                "--by-key",kf[0].toString(),"--approved-by-key",kf[1].toString(),
                "--anchor-dir",root.toString()});
        assertEquals(0, code, "signed activate should succeed");
        Optional<dev.krillin.bifrost.core.activation.AnchorRecord> latest =
                new FileAnchorStore(root).latest("Line1");
        assertTrue(latest.isPresent(), "signed activate must record the anchor");
        assertEquals(0L, latest.get().seq(), "first anchor is seq 0");
    }
}
