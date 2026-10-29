package dev.krillin.bifrost.core.schema;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

/** Muninn and resequence-twin-lab read manifest.json by path; its bytes are a contract, signed or not. */
class RecipeManifestBytesTest {
    static String sha(Path p) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));
    }

    // Taken from main before the publication attestation existed (5a808b4).
    static final String MANIFEST_SHA = "03b1beddb850b1c85c02c711a498349bbaab87d9b339375ec33aca7c2d4cc543";

    @Test void unsignedManifestBytesAreUnchanged(@TempDir Path tmp) throws Exception {
        byte[] content = "endpoint: x\nsetpoints: {}\n".getBytes(StandardCharsets.UTF_8);
        new RecipeDefinitionStore(tmp).publish("recipe-setpoints", "line1", "1.0.0", content,
                "0123456789abcdef0123456789abcdef01234567", sha256(content), "model/recipe-setpoints.yaml", 1_760_659_200_123L);
        assertEquals(MANIFEST_SHA, sha(tmp.resolve("recipe/line1/1.0.0/manifest.json")));
    }

    static String sha256(byte[] b) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));
    }
}
