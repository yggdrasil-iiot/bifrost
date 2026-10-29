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

    // The bytes main (5a808b4) wrote on Linux. On Windows it wrote CRLF instead; the manifest is LF on every OS now.
    static final String MANIFEST_SHA = "5e65bbff38ea22b74c8cc5fe9c73c8530e30aa8db1b08b5c03274075f7048022";

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
