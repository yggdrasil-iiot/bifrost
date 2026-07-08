package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.schema.RecipeDefinitionStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;

class ProvenancePublishTest {

    private void run(Path dir, String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        p.getInputStream().readAllBytes();
        assertEquals(0, p.waitFor(), "cmd failed: " + String.join(" ", cmd));
    }

    private String sha256hex(byte[] b) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(b);
        StringBuilder s = new StringBuilder();
        for (byte x : d) s.append(String.format("%02x", x));
        return s.toString();
    }

    private Path seedRepo(Path tmp, byte[] content) throws Exception {
        Path repo = Files.createDirectories(tmp.resolve("repo"));
        Files.createDirectories(repo.resolve("model"));
        Files.write(repo.resolve("model/recipe-setpoints.yaml"), content);
        run(repo, "git", "init", "-q");
        run(repo, "git", "config", "user.email", "t@t");
        run(repo, "git", "config", "user.name", "t");
        run(repo, "git", "add", ".");
        run(repo, "git", "commit", "-q", "-m", "seed");
        return repo;
    }

    @Test void mintAndVerify_roundTrips(@TempDir Path tmp) throws Exception {
        byte[] content = "endpoint: x\nsetpoints: {rpm: 1500}\n".getBytes(StandardCharsets.UTF_8);
        Path repo = seedRepo(tmp, content);
        Path registry = tmp.resolve("registry");

        int publishCode = ProvenancePublish.run(new String[]{
                "publish", registry.toString(), repo.toString(), "model/recipe-setpoints.yaml", "line1", "1.0.0"
        });
        assertEquals(0, publishCode);

        var resolved = new RecipeDefinitionStore(registry).latest("line1").orElseThrow();
        assertEquals(sha256hex(content), resolved.manifest().contentSha256());

        int verifyCode = ProvenancePublish.run(new String[]{ "verify", registry.toString(), "line1" });
        assertEquals(0, verifyCode);
    }

    @Test void verify_detectsTamper(@TempDir Path tmp) throws Exception {
        byte[] content = "endpoint: x\nsetpoints: {rpm: 1500}\n".getBytes(StandardCharsets.UTF_8);
        Path repo = seedRepo(tmp, content);
        Path registry = tmp.resolve("registry");

        int publishCode = ProvenancePublish.run(new String[]{
                "publish", registry.toString(), repo.toString(), "model/recipe-setpoints.yaml", "line1", "1.0.0"
        });
        assertEquals(0, publishCode);

        Path materialized = registry.resolve("recipe").resolve("line1").resolve("1.0.0").resolve("recipe-setpoints.yaml");
        assertTrue(Files.exists(materialized));
        Files.write(materialized, "endpoint: x\nsetpoints: {rpm: 9999}  # tampered\n".getBytes(StandardCharsets.UTF_8));

        int verifyCode = ProvenancePublish.run(new String[]{ "verify", registry.toString(), "line1" });
        assertNotEquals(0, verifyCode, "tampered canonical must be detected (non-zero exit)");
    }

    @Test void badUsage_returnsTwo(@TempDir Path tmp) throws Exception {
        assertEquals(2, ProvenancePublish.run(new String[]{}));
        assertEquals(2, ProvenancePublish.run(new String[]{ "bogus" }));
        Path emptyRegistry = tmp.resolve("empty-registry");
        Files.createDirectories(emptyRegistry);
        assertEquals(2, ProvenancePublish.run(new String[]{ "verify", emptyRegistry.toString(), "no-such-ref" }));
    }
}
