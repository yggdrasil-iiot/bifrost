package dev.krillin.bifrost.core.schema;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import static org.junit.jupiter.api.Assertions.*;

class RecipePublishTest {

    private void run(Path dir, String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        p.getInputStream().readAllBytes();
        assertEquals(0, p.waitFor(), "cmd failed: " + String.join(" ", cmd));
    }
    private String sha256hex(byte[] b) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(b);
        StringBuilder s = new StringBuilder(); for (byte x : d) s.append(String.format("%02x", x)); return s.toString();
    }

    @Test void publishesCleanSourceAndRoundTrips(@TempDir Path tmp) throws Exception {
        Path repo = Files.createDirectories(tmp.resolve("repo"));
        Path registry = tmp.resolve("registry");
        Files.createDirectories(repo.resolve("model"));
        byte[] content = "endpoint: x\nsetpoints: {}\n".getBytes(StandardCharsets.UTF_8);
        Files.write(repo.resolve("model/recipe-setpoints.yaml"), content);
        run(repo, "git", "init", "-q");
        run(repo, "git", "config", "user.email", "t@t"); run(repo, "git", "config", "user.name", "t");
        run(repo, "git", "add", "."); run(repo, "git", "commit", "-q", "-m", "seed");

        int code = RecipePublish.run(new String[]{ registry.toString(), repo.toString(), "model/recipe-setpoints.yaml", "line1", "1.0.0" });
        assertEquals(0, code);

        var resolved = new RecipeDefinitionStore(registry).latest("line1").orElseThrow();
        assertArrayEquals(content, Files.readAllBytes(resolved.canonicalPath()));
        assertEquals(sha256hex(content), resolved.manifest().contentSha256());
        assertTrue(resolved.manifest().defRef().matches("[0-9a-f]{40}"));
    }

    @Test void defaultKindIsRecipeSetpoints(@TempDir Path tmp) throws Exception {
        Path repo = Files.createDirectories(tmp.resolve("repo"));
        Path registry = tmp.resolve("registry");
        Files.createDirectories(repo.resolve("model"));
        Files.write(repo.resolve("model/recipe-setpoints.yaml"), "a: 1\n".getBytes(StandardCharsets.UTF_8));
        run(repo, "git", "init", "-q");
        run(repo, "git", "config", "user.email", "t@t"); run(repo, "git", "config", "user.name", "t");
        run(repo, "git", "add", "."); run(repo, "git", "commit", "-q", "-m", "seed");

        int code = RecipePublish.run(new String[]{ registry.toString(), repo.toString(), "model/recipe-setpoints.yaml", "line1" });
        assertEquals(0, code);
        var resolved = new RecipeDefinitionStore(registry).latest("line1").orElseThrow();
        assertEquals("recipe-setpoints", resolved.manifest().kind(), "no --kind flag must default to recipe-setpoints (back-compat)");
    }

    @Test void explicitKindMasterSpec(@TempDir Path tmp) throws Exception {
        Path repo = Files.createDirectories(tmp.resolve("repo"));
        Path registry = tmp.resolve("registry");
        Files.createDirectories(repo.resolve("model"));
        Files.write(repo.resolve("model/recipe-setpoints.yaml"), "a: 1\n".getBytes(StandardCharsets.UTF_8));
        run(repo, "git", "init", "-q");
        run(repo, "git", "config", "user.email", "t@t"); run(repo, "git", "config", "user.name", "t");
        run(repo, "git", "add", "."); run(repo, "git", "commit", "-q", "-m", "seed");

        // --kind at index 4 (no version given)
        int code = RecipePublish.run(new String[]{ registry.toString(), repo.toString(), "model/recipe-setpoints.yaml", "line1", "--kind", "master-spec" });
        assertEquals(0, code);
        var resolved = new RecipeDefinitionStore(registry).latest("line1").orElseThrow();
        assertEquals("master-spec", resolved.manifest().kind());
    }

    @Test void explicitKindMasterSpecWithVersion(@TempDir Path tmp) throws Exception {
        Path repo = Files.createDirectories(tmp.resolve("repo"));
        Path registry = tmp.resolve("registry");
        Files.createDirectories(repo.resolve("model"));
        Files.write(repo.resolve("model/recipe-setpoints.yaml"), "a: 1\n".getBytes(StandardCharsets.UTF_8));
        run(repo, "git", "init", "-q");
        run(repo, "git", "config", "user.email", "t@t"); run(repo, "git", "config", "user.name", "t");
        run(repo, "git", "add", "."); run(repo, "git", "commit", "-q", "-m", "seed");

        // --kind after version (index 5), proving position-independence
        int code = RecipePublish.run(new String[]{ registry.toString(), repo.toString(), "model/recipe-setpoints.yaml", "line1", "2.0.0", "--kind", "master-spec" });
        assertEquals(0, code);
        var resolved = new RecipeDefinitionStore(registry).latest("line1").orElseThrow();
        assertEquals("master-spec", resolved.manifest().kind());
        assertEquals("2.0.0", resolved.manifest().version());
    }

    @Test void kindFlagWithoutValueIsUsageError(@TempDir Path tmp) throws Exception {
        Path registry = tmp.resolve("registry");
        int code = RecipePublish.run(new String[]{ registry.toString(), tmp.resolve("repo").toString(), "model/recipe-setpoints.yaml", "line1", "--kind" });
        assertEquals(2, code, "--kind with no following value must be a usage error (exit 2)");
    }

    @Test void refusesDirtySource(@TempDir Path tmp) throws Exception {
        Path repo = Files.createDirectories(tmp.resolve("repo"));
        Files.createDirectories(repo.resolve("model"));
        Files.write(repo.resolve("model/recipe-setpoints.yaml"), "a: 1\n".getBytes());
        run(repo, "git", "init", "-q");
        run(repo, "git", "config", "user.email", "t@t"); run(repo, "git", "config", "user.name", "t");
        run(repo, "git", "add", "."); run(repo, "git", "commit", "-q", "-m", "seed");
        Files.write(repo.resolve("model/recipe-setpoints.yaml"), "a: 2  # uncommitted\n".getBytes());
        int code = RecipePublish.run(new String[]{ tmp.resolve("registry").toString(), repo.toString(), "model/recipe-setpoints.yaml", "line1" });
        assertEquals(1, code, "dirty source must be refused (exit 1)");
    }
}
