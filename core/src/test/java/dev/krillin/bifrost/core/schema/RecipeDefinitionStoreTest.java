package dev.krillin.bifrost.core.schema;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

class RecipeDefinitionStoreTest {

    private byte[] bytes(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    @Test void publishThenLatestRoundTrips(@TempDir Path root) throws IOException {
        var store = new RecipeDefinitionStore(root);
        byte[] content = bytes("endpoint: x\nsetpoints: {}\n");
        RecipeManifest m = store.publish("recipe-setpoints", "line1", "1.0.0", content, "a".repeat(40), "sha-1", "model/recipe-setpoints.yaml", 42L);
        assertEquals("recipe-setpoints", m.kind());
        assertEquals("line1", m.ref());
        assertEquals("sha-1", m.contentSha256());
        Optional<RecipeDefinitionStore.Resolved> r = store.latest("line1");
        assertTrue(r.isPresent());
        assertArrayEquals(content, Files.readAllBytes(r.get().canonicalPath()));
        assertEquals("a".repeat(40), r.get().manifest().defRef());
    }

    @Test void latestPicksHighestSemVerDir(@TempDir Path root) throws IOException {
        var store = new RecipeDefinitionStore(root);
        store.publish("recipe-setpoints", "line1", "1.0.0", bytes("v1"), "a".repeat(40), "sha-1", "p", 1L);
        store.publish("recipe-setpoints", "line1", "1.2.0", bytes("v2"), "b".repeat(40), "sha-2", "p", 2L);
        assertEquals("1.2.0", store.latest("line1").get().manifest().version());
    }

    @Test void republishIdenticalIsNoOp_butDifferentBytesRefused(@TempDir Path root) throws IOException {
        var store = new RecipeDefinitionStore(root);
        store.publish("recipe-setpoints", "line1", "1.0.0", bytes("same"), "a".repeat(40), "sha-same", "p", 1L);
        store.publish("recipe-setpoints", "line1", "1.0.0", bytes("same"), "a".repeat(40), "sha-same", "p", 9L);
        assertThrows(IOException.class, () ->
            store.publish("recipe-setpoints", "line1", "1.0.0", bytes("DIFFERENT"), "c".repeat(40), "sha-diff", "p", 3L));
    }

    @Test void latestEmptyWhenAbsent(@TempDir Path root) throws IOException {
        assertTrue(new RecipeDefinitionStore(root).latest("nope").isEmpty());
    }
}
