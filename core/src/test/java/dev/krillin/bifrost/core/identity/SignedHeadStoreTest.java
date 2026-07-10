package dev.krillin.bifrost.core.identity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

class SignedHeadStoreTest {

    @Test void absent_head_reads_empty(@TempDir Path root) throws Exception {
        assertTrue(new SignedHeadStore(root).read("Line1").isEmpty());
    }

    @Test void write_then_read_roundtrips(@TempDir Path root) throws Exception {
        SignedHeadStore store = new SignedHeadStore(root);
        SignedHead h = new SignedHead("Line1", 0L, "abc123", "bob", "sigB64");
        store.write(h);
        Optional<SignedHead> back = store.read("Line1");
        assertTrue(back.isPresent());
        assertEquals(h, back.get());
    }

    @Test void head_preimage_is_stable_and_field_ordered() {
        String p = SignedHeadStore.preimage("Line1", 3L, "deadbeef");
        assertEquals("Line1\u001F3\u001Fdeadbeef", p);   // fields joined by U+001F Unit Separator
    }

    @Test void write_overwrites_prior_head(@TempDir Path root) throws Exception {
        SignedHeadStore store = new SignedHeadStore(root);
        store.write(new SignedHead("Line1", 0L, "h0", "bob", "s0"));
        store.write(new SignedHead("Line1", 1L, "h1", "bob", "s1"));
        assertEquals(1L, store.read("Line1").get().seq());
        assertEquals("h1", store.read("Line1").get().tailEntryHash());
    }
}
