package dev.krillin.bifrost.core.activation;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.*;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

class AnchorStoreTest {
    @TempDir Path reg;
    private FileAnchorStore store;

    @BeforeEach void setup() { store = new FileAnchorStore(reg); }

    @Test void latestEmptyWhenNeverAnchored() throws IOException {
        assertTrue(store.latest("mixer-01").isEmpty());
    }

    @Test void recordThenLatestRoundTrips() throws IOException {
        store.record(new AnchorRecord("mixer-01", 0, "h0"));
        store.record(new AnchorRecord("mixer-01", 1, "h1"));
        Optional<AnchorRecord> l = store.latest("mixer-01");
        assertTrue(l.isPresent());
        assertEquals(1, l.get().seq());
        assertEquals("h1", l.get().tailEntryHash());
    }

    @Test void perTargetIsolation() throws IOException {
        store.record(new AnchorRecord("mixer-01", 0, "h0"));
        assertTrue(store.latest("mixer-02").isEmpty());
    }

    @Test void seqRegressionThrows() throws IOException {
        store.record(new AnchorRecord("mixer-01", 5, "h5"));
        assertThrows(IllegalStateException.class,
                () -> store.record(new AnchorRecord("mixer-01", 4, "h4")));
    }

    @Test void sameSeqDifferentTailThrows() throws IOException {
        store.record(new AnchorRecord("mixer-01", 5, "h5"));
        assertThrows(IllegalStateException.class,
                () -> store.record(new AnchorRecord("mixer-01", 5, "hDIFFERENT")));
    }

    @Test void identicalReRecordIsIdempotentNoop() throws IOException {
        store.record(new AnchorRecord("mixer-01", 5, "h5"));
        store.record(new AnchorRecord("mixer-01", 5, "h5"));   // no throw
        assertEquals(5, store.latest("mixer-01").orElseThrow().seq());
    }
}
