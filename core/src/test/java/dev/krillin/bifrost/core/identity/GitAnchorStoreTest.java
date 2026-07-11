package dev.krillin.bifrost.core.identity;

import dev.krillin.bifrost.core.activation.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;

class GitAnchorStoreTest {
    @TempDir Path repo;

    @Test void recordCommitsAndLatestReadsCommittedHead() throws Exception {
        GitAnchorStore s = new GitAnchorStore(repo);
        s.record(new AnchorRecord("mixer-01", 0, "h0"));
        s.record(new AnchorRecord("mixer-01", 1, "h1"));
        assertEquals(1, s.latest("mixer-01").orElseThrow().seq());
    }

    @Test void latestSurvivesWorkingTreeRollback() throws Exception {
        GitAnchorStore s = new GitAnchorStore(repo);
        s.record(new AnchorRecord("mixer-01", 0, "h0"));
        s.record(new AnchorRecord("mixer-01", 1, "h1"));
        // attacker rewrites the WORKING-TREE file back to seq 0 WITHOUT committing
        Files.writeString(repo.resolve("mixer-01.anchor.jsonl"),
                "{\"target\":\"mixer-01\",\"seq\":0,\"tailEntryHash\":\"h0\"}\n");
        // committed HEAD still witnesses seq 1  (the AN4 property)
        assertEquals(1, s.latest("mixer-01").orElseThrow().seq());
    }

    @Test void latestEmptyForUnknownTarget() throws Exception {
        GitAnchorStore s = new GitAnchorStore(repo);
        assertTrue(s.latest("nope").isEmpty());
    }

    @Test void latestEmptyOnFreshRepoThenFirstRecordCreatesHead() throws Exception {
        GitAnchorStore s = new GitAnchorStore(repo);
        assertTrue(s.latest("mixer-01").isEmpty());          // no commits yet
        s.record(new AnchorRecord("mixer-01", 0, "h0"));
        assertEquals(0, s.latest("mixer-01").orElseThrow().seq());
    }

    @Test void seqRegressionThrows() throws Exception {
        GitAnchorStore s = new GitAnchorStore(repo);
        s.record(new AnchorRecord("mixer-01", 5, "h5"));
        assertThrows(IllegalStateException.class, () -> s.record(new AnchorRecord("mixer-01", 4, "h4")));
    }
}
