package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.krillin.bifrost.core.command.CommandEvent;
import dev.krillin.bifrost.core.command.CommandLedger;

class CommandLogGateTest {

    private static final String G = "Bifrost:Line1";
    private static final String E = "recipe-edge";

    private CommandLedger seed(Path dir, int n) throws Exception {
        CommandLedger l = new CommandLedger(dir, Clock.systemUTC());
        for (int i = 0; i < n; i++) {
            l.append(new CommandEvent(G, E, "c-" + i, "recipe-writer", "ns=2;s=Recipe/Rpm",
                    String.valueOf(1500 + i), "Double", CommandEvent.OUTCOME, "applied", null,
                    "2026-09-08T00:00:00Z"));
        }
        return l;
    }

    @Test void an_intact_segment_verifies(@TempDir Path dir) throws Exception {
        CommandLedger l = seed(dir, 3);
        assertEquals(0, CommandLogGate.run(new String[]{ "verify", l.segment(G, E).toString() }));
    }

    @Test void an_edited_segment_is_broken(@TempDir Path dir) throws Exception {
        CommandLedger l = seed(dir, 3);
        Path seg = l.segment(G, E);
        Files.writeString(seg, Files.readString(seg).replace("\"1501\"", "\"9999\""));
        assertEquals(1, CommandLogGate.run(new String[]{ "verify", seg.toString() }));
    }

    /**
     * A missing segment is exit 2, not 1. The R2 gate deliberately makes a path unwritable, so
     * "the chain is broken" and "you pointed at nothing" must not be the same answer.
     */
    @Test void a_missing_segment_is_usage_not_broken(@TempDir Path dir) {
        assertEquals(2, CommandLogGate.run(new String[]{ "verify", dir.resolve("nope.jsonl").toString() }));
    }

    @Test void tail_reads_back(@TempDir Path dir) throws Exception {
        CommandLedger l = seed(dir, 5);
        assertEquals(0, CommandLogGate.run(new String[]{ "tail", l.segment(G, E).toString(), "2" }));
    }

    @Test void noArgs_returnsTwo() {
        assertEquals(2, CommandLogGate.run(new String[]{}));
    }
}
