package dev.krillin.bifrost.core.command;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CommandLedgerTest {

    private static final String GROUP = "Bifrost:Line1";
    private static final String EDGE = "recipe-edge";

    private static Clock at(String instant) {
        return Clock.fixed(Instant.parse(instant), ZoneOffset.UTC);
    }

    private static CommandEvent ev(String cmdId, String value) {
        return new CommandEvent(GROUP, EDGE, cmdId, "recipe-writer", "ns=2;s=Recipe/Rpm",
                value, "Double", CommandEvent.OUTCOME, "applied", null, "2026-09-08T00:00:00Z");
    }

    /**
     * Drives the race; it does not prove its absence. Eight threads released together by a barrier,
     * 200 appends each, repeated. Without {@code synchronized} this fails in one of two ways and the
     * test distinguishes them: two entries claiming the same prevHash (a BROKEN verdict), or two
     * interleaved writes producing a malformed line (an UNPARSEABLE verdict). Dying in the JSON
     * parser would be a third, and the named verdict exists so that never happens.
     */
    @RepeatedTest(3)
    void concurrent_appends_leave_a_verifiable_chain(@TempDir Path dir) throws Exception {
        CommandLedger ledger = new CommandLedger(dir, at("2026-09-08T10:00:00Z"));
        int threads = 8;
        int per = 200;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        for (int t = 0; t < threads; t++) {
            final int id = t;
            Thread th = new Thread(() -> {
                try {
                    start.await(5, TimeUnit.SECONDS);
                    for (int i = 0; i < per; i++) {
                        ledger.append(ev("t" + id + "-" + i, String.valueOf(i)));
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    done.countDown();
                }
            });
            th.setDaemon(true);
            th.start();
        }
        start.countDown();
        assertTrue(done.await(60, TimeUnit.SECONDS), "appenders did not finish");

        CommandChainVerdict v = ledger.verifyCurrent(GROUP, EDGE, CommandChain.GENESIS);
        assertTrue(v.intact(), "chain broken at " + v.brokenIndex() + ": " + v.rule());
        assertEquals(threads * per, ledger.readCurrent(GROUP, EDGE).size());
    }

    @Test void a_new_utc_day_starts_a_new_segment_linked_to_the_previous_tail(@TempDir Path dir) throws Exception {
        CommandLedger day1 = new CommandLedger(dir, at("2026-09-08T23:59:00Z"));
        day1.append(ev("c-1", "1500.0"));
        day1.append(ev("c-2", "1600.0"));
        String tail = day1.tailHash(GROUP, EDGE);
        assertNotEquals(CommandChain.GENESIS, tail);

        CommandLedger day2 = new CommandLedger(dir, at("2026-09-09T00:01:00Z"));
        day2.append(ev("c-3", "1700.0"));

        List<CommandLedgerEntry> seg2 = day2.readCurrent(GROUP, EDGE);
        assertEquals(1, seg2.size(), "the new day must start its own segment");
        assertEquals(tail, seg2.get(0).prevHash(),
                "a segment restarting at genesis could be deleted or rewritten with nothing to contradict it");
    }

    @Test void the_previous_segment_still_verifies_on_its_own(@TempDir Path dir) throws Exception {
        CommandLedger day1 = new CommandLedger(dir, at("2026-09-08T12:00:00Z"));
        day1.append(ev("c-1", "1500.0"));
        day1.append(ev("c-2", "1600.0"));
        assertTrue(day1.verifyCurrent(GROUP, EDGE, CommandChain.GENESIS).intact());
    }

    /** An interleaved write is a finding, not a crash. */
    @Test void an_unparseable_line_is_a_named_verdict(@TempDir Path dir) throws Exception {
        CommandLedger ledger = new CommandLedger(dir, at("2026-09-08T12:00:00Z"));
        ledger.append(ev("c-1", "1500.0"));
        Path seg = ledger.segment(GROUP, EDGE);
        Files.writeString(seg, Files.readString(seg) + "{not json\n");
        CommandChainVerdict v = ledger.verifyCurrent(GROUP, EDGE, CommandChain.GENESIS);
        assertFalse(v.intact());
        assertEquals("command.chain.unparseable-line", v.rule());
        assertEquals(1, v.brokenIndex());
    }

    @Test void the_first_segment_starts_at_genesis(@TempDir Path dir) throws Exception {
        CommandLedger ledger = new CommandLedger(dir, at("2026-09-08T12:00:00Z"));
        ledger.append(ev("c-1", "1500.0"));
        assertEquals(CommandChain.GENESIS, ledger.readCurrent(GROUP, EDGE).get(0).prevHash());
    }
}
