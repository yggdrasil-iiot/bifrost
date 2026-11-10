package yggdrasil.bifrost.core.command;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    private static CommandEvent reservation(String cmdId) {
        return new CommandEvent(GROUP, EDGE, cmdId, "agent", "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1.SetTemperature",
                "42.0", "Double", CommandEvent.INTENT, CommandLedger.RESERVED, null, "2026-11-02T10:00:00Z");
    }

    @Test
    void a_cmdId_is_reserved_once_and_the_reservation_outlives_the_instance(@TempDir Path dir) throws Exception {
        Instant from = Instant.parse("2026-11-02T09:55:00Z");
        CommandLedger ledger = new CommandLedger(dir, at("2026-11-02T10:00:00Z"));
        assertTrue(ledger.reserve(reservation("c1"), from));
        assertFalse(ledger.reserve(reservation("c1"), from), "the same cmdId again");
        assertEquals(1, ledger.readCurrent(GROUP, EDGE).size(), "a refused reservation writes nothing");
        // A new instance is what a restarted edge has: only the file carries the reservation over.
        CommandLedger restarted = new CommandLedger(dir, at("2026-11-02T10:05:00Z"));
        assertTrue(restarted.reserved(GROUP, EDGE, "c1", from));
        assertFalse(restarted.reserve(reservation("c1"), from));
        assertTrue(restarted.reserve(reservation("c2"), from));
        assertTrue(restarted.verifyCurrent(GROUP, EDGE, CommandChain.GENESIS).intact(), "reservations are chain entries");
    }

    @Test
    void only_a_reservation_reserves(@TempDir Path dir) throws Exception {
        Instant from = Instant.parse("2026-11-02T09:55:00Z");
        CommandLedger ledger = new CommandLedger(dir, at("2026-11-02T10:00:00Z"));
        ledger.append(new CommandEvent(GROUP, EDGE, "c1", null, "bifrost/command/v1", null, null,
                CommandEvent.INTENT, "denied", "command.window", "2026-11-02T10:00:00Z"));
        ledger.append(new CommandEvent(GROUP, EDGE, "c1", "agent", "x", "1", "Double",
                CommandEvent.INTENT, "pending", null, "2026-11-02T10:00:00Z"));
        assertFalse(ledger.reserved(GROUP, EDGE, "c1", from), "an audit refusal or a write intent does not consume the cmdId");
        assertTrue(ledger.reserve(reservation("c1"), from));
        assertThrows(IllegalArgumentException.class, () -> ledger.reserve(ev("c3", "1"), from), "an outcome is not a reservation");
    }

    @Test
    void the_scan_covers_every_segment_the_window_spans(@TempDir Path dir) throws Exception {
        new CommandLedger(dir, at("2026-11-01T23:58:00Z")).reserve(reservation("c1"), Instant.parse("2026-11-01T23:50:00Z"));
        CommandLedger nextDay = new CommandLedger(dir, at("2026-11-02T00:03:00Z"));
        assertTrue(nextDay.reserved(GROUP, EDGE, "c1", Instant.parse("2026-11-01T23:50:00Z")),
                "a window that started yesterday reads yesterday's segment");
        assertFalse(nextDay.reserved(GROUP, EDGE, "c1", Instant.parse("2026-11-02T00:00:00Z")),
                "a segment before the window's first day is not a reservation for it");
    }

    @Test
    void an_unparseable_segment_is_an_error_not_an_absence(@TempDir Path dir) throws Exception {
        Instant from = Instant.parse("2026-11-02T09:55:00Z");
        CommandLedger ledger = new CommandLedger(dir, at("2026-11-02T10:00:00Z"));
        ledger.reserve(reservation("c1"), from);
        Path seg = ledger.segment(GROUP, EDGE);
        Files.writeString(seg, "{not json\n" + Files.readString(seg));
        assertThrows(java.io.IOException.class, () -> ledger.reserved(GROUP, EDGE, "c1", from));
        assertThrows(java.io.IOException.class, () -> ledger.reserve(reservation("c2"), from));
    }
}
