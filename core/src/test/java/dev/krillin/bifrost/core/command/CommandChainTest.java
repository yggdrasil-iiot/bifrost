package dev.krillin.bifrost.core.command;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

class CommandChainTest {

    private static CommandEvent ev(String cmdId, String subject, String command, String value,
                                   String phase, String outcome, String reason) {
        return new CommandEvent("Bifrost:Line1", "recipe-edge", cmdId, subject,
                command, value, "Double", phase, outcome, reason, "2026-09-08T00:00:00Z");
    }

    private static CommandEvent applied() {
        return ev("c-1", "recipe-writer", "ns=2;s=Recipe/Rpm", "1500.0", "outcome", "applied", null);
    }

    /** Build a chain of n entries, each linked to the previous, starting from expectedPrev. */
    private static List<CommandLedgerEntry> chain(int n, String expectedPrev) {
        List<CommandLedgerEntry> out = new ArrayList<>();
        String prev = expectedPrev;
        for (int i = 0; i < n; i++) {
            CommandEvent e = ev("c-" + i, "recipe-writer", "ns=2;s=Recipe/Rpm", String.valueOf(1500 + i),
                    "outcome", "applied", null);
            String h = CommandChain.entryHash(e, prev);
            out.add(new CommandLedgerEntry(e, prev, h));
            prev = h;
        }
        return out;
    }

    // ----- the preimage binds every field -----

    @Test void every_field_participates_in_the_hash() {
        CommandEvent base = applied();
        String h = CommandChain.entryHash(base, CommandChain.GENESIS);
        // Each variant differs from base in exactly one field.
        List<CommandEvent> variants = List.of(
                new CommandEvent("other", base.edge(), base.cmdId(), base.subject(), base.command(),
                        base.value(), base.type(), base.phase(), base.outcome(), base.reason(), base.at()),
                new CommandEvent(base.group(), "other", base.cmdId(), base.subject(), base.command(),
                        base.value(), base.type(), base.phase(), base.outcome(), base.reason(), base.at()),
                new CommandEvent(base.group(), base.edge(), "other", base.subject(), base.command(),
                        base.value(), base.type(), base.phase(), base.outcome(), base.reason(), base.at()),
                new CommandEvent(base.group(), base.edge(), base.cmdId(), "other", base.command(),
                        base.value(), base.type(), base.phase(), base.outcome(), base.reason(), base.at()),
                new CommandEvent(base.group(), base.edge(), base.cmdId(), base.subject(), "other",
                        base.value(), base.type(), base.phase(), base.outcome(), base.reason(), base.at()),
                new CommandEvent(base.group(), base.edge(), base.cmdId(), base.subject(), base.command(),
                        "other", base.type(), base.phase(), base.outcome(), base.reason(), base.at()),
                new CommandEvent(base.group(), base.edge(), base.cmdId(), base.subject(), base.command(),
                        base.value(), "other", base.phase(), base.outcome(), base.reason(), base.at()),
                new CommandEvent(base.group(), base.edge(), base.cmdId(), base.subject(), base.command(),
                        base.value(), base.type(), "other", base.outcome(), base.reason(), base.at()),
                new CommandEvent(base.group(), base.edge(), base.cmdId(), base.subject(), base.command(),
                        base.value(), base.type(), base.phase(), "other", base.reason(), base.at()),
                new CommandEvent(base.group(), base.edge(), base.cmdId(), base.subject(), base.command(),
                        base.value(), base.type(), base.phase(), base.outcome(), "other", base.at()),
                new CommandEvent(base.group(), base.edge(), base.cmdId(), base.subject(), base.command(),
                        base.value(), base.type(), base.phase(), base.outcome(), base.reason(), "other"));
        for (CommandEvent v : variants) {
            assertNotEquals(h, CommandChain.entryHash(v, CommandChain.GENESIS),
                    "a field is missing from the preimage: " + v);
        }
    }

    /** All four nullable fields get the sentinel, and null is distinguishable from the literal. */
    @Test void nullable_fields_are_distinguishable_from_the_literal_string() {
        // subject, reason, cmdId and value are all nullable in practice - cmdId comes from the
        // payload uuid, which the bridge does not require unless R1's bar is on, and value comes
        // straight off a metric that may carry none.
        CommandEvent withNulls = ev(null, null, "ns=2;s=Recipe/Rpm", null, "intent", "pending", null);
        CommandEvent withLiterals = ev("null", "null", "ns=2;s=Recipe/Rpm", "null", "intent", "pending", "null");
        assertNotEquals(CommandChain.entryHash(withNulls, CommandChain.GENESIS),
                CommandChain.entryHash(withLiterals, CommandChain.GENESIS));
    }

    @Test void field_boundaries_are_not_ambiguous() {
        assertNotEquals(
                CommandChain.preimage(ev("a", "b", "c", "1", "intent", "pending", null), CommandChain.GENESIS),
                CommandChain.preimage(ev("ab", "", "c", "1", "intent", "pending", null), CommandChain.GENESIS));
    }

    // ----- verification -----

    @Test void an_intact_chain_verifies() {
        assertTrue(CommandChain.verify(chain(5, CommandChain.GENESIS), CommandChain.GENESIS).intact());
    }

    @Test void an_edited_entry_is_reported_at_its_index() {
        List<CommandLedgerEntry> c = new ArrayList<>(chain(5, CommandChain.GENESIS));
        CommandLedgerEntry third = c.get(2);
        CommandEvent tampered = new CommandEvent(third.event().group(), third.event().edge(),
                third.event().cmdId(), third.event().subject(), third.event().command(),
                "9999.0", third.event().type(), third.event().phase(), third.event().outcome(),
                third.event().reason(), third.event().at());
        c.set(2, new CommandLedgerEntry(tampered, third.prevHash(), third.entryHash()));
        CommandChainVerdict v = CommandChain.verify(c, CommandChain.GENESIS);
        assertFalse(v.intact());
        assertEquals(2, v.brokenIndex());
    }

    /**
     * Segments are linked by tail hash, not restarted at genesis: without that, any segment -
     * including the current one - could be deleted or rewritten from genesis with nothing to
     * contradict it.
     */
    @Test void a_segment_verifies_against_its_expected_predecessor() {
        String prevTail = "a".repeat(64);
        List<CommandLedgerEntry> seg = chain(3, prevTail);
        assertTrue(CommandChain.verify(seg, prevTail).intact());
        assertFalse(CommandChain.verify(seg, CommandChain.GENESIS).intact(),
                "a segment must not verify against the wrong predecessor");
    }

    /**
     * <b>Truncation is NOT detected, and this test exists to document that rather than let it be
     * discovered.</b> Deleting trailing entries leaves genesis, every self-hash and every prev-link
     * satisfied. That is the T4 limit the activation ladder closes with a signed head and an
     * external anchor, and R2 declines both - so the docs must say so, and here is the proof they
     * are telling the truth.
     */
    @Test void truncation_is_NOT_detected_which_is_the_limit_of_a_chain() {
        List<CommandLedgerEntry> full = chain(5, CommandChain.GENESIS);
        List<CommandLedgerEntry> truncated = new ArrayList<>(full.subList(0, 3));
        assertTrue(CommandChain.verify(truncated, CommandChain.GENESIS).intact(),
                "if this ever fails, the chain gained a property the docs do not claim - update them");
    }
}
