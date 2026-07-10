package dev.krillin.bifrost.core.activation;

import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class LedgerChainTest {

    private static ActivationEvent ev(String version, String approvedBy, String prior) {
        return new ActivationEvent("Line1", "recipe", "mix-recipe", version,
                "sha-" + version, "alice", approvedBy, 1000L, prior, "ACTIVATE");
    }

    /** Build a well-formed chain of N entries from the given events. */
    private static List<LedgerEntry> chain(ActivationEvent... events) {
        List<LedgerEntry> out = new ArrayList<>();
        String prev = LedgerChain.GENESIS;
        for (ActivationEvent e : events) {
            String h = LedgerChain.entryHash(e, prev);
            out.add(LedgerEntry.unsigned(e, prev, h));
            prev = h;
        }
        return out;
    }

    @Test void genesis_is_64_hex_zeros() {
        assertEquals(64, LedgerChain.GENESIS.length());
        assertTrue(LedgerChain.GENESIS.chars().allMatch(c -> c == '0'));
    }

    @Test void entryHash_is_deterministic_and_field_sensitive() {
        ActivationEvent e = ev("1.0.0", "bob", null);
        assertEquals(LedgerChain.entryHash(e, LedgerChain.GENESIS),
                     LedgerChain.entryHash(e, LedgerChain.GENESIS), "same inputs => same hash");
        assertNotEquals(LedgerChain.entryHash(e, LedgerChain.GENESIS),
                        LedgerChain.entryHash(ev("1.0.0", "mallory", null), LedgerChain.GENESIS),
                        "changed approvedBy => different hash");
        assertNotEquals(LedgerChain.entryHash(e, LedgerChain.GENESIS),
                        LedgerChain.entryHash(e, "ffff"), "changed prevHash => different hash");
    }

    @Test void null_priorVersion_does_not_collide_with_literal_null_string() {
        assertNotEquals(LedgerChain.entryHash(ev("1.0.0", "bob", null), LedgerChain.GENESIS),
                        LedgerChain.entryHash(ev("1.0.0", "bob", "null"), LedgerChain.GENESIS));
    }

    @Test void verify_intact_chain() {
        assertTrue(LedgerChain.verify(chain(ev("1.0.0","bob",null), ev("1.1.0","bob","1.0.0"))).intact());
        assertTrue(LedgerChain.verify(List.of()).intact(), "empty chain is vacuously intact");
    }

    @Test void verify_detects_edited_event_content() {
        List<LedgerEntry> c = new ArrayList<>(chain(ev("1.0.0","bob",null), ev("1.1.0","bob","1.0.0")));
        LedgerEntry orig = c.get(0);
        c.set(0, LedgerEntry.unsigned(ev("1.0.0","mallory",null), orig.prevHash(), orig.entryHash()));
        ChainVerdict v = LedgerChain.verify(c);
        assertFalse(v.intact());
        assertEquals(0, v.brokenIndex());
        assertEquals("ledger.chain.entry-hash-mismatch", v.rule());
    }

    @Test void verify_detects_edited_prevHash_in_place() {
        List<LedgerEntry> c = new ArrayList<>(chain(ev("1.0.0","bob",null), ev("1.1.0","bob","1.0.0")));
        LedgerEntry e1 = c.get(1);
        c.set(1, LedgerEntry.unsigned(e1.event(), "deadbeef", e1.entryHash()));
        ChainVerdict v = LedgerChain.verify(c);
        assertFalse(v.intact());
        assertEquals("ledger.chain.entry-hash-mismatch", v.rule());
    }

    @Test void verify_detects_deleted_middle_entry() {
        List<LedgerEntry> c = new ArrayList<>(chain(
                ev("1.0.0","bob",null), ev("1.1.0","bob","1.0.0"), ev("1.2.0","bob","1.1.0")));
        c.remove(1);
        ChainVerdict v = LedgerChain.verify(c);
        assertFalse(v.intact());
        assertEquals(1, v.brokenIndex());
        assertEquals("ledger.chain.prev-link-broken", v.rule());
    }

    @Test void verify_detects_reordered_middle_entries() {
        List<LedgerEntry> c = new ArrayList<>(chain(
                ev("1.0.0","bob",null), ev("1.1.0","bob","1.0.0"), ev("1.2.0","bob","1.1.0")));
        LedgerEntry a = c.get(1); c.set(1, c.get(2)); c.set(2, a);
        ChainVerdict v = LedgerChain.verify(c);
        assertFalse(v.intact());
        assertEquals("ledger.chain.prev-link-broken", v.rule());
    }

    @Test void verify_detects_broken_genesis() {
        List<LedgerEntry> c = new ArrayList<>(chain(ev("1.0.0","bob",null)));
        LedgerEntry g = c.get(0);
        String badPrev = "1".repeat(64);
        c.set(0, LedgerEntry.unsigned(g.event(), badPrev, LedgerChain.entryHash(g.event(), badPrev)));
        ChainVerdict v = LedgerChain.verify(c);
        assertFalse(v.intact());
        assertEquals(0, v.brokenIndex());
        assertEquals("ledger.chain.genesis-broken", v.rule());
    }
}
