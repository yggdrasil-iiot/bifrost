package dev.krillin.bifrost.core.activation;

import dev.krillin.bifrost.core.identity.SignedLedgerVerifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Ledgers written by the activation and anchored gates before an event could name its publication (2026-09),
 *  copied byte for byte. They must still read, chain and verify their signatures, and an entry appended after them
 *  carries a publication while the old lines stay untouched. */
class LegacyLedgerCompatTest {

    static Path copy(String name, Path to) throws Exception {
        Path from = Path.of(LegacyLedgerCompatTest.class.getResource("/legacy-ledger/" + name).toURI());
        try (Stream<Path> files = Files.walk(from)) {
            for (Path p : (Iterable<Path>) files::iterator) {
                Path dest = to.resolve(from.relativize(p).toString());
                if (Files.isDirectory(p)) Files.createDirectories(dest); else Files.copy(p, dest);
            }
        }
        return to;
    }

    @Test void anUnsignedLedgerFromBeforeTheFieldStillChains(@TempDir Path reg) throws Exception {
        copy("unsigned", reg);
        ActivationLedger ledger = new ActivationLedger(reg);
        assertEquals(3, ledger.history("Line1").size());
        assertTrue(ledger.verifyChain("Line1").intact());
        for (LedgerEntry e : ledger.history("Line1")) assertNull(e.event().publication());
    }

    @Test void aSignedLedgerFromBeforeTheFieldStillVerifiesItsSignaturesAndHead(@TempDir Path reg) throws Exception {
        copy("signed", reg);
        assertTrue(SignedLedgerVerifier.forRegistry(reg).verify("Line1").intact());
    }

    @Test void anEntryWithAPublicationAppendsAfterOldLinesWithoutRewritingThem(@TempDir Path reg) throws Exception {
        copy("unsigned", reg);
        Path file = reg.resolve("activation/Line1.jsonl");
        byte[] before = Files.readAllBytes(file);
        ActivationLedger ledger = new ActivationLedger(reg);
        PublicationRef p = new PublicationRef("m".repeat(64), "0123456789abcdef0123456789abcdef01234567", null);
        ledger.append(new ActivationEvent("Line1", "recipe", "mix-recipe", "1.1.0", "c".repeat(64), "alice", "bob",
                1L, "1.0.0", "ACTIVATE", p));
        byte[] after = Files.readAllBytes(file);
        assertArrayEquals(before, java.util.Arrays.copyOf(after, before.length));
        assertTrue(ledger.verifyChain("Line1").intact());
        assertEquals(p, ledger.active("Line1", "recipe", "mix-recipe").orElseThrow().publication());
    }

    @Test void thePublicationIsInTheHashSoEditingItBreaksTheChain(@TempDir Path reg) throws Exception {
        ActivationLedger ledger = new ActivationLedger(reg);
        ledger.append(new ActivationEvent("Line1", "recipe", "mix-recipe", "1.0.0", "c".repeat(64), "alice", "bob",
                1L, null, "ACTIVATE", new PublicationRef("m".repeat(64), "a".repeat(40), null)));
        Path file = reg.resolve("activation/Line1.jsonl");
        Files.writeString(file, Files.readString(file).replace("a".repeat(40), "b".repeat(40)));
        assertEquals("ledger.chain.entry-hash-mismatch", ledger.verifyChain("Line1").rule());
    }

    @Test void anEventWithoutAPublicationHashesAsItAlwaysDid() {
        ActivationEvent e = new ActivationEvent("Line1", "recipe", "mix", "1.0.0", "sha", "alice", "bob", 1000L, null, "ACTIVATE");
        assertEquals(LedgerChain.entryHash(e, LedgerChain.GENESIS),
                LedgerChain.entryHash(new ActivationEvent("Line1", "recipe", "mix", "1.0.0", "sha", "alice", "bob", 1000L,
                        null, "ACTIVATE", null), LedgerChain.GENESIS));
        assertNotEquals(LedgerChain.entryHash(e, LedgerChain.GENESIS),
                LedgerChain.entryHash(new ActivationEvent("Line1", "recipe", "mix", "1.0.0", "sha", "alice", "bob", 1000L,
                        null, "ACTIVATE", new PublicationRef("m", "d", null)), LedgerChain.GENESIS));
    }
}
