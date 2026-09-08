package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.krillin.bifrost.core.identity.AuthorizedKeys;
import dev.krillin.bifrost.core.identity.Ed25519Keys;
import dev.krillin.bifrost.core.identity.KeyFileLedgerSigner;

/**
 * Rotating a signing key.
 *
 * <p>The command PRINTS a replacement block rather than editing authorized-keys.jsonl in place, for
 * the same reason {@code duty-key-mint} does: the trust anchor is the one file whose change control
 * is deliberately out-of-band, and a CLI that rewrites it silently is the wrong tool. The block is
 * the whole principal — every existing line re-emitted with a retirement stamp, plus the successor —
 * so an operator replaces a contiguous region instead of hand-editing JSON under time pressure.
 */
class IdentityGateRotateKeyTest {

    private static final Instant NOW = Instant.parse("2026-06-01T00:00:00Z");

    private static String line(String principal, KeyPair kp) {
        return "{\"principal\":\"" + principal + "\",\"publicKey\":\""
                + Ed25519Keys.publicKeyB64(kp.getPublic()) + "\"}";
    }

    private static void writeAnchor(Path root, String... lines) throws Exception {
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.write(akf, List.of(lines));
    }

    private static String[] args(Path reg, Path out, String principal) {
        return new String[]{"rotate-key", reg.toString(), principal, "--out", out.toString()};
    }

    /** Run capturing stdout, so the printed replacement block can be asserted. */
    private static String run(int expected, String[] a) {
        PrintStream saved = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
            assertEquals(expected, IdentityGate.run(a, Clock.fixed(NOW, ZoneOffset.UTC)));
        } finally {
            System.setOut(saved);
        }
        return buf.toString(StandardCharsets.UTF_8);
    }

    /** Lines of the printed block that are authorized-keys.jsonl content. */
    private static List<String> block(String out) {
        return out.lines().filter(l -> l.startsWith("{\"principal\"")).toList();
    }

    // ----- refusals -----

    @Test void rotating_an_unregistered_principal_is_refused(@TempDir Path reg, @TempDir Path out)
            throws Exception {
        writeAnchor(reg, line("bob", Ed25519Keys.generate()));
        String o = run(1, args(reg, out, "alice"));
        assertTrue(o.contains("identity.principal.not-registered"), o);
        assertFalse(Files.exists(out.resolve("alice.key")), "a refused rotation must mint nothing");
    }

    @Test void missing_arguments_are_usage_errors(@TempDir Path reg, @TempDir Path out) throws Exception {
        writeAnchor(reg, line("alice", Ed25519Keys.generate()));
        assertEquals(2, IdentityGate.run(new String[]{"rotate-key"}));
        assertEquals(2, IdentityGate.run(new String[]{"rotate-key", reg.toString(), "alice"}));
    }

    @Test void a_traversing_principal_is_refused(@TempDir Path reg, @TempDir Path out) throws Exception {
        writeAnchor(reg, line("alice", Ed25519Keys.generate()));
        assertEquals(2, IdentityGate.run(args(reg, out, "../../evil")));
    }

    // ----- the rotation itself -----

    @Test void it_mints_a_successor_keypair(@TempDir Path reg, @TempDir Path out) throws Exception {
        writeAnchor(reg, line("alice", Ed25519Keys.generate()));
        run(0, args(reg, out, "alice"));
        assertTrue(Files.isRegularFile(out.resolve("alice.key")));
        assertTrue(Files.isRegularFile(out.resolve("alice.pub")));
    }

    /**
     * The block must be the WHOLE principal: the predecessor retired, the successor opened. An
     * operator who pasted only the successor would leave the predecessor live; one who replaced the
     * predecessor would arm the deletion landmine.
     */
    @Test void the_block_retires_the_predecessor_and_opens_the_successor(@TempDir Path reg,
            @TempDir Path out) throws Exception {
        KeyPair old = Ed25519Keys.generate();
        writeAnchor(reg, line("alice", old), line("bob", Ed25519Keys.generate()));
        String o = run(0, args(reg, out, "alice"));

        List<String> b = block(o);
        assertEquals(2, b.size(), "the predecessor and the successor, both: " + o);
        String oldB64 = Ed25519Keys.publicKeyB64(old.getPublic());
        String predecessor = b.stream().filter(l -> l.contains(oldB64)).findFirst().orElseThrow();
        assertTrue(predecessor.contains("\"notAfter\":\"" + NOW + "\""), predecessor);
        String successor = b.stream().filter(l -> !l.contains(oldB64)).findFirst().orElseThrow();
        assertTrue(successor.contains("\"notBefore\":\"" + NOW + "\""), successor);
        assertFalse(successor.contains("notAfter"), "the successor is open-ended: " + successor);
        assertTrue(b.stream().noneMatch(l -> l.contains("\"bob\"")),
                "the block is one principal; touching another would be an edit nobody asked for");
    }

    /** A principal already rotated once keeps ALL its predecessors — each is history somebody signed. */
    @Test void an_already_retired_predecessor_stays_in_the_block(@TempDir Path reg, @TempDir Path out)
            throws Exception {
        KeyPair k1 = Ed25519Keys.generate();
        KeyPair k2 = Ed25519Keys.generate();
        writeAnchor(reg,
                "{\"principal\":\"alice\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(k1.getPublic())
                        + "\",\"notAfter\":\"2025-01-01T00:00:00Z\"}",
                "{\"principal\":\"alice\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(k2.getPublic())
                        + "\",\"notBefore\":\"2025-01-01T00:00:00Z\"}");
        String o = run(0, args(reg, out, "alice"));
        List<String> b = block(o);
        assertEquals(3, b.size(), "two predecessors and the successor: " + o);
        assertTrue(b.stream().anyMatch(l -> l.contains("\"notAfter\":\"2025-01-01T00:00:00Z\"")),
                "an earlier retirement stamp must not be rewritten: " + o);
    }

    /** The successor must actually bind, or the operator has pasted a line that signs nothing. */
    @Test void the_successor_line_binds_the_key_it_minted(@TempDir Path reg, @TempDir Path out)
            throws Exception {
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(reg, line("alice", Ed25519Keys.generate()), line("bob", bob));
        String o = run(0, args(reg, out, "alice"));

        Path akf = reg.resolve("identity").resolve("authorized-keys.jsonl");
        Files.write(akf, List.of(block(o).get(0), block(o).get(1), line("bob", bob)));
        Path bobKey = out.resolve("bob.key");
        Files.writeString(bobKey, Ed25519Keys.privateKeyB64(bob.getPrivate()));

        assertEquals(List.of(), KeyFileLedgerSigner.create("alice", out.resolve("alice.key"),
                "bob", bobKey, AuthorizedKeys.load(reg),
                Clock.fixed(NOW.plusSeconds(60), ZoneOffset.UTC)).preflight(),
                "the successor must be able to sign immediately after the block is pasted");
    }

    @Test void it_says_what_the_operator_must_do_and_must_not(@TempDir Path reg, @TempDir Path out)
            throws Exception {
        writeAnchor(reg, line("alice", Ed25519Keys.generate()));
        String o = run(0, args(reg, out, "alice"));
        assertTrue(o.toLowerCase(java.util.Locale.ROOT).contains("replace"), o);
        assertTrue(o.toLowerCase(java.util.Locale.ROOT).contains("delete"),
                "it must say plainly that deleting a predecessor line breaks the history it signed: " + o);
    }

    /** --retire-at lets an operator schedule the cutover instead of taking it at the instant they type. */
    @Test void retire_at_overrides_the_stamp(@TempDir Path reg, @TempDir Path out) throws Exception {
        writeAnchor(reg, line("alice", Ed25519Keys.generate()));
        PrintStream saved = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
            assertEquals(0, IdentityGate.run(new String[]{"rotate-key", reg.toString(), "alice",
                    "--out", out.toString(), "--retire-at", "2026-12-25T00:00:00Z"},
                    Clock.fixed(NOW, ZoneOffset.UTC)));
        } finally {
            System.setOut(saved);
        }
        String o = buf.toString(StandardCharsets.UTF_8);
        assertTrue(o.contains("2026-12-25T00:00:00Z"), o);
        assertFalse(o.contains(NOW.toString()), "the typed instant wins over the clock: " + o);
    }

    @Test void an_unparseable_retire_at_is_a_usage_error(@TempDir Path reg, @TempDir Path out)
            throws Exception {
        writeAnchor(reg, line("alice", Ed25519Keys.generate()));
        assertEquals(2, IdentityGate.run(new String[]{"rotate-key", reg.toString(), "alice",
                "--out", out.toString(), "--retire-at", "christmas"}));
    }
}
