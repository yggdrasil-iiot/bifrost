package dev.krillin.bifrost.core.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.krillin.bifrost.core.schema.Violation;

/**
 * Rotation takes effect at SIGNING time, which is the half of it the verifier deliberately does not do.
 *
 * <p>Verification cannot filter by window — an entry carries no key id and its timestamp is
 * self-asserted — so a retired key keeps verifying the history it signed. What retirement has to stop
 * is that key producing anything NEW, and preflight is where the ladder already refuses: an
 * unregistered key, a key file that does not match its principal, or two principals resolving to one
 * key are all caught here, before a single byte reaches the ledger.
 *
 * <p>The clock is injected for the same reason {@code ActivationService} and {@code CommandLedger}
 * inject theirs: a test that has to sleep to cross a boundary is a test that will be deleted.
 */
class KeyFileLedgerSignerRotationTest {

    private static final Instant NOW = Instant.parse("2026-06-01T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private static String line(String principal, KeyPair kp, String notBefore, String notAfter) {
        StringBuilder sb = new StringBuilder("{\"principal\":\"" + principal + "\",\"publicKey\":\""
                + Ed25519Keys.publicKeyB64(kp.getPublic()) + "\"");
        if (notBefore != null) sb.append(",\"notBefore\":\"").append(notBefore).append('"');
        if (notAfter != null) sb.append(",\"notAfter\":\"").append(notAfter).append('"');
        return sb.append('}').toString();
    }

    private static void writeAnchor(Path root, String... lines) throws Exception {
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.write(akf, List.of(lines));
    }

    private static Path keyFile(Path keys, String name, KeyPair kp) throws Exception {
        Path f = keys.resolve(name);
        Files.writeString(f, Ed25519Keys.privateKeyB64(kp.getPrivate()));
        return f;
    }

    private static String rules(List<Violation> v) {
        return v.stream().map(Violation::rule).reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    // ----- the window bites at signing -----

    @Test void a_retired_key_cannot_sign(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair aliceOld = Ed25519Keys.generate();
        KeyPair aliceNew = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(root,
                line("alice", aliceOld, null, "2026-01-01T00:00:00Z"),
                line("alice", aliceNew, "2026-01-01T00:00:00Z", null),
                line("bob", bob, null, null));

        List<Violation> v = KeyFileLedgerSigner.create("alice", keyFile(keys, "old", aliceOld),
                "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root), CLOCK).preflight();
        assertTrue(rules(v).contains("identity.key.expired"), rules(v));
    }

    @Test void the_successor_can_sign_while_the_predecessor_is_still_registered(@TempDir Path root,
            @TempDir Path keys) throws Exception {
        KeyPair aliceOld = Ed25519Keys.generate();
        KeyPair aliceNew = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(root,
                line("alice", aliceOld, null, "2026-01-01T00:00:00Z"),
                line("alice", aliceNew, "2026-01-01T00:00:00Z", null),
                line("bob", bob, null, null));

        List<Violation> v = KeyFileLedgerSigner.create("alice", keyFile(keys, "new", aliceNew),
                "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root), CLOCK).preflight();
        assertEquals(List.of(), v, rules(v));
    }

    @Test void a_key_whose_window_has_not_opened_cannot_sign_yet(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(root,
                line("alice", alice, "2030-01-01T00:00:00Z", null),
                line("bob", bob, null, null));

        List<Violation> v = KeyFileLedgerSigner.create("alice", keyFile(keys, "a", alice),
                "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root), CLOCK).preflight();
        assertTrue(rules(v).contains("identity.key.not-yet-valid"), rules(v));
    }

    /** The approver leg is checked too — a maker-checker where only the maker's key is current is not one. */
    @Test void a_retired_approver_key_is_refused(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair bobOld = Ed25519Keys.generate();
        writeAnchor(root,
                line("alice", alice, null, null),
                line("bob", bobOld, null, "2026-01-01T00:00:00Z"));

        List<Violation> v = KeyFileLedgerSigner.create("alice", keyFile(keys, "a", alice),
                "bob", keyFile(keys, "b", bobOld), AuthorizedKeys.load(root), CLOCK).preflight();
        assertTrue(rules(v).contains("identity.key.expired"), rules(v));
    }

    // ----- everything a registry written before rotation relies on -----

    @Test void an_unbounded_key_signs_exactly_as_before(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(root, line("alice", alice, null, null), line("bob", bob, null, null));
        List<Violation> v = KeyFileLedgerSigner.create("alice", keyFile(keys, "a", alice),
                "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root), CLOCK).preflight();
        assertEquals(List.of(), v, rules(v));
    }

    /** Four-eyes compares the two BOUND keys, not "the principal's key" — there may be several now. */
    @Test void four_eyes_compares_the_keys_that_actually_bound(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        KeyPair shared = Ed25519Keys.generate();
        KeyPair aliceOther = Ed25519Keys.generate();
        // alice holds two keys; bob holds the one alice is about to sign with
        writeAnchor(root,
                line("alice", aliceOther, null, null),
                line("alice", shared, null, null),
                line("bob", shared, null, null));

        List<Violation> v = KeyFileLedgerSigner.create("alice", keyFile(keys, "s1", shared),
                "bob", keyFile(keys, "s2", shared), AuthorizedKeys.load(root), CLOCK).preflight();
        assertTrue(rules(v).contains("identity.four-eyes.same-key"), rules(v));
    }

    /** A key file for a principal that holds keys, but none of them this one, is still a mismatch. */
    @Test void a_key_file_matching_no_registered_key_is_a_mismatch(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair stranger = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(root, line("alice", alice, null, null), line("bob", bob, null, null));
        List<Violation> v = KeyFileLedgerSigner.create("alice", keyFile(keys, "x", stranger),
                "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root), CLOCK).preflight();
        assertTrue(rules(v).contains("identity.key.principal-mismatch"), rules(v));
    }

    /** The no-clock factory still exists and defaults to the system clock. */
    @Test void the_existing_factory_still_works(@TempDir Path root, @TempDir Path keys) throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair bob = Ed25519Keys.generate();
        writeAnchor(root, line("alice", alice, null, null), line("bob", bob, null, null));
        assertEquals(List.of(), KeyFileLedgerSigner.create("alice", keyFile(keys, "a", alice),
                "bob", keyFile(keys, "b", bob), AuthorizedKeys.load(root)).preflight());
    }
}
