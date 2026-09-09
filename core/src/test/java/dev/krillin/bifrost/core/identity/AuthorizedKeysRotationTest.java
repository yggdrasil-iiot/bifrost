package dev.krillin.bifrost.core.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A principal may hold more than one key, which is what makes rotation expressible at all.
 *
 * <p>Until now {@code AuthorizedKeys} mapped a principal to exactly ONE key and treated a second
 * line as a load error, so {@code ADOPTION.md}'s instruction to retire a key by policy rather than
 * by deleting its line had no mechanism behind it: there was no way to write down "this principal's
 * old key and its successor".
 *
 * <p><b>Verification is deliberately not time-filtered.</b> A ledger entry carries no key id and its
 * timestamp is self-asserted, so the only honest question at verification time is whether ANY key the
 * principal is registered with produced this signature. The validity window restricts <i>signing</i>
 * instead — see {@link KeyFileLedgerSignerRotationTest}.
 */
class AuthorizedKeysRotationTest {

    private static final byte[] MSG = "m".getBytes(StandardCharsets.UTF_8);

    private static void writeKeys(Path root, String... lines) throws Exception {
        Path f = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(f.getParent());
        Files.write(f, List.of(lines));
    }

    /** A line in the shape every registry written before rotation existed uses. */
    private static String line(String principal, KeyPair kp) {
        return "{\"principal\":\"" + principal + "\",\"publicKey\":\""
                + Ed25519Keys.publicKeyB64(kp.getPublic()) + "\"}";
    }

    private static String line(String principal, KeyPair kp, String notBefore, String notAfter) {
        StringBuilder sb = new StringBuilder("{\"principal\":\"" + principal + "\",\"publicKey\":\""
                + Ed25519Keys.publicKeyB64(kp.getPublic()) + "\"");
        if (notBefore != null) sb.append(",\"notBefore\":\"").append(notBefore).append('"');
        if (notAfter != null) sb.append(",\"notAfter\":\"").append(notAfter).append('"');
        return sb.append('}').toString();
    }

    // ----- more than one key per principal -----

    @Test void two_different_keys_for_one_principal_load(@TempDir Path root) throws Exception {
        KeyPair old = Ed25519Keys.generate();
        KeyPair now = Ed25519Keys.generate();
        writeKeys(root, line("alice", old), line("alice", now));
        assertEquals(2, AuthorizedKeys.load(root).allForPrincipal("alice").size(),
                "a second key for a principal is how rotation is written down, not a load error");
    }

    @Test void an_identical_duplicate_line_is_still_collapsed(@TempDir Path root) throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        writeKeys(root, line("alice", alice), line("alice", alice));
        assertEquals(1, AuthorizedKeys.load(root).allForPrincipal("alice").size());
    }

    // ----- verifying(): the resolution primitive -----

    @Test void verifying_finds_the_key_that_signed(@TempDir Path root) throws Exception {
        KeyPair old = Ed25519Keys.generate();
        KeyPair now = Ed25519Keys.generate();
        writeKeys(root, line("alice", old), line("alice", now));
        AuthorizedKeys ak = AuthorizedKeys.load(root);

        Optional<PublicKey> byOld = ak.verifying("alice", MSG, Ed25519Keys.sign(MSG, old.getPrivate()));
        Optional<PublicKey> byNow = ak.verifying("alice", MSG, Ed25519Keys.sign(MSG, now.getPrivate()));
        assertTrue(byOld.isPresent(), "a signature from the retired key must still resolve");
        assertTrue(byNow.isPresent());
        assertFalse(byOld.get().equals(byNow.get()), "it must return WHICH key verified");
    }

    /** Order independence: an operator appends the successor, but a rewritten file may sort either way. */
    @Test void the_successor_may_be_listed_before_the_predecessor(@TempDir Path root) throws Exception {
        KeyPair old = Ed25519Keys.generate();
        KeyPair now = Ed25519Keys.generate();
        writeKeys(root, line("alice", now), line("alice", old));
        AuthorizedKeys ak = AuthorizedKeys.load(root);
        assertTrue(ak.verifying("alice", MSG, Ed25519Keys.sign(MSG, old.getPrivate())).isPresent());
        assertTrue(ak.verifying("alice", MSG, Ed25519Keys.sign(MSG, now.getPrivate())).isPresent());
    }

    @Test void verifying_is_empty_for_an_unregistered_principal(@TempDir Path root) throws Exception {
        writeKeys(root, line("alice", Ed25519Keys.generate()));
        assertTrue(AuthorizedKeys.load(root)
                .verifying("stranger", MSG, "AAAA").isEmpty());
    }

    @Test void verifying_is_empty_when_no_registered_key_verifies(@TempDir Path root) throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair stranger = Ed25519Keys.generate();
        writeKeys(root, line("alice", alice));
        assertTrue(AuthorizedKeys.load(root)
                .verifying("alice", MSG, Ed25519Keys.sign(MSG, stranger.getPrivate())).isEmpty());
    }

    /** A malformed signature is a failed verification, never an exception out of the trust anchor. */
    @Test void a_malformed_signature_is_just_not_verified(@TempDir Path root) throws Exception {
        writeKeys(root, line("alice", Ed25519Keys.generate()));
        assertTrue(AuthorizedKeys.load(root).verifying("alice", MSG, "!!!not-base64!!!").isEmpty());
    }

    // ----- validity windows -----

    @Test void absent_window_means_unbounded(@TempDir Path root) throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        writeKeys(root, line("alice", alice));
        AuthorizedKeys ak = AuthorizedKeys.load(root);
        assertEquals(1, ak.validForPrincipal("alice", Instant.parse("1999-01-01T00:00:00Z")).size());
        assertEquals(1, ak.validForPrincipal("alice", Instant.parse("2099-01-01T00:00:00Z")).size());
    }

    @Test void a_retired_key_is_not_valid_for_signing_but_still_verifies(@TempDir Path root) throws Exception {
        KeyPair old = Ed25519Keys.generate();
        KeyPair now = Ed25519Keys.generate();
        writeKeys(root,
                line("alice", old, null, "2026-01-01T00:00:00Z"),
                line("alice", now, "2026-01-01T00:00:00Z", null));
        AuthorizedKeys ak = AuthorizedKeys.load(root);
        Instant t = Instant.parse("2026-06-01T00:00:00Z");

        List<PublicKey> valid = ak.validForPrincipal("alice", t);
        assertEquals(1, valid.size(), "only the successor may sign now");
        assertTrue(Ed25519Keys.verify(MSG, Ed25519Keys.sign(MSG, now.getPrivate()), valid.get(0)));

        assertTrue(ak.verifying("alice", MSG, Ed25519Keys.sign(MSG, old.getPrivate())).isPresent(),
                "the retired key must keep verifying the history it signed");
    }

    @Test void a_not_yet_valid_key_cannot_sign_yet(@TempDir Path root) throws Exception {
        KeyPair future = Ed25519Keys.generate();
        writeKeys(root, line("alice", future, "2030-01-01T00:00:00Z", null));
        AuthorizedKeys ak = AuthorizedKeys.load(root);
        assertTrue(ak.validForPrincipal("alice", Instant.parse("2026-06-01T00:00:00Z")).isEmpty());
        assertEquals(1, ak.validForPrincipal("alice", Instant.parse("2031-01-01T00:00:00Z")).size());
    }

    /** notAfter is exclusive, notBefore inclusive — stated by a test so a later edit cannot drift it. */
    @Test void the_window_boundaries_are_pinned(@TempDir Path root) throws Exception {
        KeyPair k = Ed25519Keys.generate();
        writeKeys(root, line("alice", k, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"));
        AuthorizedKeys ak = AuthorizedKeys.load(root);
        assertEquals(1, ak.validForPrincipal("alice", Instant.parse("2026-01-01T00:00:00Z")).size(),
                "notBefore is inclusive");
        assertTrue(ak.validForPrincipal("alice", Instant.parse("2026-02-01T00:00:00Z")).isEmpty(),
                "notAfter is exclusive");
    }

    @Test void a_malformed_window_is_a_coded_load_error(@TempDir Path root) throws Exception {
        KeyPair k = Ed25519Keys.generate();
        writeKeys(root, "{\"principal\":\"alice\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(k.getPublic())
                + "\",\"notAfter\":\"not-an-instant\"}");
        IllegalStateException ex = org.junit.jupiter.api.Assertions.assertThrows(
                IllegalStateException.class, () -> AuthorizedKeys.load(root));
        assertTrue(ex.getMessage().startsWith("identity.authorized-keys."), ex.getMessage());
    }

    // ----- the record itself -----

    @Test void validAt_treats_null_bounds_as_unbounded() {
        AuthorizedKey k = new AuthorizedKey("alice", "x");
        assertTrue(k.validAt(Instant.EPOCH));
        assertSame(null, k.notAfter());
    }
}
