package dev.krillin.bifrost.core.activation;

import static dev.krillin.bifrost.core.activation.ActivationAction.ACTIVATE;
import static dev.krillin.bifrost.core.activation.ActivationAction.APPROVE;
import static dev.krillin.bifrost.core.activation.ActivationAction.BREAK_GLASS_APPROVE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Clock;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.krillin.bifrost.core.identity.AuthorizedKeys;
import dev.krillin.bifrost.core.identity.Ed25519Keys;
import dev.krillin.bifrost.core.identity.KeyFileLedgerSigner;

/**
 * The emergency path: one person signs with their own key AND a duty key that two people minted.
 *
 * <p>To {@code SignedLedgerVerifier} this is an ordinary four-eyes line — two signatures, two
 * registered principals, two distinct keys — which is why no verifier changes. What makes it an
 * emergency is <b>which principal approved</b>, and that is a policy fact the operator cannot
 * restate: a duty principal is granted {@code BREAK_GLASS_APPROVE} and NOT {@code APPROVE}, so it
 * cannot produce an unmarked activation.
 */
class BreakGlassTest {

    private ArtifactResolver okResolver() {
        return (kind, ref, version) -> java.util.Optional.of(
                new ArtifactResolver.ResolvedArtifact(Path.of("x"), "shaX"));
    }

    /** Registers alice + the named approver, and returns a signer naming alice as activator. */
    private LedgerSigner signerWith(Path root, Path keys, String approver) throws Exception {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair other = Ed25519Keys.generate();
        Path akf = root.resolve("identity").resolve("authorized-keys.jsonl");
        Files.createDirectories(akf.getParent());
        Files.writeString(akf,
                "{\"principal\":\"alice\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(alice.getPublic()) + "\"}\n"
              + "{\"principal\":\"" + approver + "\",\"publicKey\":\""
                    + Ed25519Keys.publicKeyB64(other.getPublic()) + "\"}\n");
        Path a = keys.resolve("a");
        Path b = keys.resolve("b");
        Files.writeString(a, Ed25519Keys.privateKeyB64(alice.getPrivate()));
        Files.writeString(b, Ed25519Keys.privateKeyB64(other.getPrivate()));
        return KeyFileLedgerSigner.create("alice", a, approver, b, AuthorizedKeys.load(root));
    }

    private static ActivationPolicy policy(ActivationRule... rules) {
        return new ActivationPolicy("1", List.of(rules), "deny");
    }

    private ActivationRule r(String id, String p, ActivationAction a) {
        return new ActivationRule(id, p, a, "Line1", "recipe", "mix");
    }

    private ActivationRequest req(String approver) {
        return new ActivationRequest("Line1", "recipe", "mix", "1.0.0", "alice", approver, false);
    }

    private ActivationVerdict run(Path root, Path keys, String approver, ActivationPolicy p) throws Exception {
        return new ActivationService(okResolver(), new ActivationLedger(root), Clock.systemUTC())
                .activate(req(approver), signerWith(root, keys, approver), p);
    }

    // ----- the derived marking -----

    @Test void a_duty_principal_approving_yields_a_BREAK_GLASS_action(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        ActivationVerdict v = run(root, keys, "breakglass-duty",
                policy(r("r-act", "alice", ACTIVATE), r("r-bg", "breakglass-duty", BREAK_GLASS_APPROVE)));
        assertTrue(v.ok(), String.valueOf(v.violations()));
        assertEquals("BREAK_GLASS", v.event().action());
        assertEquals("breakglass-duty", v.event().approvedBy(),
                "the record must name which duty key approved it");
    }

    /**
     * The failure this round exists to prevent. If the marking were a request flag, the one person
     * holding both keys could omit it and the emergency would look like an ordinary change. It is
     * derived instead: a duty principal has no APPROVE grant, so there is nothing to omit.
     */
    @Test void a_duty_principal_cannot_produce_an_ordinary_ACTIVATE(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        ActivationVerdict v = run(root, keys, "breakglass-duty",
                policy(r("r-act", "alice", ACTIVATE), r("r-bg", "breakglass-duty", BREAK_GLASS_APPROVE)));
        assertTrue(v.ok());
        assertFalse("ACTIVATE".equals(v.event().action()),
                "a duty key must not be able to write an unmarked activation");
    }

    /** The regression that matters: an ordinary approver's path is unchanged. */
    @Test void an_ordinary_approver_still_yields_ACTIVATE(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        ActivationVerdict v = run(root, keys, "bob",
                policy(r("r-act", "alice", ACTIVATE), r("r-app", "bob", APPROVE)));
        assertTrue(v.ok(), String.valueOf(v.violations()));
        assertEquals("ACTIVATE", v.event().action());
    }

    @Test void a_principal_with_neither_grant_is_denied(@TempDir Path root, @TempDir Path keys) throws Exception {
        ActivationVerdict v = run(root, keys, "stranger", policy(r("r-act", "alice", ACTIVATE)));
        assertFalse(v.ok());
        assertTrue(String.valueOf(v.violations()).contains("activation.authz.denied"),
                String.valueOf(v.violations()));
    }

    /** Scope is ActivationPolicy's job: a duty grant on one resource does not reach another. */
    @Test void a_duty_grant_does_not_reach_another_target(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        ActivationVerdict v = run(root, keys, "breakglass-duty",
                policy(r("r-act", "alice", ACTIVATE),
                        new ActivationRule("r-bg", "breakglass-duty", BREAK_GLASS_APPROVE,
                                "OtherLine", "recipe", "mix")));
        assertFalse(v.ok(), "a duty key scoped to another target must not approve here");
    }

    /** Four-eyes itself is untouched: the approver must still differ from the activator. */
    @Test void four_eyes_still_requires_a_distinct_approver(@TempDir Path root, @TempDir Path keys)
            throws Exception {
        ActivationVerdict v = new ActivationService(okResolver(), new ActivationLedger(root), Clock.systemUTC())
                .activate(new ActivationRequest("Line1", "recipe", "mix", "1.0.0", "alice", "alice", false),
                        signerWith(root, keys, "breakglass-duty"),
                        policy(r("r-act", "alice", ACTIVATE), r("r-bg", "breakglass-duty", BREAK_GLASS_APPROVE)));
        assertFalse(v.ok());
        assertTrue(String.valueOf(v.violations()).contains("activation.approval.self"),
                String.valueOf(v.violations()));
    }
}
