package dev.krillin.bifrost.core.acl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import dev.krillin.bifrost.core.identity.Ed25519Keys;

/**
 * A command in flight must survive a key rotation.
 *
 * <p>The reasoning is the ledger's, applied to the write path: an envelope carries a subject and a
 * signature but no key id, so the only honest question is whether any key that subject is registered
 * with produced it. Refusing a signature from the predecessor key would mean every rotation had a
 * window in which authenticated commands were rejected at the boundary -- a rotation that stops the
 * line, which is precisely what R5 exists to avoid.
 *
 * <p>Retiring a key stops it SIGNING new work; it does not un-authenticate work it already signed.
 * That is rotation, not revocation, and the difference is stated in {@code ENTERPRISE.md}.
 */
class CommandEnvelopeRotationTest {

    private static final String G = "Bifrost:Line1", E = "recipe-edge", ID = "c-1";
    private static final String CMD = "ns=2;s=Recipe/Rpm", TYPE = "Double";
    private static final Object VAL = 1500.0;

    private static Function<String, List<PublicKey>> anchor(Map<String, List<PublicKey>> m) {
        return name -> m.getOrDefault(name, List.of());
    }

    private static String sign(KeyPair kp) {
        return CommandEnvelope.sign(G, E, ID, CMD, VAL, TYPE, kp.getPrivate());
    }

    private static CommandEnvelope.Verdict verify(Function<String, List<PublicKey>> a, String sig) {
        return CommandEnvelope.verify(a, "alice", sig, G, E, ID, CMD, VAL, TYPE);
    }

    @Test void a_command_signed_with_the_successor_key_verifies() {
        KeyPair old = Ed25519Keys.generate();
        KeyPair now = Ed25519Keys.generate();
        var a = anchor(Map.of("alice", List.of(old.getPublic(), now.getPublic())));
        assertEquals(CommandEnvelope.Verdict.OK, verify(a, sign(now)));
    }

    /** The one that matters: a command signed before the rotation is still authenticated. */
    @Test void a_command_signed_with_the_retired_key_still_verifies() {
        KeyPair old = Ed25519Keys.generate();
        KeyPair now = Ed25519Keys.generate();
        var a = anchor(Map.of("alice", List.of(old.getPublic(), now.getPublic())));
        assertEquals(CommandEnvelope.Verdict.OK, verify(a, sign(old)));
    }

    @Test void a_single_key_principal_behaves_exactly_as_before() {
        KeyPair alice = Ed25519Keys.generate();
        var a = anchor(Map.of("alice", List.of(alice.getPublic())));
        assertEquals(CommandEnvelope.Verdict.OK, verify(a, sign(alice)));
    }

    @Test void an_empty_key_list_is_an_unknown_principal() {
        assertEquals(CommandEnvelope.Verdict.UNKNOWN_PRINCIPAL,
                verify(anchor(Map.of()), sign(Ed25519Keys.generate())));
    }

    @Test void a_signature_no_registered_key_verifies_is_a_bad_signature() {
        KeyPair alice = Ed25519Keys.generate();
        KeyPair stranger = Ed25519Keys.generate();
        var a = anchor(Map.of("alice", List.of(alice.getPublic())));
        assertEquals(CommandEnvelope.Verdict.BAD_SIGNATURE, verify(a, sign(stranger)));
    }

    /** An undecodable signature is still a bad signature rather than a crash, across every key. */
    @Test void a_malformed_signature_is_a_bad_signature_not_a_crash() {
        KeyPair a1 = Ed25519Keys.generate();
        KeyPair a2 = Ed25519Keys.generate();
        var a = anchor(Map.of("alice", List.of(a1.getPublic(), a2.getPublic())));
        assertEquals(CommandEnvelope.Verdict.BAD_SIGNATURE, verify(a, "!!!not-base64!!!"));
    }
}
