package dev.krillin.bifrost.core.acl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.security.KeyPair;

import org.junit.jupiter.api.Test;

import dev.krillin.bifrost.core.identity.Ed25519Keys;

class CommandEnvelopeTest {

    private static final String GROUP = "Bifrost:Line1";
    private static final String EDGE = "recipe-edge";
    private static final String CMD = "ns=2;s=Recipe/Rpm";

    private final KeyPair writer = Ed25519Keys.generate();
    private final KeyPair other = Ed25519Keys.generate();

    private String sign(KeyPair kp, String cmdId, String command, Object value, String type) {
        return CommandEnvelope.sign(GROUP, EDGE, cmdId, command, value, type, kp.getPrivate());
    }

    private CommandEnvelope.Verdict verify(String subject, String sig, String cmdId,
                                           String command, Object value, String type,
                                           java.util.Map<String, java.security.PublicKey> anchor) {
        return CommandEnvelope.verify(anchor::get, subject, sig, GROUP, EDGE, cmdId, command, value, type);
    }

    private java.util.Map<String, java.security.PublicKey> anchorWith(String name, KeyPair kp) {
        return java.util.Map.of(name, kp.getPublic());
    }

    @Test void a_good_signature_verifies() {
        String sig = sign(writer, "c-1", CMD, 1500.0, "Double");
        assertEquals(CommandEnvelope.Verdict.OK,
                verify("recipe-writer", sig, "c-1", CMD, 1500.0, "Double", anchorWith("recipe-writer", writer)));
    }

    @Test void a_tampered_value_does_not_verify() {
        String sig = sign(writer, "c-1", CMD, 1500.0, "Double");
        assertEquals(CommandEnvelope.Verdict.BAD_SIGNATURE,
                verify("recipe-writer", sig, "c-1", CMD, 9999.0, "Double", anchorWith("recipe-writer", writer)));
    }

    @Test void a_tampered_command_does_not_verify() {
        String sig = sign(writer, "c-1", CMD, 1500.0, "Double");
        assertEquals(CommandEnvelope.Verdict.BAD_SIGNATURE,
                verify("recipe-writer", sig, "c-1", "ns=2;s=Recipe/Temp", 1500.0, "Double",
                        anchorWith("recipe-writer", writer)));
    }

    /** The cmdId is bound, so one command's signature is not a signature for the next one. */
    @Test void a_different_cmdId_does_not_verify() {
        String sig = sign(writer, "c-1", CMD, 1500.0, "Double");
        assertEquals(CommandEnvelope.Verdict.BAD_SIGNATURE,
                verify("recipe-writer", sig, "c-2", CMD, 1500.0, "Double", anchorWith("recipe-writer", writer)));
    }

    @Test void another_principals_key_does_not_verify() {
        String sig = sign(other, "c-1", CMD, 1500.0, "Double");
        assertEquals(CommandEnvelope.Verdict.BAD_SIGNATURE,
                verify("recipe-writer", sig, "c-1", CMD, 1500.0, "Double", anchorWith("recipe-writer", writer)));
    }

    /**
     * A name absent from the trust anchor is a DIFFERENT outcome from a bad signature. The gate's
     * C3 and C4 legs distinguish them, and collapsing the two would make one of those legs pass
     * for the other's reason.
     */
    @Test void an_unknown_principal_is_distinct_from_a_bad_signature() {
        String sig = sign(writer, "c-1", CMD, 1500.0, "Double");
        assertEquals(CommandEnvelope.Verdict.UNKNOWN_PRINCIPAL,
                verify("nobody", sig, "c-1", CMD, 1500.0, "Double", anchorWith("recipe-writer", writer)));
    }

    /**
     * The encoding that would otherwise break the very first live run: the signer holds a parsed
     * Double, the verifier reads an Object off a decoded Sparkplug metric. "1500" and "1500.0" are
     * different preimages, so the canonicalization has to be pinned to the TYPED value.
     */
    @Test void the_value_is_canonicalized_from_the_typed_object() {
        String signedAsDouble = sign(writer, "c-1", CMD, Double.valueOf("1500"), "Double");
        assertEquals(CommandEnvelope.Verdict.OK,
                verify("recipe-writer", signedAsDouble, "c-1", CMD, 1500.0, "Double",
                        anchorWith("recipe-writer", writer)));
        assertNotEquals(CommandEnvelope.preimage(GROUP, EDGE, "c-1", CMD, "1500", "Double"),
                CommandEnvelope.preimage(GROUP, EDGE, "c-1", CMD, "1500.0", "Double"),
                "a raw string and the typed rendering must not collide silently");
    }

    /**
     * Field-boundary: moving the delimiter must change the preimage. Carried over from
     * LedgerChain's documented limitation, which this envelope inherits unchanged.
     */
    @Test void field_boundaries_are_not_ambiguous() {
        assertNotEquals(CommandEnvelope.preimage(GROUP, EDGE, "a", "b", "1", "Double"),
                CommandEnvelope.preimage(GROUP, EDGE, "ab", "", "1", "Double"));
    }
}
