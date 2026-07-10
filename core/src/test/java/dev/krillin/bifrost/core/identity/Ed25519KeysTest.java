package dev.krillin.bifrost.core.identity;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import static org.junit.jupiter.api.Assertions.*;

class Ed25519KeysTest {
    private static final byte[] MSG = "the exact bytes".getBytes(StandardCharsets.UTF_8);

    @Test void sign_then_verify_roundtrips() {
        KeyPair kp = Ed25519Keys.generate();
        String sig = Ed25519Keys.sign(MSG, kp.getPrivate());
        assertTrue(Ed25519Keys.verify(MSG, sig, kp.getPublic()));
    }

    @Test void verify_rejects_tampered_message() {
        KeyPair kp = Ed25519Keys.generate();
        String sig = Ed25519Keys.sign(MSG, kp.getPrivate());
        assertFalse(Ed25519Keys.verify("other bytes".getBytes(StandardCharsets.UTF_8), sig, kp.getPublic()));
    }

    @Test void verify_rejects_wrong_key() {
        KeyPair a = Ed25519Keys.generate();
        KeyPair b = Ed25519Keys.generate();
        String sig = Ed25519Keys.sign(MSG, a.getPrivate());
        assertFalse(Ed25519Keys.verify(MSG, sig, b.getPublic()));
    }

    @Test void verify_returns_false_on_garbage_signature_not_throw() {
        KeyPair kp = Ed25519Keys.generate();
        assertFalse(Ed25519Keys.verify(MSG, "not-base64-!!!", kp.getPublic()));
        assertFalse(Ed25519Keys.verify(MSG, "", kp.getPublic()));
    }

    @Test void public_key_base64_roundtrips() {
        KeyPair kp = Ed25519Keys.generate();
        String b64 = Ed25519Keys.publicKeyB64(kp.getPublic());
        PublicKey back = Ed25519Keys.publicKey(b64);
        String sig = Ed25519Keys.sign(MSG, kp.getPrivate());
        assertTrue(Ed25519Keys.verify(MSG, sig, back), "reloaded pubkey verifies a sig from its pair");
    }

    @Test void private_key_base64_roundtrips() {
        KeyPair kp = Ed25519Keys.generate();
        String b64 = Ed25519Keys.privateKeyB64(kp.getPrivate());
        PrivateKey back = Ed25519Keys.privateKey(b64);
        String sig = Ed25519Keys.sign(MSG, back);
        assertTrue(Ed25519Keys.verify(MSG, sig, kp.getPublic()), "reloaded privkey signs verifiably");
    }
}
