package dev.krillin.bifrost.core.identity;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Pure Ed25519 crypto — the one signing/verification discipline shared by the ledger writer, the
 *  verifier (gate + Heimdall edge), and keygen. JDK built-in ("Ed25519", JEP 339, JDK 15+); no external
 *  dependency. Serialization is base64: public key = X.509 SubjectPublicKeyInfo, private key = PKCS8,
 *  signature = raw 64-byte Ed25519. verify() NEVER throws — any malformed input is a false (fail-closed). */
public final class Ed25519Keys {
    private Ed25519Keys() {}

    private static final String ALG = "Ed25519";

    public static KeyPair generate() {
        try { return KeyPairGenerator.getInstance(ALG).generateKeyPair(); }
        catch (GeneralSecurityException e) { throw new IllegalStateException("Ed25519 unavailable", e); }
    }

    public static String sign(byte[] msg, PrivateKey key) {
        try {
            Signature s = Signature.getInstance(ALG);
            s.initSign(key);
            s.update(msg);
            return Base64.getEncoder().encodeToString(s.sign());
        } catch (GeneralSecurityException e) { throw new IllegalStateException("sign failed", e); }
    }

    /** True iff sigB64 is a valid Ed25519 signature of msg under key. False on ANY error (fail-closed). */
    public static boolean verify(byte[] msg, String sigB64, PublicKey key) {
        try {
            Signature s = Signature.getInstance(ALG);
            s.initVerify(key);
            s.update(msg);
            return s.verify(Base64.getDecoder().decode(sigB64));
        } catch (RuntimeException | GeneralSecurityException e) { return false; }
    }

    public static String publicKeyB64(PublicKey k)  { return Base64.getEncoder().encodeToString(k.getEncoded()); }
    public static String privateKeyB64(PrivateKey k) { return Base64.getEncoder().encodeToString(k.getEncoded()); }

    public static PublicKey publicKey(String b64) {
        try {
            return KeyFactory.getInstance(ALG)
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64)));
        } catch (GeneralSecurityException | RuntimeException e) { throw new IllegalArgumentException("bad public key", e); }
    }

    public static PrivateKey privateKey(String b64) {
        try {
            return KeyFactory.getInstance(ALG)
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64)));
        } catch (GeneralSecurityException | RuntimeException e) { throw new IllegalArgumentException("bad private key", e); }
    }
}
