package dev.krillin.bifrost.core.identity;

import dev.krillin.bifrost.core.activation.HeadSignatures;
import dev.krillin.bifrost.core.activation.LedgerSigner;
import dev.krillin.bifrost.core.activation.Signatures;
import dev.krillin.bifrost.core.schema.Violation;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

/** LedgerSigner backed by two private-key FILES (base64 PKCS8) + the AuthorizedKeys trust anchor.
 *  Because a public key cannot be cleanly recomputed from a PKCS8 private key in JDK 17, we bind each key
 *  FILE to its claimed principal by signing a fixed probe and verifying it against the principal's
 *  REGISTERED public key. The registered pubkeys are also what the four-eyes distinctness check compares. */
public final class KeyFileLedgerSigner implements LedgerSigner {
    private static final byte[] PROBE = "bifrost-identity-probe".getBytes(StandardCharsets.UTF_8);

    private final String activatorPrincipal, approverPrincipal;
    private final PrivateKey activatorKey, approverKey;
    private final AuthorizedKeys authorized;

    private KeyFileLedgerSigner(String ap, PrivateKey ak, String pp, PrivateKey pk, AuthorizedKeys auth) {
        this.activatorPrincipal = ap; this.activatorKey = ak;
        this.approverPrincipal = pp;  this.approverKey = pk; this.authorized = auth;
    }

    public static KeyFileLedgerSigner create(String activatorPrincipal, Path activatorKeyFile,
                                             String approverPrincipal, Path approverKeyFile,
                                             AuthorizedKeys authorized) {
        return new KeyFileLedgerSigner(activatorPrincipal, readKey(activatorKeyFile),
                approverPrincipal, readKey(approverKeyFile), authorized);
    }

    private static PrivateKey readKey(Path f) {
        try { return Ed25519Keys.privateKey(Files.readString(f).strip()); }
        catch (IOException e) { throw new IdentityException("identity.key.unreadable", "cannot read key file " + f); }
    }

    @Override public List<Violation> preflight() {
        List<Violation> v = new ArrayList<>();
        Optional<PublicKey> aReg = bindsToPrincipal(activatorPrincipal, activatorKey, v);
        Optional<PublicKey> pReg = bindsToPrincipal(approverPrincipal, approverKey, v);
        // cryptographic four-eyes: the two registered pubkeys must differ (only reachable if both bound)
        if (aReg.isPresent() && pReg.isPresent()
                && Arrays.equals(aReg.get().getEncoded(), pReg.get().getEncoded()))
            v.add(new Violation("identity.four-eyes.same-key",
                    "activator '" + activatorPrincipal + "' and approver '" + approverPrincipal
                    + "' resolve to the same registered key"));
        return v;
    }

    /** The key file signs a probe that verifies under the principal's REGISTERED pubkey; else a violation. */
    private Optional<PublicKey> bindsToPrincipal(String principal, PrivateKey key, List<Violation> sink) {
        Optional<PublicKey> bound = authorized.verifying(principal, PROBE, Ed25519Keys.sign(PROBE, key));
        if (bound.isEmpty()) {
            sink.add(new Violation("identity.key.principal-mismatch",
                    "key file for '" + principal + "' does not match any of its registered public keys (or principal not registered)"));
            return Optional.empty();
        }
        return bound;
    }

    @Override public Signatures sign(String entryHash) {
        byte[] msg = entryHash.getBytes(StandardCharsets.UTF_8);
        return new Signatures(Ed25519Keys.sign(msg, activatorKey), Ed25519Keys.sign(msg, approverKey));
    }

    @Override public HeadSignatures signHead(String headPreimage) {
        byte[] msg = headPreimage.getBytes(StandardCharsets.UTF_8);
        return new HeadSignatures(Ed25519Keys.sign(msg, approverKey), Ed25519Keys.sign(msg, activatorKey));
    }

    @Override public String activatorPrincipal() { return activatorPrincipal; }
    @Override public String approverPrincipal() { return approverPrincipal; }
}
