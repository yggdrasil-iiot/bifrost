package dev.krillin.bifrost.core.identity;

import dev.krillin.bifrost.core.schema.Violation;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.*;

/** One principal's private-key FILE bound to its registered public key, for an act one person performs alone
 *  (publishing a recipe). The binding and the validity window are the same checks {@link KeyFileLedgerSigner}
 *  applies to each of its two keys; a single-key act is not modelled as two principals sharing one key. */
public final class KeyFileSigner {
    private final String principal;
    private final PrivateKey key;
    private final AuthorizedKeys authorized;
    private final java.time.Clock clock;

    private KeyFileSigner(String principal, PrivateKey key, AuthorizedKeys authorized, java.time.Clock clock) {
        this.principal = principal; this.key = key; this.authorized = authorized; this.clock = clock;
    }

    public static KeyFileSigner create(String principal, Path keyFile, AuthorizedKeys authorized, java.time.Clock clock) {
        return new KeyFileSigner(principal, KeyFileLedgerSigner.readKey(keyFile), authorized, clock);
    }

    public List<Violation> preflight() {
        List<Violation> v = new ArrayList<>();
        KeyFileLedgerSigner.bindsToPrincipal(authorized, principal, key, v)
                .ifPresent(k -> KeyFileLedgerSigner.checkWindow(authorized, principal, k, clock.instant(), v));
        return v;
    }

    /** The key over exact bytes (a DSSE PAE). */
    public String signRaw(byte[] msg) { return Ed25519Keys.sign(msg, key); }

    public String principal() { return principal; }
}
