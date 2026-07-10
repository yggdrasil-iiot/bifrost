package dev.krillin.bifrost.core.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import java.io.IOException;
import java.nio.file.*;
import java.security.PublicKey;
import java.util.*;

/** The trust anchor: principal -> Ed25519 public key, loaded from registry/identity/authorized-keys.jsonl
 *  (one {@link AuthorizedKey} JSON object per line). Fail-closed: an absent file authorizes nobody, and an
 *  unregistered principal resolves to empty. A duplicate principal line with a DIFFERENT key is a load
 *  error (ambiguous identity) — an identical duplicate is tolerated. Whole-file read per load (small
 *  registry, matches T4's ledger reads); not cached. Bootstrap/distribution/revocation are out-of-band
 *  (spec §9) — registering a key is adding a line, revoking is deleting one. */
public final class AuthorizedKeys {
    private final Map<String, PublicKey> byPrincipal;
    private AuthorizedKeys(Map<String, PublicKey> m) { this.byPrincipal = m; }

    public Optional<PublicKey> forPrincipal(String principal) {
        return Optional.ofNullable(byPrincipal.get(principal));
    }

    public static AuthorizedKeys load(Path registryRoot) {
        Path f = registryRoot.resolve("identity").resolve("authorized-keys.jsonl");
        if (!Files.isRegularFile(f)) return new AuthorizedKeys(Map.of());
        ObjectMapper mapper = JsonMapperFactory.create();
        Map<String, String> b64ByPrincipal = new HashMap<>();
        Map<String, PublicKey> keys = new HashMap<>();
        try {
            for (String line : Files.readAllLines(f)) {
                if (line.isBlank()) continue;
                AuthorizedKey ak = mapper.readValue(line, AuthorizedKey.class);
                String prev = b64ByPrincipal.putIfAbsent(ak.principal(), ak.publicKey());
                if (prev != null && !prev.equals(ak.publicKey()))
                    throw new IllegalStateException("identity.authorized-keys.duplicate-principal-different-key: "
                            + ak.principal());
                keys.putIfAbsent(ak.principal(), Ed25519Keys.publicKey(ak.publicKey()));
            }
        } catch (IOException e) {
            throw new IllegalStateException("identity.authorized-keys.read-error: " + f, e);
        }
        return new AuthorizedKeys(Map.copyOf(keys));
    }
}
