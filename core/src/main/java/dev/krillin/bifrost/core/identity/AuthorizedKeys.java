package dev.krillin.bifrost.core.identity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;

import dev.krillin.bifrost.core.schema.JsonMapperFactory;

/**
 * The trust anchor: principal -&gt; the Ed25519 public keys it is registered with, loaded from
 * registry/identity/authorized-keys.jsonl (one {@link AuthorizedKey} JSON object per line).
 *
 * <p>Fail-closed: an absent file authorizes nobody, and an unregistered principal resolves to
 * nothing. A line whose key value will not decode is a coded load error rather than a silently
 * skipped line.
 *
 * <p><b>A principal may hold several keys, and that is how rotation is written down.</b> A second
 * line for a principal used to be a load error, which left {@code ADOPTION.md}'s "retire a key by
 * policy, never by deleting its line" with no mechanism behind it — there was no way to express a
 * predecessor and its successor at once. An identical duplicate line is still collapsed.
 *
 * <p>Two questions, deliberately separated:
 * <ul>
 *   <li>{@link #verifying} — <b>did any key this principal is registered with sign this?</b> The
 *       resolution primitive for history. Not time-filtered: an entry carries no key id and its
 *       timestamp is self-asserted, so no honest filter exists. Returns WHICH key verified, because
 *       the four-eyes distinctness checks compare the keys that actually did the work.
 *   <li>{@link #validForPrincipal} — <b>which keys may sign right now?</b> Rotation takes effect
 *       here. A retired key keeps verifying its own history and stops signing anything new.
 * </ul>
 *
 * <p>Whole-file read per load, not cached (small registry, matches T4's ledger reads). Bootstrap and
 * distribution remain out-of-band (spec §9). Note that retiring a key is NOT revoking it: a stolen
 * key's past signatures cannot be invalidated without a time source the site trusts, which
 * {@code ENTERPRISE.md} records as out of scope for the same reason it does for command replay.
 */
public final class AuthorizedKeys {

    /** A registered key with its window, kept together so validity survives decoding. */
    private record RegisteredKey(PublicKey key, AuthorizedKey declared) {
    }

    private final Map<String, List<RegisteredKey>> byPrincipal;

    private AuthorizedKeys(Map<String, List<RegisteredKey>> m) {
        this.byPrincipal = m;
    }

    /**
     * Which of {@code principal}'s registered keys verifies {@code sigB64} over {@code msg}, if any.
     *
     * <p>A malformed signature is a failed verification, never an exception: the trust anchor is on
     * the path of every verification, and a caller that must catch to stay fail-closed will
     * eventually forget to.
     */
    public Optional<PublicKey> verifying(String principal, byte[] msg, String sigB64) {
        if (sigB64 == null) return Optional.empty();
        for (RegisteredKey rk : byPrincipal.getOrDefault(principal, List.of())) {
            try {
                if (Ed25519Keys.verify(msg, sigB64, rk.key())) return Optional.of(rk.key());
            } catch (RuntimeException malformed) {
                return Optional.empty();   // an undecodable signature verifies under no key
            }
        }
        return Optional.empty();
    }

    /** Every key registered to a principal, in file order. */
    public List<PublicKey> allForPrincipal(String principal) {
        List<PublicKey> out = new ArrayList<>();
        for (RegisteredKey rk : byPrincipal.getOrDefault(principal, List.of())) out.add(rk.key());
        return List.copyOf(out);
    }

    /** The keys a principal may SIGN with at {@code at}. Rotation takes effect here. */
    public List<PublicKey> validForPrincipal(String principal, Instant at) {
        List<PublicKey> out = new ArrayList<>();
        for (RegisteredKey rk : byPrincipal.getOrDefault(principal, List.of()))
            if (rk.declared().validAt(at)) out.add(rk.key());
        return List.copyOf(out);
    }

    /** Whether a specific registered key of this principal may sign at {@code at}. */
    public boolean maySign(String principal, PublicKey key, Instant at) {
        for (RegisteredKey rk : byPrincipal.getOrDefault(principal, List.of()))
            if (rk.key().equals(key)) return rk.declared().validAt(at);
        return false;
    }

    /** The declared lines for a principal, in file order — what {@code rotate-key} re-emits. */
    public List<AuthorizedKey> declaredFor(String principal) {
        List<AuthorizedKey> out = new ArrayList<>();
        for (RegisteredKey rk : byPrincipal.getOrDefault(principal, List.of())) out.add(rk.declared());
        return List.copyOf(out);
    }

    public static AuthorizedKeys load(Path registryRoot) {
        Path f = registryRoot.resolve("identity").resolve("authorized-keys.jsonl");
        if (!Files.isRegularFile(f)) return new AuthorizedKeys(Map.of());
        ObjectMapper mapper = JsonMapperFactory.create();
        Map<String, List<RegisteredKey>> keys = new HashMap<>();
        Map<String, Set<String>> seenB64 = new HashMap<>();
        try {
            for (String line : Files.readAllLines(f)) {
                if (line.isBlank()) continue;
                AuthorizedKey ak;
                try {
                    ak = mapper.readValue(line, AuthorizedKey.class);
                } catch (com.fasterxml.jackson.databind.JsonMappingException bad) {
                    // a bad field value (e.g. an unparseable instant) — coded, fail-closed
                    throw new IllegalStateException("identity.authorized-keys.bad-line: " + f, bad);
                }
                // An identical duplicate is tolerated and collapsed; a DIFFERENT key is a rotation.
                if (!seenB64.computeIfAbsent(ak.principal(), k -> new HashSet<>()).add(ak.publicKey())) continue;
                PublicKey decoded;
                try {
                    decoded = Ed25519Keys.publicKey(ak.publicKey());
                } catch (IllegalArgumentException badKey) {
                    throw new IllegalStateException("identity.authorized-keys.bad-public-key: "
                            + ak.principal(), badKey);
                }
                keys.computeIfAbsent(ak.principal(), k -> new ArrayList<>()).add(new RegisteredKey(decoded, ak));
            }
        } catch (IOException e) {
            throw new IllegalStateException("identity.authorized-keys.read-error: " + f, e);
        }
        Map<String, List<RegisteredKey>> frozen = new HashMap<>();
        keys.forEach((p, l) -> frozen.put(p, List.copyOf(l)));
        return new AuthorizedKeys(Map.copyOf(frozen));
    }
}
