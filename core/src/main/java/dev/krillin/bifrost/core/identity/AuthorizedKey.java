package dev.krillin.bifrost.core.identity;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * One line of registry/identity/authorized-keys.jsonl: a principal, its X.509-b64 Ed25519 public key,
 * and an optional validity window.
 *
 * <p>Both bounds are nullable and a null bound is unbounded, which is exactly the shape of every
 * registry written before rotation existed — such a line parses and behaves as it always did.
 *
 * <p><b>The window restricts signing, not verification.</b> A ledger entry carries no key id and its
 * timestamp is self-asserted, so the window cannot be used to decide which key was valid when an
 * entry was written. Retiring a key therefore stops it signing anything new and leaves the history
 * it already signed verifiable — which is what lets a key be retired at all, given that deleting its
 * line breaks every entry it ever signed.
 */
public record AuthorizedKey(String principal, String publicKey,
                            @JsonInclude(JsonInclude.Include.NON_NULL) Instant notBefore,
                            @JsonInclude(JsonInclude.Include.NON_NULL) Instant notAfter) {

    /** The pre-rotation shape: an unbounded key. */
    public AuthorizedKey(String principal, String publicKey) {
        this(principal, publicKey, null, null);
    }

    /** notBefore is inclusive, notAfter exclusive. */
    public boolean validAt(Instant t) {
        return (notBefore == null || !t.isBefore(notBefore))
            && (notAfter == null || t.isBefore(notAfter));
    }
}
