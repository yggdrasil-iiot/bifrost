package dev.krillin.bifrost.core.identity;

/** One line of registry/identity/authorized-keys.jsonl: a principal and its X.509-b64 Ed25519 public key. */
public record AuthorizedKey(String principal, String publicKey) {}
