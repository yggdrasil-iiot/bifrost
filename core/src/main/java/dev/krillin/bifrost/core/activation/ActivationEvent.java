package dev.krillin.bifrost.core.activation;
/** One immutable, audited activation act. Appended verbatim as a JSONL line to the ledger.
 *  contentSha256 = sha256 of the exact runtime bytes activated (spec/<ref>/<version>.json) — the
 *  four-eyes-attested seal the edge re-checks. action = ACTIVATE | ROLLBACK. */
public record ActivationEvent(String target, String kind, String ref, String version,
                              String contentSha256, String activatedBy, String approvedBy,
                              long activatedAt, String priorVersion, String action) {}
