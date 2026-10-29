package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.annotation.JsonInclude;

/** One immutable, audited activation act. Appended verbatim as a JSONL line to the ledger.
 *  contentSha256 = sha256 of the exact runtime bytes activated (the published canonical
 *  recipe/<ref>/<version>/recipe-setpoints.yaml; spec/<ref>/<version>.json on entries written before an activation
 *  named its publication) — the four-eyes-attested seal the edge re-checks. action = ACTIVATE | ROLLBACK.
 *  publication names the publication those bytes came from; it is null on older entries and then omitted, so an
 *  older line is read and re-hashed exactly as it was written. */
public record ActivationEvent(String target, String kind, String ref, String version,
                              String contentSha256, String activatedBy, String approvedBy,
                              long activatedAt, String priorVersion, String action,
                              @JsonInclude(JsonInclude.Include.NON_NULL) PublicationRef publication) {

    /** An event with no publication: the shape of every entry written before activation named one. */
    public ActivationEvent(String target, String kind, String ref, String version, String contentSha256,
                           String activatedBy, String approvedBy, long activatedAt, String priorVersion, String action) {
        this(target, kind, ref, version, contentSha256, activatedBy, approvedBy, activatedAt, priorVersion, action, null);
    }
}
