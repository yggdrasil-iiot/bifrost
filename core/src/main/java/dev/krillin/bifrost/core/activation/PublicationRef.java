package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Which publication an activation bound: the raw SHA-256 of recipe/<ref>/<version>/manifest.json, the git commit
 *  the manifest names, and the raw SHA-256 of manifest.dsse.json (null for an unsigned publication). The manifest
 *  digest pins defRef and contentSha256 together, so a manifest swapped in later is caught at the edge. */
public record PublicationRef(String manifestSha256, String defRef,
                             @JsonInclude(JsonInclude.Include.NON_NULL) String attestationSha256) {}
