package dev.krillin.bifrost.core.schema;

/** The version reference minted for a published recipe canonical. contentSha256 is the operative
 *  self-verifying reference (sha256 of the materialized blob bytes); defRef is git-commit provenance. */
public record RecipeManifest(
        String kind,            // "recipe-setpoints"
        String ref,             // e.g. "line1"
        String version,         // SemVer string, e.g. "1.0.0"
        String defRef,          // git commit SHA (provenance)
        String contentSha256,   // sha256 of the materialized canonical bytes (operative ref)
        String sourcePath,      // path within the source repo
        long publishedAt) {}
