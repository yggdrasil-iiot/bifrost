# Bifrost published-canonical provenance manifest

This document describes the manifest emitted when a canonical (a "recipe" or other
publishable artifact) is published into the Bifrost registry, and the hashing scheme any
consumer — regardless of language — must reimplement to independently verify it. It
documents what the current Java implementation (`RecipeManifest` / `RecipePublish` /
`RecipeDefinitionStore` in `dev.krillin.bifrost.core.schema`) actually does; it is not an
aspirational spec.

## On-disk layout

The publish path writes into a registry directory:

```
<registryRoot>/recipe/<ref>/<version>/
  recipe-setpoints.yaml   # the materialized canonical bytes, exactly as committed
  manifest.json           # the RecipeManifest below, pretty-printed
```

Versions are immutable: publishing the same `<ref>/<version>` again with different content
bytes is refused (the existing manifest's `contentSha256` is compared against the
newly-computed one).

## Manifest fields (`RecipeManifest`)

| field           | type   | meaning                                                                 |
|-----------------|--------|--------------------------------------------------------------------------|
| `kind`          | string | artifact kind discriminator, currently always `"recipe-setpoints"`       |
| `ref`           | string | logical name of the published thing, e.g. `"line1"`                      |
| `version`       | string | SemVer string `major.minor.patch` of this publication                    |
| `defRef`        | string | git commit SHA the canonical bytes were read from (provenance — see below) |
| `contentSha256` | string | SHA-256 of the materialized canonical bytes (operative, self-verifying reference — see below) |
| `sourcePath`    | string | path of the canonical file relative to the source repo it was published from |
| `publishedAt`   | number | publish timestamp, epoch milliseconds (`System.currentTimeMillis()`)     |

There is no separate `templateRef`/definition-id field distinct from `ref` — a recipe
canonical is identified by `(ref, version)`, and `kind` distinguishes artifact families.

## `defRef` — provenance

`defRef` is the git commit SHA (40 lowercase hex characters) of the most recent commit that
touched `sourcePath` in the source repository, at the moment of publish:

```
git log -1 --format=%H -- <sourcePath>
```

Publish refuses to run (exit 1) if `sourcePath` has uncommitted changes
(`git status --porcelain -- <sourcePath>` is non-blank) or if no commit touches it. `defRef`
is therefore always a real, resolvable commit — it answers "what commit produced this
publication," independent of the content hash below.

## `contentSha256` — the operative, self-verifying reference

This is the field a consumer should actually use to verify content integrity; it does not
require trusting the registry, the git history, or the network path — only recomputing a
hash over bytes you already have.

Algorithm, exactly as implemented (`RecipePublish.sha256hex`):

1. Read the raw committed blob bytes for `sourcePath` at commit `defRef`, i.e. the exact
   bytes git stores for that file at that commit — `git show <defRef>:<sourcePath>`. These
   are raw bytes, **not** charset-decoded/re-encoded text; do not normalize line endings,
   trim whitespace, or reinterpret the encoding before hashing.
2. Compute `SHA-256` over those raw bytes (`MessageDigest.getInstance("SHA-256").digest(bytes)`).
3. Render the digest as lowercase hexadecimal, two hex characters per byte, no separators,
   64 characters total (`String.format("%02x", b)` per byte, concatenated) — e.g.
   `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`.

Any-language reimplementation: read the file's bytes exactly as committed (e.g.
`git show <sha>:<path>` or an equivalent content-addressable read), SHA-256 those bytes, and
lowercase-hex-encode the digest. A consumer that recomputes this over the
`recipe-setpoints.yaml` bytes it received and compares it to `manifest.json`'s
`contentSha256` has verified the content independent of transport.

## Deliberately out of scope here

This document covers the recipe/canonical publish manifest only. It does not cover the UDT
definition (`definition.schema.json`), spec/recipe (`spec.schema.json`), or command-policy
(`policy.schema.json`) document formats, which are separate JSON-Schema specs alongside this file.
