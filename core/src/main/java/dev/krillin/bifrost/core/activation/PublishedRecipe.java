package dev.krillin.bifrost.core.activation;

import dev.krillin.bifrost.core.schema.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.Optional;

/** A recipe published by `provenance publish` at recipe/<ref>/<version>/, as activation binds it. The files are read
 *  once into a {@link Snapshot}; every hash, signature check and parse runs over those bytes, so what is checked is
 *  what is bound. Activation kind "recipe" binds a manifest of kind {@value #MANIFEST_KIND} whose canonical is a
 *  MasterSpec naming the same ref and version — a published UDT or policy is not a recipe. The control plane
 *  ({@link RecipeArtifactResolver}) and the edge (Heimdall) both check through here. */
public final class PublishedRecipe {
    public static final String MANIFEST_KIND = "recipe-setpoints";
    private static final String CANONICAL = "recipe-setpoints.yaml", MANIFEST = "manifest.json";

    /** The raw bytes of one publication; envelope is null when the publication is unsigned. */
    public record Snapshot(Path canonical, byte[] canonicalBytes, byte[] manifestBytes, byte[] envelope) {
        public PublicationRef ref(RecipeManifest m) {
            return new PublicationRef(Sha256.hex(manifestBytes), m.defRef(), envelope == null ? null : Sha256.hex(envelope));
        }
    }

    /** A checked publication: the bytes to bind, their hash, the MasterSpec they parse to, and the reference to record. */
    public record Checked(Path canonical, String sha256, MasterSpec spec, PublicationRef publication) {}

    private PublishedRecipe() {}

    /** Empty when nothing is published for ref@version; a half-written version (one of the two files) is refused. */
    public static Optional<Snapshot> read(Path registry, String ref, String version) throws IOException {
        Path dir = registry.resolve("recipe").resolve(ref).resolve(version);
        Path canonical = dir.resolve(CANONICAL), manifest = dir.resolve(MANIFEST), envelope = dir.resolve(RecipeAttestation.FILE);
        boolean hasCanonical = Files.isRegularFile(canonical), hasManifest = Files.isRegularFile(manifest);
        if (!hasCanonical && !hasManifest) return Optional.empty();
        if (!hasCanonical || !hasManifest)
            throw new ArtifactResolver.Unresolvable("activation.publication.incomplete",
                    "recipe/" + ref + "/" + version + " has " + (hasCanonical ? CANONICAL : MANIFEST) + " but not "
                            + (hasCanonical ? MANIFEST : CANONICAL));
        return Optional.of(new Snapshot(canonical, Files.readAllBytes(canonical), Files.readAllBytes(manifest),
                Files.isRegularFile(envelope) ? Files.readAllBytes(envelope) : null));
    }

    /** Checks one snapshot: the manifest names this ref, version and kind and hashes the canonical; a present
     *  envelope verifies (a broken one refuses even an unsigned activation); the canonical is a MasterSpec for this
     *  ref and version. Throws {@link ArtifactResolver.Unresolvable} naming the first failure. */
    public static Checked check(Path registry, String ref, String version, Snapshot s) {
        RecipeManifest m;
        try { m = JsonMapperFactory.create().readValue(s.manifestBytes(), RecipeManifest.class); }
        catch (IOException e) { throw refuse("activation.publication.manifest-invalid", "manifest.json does not parse: " + e.getMessage()); }
        if (m.contentSha256() == null || m.defRef() == null)
            throw refuse("activation.publication.manifest-invalid", "manifest.json lacks contentSha256 or defRef");
        if (!ref.equals(m.ref()) || !version.equals(m.version()))
            throw refuse("activation.publication.manifest-mismatch",
                    "manifest.json names " + m.ref() + "@" + m.version() + ", not " + ref + "@" + version);
        if (!MANIFEST_KIND.equals(m.kind()))
            throw refuse("activation.publication.kind-mismatch",
                    "manifest kind " + m.kind() + " is not activatable as a recipe (needs " + MANIFEST_KIND + ")");
        String sha = Sha256.hex(s.canonicalBytes());
        if (!sha.equals(m.contentSha256()))
            throw refuse("activation.publication.content-mismatch"
                    + (LineEndings.explainMismatch(s.canonicalBytes(), m.contentSha256()) ? ":line-endings" : ""),
                    CANONICAL + " sha " + sha + " != manifest contentSha256 " + m.contentSha256());
        if (s.envelope() != null) {
            try { RecipeAttestation.verify(registry, ref, version, s.canonicalBytes(), s.manifestBytes(), s.envelope()); }
            catch (RecipeAttestation.Refused e) { throw refuse("activation.publication.attestation:" + e.getMessage(), "manifest.dsse.json does not verify"); }
            catch (IOException e) { throw refuse("activation.publication.attestation:recipe.unreadable", e.getMessage()); }
        }
        MasterSpec spec;
        try { spec = JsonMapperFactory.create().readValue(s.canonicalBytes(), MasterSpec.class); }
        catch (IOException e) { throw refuse("activation.artifact.unresolved", CANONICAL + " is not a MasterSpec: " + e.getMessage()); }
        if (!ref.equals(spec.specRef()) || !version.equals(spec.version()))
            throw refuse("activation.publication.spec-identity",
                    "MasterSpec names " + spec.specRef() + "@" + spec.version() + ", not " + ref + "@" + version);
        return new Checked(s.canonical(), sha, spec, s.ref(m));
    }

    private static ArtifactResolver.Unresolvable refuse(String rule, String detail) {
        return new ArtifactResolver.Unresolvable(rule, detail);
    }
}
