package dev.krillin.bifrost.core.activation;
import dev.krillin.bifrost.core.conformance.MasterSpecStore;
import java.nio.file.*;
import java.util.Optional;
/** recipe kind → the published canonical at recipe/<ref>/<version>/recipe-setpoints.yaml, checked through
 *  {@link PublishedRecipe} (manifest, kind, content hash, envelope if present, MasterSpec for this ref@version).
 *  Returns path + sha256 of the exact canonical bytes and the publication they came from. A spec/<ref>/<version>.json
 *  with no publication is refused as activation.publication.missing: it is the file Heimdall bound before
 *  activation named a publication, and it is no longer activatable on its own. Nothing at all ⇒ empty.
 *  Non-recipe kinds are not yet resolvable (empty — honest, recipe is demoed). */
public final class RecipeArtifactResolver implements ArtifactResolver {
    private final Path registryDir;
    public RecipeArtifactResolver(Path registryDir) { this.registryDir = registryDir; }

    public Optional<ResolvedArtifact> resolve(String kind, String ref, String version) {
        if (!"recipe".equals(kind)) return Optional.empty();
        Optional<PublishedRecipe.Snapshot> snapshot;
        try { snapshot = PublishedRecipe.read(registryDir, ref, version); }
        catch (java.io.IOException e) { return Optional.empty(); }   // unreadable ⇒ unresolvable (fail-closed)
        if (snapshot.isPresent()) {
            PublishedRecipe.Checked c = PublishedRecipe.check(registryDir, ref, version, snapshot.get());
            return Optional.of(new ResolvedArtifact(c.canonical(), c.sha256(), c.publication()));
        }
        if (Files.isRegularFile(new MasterSpecStore().file(registryDir, ref, version)))
            throw new Unresolvable("activation.publication.missing", "spec/" + ref + "/" + version
                    + ".json exists but recipe/" + ref + "/" + version + " is not published - run provenance publish");
        return Optional.empty();
    }
}
