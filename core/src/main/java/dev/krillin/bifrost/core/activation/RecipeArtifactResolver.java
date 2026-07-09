package dev.krillin.bifrost.core.activation;
import dev.krillin.bifrost.core.conformance.MasterSpecStore;
import java.nio.file.*;
import java.util.Optional;
/** recipe kind → the runtime MasterSpec at spec/<ref>/<version>.json (the store Heimdall actually binds).
 *  Refuses (empty) if the file is absent or does not parse as a MasterSpec; else returns path + sha256 of
 *  the exact file bytes. Non-recipe kinds are not yet resolvable (return empty — honest, recipe is demoed). */
public final class RecipeArtifactResolver implements ArtifactResolver {
    private final Path registryDir;
    private final MasterSpecStore store = new MasterSpecStore();
    public RecipeArtifactResolver(Path registryDir) { this.registryDir = registryDir; }

    public Optional<ResolvedArtifact> resolve(String kind, String ref, String version) {
        if (!"recipe".equals(kind)) return Optional.empty();
        try {
            Path f = store.file(registryDir, ref, version);
            if (!Files.isRegularFile(f)) return Optional.empty();
            if (store.load(registryDir, ref, version).isEmpty()) return Optional.empty(); // parse-validate
            return Optional.of(new ResolvedArtifact(f, Sha256.hex(Files.readAllBytes(f))));
        } catch (Exception e) { return Optional.empty(); }   // invalid/unreadable ⇒ unresolvable (fail-closed)
    }
}
