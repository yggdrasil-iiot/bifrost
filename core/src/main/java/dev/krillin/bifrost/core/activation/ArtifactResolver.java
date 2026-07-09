package dev.krillin.bifrost.core.activation;
import java.nio.file.Path;
import java.util.Optional;
/** Resolves a governed runtime artifact (kind,ref,version) to its on-disk bytes' identity. Empty ⇒
 *  unresolvable (absent or invalid) ⇒ activation refuses. Decouples ActivationService from any one store. */
public interface ArtifactResolver {
    Optional<ResolvedArtifact> resolve(String kind, String ref, String version);
    record ResolvedArtifact(Path path, String sha256) {}
}
