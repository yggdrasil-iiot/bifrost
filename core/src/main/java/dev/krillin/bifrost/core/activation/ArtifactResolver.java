package dev.krillin.bifrost.core.activation;
import java.nio.file.Path;
import java.util.Optional;
/** Resolves a governed runtime artifact (kind,ref,version) to its on-disk bytes' identity. Empty ⇒
 *  unresolvable (absent or invalid) ⇒ activation refuses. A resolver that knows why it cannot resolve throws
 *  {@link Unresolvable} with its own rule instead. Decouples ActivationService from any one store. */
public interface ArtifactResolver {
    Optional<ResolvedArtifact> resolve(String kind, String ref, String version);

    /** publication is the publication the bytes came from, or null for an artifact that has none. */
    record ResolvedArtifact(Path path, String sha256, PublicationRef publication) {
        public ResolvedArtifact(Path path, String sha256) { this(path, sha256, null); }
    }

    /** A coded refusal: activation is refused with this rule instead of activation.artifact.unresolved. */
    final class Unresolvable extends RuntimeException {
        private final String rule;
        public Unresolvable(String rule, String detail) { super(detail); this.rule = rule; }
        public String rule() { return rule; }
    }
}
