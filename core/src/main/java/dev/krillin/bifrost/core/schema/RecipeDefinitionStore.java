package dev.krillin.bifrost.core.schema;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.*;
import java.util.Comparator;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Disk registry for versioned recipe canonicals, rooted at a caller-supplied dir:
 * registry/recipe/<ref>/<version>/{recipe-setpoints.yaml, manifest.json}. The registry is the
 * source of truth (peer to udt/policy in DefinitionStore). Versions are IMMUTABLE — publish refuses to
 * overwrite an existing version with different bytes.
 */
public final class RecipeDefinitionStore {

    private final Path root;
    private final ObjectMapper mapper = JsonMapperFactory.create();

    public RecipeDefinitionStore(Path root) { this.root = root; }

    public record Resolved(Path canonicalPath, RecipeManifest manifest) {}

    public RecipeManifest publish(String kind, String ref, String version, byte[] contentBytes,
                                  String defRef, String contentSha256, String sourcePath, long atMillis) throws IOException {
        Path dir = root.resolve("recipe").resolve(ref).resolve(version);
        Path manifestFile = dir.resolve("manifest.json");
        if (Files.exists(manifestFile)) {
            RecipeManifest existing = mapper.readValue(manifestFile.toFile(), RecipeManifest.class);
            if (!existing.contentSha256().equals(contentSha256))
                throw new IOException("recipe " + ref + "/" + version + " already published with different content (immutable — bump version)");
            return existing;
        }
        Files.createDirectories(dir);
        // SKELETON WART: this store is recipe-shaped throughout — the on-disk path is registry/recipe/<ref>/…,
        // the canonical file is always named recipe-setpoints.yaml (here and in resolveUnchecked), and the
        // RecipePublish log line says "recipe". Only the manifest's `kind` field distinguishes a master-spec
        // artifact. Acceptable for the skeleton; a real master-spec store (Chunk 4/5) must generalize path +
        // filename + naming, not just this line.
        Files.write(dir.resolve("recipe-setpoints.yaml"), contentBytes);
        RecipeManifest m = new RecipeManifest(kind, ref, version, defRef, contentSha256, sourcePath, atMillis);
        mapper.writerWithDefaultPrettyPrinter().writeValue(manifestFile.toFile(), m);
        return m;
    }

    public Optional<Resolved> latest(String ref) throws IOException {
        Path dir = root.resolve("recipe").resolve(ref);
        if (!Files.isDirectory(dir)) return Optional.empty();
        try (Stream<Path> versions = Files.list(dir)) {
            return versions.filter(Files::isDirectory)
                    .max(Comparator.comparing(p -> SemVer.parse(p.getFileName().toString())))
                    .map(this::resolveUnchecked);
        }
    }

    private Resolved resolveUnchecked(Path vdir) {
        try {
            Path canonical = vdir.resolve("recipe-setpoints.yaml");
            if (!Files.exists(canonical)) throw new IOException("canonical missing in " + vdir);
            RecipeManifest m = mapper.readValue(vdir.resolve("manifest.json").toFile(), RecipeManifest.class);
            return new Resolved(canonical, m);
        } catch (IOException e) { throw new RuntimeException(e); }
    }
}
