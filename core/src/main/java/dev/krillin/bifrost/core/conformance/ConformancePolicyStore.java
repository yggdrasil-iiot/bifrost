package dev.krillin.bifrost.core.conformance;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Disk-based JSON access for governed {@link ConformancePolicy} artifacts, mirroring
 * {@link dev.krillin.bifrost.core.schema.DefinitionStore}. Path convention:
 * {@code <registryDir>/conformance/<ref>/<version>.json}. A missing file is not an error
 * (returns empty) — the evaluator graceful-degrades to structural+type+envelope when no policy exists.
 */
public final class ConformancePolicyStore {

    private final ObjectMapper mapper = JsonMapperFactory.create();

    /** Loads the pinned policy at conformance/&lt;ref&gt;/&lt;version&gt;.json, or empty if that file does not exist. */
    public Optional<ConformancePolicy> loadFor(Path registryDir, String ref, String version) throws IOException {
        Path file = registryDir.resolve("conformance").resolve(ref).resolve(version + ".json");
        if (!Files.isRegularFile(file)) return Optional.empty();
        return Optional.of(mapper.readValue(file.toFile(), ConformancePolicy.class));
    }
}
