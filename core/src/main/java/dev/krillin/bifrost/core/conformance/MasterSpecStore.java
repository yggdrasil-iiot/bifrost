package dev.krillin.bifrost.core.conformance;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import dev.krillin.bifrost.core.schema.MasterSpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Disk-based JSON access for governed {@link MasterSpec} (active recipe) artifacts, mirroring
 * {@link dev.krillin.bifrost.core.schema.DefinitionStore} and {@link ConformancePolicyStore}.
 * Path convention: {@code <registryDir>/spec/<ref>/<version>.json}. A missing file is not an
 * error (returns empty) — recipe-mode conformance only binds a recipe when one is registered.
 */
public final class MasterSpecStore {

    private final ObjectMapper mapper = JsonMapperFactory.create();

    /** Pure path of the pinned recipe artifact: {@code <registryDir>/spec/<ref>/<version>.json}. */
    public Path file(Path registryDir, String ref, String version) {
        return registryDir.resolve("spec").resolve(ref).resolve(version + ".json");
    }

    /** Loads the pinned recipe at spec/&lt;ref&gt;/&lt;version&gt;.json, or empty if that file does not exist. */
    public Optional<MasterSpec> load(Path registryDir, String ref, String version) throws IOException {
        Path file = file(registryDir, ref, version);
        if (!Files.isRegularFile(file)) return Optional.empty();
        return Optional.of(mapper.readValue(file.toFile(), MasterSpec.class));
    }
}
