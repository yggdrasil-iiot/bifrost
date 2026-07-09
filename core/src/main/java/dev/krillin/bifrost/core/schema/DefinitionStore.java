package dev.krillin.bifrost.core.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.*;
import java.util.Comparator;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Disk-based JSON registry access rooted at a caller-supplied directory
 * (default layout: registry/policy.json + registry/udt/&lt;ref&gt;/&lt;version&gt;.json).
 * The registry is the source of truth. NBIRTH _types_ is only wire truth (ADR-0005).
 */
public final class DefinitionStore {

    private final Path root;
    private final ObjectMapper mapper = JsonMapperFactory.create();

    public DefinitionStore(Path root) { this.root = root; }

    /** Returns the latest (highest SemVer) registered definition for a templateRef, or empty if none exists. */
    public Optional<UdtDefinition> latest(String templateRef) throws IOException {
        Path dir = root.resolve("udt").resolve(templateRef);
        if (!Files.isDirectory(dir)) return Optional.empty();
        try (Stream<Path> files = Files.list(dir)) {
            return files
                    .filter(p -> p.getFileName().toString().endsWith(".json"))
                    .map(this::loadUnchecked)
                    .max(Comparator.comparing(UdtDefinition::version));
        }
    }

    /** Promotes a definition by writing it to udt/&lt;ref&gt;/&lt;version&gt;.json. */
    public void promote(UdtDefinition def) throws IOException {
        Path dir = root.resolve("udt").resolve(def.templateRef());
        Files.createDirectories(dir);
        Path file = dir.resolve(def.version().toString() + ".json");
        mapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), def);
    }

    public UdtDefinition load(Path file) throws IOException {
        return mapper.readValue(file.toFile(), UdtDefinition.class);
    }

    /** Loads the pinned definition at udt/&lt;ref&gt;/&lt;version&gt;.json, or empty if that file does not exist. */
    public Optional<UdtDefinition> load(String templateRef, String version) throws IOException {
        Path file = root.resolve("udt").resolve(templateRef).resolve(version + ".json");
        if (!Files.isRegularFile(file)) return Optional.empty();
        return Optional.of(load(file));
    }

    /** Returns the compatibility mode from policy.json. Throws IOException (fail-closed) if the file is absent or unparseable. */
    public CompatMode policyMode() throws IOException {
        Path p = root.resolve("policy.json");
        if (!Files.exists(p)) throw new IOException("policy.json not found (fail-closed): " + p);
        JsonNode node = mapper.readTree(p.toFile());
        JsonNode mode = node.get("mode");
        if (mode == null) throw new IOException("policy.json missing 'mode' field: " + p);
        return CompatMode.valueOf(mode.asText());
    }

    private UdtDefinition loadUnchecked(Path file) {
        try { return load(file); } catch (IOException e) { throw new RuntimeException(e); }
    }
}
