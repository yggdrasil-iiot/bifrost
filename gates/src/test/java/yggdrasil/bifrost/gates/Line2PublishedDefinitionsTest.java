package yggdrasil.bifrost.gates;

import yggdrasil.bifrost.core.schema.DefinitionStore;
import yggdrasil.bifrost.core.schema.Member;
import yggdrasil.bifrost.core.schema.RecipeDefinitionStore;
import yggdrasil.bifrost.core.schema.RecipeManifest;
import yggdrasil.bifrost.core.schema.UdtDefinition;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The committed Line2 provenance pairs (scripts/fixtures/line2/published, written by
 * scripts/publish-line2-definitions.sh from Mimir's candidates) verify, carry the expected members,
 * and are refused after a one-byte tamper.
 */
class Line2PublishedDefinitionsTest {

    static final Path PUBLISHED = Path.of("../scripts/fixtures/line2/published");

    static final Map<String, Map<String, String>> EXPECTED = Map.of(
            "station-model", ordered("Running", "Boolean", "UnitId", "String", "VisitId", "String", "VisitPresent", "Boolean"),
            "tool-model", ordered("Torque", "Double", "Running", "Boolean", "UnitId", "String", "VisitId", "String",
                    "VisitPresent", "Boolean"));

    private static Map<String, String> ordered(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    private static String sha256hex(byte[] b) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(b);
        StringBuilder s = new StringBuilder();
        for (byte x : d) s.append(String.format("%02x", x));
        return s.toString();
    }

    @ParameterizedTest
    @ValueSource(strings = {"station-model", "tool-model"})
    void committedPairVerifiesAndCarriesTheExpectedMembers(String ref) throws Exception {
        assertEquals(0, ProvenancePublish.run(new String[]{"verify", PUBLISHED.toString(), ref}));

        RecipeDefinitionStore.Resolved r = new RecipeDefinitionStore(PUBLISHED).latest(ref).orElseThrow();
        RecipeManifest m = r.manifest();
        byte[] canonical = Files.readAllBytes(r.canonicalPath());
        assertEquals(sha256hex(canonical), m.contentSha256());
        assertEquals("recipe-setpoints", m.kind());
        assertEquals(ref, m.ref());
        assertEquals("1.0.0", m.version());
        assertEquals("fixtures/line2/" + ref + "-1.0.0.json", m.sourcePath());
        assertTrue(m.defRef().matches("[0-9a-f]{40}"), m.defRef());

        UdtDefinition def = new DefinitionStore(PUBLISHED).load(r.canonicalPath());
        assertEquals(ref, def.templateRef());
        assertEquals("1.0.0", def.version().toString());
        assertTrue(def.params().isEmpty());
        Map<String, String> actual = new LinkedHashMap<>();
        for (Member mem : def.members()) assertNull(actual.put(mem.name(), mem.type()), "duplicate member " + mem.name());
        assertEquals(EXPECTED.get(ref), actual);
    }

    @ParameterizedTest
    @ValueSource(strings = {"station-model", "tool-model"})
    void oneByteTamperIsRefused(String ref, @TempDir Path tmp) throws Exception {
        Path copy = tmp.resolve("published");
        try (Stream<Path> files = Files.walk(PUBLISHED)) {
            for (Path p : (Iterable<Path>) files::iterator) {
                Path target = copy.resolve(PUBLISHED.relativize(p).toString());
                if (Files.isDirectory(p)) Files.createDirectories(target); else Files.copy(p, target);
            }
        }
        assertEquals(0, ProvenancePublish.run(new String[]{"verify", copy.toString(), ref}));

        Path canonical = copy.resolve("recipe").resolve(ref).resolve("1.0.0").resolve("recipe-setpoints.yaml");
        byte[] bytes = Files.readAllBytes(canonical);
        bytes[bytes.length / 2] ^= 0x01;
        Files.write(canonical, bytes);
        assertEquals(1, ProvenancePublish.run(new String[]{"verify", copy.toString(), ref}));
    }
}
