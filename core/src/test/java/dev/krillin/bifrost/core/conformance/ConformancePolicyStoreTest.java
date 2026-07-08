package dev.krillin.bifrost.core.conformance;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConformancePolicyStoreTest {

    private final ConformancePolicyStore store = new ConformancePolicyStore();
    private final ObjectMapper mapper = JsonMapperFactory.create();

    private ConformancePolicy policy() {
        return new ConformancePolicy("WeldPolicy", "1.0.0", "Weld-Controller", "1.0.0",
                new ConformancePolicy.Dial("envelope", null, null, null),
                List.of(new CrossConstraint("weld-lobe", "ElectrodeForce", "lt", 3.0, "WeldCurrent", "le", 8.0)),
                List.of());
    }

    @Test void presentFile_loadsPolicy(@TempDir Path registryDir) throws Exception {
        Path dir = registryDir.resolve("conformance").resolve("Weld-Controller");
        Files.createDirectories(dir);
        mapper.writeValue(dir.resolve("1.0.0.json").toFile(), policy());

        Optional<ConformancePolicy> loaded = store.loadFor(registryDir, "Weld-Controller", "1.0.0");
        assertTrue(loaded.isPresent());
        assertEquals("WeldPolicy", loaded.get().policyRef());
        assertEquals(1, loaded.get().crossConstraints().size());
        assertEquals("weld-lobe", loaded.get().crossConstraints().get(0).id());
    }

    @Test void absentFile_returnsEmpty(@TempDir Path registryDir) throws Exception {
        assertTrue(store.loadFor(registryDir, "Weld-Controller", "1.0.0").isEmpty());
    }
}
