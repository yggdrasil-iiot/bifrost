package dev.krillin.bifrost.core.conformance;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import dev.krillin.bifrost.core.schema.MasterSpec;
import dev.krillin.bifrost.core.schema.Setpoint;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MasterSpecStoreTest {

    private final MasterSpecStore store = new MasterSpecStore();
    private final ObjectMapper mapper = JsonMapperFactory.create();

    private MasterSpec spec() {
        return new MasterSpec("Mix-Recipe", "1.0.0", "Busan", "Line1-Mixer", "1.0.0",
                List.of(new Setpoint("Rpm", "Double", 1500)));
    }

    @Test void presentFile_loadsSpec(@TempDir Path registryDir) throws Exception {
        Path dir = registryDir.resolve("spec").resolve("Mix-Recipe");
        Files.createDirectories(dir);
        mapper.writeValue(dir.resolve("1.0.0.json").toFile(), spec());

        Optional<MasterSpec> loaded = store.load(registryDir, "Mix-Recipe", "1.0.0");
        assertTrue(loaded.isPresent());
        assertEquals("Mix-Recipe", loaded.get().specRef());
        assertEquals("Line1-Mixer", loaded.get().equipmentRef());
        assertEquals(1, loaded.get().setpoints().size());
    }

    @Test void absentFile_returnsEmpty(@TempDir Path registryDir) throws Exception {
        assertTrue(store.load(registryDir, "Mix-Recipe", "1.0.0").isEmpty());
    }
}
