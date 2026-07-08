package dev.krillin.bifrost.core.schema;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DefinitionStoreTest {

    private void write(Path file, UdtDefinition def) throws Exception {
        Files.createDirectories(file.getParent());
        JsonMapperFactory.create().writeValue(file.toFile(), def);
    }

    @Test void latest_picksHighestSemVer(@TempDir Path root) throws Exception {
        UdtDefinition v100 = new UdtDefinition("Motor", SemVer.parse("1.0.0"), List.of(new Member("Rpm","Double")), List.of());
        UdtDefinition v110 = new UdtDefinition("Motor", SemVer.parse("1.10.0"), List.of(new Member("Rpm","Double")), List.of());
        UdtDefinition v19  = new UdtDefinition("Motor", SemVer.parse("1.9.0"),  List.of(new Member("Rpm","Double")), List.of());
        write(root.resolve("udt/Motor/1.0.0.json"), v100);
        write(root.resolve("udt/Motor/1.10.0.json"), v110);
        write(root.resolve("udt/Motor/1.9.0.json"), v19);

        DefinitionStore store = new DefinitionStore(root);
        Optional<UdtDefinition> latest = store.latest("Motor");
        assertTrue(latest.isPresent());
        assertEquals(SemVer.parse("1.10.0"), latest.get().version());
    }

    @Test void latest_emptyForUnknownRef(@TempDir Path root) throws Exception {
        assertTrue(new DefinitionStore(root).latest("Nope").isEmpty());
    }

    @Test void promote_writesVersionedFile(@TempDir Path root) throws Exception {
        DefinitionStore store = new DefinitionStore(root);
        UdtDefinition def = new UdtDefinition("Motor2", SemVer.parse("2.0.0"), List.of(new Member("Rpm","Double")), List.of());
        store.promote(def);
        Path expected = root.resolve("udt/Motor2/2.0.0.json");
        assertTrue(Files.exists(expected));
        assertEquals(def, store.latest("Motor2").orElseThrow());
    }

    @Test void policyMode_readsPolicyJson(@TempDir Path root) throws Exception {
        Files.writeString(root.resolve("policy.json"), "{\"mode\":\"FORWARD\"}");
        assertEquals(CompatMode.FORWARD, new DefinitionStore(root).policyMode());
    }

    @Test void policyMode_failsClosedWhenMissing(@TempDir Path root) {
        assertThrows(java.io.IOException.class, () -> new DefinitionStore(root).policyMode());
    }

    @Test void load_readsDefinitionFile(@TempDir Path root) throws Exception {
        UdtDefinition def = new UdtDefinition("Motor", SemVer.parse("1.0.0"), List.of(new Member("Rpm","Double")), List.of());
        Path f = root.resolve("proposed.json");
        write(f, def);
        assertEquals(def, new DefinitionStore(root).load(f));
    }
}
