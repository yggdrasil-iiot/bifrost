package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.CompatMode;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import dev.krillin.bifrost.core.schema.Member;
import dev.krillin.bifrost.core.schema.SemVer;
import dev.krillin.bifrost.core.schema.UdtDefinition;
import java.nio.file.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SchemaGateTest {

    private final ObjectMapper mapper = JsonMapperFactory.create();

    private void seed(Path root, CompatMode mode, UdtDefinition... defs) throws Exception {
        Files.createDirectories(root);
        Files.writeString(root.resolve("policy.json"), "{\"mode\":\"" + mode + "\"}");
        for (UdtDefinition d : defs) {
            Path dir = root.resolve("udt").resolve(d.templateRef());
            Files.createDirectories(dir);
            mapper.writeValue(dir.resolve(d.version() + ".json").toFile(), d);
        }
    }

    private Path proposal(Path root, UdtDefinition def) throws Exception {
        Path f = root.resolve("proposed-" + def.version() + ".json");
        mapper.writeValue(f.toFile(), def);
        return f;
    }

    private final List<Member> v1 = List.of(new Member("Rpm","Double"), new Member("Running","Boolean"));

    @Test void compatibleChange_returnsZero(@TempDir Path root) throws Exception {
        seed(root, CompatMode.FORWARD, new UdtDefinition("Motor", SemVer.parse("1.0.0"), v1, List.of()));
        UdtDefinition add = new UdtDefinition("Motor", SemVer.parse("1.1.0"),
                List.of(new Member("Rpm","Double"), new Member("Running","Boolean"), new Member("Temperature","Double")), List.of());
        int code = SchemaGate.run(new String[]{ root.toString(), proposal(root, add).toString() });
        assertEquals(0, code);
    }

    @Test void breakingChange_returnsOne(@TempDir Path root) throws Exception {
        seed(root, CompatMode.FORWARD, new UdtDefinition("Motor", SemVer.parse("1.0.0"), v1, List.of()));
        UdtDefinition remove = new UdtDefinition("Motor", SemVer.parse("1.1.0"),
                List.of(new Member("Rpm","Double")), List.of());
        int code = SchemaGate.run(new String[]{ root.toString(), proposal(root, remove).toString() });
        assertEquals(1, code);
    }

    @Test void newTemplateRef_returnsZeroAsInitialRegistration(@TempDir Path root) throws Exception {
        seed(root, CompatMode.FORWARD, new UdtDefinition("Motor", SemVer.parse("1.0.0"), v1, List.of()));
        UdtDefinition motor2 = new UdtDefinition("Motor2", SemVer.parse("2.0.0"),
                List.of(new Member("Rpm","Double")), List.of());
        int code = SchemaGate.run(new String[]{ root.toString(), proposal(root, motor2).toString() });
        assertEquals(0, code);
    }

    @Test void missingPolicy_returnsTwoFailClosed(@TempDir Path root) throws Exception {
        Path dir = root.resolve("udt/Motor"); Files.createDirectories(dir);
        mapper.writeValue(dir.resolve("1.0.0.json").toFile(),
                new UdtDefinition("Motor", SemVer.parse("1.0.0"), v1, List.of()));
        UdtDefinition add = new UdtDefinition("Motor", SemVer.parse("1.1.0"),
                List.of(new Member("Rpm","Double"), new Member("Running","Boolean"), new Member("X","Double")), List.of());
        int code = SchemaGate.run(new String[]{ root.toString(), proposal(root, add).toString() });
        assertEquals(2, code);
    }

    @Test void badArgs_returnsTwo(@TempDir Path root) {
        assertEquals(2, SchemaGate.run(new String[]{ root.toString() }));
    }

    @Test void promoteFlag_writesToRegistry(@TempDir Path root) throws Exception {
        seed(root, CompatMode.FORWARD, new UdtDefinition("Motor", SemVer.parse("1.0.0"), v1, List.of()));
        UdtDefinition add = new UdtDefinition("Motor", SemVer.parse("1.1.0"),
                List.of(new Member("Rpm","Double"), new Member("Running","Boolean"), new Member("Temperature","Double")), List.of());
        int code = SchemaGate.run(new String[]{ root.toString(), proposal(root, add).toString(), "--promote" });
        assertEquals(0, code);
        assertTrue(Files.exists(root.resolve("udt/Motor/1.1.0.json")));
    }
}
