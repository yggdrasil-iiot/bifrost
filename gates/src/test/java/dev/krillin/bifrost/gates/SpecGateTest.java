package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import dev.krillin.bifrost.core.schema.MasterSpec;
import dev.krillin.bifrost.core.schema.Member;
import dev.krillin.bifrost.core.schema.Range;
import dev.krillin.bifrost.core.schema.SemVer;
import dev.krillin.bifrost.core.schema.Setpoint;
import dev.krillin.bifrost.core.schema.UdtDefinition;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SpecGateTest {

    private final ObjectMapper mapper = JsonMapperFactory.create();

    /** Seeds a Mixer equipment def at {@code <root>/udt/Line1-Mixer/1.0.0.json}. */
    private void seedMixer(Path root) throws Exception {
        UdtDefinition mixer = new UdtDefinition("Line1-Mixer", SemVer.parse("1.0.0"),
                List.of(
                        new Member("Rpm", "Double", null, new Range(0, 3000)),
                        new Member("Temp", "Double", null, new Range(0, 450)),
                        new Member("Running", "Boolean", null, null)),
                List.of(), null);
        Path dir = root.resolve("udt").resolve(mixer.templateRef());
        Files.createDirectories(dir);
        mapper.writeValue(dir.resolve(mixer.version() + ".json").toFile(), mixer);
    }

    private Path writeSpec(Path root, String name, MasterSpec spec) throws Exception {
        Path f = root.resolve(name);
        mapper.writeValue(f.toFile(), spec);
        return f;
    }

    @Test void conformantMaster_returnsZero(@TempDir Path root) throws Exception {
        seedMixer(root);
        MasterSpec spec = new MasterSpec("Mix-Recipe", "1.0.0", "Busan", "Line1-Mixer", "1.0.0",
                List.of(new Setpoint("Rpm", "Double", 1500), new Setpoint("Temp", "Double", 200)));
        Path f = writeSpec(root, "conformant.json", spec);
        assertEquals(0, SpecGate.run(new String[]{ root.toString(), f.toString() }));
    }

    @Test void outOfRangeMaster_returnsOne(@TempDir Path root) throws Exception {
        seedMixer(root);
        MasterSpec spec = new MasterSpec("Mix-Recipe", "1.0.0", "Busan", "Line1-Mixer", "1.0.0",
                List.of(new Setpoint("Rpm", "Double", 9999), new Setpoint("Temp", "Double", 200)));
        Path f = writeSpec(root, "out-of-range.json", spec);
        assertEquals(1, SpecGate.run(new String[]{ root.toString(), f.toString() }));
    }

    @Test void unknownMemberMaster_returnsOne(@TempDir Path root) throws Exception {
        seedMixer(root);
        MasterSpec spec = new MasterSpec("Mix-Recipe", "1.0.0", "Busan", "Line1-Mixer", "1.0.0",
                List.of(new Setpoint("Ghost", "Double", 1)));
        Path f = writeSpec(root, "unknown-member.json", spec);
        assertEquals(1, SpecGate.run(new String[]{ root.toString(), f.toString() }));
    }

    @Test void badArgs_returnsTwo(@TempDir Path root) {
        assertEquals(2, SpecGate.run(new String[]{ root.toString() }));
    }

    @Test void equipmentNotInRegistry_returnsTwo(@TempDir Path root) throws Exception {
        seedMixer(root);
        MasterSpec spec = new MasterSpec("Mix-Recipe", "1.0.0", "Busan", "Line1-Mixer", "9.9.9",
                List.of(new Setpoint("Rpm", "Double", 1500)));
        Path f = writeSpec(root, "missing-equipment.json", spec);
        assertEquals(2, SpecGate.run(new String[]{ root.toString(), f.toString() }));
    }
}
