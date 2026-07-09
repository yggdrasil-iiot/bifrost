package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import dev.krillin.bifrost.core.schema.Member;
import dev.krillin.bifrost.core.schema.Range;
import dev.krillin.bifrost.core.schema.SemVer;
import dev.krillin.bifrost.core.schema.UdtDefinition;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TemplateGateTest {

    private final ObjectMapper mapper = JsonMapperFactory.create();

    /** Seeds the native enterprise template at {@code <reg>/udt/WeldController-corp/1.0.0.json}. */
    private Path seedRegistry(Path tmp) throws Exception {
        Path reg = tmp.resolve("reg");
        UdtDefinition template = new UdtDefinition("WeldController-corp", SemVer.parse("1.0.0"),
                List.of(
                        new Member("WeldCurrent", "Double", "corp:weld/current", new Range(0, 15)),
                        new Member("WeldTime", "Double", "corp:weld/time", new Range(0, 600)),
                        new Member("ElectrodeForce", "Double", "corp:weld/force", new Range(0, 8))),
                List.of(), null);
        Path dir = reg.resolve("udt").resolve(template.templateRef());
        Files.createDirectories(dir);
        mapper.writeValue(dir.resolve(template.version() + ".json").toFile(), template);
        return reg;
    }

    private Path writeSite(Path tmp, String name, UdtDefinition site) throws Exception {
        Path f = tmp.resolve(name);
        mapper.writeValue(f.toFile(), site);
        return f;
    }

    @Test void conformingSite_returnsZero(@TempDir Path tmp) throws Exception {
        Path reg = seedRegistry(tmp);
        UdtDefinition site = new UdtDefinition("WeldController-busan", SemVer.parse("1.0.0"),
                List.of(
                        new Member("WeldCurrent", "Double", "corp:weld/current", new Range(0, 12)),
                        new Member("WeldTime", "Double", "corp:weld/time", new Range(0, 500)),
                        new Member("ElectrodeForce", "Double", "corp:weld/force", new Range(0, 6))),
                List.of(), "WeldController-corp@1.0.0");
        Path f = writeSite(tmp, "site-conform.json", site);
        assertEquals(0, TemplateGate.run(new String[]{ reg.toString(), f.toString() }));
    }

    @Test void violatingSite_returnsOne(@TempDir Path tmp) throws Exception {
        Path reg = seedRegistry(tmp);
        UdtDefinition site = new UdtDefinition("WeldController-busan", SemVer.parse("1.0.0"),
                List.of(
                        new Member("WeldCurrent", "Double", "corp:weld/current", new Range(0, 20)),
                        new Member("WeldTime", "Double", "corp:weld/time", new Range(0, 500)),
                        new Member("ElectrodeForce", "Double", "corp:weld/force", new Range(0, 6))),
                List.of(), "WeldController-corp@1.0.0");
        Path f = writeSite(tmp, "site-violate.json", site);
        assertEquals(1, TemplateGate.run(new String[]{ reg.toString(), f.toString() }));
    }

    @Test void absentTemplate_returnsTwo(@TempDir Path tmp) throws Exception {
        Path reg = seedRegistry(tmp);
        UdtDefinition site = new UdtDefinition("WeldController-busan", SemVer.parse("1.0.0"),
                List.of(new Member("WeldCurrent", "Double", "corp:weld/current", new Range(0, 12))),
                List.of(), "Nope@9.9.9");
        Path f = writeSite(tmp, "site-absent.json", site);
        assertEquals(2, TemplateGate.run(new String[]{ reg.toString(), f.toString() }));
    }

    @Test void badArgs_returnsTwo(@TempDir Path tmp) {
        assertEquals(2, TemplateGate.run(new String[]{ tmp.toString() }));
    }

    @Test void siteMissingConformsTo_returnsTwo(@TempDir Path tmp) throws Exception {
        Path reg = seedRegistry(tmp);
        UdtDefinition site = new UdtDefinition("WeldController-busan", SemVer.parse("1.0.0"),
                List.of(new Member("WeldCurrent", "Double", "corp:weld/current", new Range(0, 12))),
                List.of(), null);
        Path f = writeSite(tmp, "site-no-conformsto.json", site);
        assertEquals(2, TemplateGate.run(new String[]{ reg.toString(), f.toString() }));
    }
}
