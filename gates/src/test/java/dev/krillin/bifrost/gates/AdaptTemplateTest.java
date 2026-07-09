package dev.krillin.bifrost.gates;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.List;
import dev.krillin.bifrost.core.schema.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AdaptTemplateTest {
    static UdtDefinition nativeTemplate() {
        return new UdtDefinition("WeldController-corp", SemVer.parse("1.0.0"), List.of(
            new Member("WeldCurrent","Double","corp:weld/current", new Range(0,15)),
            new Member("WeldTime","Double","corp:weld/time", new Range(0,600)),
            new Member("ElectrodeForce","Double","corp:weld/force", new Range(0,8))), List.of(), null);
    }
    @Test void ignitionExternalAdaptsAndRoundTrips(@TempDir Path dir) throws Exception {
        Path ext = dir.resolve("ext.json"), out = dir.resolve("out.json");
        Files.writeString(ext, """
          { "name":"WeldController-corp",
            "tags":[
              {"name":"WeldCurrent","dataType":"Float8","engLow":0,"engHigh":15,"semanticId":"corp:weld/current"},
              {"name":"WeldTime","dataType":"Float8","engLow":0,"engHigh":600,"semanticId":"corp:weld/time"},
              {"name":"ElectrodeForce","dataType":"Float8","engLow":0,"engHigh":8,"semanticId":"corp:weld/force"}] }
          """);
        int rc = AdaptTemplate.run(new String[]{"ignition", ext.toString(), out.toString(), "WeldController-corp", "1.0.0"});
        assertEquals(0, rc);
        UdtDefinition written = JsonMapperFactory.create().readValue(out.toFile(), UdtDefinition.class);
        assertEquals(nativeTemplate(), written);
    }
    @Test void unknownKindExits2(@TempDir Path dir) throws Exception {
        Path ext = dir.resolve("ext.json"); Files.writeString(ext, "{}");
        assertEquals(2, AdaptTemplate.run(new String[]{"bogus", ext.toString(), dir.resolve("o.json").toString(), "R", "1.0.0"}));
    }
}
