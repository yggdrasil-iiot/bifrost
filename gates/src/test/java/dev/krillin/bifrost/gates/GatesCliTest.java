package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.CompatMode;
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

class GatesCliTest {

    private static final String GOOD_POLICY = """
        {"version":"1.0.0","rules":[
          {"id":"rebirth","principal":"ops","target":{"group":"Acme:Busan:Press","edge":"L1:GW3"},
           "command":"Node Control/Rebirth"},
          {"id":"rpm","principal":"engineer","target":{"group":"Acme:Busan:Press","edge":"L1:GW3"},
           "command":"Setpoint/Rpm","constraint":{"type":"Double","min":0,"max":3000}}
        ],"default":"deny"}""";

    @Test void noArgs_returnsTwo() {
        assertEquals(2, GatesCli.run(new String[]{}));
    }

    @Test void unknownSubcommand_returnsTwo() {
        assertEquals(2, GatesCli.run(new String[]{ "bogus" }));
    }

    @Test void provenanceSubcommand_returnsTwoStub() {
        assertEquals(2, GatesCli.run(new String[]{ "provenance" }));
    }

    @Test void policyDispatch_goodPolicy_returnsZero(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("p.json");
        Files.writeString(f, GOOD_POLICY);
        assertEquals(0, GatesCli.run(new String[]{ "policy", f.toString() }));
    }

    @Test void policyDispatch_allowDefault_returnsOne(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("p.json");
        Files.writeString(f, GOOD_POLICY.replace("\"default\":\"deny\"", "\"default\":\"allow\""));
        assertEquals(1, GatesCli.run(new String[]{ "policy", f.toString() }));
    }

    @Test void schemaDispatch_compatibleChange_returnsZero(@TempDir Path root) throws Exception {
        ObjectMapper mapper = JsonMapperFactory.create();
        Files.createDirectories(root);
        Files.writeString(root.resolve("policy.json"), "{\"mode\":\"" + CompatMode.FORWARD + "\"}");
        List<Member> v1 = List.of(new Member("Rpm", "Double", null, null), new Member("Running", "Boolean", null, null));
        UdtDefinition current = new UdtDefinition("Motor", SemVer.parse("1.0.0"), v1, List.of(), null);
        Path udtDir = root.resolve("udt").resolve(current.templateRef());
        Files.createDirectories(udtDir);
        mapper.writeValue(udtDir.resolve(current.version() + ".json").toFile(), current);

        UdtDefinition proposed = new UdtDefinition("Motor", SemVer.parse("1.1.0"),
                List.of(new Member("Rpm", "Double", null, null), new Member("Running", "Boolean", null, null), new Member("Temperature", "Double", null, null)),
                List.of(), null);
        Path proposalFile = root.resolve("proposed-1.1.0.json");
        mapper.writeValue(proposalFile.toFile(), proposed);

        assertEquals(0, GatesCli.run(new String[]{ "schema", root.toString(), proposalFile.toString() }));
    }

    @Test void specDispatch_conformantMaster_returnsZero(@TempDir Path root) throws Exception {
        ObjectMapper mapper = JsonMapperFactory.create();
        UdtDefinition mixer = new UdtDefinition("Line1-Mixer", SemVer.parse("1.0.0"),
                List.of(new Member("Rpm", "Double", null, new Range(0, 3000)),
                        new Member("Temp", "Double", null, new Range(0, 450)),
                        new Member("Running", "Boolean", null, null)),
                List.of(), null);
        Path udtDir = root.resolve("udt").resolve(mixer.templateRef());
        Files.createDirectories(udtDir);
        mapper.writeValue(udtDir.resolve(mixer.version() + ".json").toFile(), mixer);

        MasterSpec spec = new MasterSpec("Mix-Recipe", "1.0.0", "Busan", "Line1-Mixer", "1.0.0",
                List.of(new Setpoint("Rpm", "Double", 1500), new Setpoint("Temp", "Double", 200)));
        Path specFile = root.resolve("conformant.json");
        mapper.writeValue(specFile.toFile(), spec);

        assertEquals(0, GatesCli.run(new String[]{ "spec", root.toString(), specFile.toString() }));
    }

    @Test void schemaDispatch_breakingChange_returnsOne(@TempDir Path root) throws Exception {
        ObjectMapper mapper = JsonMapperFactory.create();
        Files.createDirectories(root);
        Files.writeString(root.resolve("policy.json"), "{\"mode\":\"" + CompatMode.FORWARD + "\"}");
        List<Member> v1 = List.of(new Member("Rpm", "Double", null, null), new Member("Running", "Boolean", null, null));
        UdtDefinition current = new UdtDefinition("Motor", SemVer.parse("1.0.0"), v1, List.of(), null);
        Path udtDir = root.resolve("udt").resolve(current.templateRef());
        Files.createDirectories(udtDir);
        mapper.writeValue(udtDir.resolve(current.version() + ".json").toFile(), current);

        UdtDefinition proposed = new UdtDefinition("Motor", SemVer.parse("1.1.0"),
                List.of(new Member("Rpm", "Double", null, null)), List.of(), null);
        Path proposalFile = root.resolve("proposed-1.1.0.json");
        mapper.writeValue(proposalFile.toFile(), proposed);

        assertEquals(1, GatesCli.run(new String[]{ "schema", root.toString(), proposalFile.toString() }));
    }
}
