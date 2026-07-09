package dev.krillin.bifrost.core.conformance.adapter;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.JsonNode;
import dev.krillin.bifrost.core.schema.*;
import java.util.List;
import org.junit.jupiter.api.Test;

class IgnitionUdtAdapterTest {
    static UdtDefinition nativeTemplate() {
        return new UdtDefinition("WeldController-corp", SemVer.parse("1.0.0"), List.of(
            new Member("WeldCurrent","Double","corp:weld/current", new Range(0,15)),
            new Member("WeldTime","Double","corp:weld/time", new Range(0,600)),
            new Member("ElectrodeForce","Double","corp:weld/force", new Range(0,8))), List.of(), null);
    }
    @Test void ignitionExportAdaptsToNative() throws Exception {
        String ignition = """
          { "name":"WeldController-corp", "typeId":"WeldController-corp",
            "tags":[
              {"name":"WeldCurrent","dataType":"Float8","engLow":0,"engHigh":15,"semanticId":"corp:weld/current"},
              {"name":"WeldTime","dataType":"Float8","engLow":0,"engHigh":600,"semanticId":"corp:weld/time"},
              {"name":"ElectrodeForce","dataType":"Float8","engLow":0,"engHigh":8,"semanticId":"corp:weld/force"}] }
          """;
        JsonNode tree = JsonMapperFactory.create().readTree(ignition);
        UdtDefinition adapted = new IgnitionUdtAdapter().adapt(tree, "WeldController-corp", "1.0.0");
        assertEquals(nativeTemplate(), adapted);   // record equality: adapt(external) ≡ native
    }
}
