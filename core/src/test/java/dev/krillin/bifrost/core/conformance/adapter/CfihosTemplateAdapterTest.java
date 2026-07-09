package dev.krillin.bifrost.core.conformance.adapter;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.JsonNode;
import dev.krillin.bifrost.core.schema.*;
import java.util.List;
import org.junit.jupiter.api.Test;

class CfihosTemplateAdapterTest {
    static UdtDefinition nativeTemplate() {
        return new UdtDefinition("WeldController-corp", SemVer.parse("1.0.0"), List.of(
            new Member("WeldCurrent","Double","corp:weld/current", new Range(0,15)),
            new Member("WeldTime","Double","corp:weld/time", new Range(0,600)),
            new Member("ElectrodeForce","Double","corp:weld/force", new Range(0,8))), List.of(), null);
    }
    @Test void cfihosClassAdaptsToNative() throws Exception {
        String cfihos = """
          { "classId":"WeldController-corp", "className":"WeldController-corp",
            "properties":[
              {"name":"WeldCurrent","propertyId":"corp:weld/current","datatype":"REAL","minValue":0,"maxValue":15,"requirement":"M"},
              {"name":"WeldTime","propertyId":"corp:weld/time","datatype":"REAL","minValue":0,"maxValue":600,"requirement":"M"},
              {"name":"ElectrodeForce","propertyId":"corp:weld/force","datatype":"REAL","minValue":0,"maxValue":8,"requirement":"M"},
              {"name":"CoolingNote","propertyId":"corp:weld/cooling-note","datatype":"STRING","requirement":"O"}] }
          """;
        JsonNode tree = JsonMapperFactory.create().readTree(cfihos);
        UdtDefinition adapted = new CfihosTemplateAdapter().adapt(tree, "WeldController-corp", "1.0.0");
        assertEquals(nativeTemplate(), adapted);   // the "O" CoolingNote is dropped → still 3 members
    }
}
