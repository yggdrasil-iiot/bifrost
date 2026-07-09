package dev.krillin.bifrost.core.conformance.adapter;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.JsonNode;
import dev.krillin.bifrost.core.schema.*;
import java.util.List;
import org.junit.jupiter.api.Test;

class AasSubmodelAdapterTest {
    static UdtDefinition nativeTemplate() {
        return new UdtDefinition("WeldController-corp", SemVer.parse("1.0.0"), List.of(
            new Member("WeldCurrent","Double","corp:weld/current", new Range(0,15)),
            new Member("WeldTime","Double","corp:weld/time", new Range(0,600)),
            new Member("ElectrodeForce","Double","corp:weld/force", new Range(0,8))), List.of(), null);
    }
    @Test void aasSubmodelAdaptsToNative() throws Exception {
        String aas = """
          { "idShort":"WeldController-corp", "modelType":"Submodel",
            "submodelElements":[
              {"modelType":"Property","idShort":"WeldCurrent","valueType":"xs:double",
               "semanticId":{"type":"ExternalReference","keys":[{"type":"GlobalReference","value":"corp:weld/current"}]},
               "qualifiers":[{"type":"Min","value":"0"},{"type":"Max","value":"15"}]},
              {"modelType":"Property","idShort":"WeldTime","valueType":"xs:double",
               "semanticId":{"type":"ExternalReference","keys":[{"type":"GlobalReference","value":"corp:weld/time"}]},
               "qualifiers":[{"type":"Min","value":"0"},{"type":"Max","value":"600"}]},
              {"modelType":"Property","idShort":"ElectrodeForce","valueType":"xs:double",
               "semanticId":{"type":"ExternalReference","keys":[{"type":"GlobalReference","value":"corp:weld/force"}]},
               "qualifiers":[{"type":"Min","value":"0"},{"type":"Max","value":"8"}]}] }
          """;
        JsonNode tree = JsonMapperFactory.create().readTree(aas);
        UdtDefinition adapted = new AasSubmodelAdapter().adapt(tree, "WeldController-corp", "1.0.0");
        assertEquals(nativeTemplate(), adapted);
    }
}
