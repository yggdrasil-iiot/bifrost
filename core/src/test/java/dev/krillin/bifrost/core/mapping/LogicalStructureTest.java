package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

class LogicalStructureTest {
    JsonNode model() throws Exception {return read(Path.of(getClass().getResource("/mapping-structures/nested-model.json").toURI()));}
    @Test void nestedMultiRankWithNegativeBounds() throws Exception {
        JsonNode m=model();schema(m,"semantic-definition");
        assertEquals(8,LogicalStructure.layout(m).leaves().size());
        JsonNode p=JSON.readTree("[{\"kind\":\"member\",\"memberId\":\"racks\"},{\"kind\":\"index\",\"indices\":[-1]},{\"kind\":\"member\",\"memberId\":\"slots\"},{\"kind\":\"index\",\"indices\":[2,4]},{\"kind\":\"member\",\"memberId\":\"value\"}]");
        assertEquals("Double",text(LogicalStructure.resolve(m,p),"valueType"));
        ((ArrayNode)p.get(3).path("indices")).set(1,JSON.getNodeFactory().numberNode(5));
        assertEquals("structure.index-range",assertThrows(IllegalArgumentException.class,()->LogicalStructure.resolve(m,p)).getMessage());
    }
    @Test void containerSignatureBindsShapeAndLowerBounds() throws Exception {
        ObjectNode m=(ObjectNode)model();JsonNode before=LogicalStructure.signature(m.path("members").get(0)).deepCopy();
        ((ArrayNode)m.path("members").get(0).path("lowerBounds")).set(0,JSON.getNodeFactory().numberNode(0));
        assertNotEquals(before,LogicalStructure.signature(m.path("members").get(0)));
    }
    @Test void recursiveSchemaHasBoundedDepthPreflight() throws Exception {
        ObjectNode m=(ObjectNode)model();ObjectNode parent=(ObjectNode)m.path("members").get(0);
        for(int i=0;i<20;i++){ObjectNode child=parent.deepCopy();ArrayNode members=JSON.createArrayNode();members.add(child);parent.set("members",members);parent=child;}
        assertEquals("structure.depth",assertThrows(IllegalArgumentException.class,()->schema(m,"semantic-definition")).getMessage());
    }
}
