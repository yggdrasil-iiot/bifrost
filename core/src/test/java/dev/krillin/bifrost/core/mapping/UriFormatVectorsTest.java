package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * semanticId "format": "uri" against the vectors Tyr also tests (a byte copy of Tyr's
 * fixtures/uri-format/bifrost-vectors.json; data only, no shared code). The "bifrost" verdict in that
 * file must stay what this validator decides, on both schema paths: 2.12.0 (logical structures) and 2.2.0.
 */
class UriFormatVectorsTest {
    JsonNode resource(String name) throws Exception {return read(Path.of(getClass().getResource(name).toURI()));}
    @Test void semanticIdVerdictsMatchTheSharedVectors() throws Exception {
        JsonNode cases=resource("/uri-format/vectors.json").path("cases");
        assertTrue(cases.size()>=19);
        for(String model:new String[]{"/mapping-structures/nested-model.json","/mapping-fixtures/a07/semantics/0.json"}){
            for(JsonNode c:cases){
                ObjectNode doc=(ObjectNode)resource(model);
                ((ObjectNode)doc.path("members").get(0)).put("semanticId",text(c,"value"));
                boolean accepted;
                try{schema(doc,"semantic-definition");accepted=true;}
                catch(IllegalArgumentException e){assertTrue(e.getMessage().startsWith("mapping.schema:"),e.getMessage());accepted=false;}
                assertEquals(text(c,"bifrost"),accepted?"accept":"reject",model+" "+text(c,"value"));
            }
        }
    }
}
