package dev.krillin.bifrost.core.schema;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

class UdtDefinitionJsonTest {
    @Test void roundTrip_preservesAllFields() throws Exception {
        ObjectMapper mapper = JsonMapperFactory.create();
        UdtDefinition def = new UdtDefinition("Motor", SemVer.parse("1.0.0"),
                List.of(new Member("Rpm", "Double"), new Member("Running", "Boolean")),
                List.of(new Param("Location", "String")));

        String json = mapper.writeValueAsString(def);
        assertTrue(json.contains("\"version\":\"1.0.0\""), json);

        UdtDefinition back = mapper.readValue(json, UdtDefinition.class);
        assertEquals(def, back);
    }
}
