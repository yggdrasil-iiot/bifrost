package dev.krillin.bifrost.core.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves the published {@code /schema/spec.schema.json} (ISA-88 two-layer spec contract) matches what
 * our own {@link GeneralSpec}/{@link MasterSpec} records serialize to — so any-language consumer can
 * validate a Bifrost spec document without depending on Bifrost code.
 */
class SpecFormatConformanceTest {

    private static final JsonSchemaFactory FACTORY =
            JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7);

    private JsonSchema loadSchema(String classpathResource) {
        InputStream in = getClass().getResourceAsStream(classpathResource);
        assertTrue(in != null, "schema resource missing: " + classpathResource);
        return FACTORY.getSchema(in);
    }

    @Test
    void masterSpecSerializationConformsToPublishedSchema() throws Exception {
        MasterSpec spec = new MasterSpec(
                "MixProductA", "1.0.0", "Line1",
                "Line1-Mixer", "1.0.0",
                List.of(new Setpoint("Rpm", "Double", 1500)));

        ObjectMapper mapper = JsonMapperFactory.create();
        String json = mapper.writeValueAsString(spec);
        System.out.println("MasterSpec JSON: " + json);

        JsonSchema schema = loadSchema("/schema/spec.schema.json");
        JsonNode node = mapper.readTree(json);
        Set<com.networknt.schema.ValidationMessage> errors = schema.validate(node);
        assertTrue(errors.isEmpty(), "expected valid MasterSpec to pass schema: " + errors);
    }

    @Test
    void masterSpecMissingEquipmentRefFailsSchema() throws Exception {
        ObjectMapper mapper = JsonMapperFactory.create();
        String badJson = "{ \"specRef\": \"MixProductA\", \"version\": \"1.0.0\", \"site\": \"Line1\", "
                + "\"equipmentVersion\": \"1.0.0\", "
                + "\"setpoints\": [{\"member\":\"Rpm\",\"type\":\"Double\",\"value\":1500}] }";
        JsonSchema schema = loadSchema("/schema/spec.schema.json");
        JsonNode node = mapper.readTree(badJson);
        Set<com.networknt.schema.ValidationMessage> errors = schema.validate(node);
        assertFalse(errors.isEmpty(), "master-spec missing equipmentRef must fail schema validation");
    }

    @Test
    void generalSpecSerializationConformsToPublishedSchema() throws Exception {
        GeneralSpec spec = new GeneralSpec(
                "MixProductA", "1.0.0", "MixProductA",
                List.of(new SetpointIntent("mixSpeed", "Double", 1500)));

        ObjectMapper mapper = JsonMapperFactory.create();
        String json = mapper.writeValueAsString(spec);
        System.out.println("GeneralSpec JSON: " + json);

        JsonSchema schema = loadSchema("/schema/spec.schema.json");
        JsonNode node = mapper.readTree(json);
        Set<com.networknt.schema.ValidationMessage> errors = schema.validate(node);
        assertTrue(errors.isEmpty(), "expected valid GeneralSpec to pass schema: " + errors);
    }
}
