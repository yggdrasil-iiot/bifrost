package dev.krillin.bifrost.core.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import dev.krillin.bifrost.core.acl.CommandPolicy;
import dev.krillin.bifrost.core.acl.AclMapperFactory;
import dev.krillin.bifrost.core.acl.Constraint;
import dev.krillin.bifrost.core.acl.Rule;
import dev.krillin.bifrost.core.acl.Target;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves the published language-neutral JSON-Schema specs under {@code /schema/*.schema.json}
 * actually match what our own Java records serialize to — so any-language consumer can validate
 * a Bifrost definition/policy document without depending on Bifrost code.
 */
class FormatSpecConformanceTest {

    private static final JsonSchemaFactory FACTORY =
            JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7);

    private JsonSchema loadSchema(String classpathResource) {
        InputStream in = getClass().getResourceAsStream(classpathResource);
        assertTrue(in != null, "schema resource missing: " + classpathResource);
        return FACTORY.getSchema(in);
    }

    @Test
    void udtDefinitionSerializationConformsToPublishedSchema() throws Exception {
        UdtDefinition def = new UdtDefinition(
                "types/Pump",
                new SemVer(1, 2, 0),
                List.of(new Member("flow", "Double"), new Member("running", "Boolean")),
                List.of(new Param("maxRpm", "Int32")));

        ObjectMapper mapper = JsonMapperFactory.create();
        String json = mapper.writeValueAsString(def);
        System.out.println("UdtDefinition JSON: " + json);

        JsonSchema schema = loadSchema("/schema/definition.schema.json");
        JsonNode node = mapper.readTree(json);
        Set<com.networknt.schema.ValidationMessage> errors = schema.validate(node);
        assertTrue(errors.isEmpty(), "expected valid UdtDefinition to pass schema: " + errors);
    }

    @Test
    void udtDefinitionWithNonStringVersionFailsSchema() throws Exception {
        ObjectMapper mapper = JsonMapperFactory.create();
        String badJson = "{ \"templateRef\": null, \"version\": 100, "
                + "\"members\": [{\"name\":\"flow\",\"type\":\"Double\"}], \"params\": [] }";
        JsonSchema schema = loadSchema("/schema/definition.schema.json");
        JsonNode node = mapper.readTree(badJson);
        Set<com.networknt.schema.ValidationMessage> errors = schema.validate(node);
        assertFalse(errors.isEmpty(), "version-as-number must fail schema validation");
    }

    @Test
    void commandPolicySerializationConformsToPublishedSchema() throws Exception {
        Rule constrained = new Rule("r1", "scada-hmi",
                new Target("Line1", "recipe-edge", "mixer-1"),
                "setpoint", new Constraint("Double", 0.0, 100.0));
        Rule triggerOnly = new Rule("r2", "scada-hmi",
                new Target("Line1", "recipe-edge", null),
                "start", null);
        CommandPolicy policy = new CommandPolicy("v1", List.of(constrained, triggerOnly), "deny");

        ObjectMapper mapper = AclMapperFactory.create();
        String json = mapper.writeValueAsString(policy);
        System.out.println("CommandPolicy JSON: " + json);

        JsonSchema schema = loadSchema("/schema/policy.schema.json");
        JsonNode node = mapper.readTree(json);
        Set<com.networknt.schema.ValidationMessage> errors = schema.validate(node);
        assertTrue(errors.isEmpty(), "expected valid CommandPolicy to pass schema: " + errors);
    }

    @Test
    void commandPolicyMissingDefaultFailsSchema() throws Exception {
        ObjectMapper mapper = AclMapperFactory.create();
        String badJson = "{ \"version\": \"v1\", \"rules\": [] }";
        JsonSchema schema = loadSchema("/schema/policy.schema.json");
        JsonNode node = mapper.readTree(badJson);
        Set<com.networknt.schema.ValidationMessage> errors = schema.validate(node);
        assertFalse(errors.isEmpty(), "missing 'default' must fail schema validation");
    }
}
