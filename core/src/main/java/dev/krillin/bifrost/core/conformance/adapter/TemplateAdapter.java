package dev.krillin.bifrost.core.conformance.adapter;
import com.fasterxml.jackson.databind.JsonNode;
import dev.krillin.bifrost.core.schema.UdtDefinition;
/** Anti-corruption adapter: maps a FOREIGN external-standard JSON tree to the internal canonical UdtDefinition.
 *  ref/version parameterize the produced template's identity (the external doc may not carry Bifrost's). */
public interface TemplateAdapter { UdtDefinition adapt(JsonNode external, String ref, String version); }
