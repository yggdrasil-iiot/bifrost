package dev.krillin.bifrost.core.conformance.adapter;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import dev.krillin.bifrost.core.schema.*;
/** CFIHOS process-RDL equipment class -> UdtDefinition. propertyId is an IRI carried NATIVELY as semanticId;
 *  datatype -> our type vocabulary; minValue/maxValue -> Range. requirement "M" mandatory is included;
 *  "O" optional is dropped (honest decision — optional-member support is a reserved future extension). */
public final class CfihosTemplateAdapter implements TemplateAdapter {
    public UdtDefinition adapt(JsonNode ext, String ref, String version) {
        List<Member> members = new ArrayList<>();
        for (JsonNode p : ext.path("properties")) {
            if (!"M".equals(p.path("requirement").asText())) continue;   // drop optional (reserved future extension)
            Range range = p.has("minValue") && p.has("maxValue")
                ? new Range(p.get("minValue").asDouble(), p.get("maxValue").asDouble()) : null;
            members.add(new Member(p.get("name").asText(), mapType(p.get("datatype").asText()),
                p.hasNonNull("propertyId") ? p.get("propertyId").asText() : null, range));
        }
        return new UdtDefinition(ref, SemVer.parse(version), members, List.of(), null);
    }
    private static String mapType(String cfihos) {
        return switch (cfihos) { case "REAL","DOUBLE" -> "Double"; case "INTEGER","INT" -> "Int32"; case "BOOLEAN" -> "Boolean"; default -> cfihos; };
    }
}
