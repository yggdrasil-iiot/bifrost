package dev.krillin.bifrost.core.conformance.adapter;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import dev.krillin.bifrost.core.schema.*;
/** Ignition UDT export (tags/dataType/engLow/engHigh) -> UdtDefinition. Ignition dataTypes map to our type
 *  vocabulary; engLow/engHigh -> Range; semanticId read from a designated custom property (honest carry). */
public final class IgnitionUdtAdapter implements TemplateAdapter {
    public UdtDefinition adapt(JsonNode ext, String ref, String version) {
        List<Member> members = new ArrayList<>();
        for (JsonNode tag : ext.path("tags")) {
            Range range = tag.has("engLow") && tag.has("engHigh")
                ? new Range(tag.get("engLow").asDouble(), tag.get("engHigh").asDouble()) : null;
            members.add(new Member(tag.get("name").asText(), mapType(tag.get("dataType").asText()),
                tag.hasNonNull("semanticId") ? tag.get("semanticId").asText() : null, range));
        }
        return new UdtDefinition(ref, SemVer.parse(version), members, List.of(), null);
    }
    private static String mapType(String ignition) {
        return switch (ignition) { case "Float8","Float4" -> "Double"; case "Int4","Int8" -> "Int32"; case "Boolean" -> "Boolean"; default -> ignition; };
    }
}
