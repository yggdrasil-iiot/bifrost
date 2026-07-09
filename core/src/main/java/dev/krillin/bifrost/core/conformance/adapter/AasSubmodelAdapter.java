package dev.krillin.bifrost.core.conformance.adapter;
import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import dev.krillin.bifrost.core.schema.*;
/** AAS (Industrie 4.0) submodel template -> UdtDefinition. Property elements: idShort->name, valueType->type,
 *  NATIVE semanticId.keys[0].value->semanticId; range from Min/Max qualifiers (STRING values -> parsed doubles). */
public final class AasSubmodelAdapter implements TemplateAdapter {
    public UdtDefinition adapt(JsonNode ext, String ref, String version) {
        List<Member> members = new ArrayList<>();
        for (JsonNode el : ext.path("submodelElements")) {
            if (!"Property".equals(el.path("modelType").asText())) continue;
            Double min = null, max = null;
            for (JsonNode q : el.path("qualifiers")) {
                if ("Min".equals(q.path("type").asText())) min = Double.parseDouble(q.path("value").asText());
                else if ("Max".equals(q.path("type").asText())) max = Double.parseDouble(q.path("value").asText());
            }
            Range range = (min != null && max != null) ? new Range(min, max) : null;
            String sem = el.path("semanticId").path("keys").path(0).path("value").asText(null);
            members.add(new Member(el.path("idShort").asText(), mapType(el.path("valueType").asText()), sem, range));
        }
        return new UdtDefinition(ref, SemVer.parse(version), members, List.of(), null);
    }
    private static String mapType(String xsd) {
        return switch (xsd) { case "xs:double","xs:float" -> "Double"; case "xs:int","xs:integer","xs:long" -> "Int32"; case "xs:boolean" -> "Boolean"; default -> xsd; };
    }
}
