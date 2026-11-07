package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Independent 2.27 impact-rule validator: the forseti stage-2 rule that judges quality incidents against the visits an
 *  attribution rule of the same bundle produces. The attribution rule resolves, every incident scope path is a hierarchy node
 *  that is a station of that rule or below one, the incident binding profile is an evidence-artifact Bifrost can read, and
 *  work-record retention is at least the attribution horizon. Refusal codes are the spec's impact.* table. AttributionRules
 *  runs first, so a referenced rule's hierarchy and stations are already known to resolve. */
final class ImpactRules {
 static final String KIND="impact-rule";
 static void validate(Collection<JsonNode> docs,AttributionRules.Reader files) throws Exception {
  for(JsonNode r:docs){
   if(!text(r,"kind").equals(KIND))continue;
   JsonNode a=AttributionRules.find(docs,AttributionRules.KIND,r.path("attributionRuleRef"));
   require(a!=null,"impact.attribution-missing");
   Set<String> known=new HashSet<>(AttributionRules.paths(AttributionRules.find(docs,EquipmentHierarchy.KIND,a.path("equipmentRef"))).values());
   List<String> stations=new ArrayList<>();for(JsonNode s:a.path("stations"))stations.add(s.asText());
   for(JsonNode s:r.path("incidentScope"))require(known.contains(s.asText())&&AttributionRules.within(stations,s.asText()),"impact.scope-containment");
   JsonNode evidence=AttributionRules.find(docs,"evidence-artifact",r.path("incidentBindingRef"));
   require(evidence!=null&&text(evidence,"schemaVersion").equals("1.1.0"),"impact.binding-unresolved");
   require(text(evidence,"id").startsWith(IncidentBindingProfile.ID_PREFIX)&&text(evidence.path("file"),"mediaType").equals(IncidentBindingProfile.MEDIA_TYPE),"impact.binding-profile");
   IncidentBindingProfile.parse(files.read(text(evidence.path("file"),"path")),"impact.binding-profile");
   require(a.path("temporal").path("horizonMs").asLong()<=r.path("retention").path("workRecordsMs").asLong(),"impact.retention-order");
  }
 }
}
