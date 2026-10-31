package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Independent 2.23 equipment-hierarchy validator. Governed metadata only: no topic, group or authorization input. */
final class EquipmentHierarchy {
 static final String KIND="equipment-hierarchy";
 static final int MAX_DEPTH=64;
 static void validate(Collection<JsonNode> docs,Set<String> equipment){
  List<JsonNode> hs=docs.stream().filter(d->text(d,"kind").equals(KIND)).toList();
  if(hs.isEmpty())return;
  require(hs.size()==1,"hierarchy.multiple");
  Map<String,JsonNode> by=new HashMap<>();
  for(JsonNode n:hs.get(0).path("nodes"))require(by.putIfAbsent(text(n,"equipmentInstanceId"),n)==null,"hierarchy.duplicate-node");
  for(JsonNode n:by.values())require(n.path("parentEquipmentInstanceId").isNull()||by.containsKey(text(n,"parentEquipmentInstanceId")),"hierarchy.parent-missing");
  for(JsonNode n:by.values()){
   Set<String> seen=new HashSet<>(Set.of(text(n,"equipmentInstanceId")));JsonNode p=n.path("parentEquipmentInstanceId");int depth=1;
   while(!p.isNull()){require(seen.add(p.asText()),"hierarchy.cycle");require(++depth<=MAX_DEPTH,"hierarchy.depth");p=by.get(p.asText()).path("parentEquipmentInstanceId");}
  }
  require(equipment.containsAll(by.keySet()),"hierarchy.context-equipment");
  for(JsonNode d:docs)if(!text(d,"kind").equals(KIND)&&d.has("equipmentInstanceId"))require(by.containsKey(text(d,"equipmentInstanceId")),"hierarchy.unresolved-instance");
  Map<String,Set<String>> scope=new HashMap<>();
  for(JsonNode d:docs)if(text(d,"kind").equals("evidence-artifact")){Set<String> s=new HashSet<>();d.path("scope").forEach(x->s.add(x.asText()));scope.put(text(d,"id"),s);}
  for(JsonNode n:by.values()){
   boolean covered=false;for(JsonNode r:n.path("evidenceRefs"))covered|=scope.getOrDefault(text(r,"artifactId"),Set.of()).contains(text(n,"equipmentInstanceId"));
   require(covered,"hierarchy.evidence-scope");
  }
 }
}
