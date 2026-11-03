package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Independent 2.25 command-binding validator: the published link between one governed member's read binding and one OPC UA
 *  Method of the same equipment. Every reference resolves inside the bundle, the read binding's device is the hierarchy path
 *  of the equipment the link names, the Method takes exactly one Double input with a UCUM unit, and no two links share a
 *  device and methodNodeId. */
final class CommandBindings {
 static final String KIND="command-binding";
 interface Reader {byte[] read(String path) throws Exception;}
 static void validate(Collection<JsonNode> docs,Reader files) throws Exception {
  Set<String> keys=new HashSet<>(),ucum=null;
  for(JsonNode c:docs){
   if(!text(c,"kind").equals(KIND))continue;
   if(ucum==null)ucum=ucum();
   JsonNode eq=c.path("equipmentRef"),hierarchy=find(docs,EquipmentHierarchy.KIND,eq),evidence=find(docs,"evidence-artifact",c.path("readBindingRef"));
   require(hierarchy!=null&&evidence!=null&&text(evidence,"schemaVersion").equals("1.1.0"),"command-binding.unresolved");
   Map<String,JsonNode> nodes=new HashMap<>();for(JsonNode n:hierarchy.path("nodes"))nodes.put(text(n,"equipmentInstanceId"),n);
   require(nodes.containsKey(text(eq,"equipmentInstanceId")),"command-binding.unresolved");
   ReadBindingProfile b=ReadBindingProfile.parse(files.read(text(evidence.path("file"),"path")),"command-binding.unresolved");
   JsonNode set=null;
   for(JsonNode d:docs)if(text(d,"kind").equals("mapping-set")&&text(d,"id").equals(b.mappingSetId())&&text(d,"version").equals(b.mappingSetVersion()))set=d;
   require(set!=null,"command-binding.unresolved");
   boolean mapped=false;for(JsonNode m:set.path("mappings"))mapped|=text(m,"mappingId").equals(b.mappingId());
   require(mapped,"command-binding.unresolved");
   require(b.equipmentInstanceId().equals(text(eq,"equipmentInstanceId"))&&b.device().equals(path(nodes,text(eq,"equipmentInstanceId"))),"command-binding.device-path");
   JsonNode in=c.path("method").path("inputs");
   require(in.size()==1&&!text(in.get(0),"name").isEmpty()&&text(in.get(0),"type").equals("Double")&&ucum.contains(text(in.get(0),"unit")),"command-binding.inputs");
   require(keys.add(b.device()+"\n"+text(c.path("method"),"methodNodeId")),"command-binding.duplicate");
  }
 }
 private static JsonNode find(Collection<JsonNode> docs,String kind,JsonNode ref){
  for(JsonNode d:docs)if(text(d,"kind").equals(kind)&&text(d,"id").equals(text(ref,"id"))&&text(d,"version").equals(text(ref,"version")))return d;
  return null;
 }
 /** Root first, joined with ':', as Muninn publishes it for the Sparkplug device id. The hierarchy validator has already
  *  refused cycles and missing parents. */
 private static String path(Map<String,JsonNode> nodes,String id){
  Deque<String> out=new ArrayDeque<>();
  for(JsonNode n=nodes.get(id);n!=null;n=n.path("parentEquipmentInstanceId").isNull()?null:nodes.get(text(n,"parentEquipmentInstanceId")))out.addFirst(text(n,"equipmentInstanceId"));
  return String.join(":",out);
 }
 /** The UCUM codes contract 2.25.0 knows: the known-unit enum of its common schema. */
 private static Set<String> ucum() throws Exception {
  try(var in=CommandBindings.class.getResourceAsStream("/mapping-contracts/2.25.0/common.schema.json")){
   Set<String> out=new HashSet<>();JSON.readTree(in).at("/$defs/unit/oneOf/0/properties/code/enum").forEach(x->out.add(x.asText()));
   require(!out.isEmpty(),"command-binding.inputs");return out;
  }
 }
}
