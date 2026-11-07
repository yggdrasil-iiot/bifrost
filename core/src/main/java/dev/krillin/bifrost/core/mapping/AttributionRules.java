package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Independent 2.27 attribution-rule validator: the forseti stage-1 rule that joins governed process members with MES
 *  occupancy per station and tool. Everything resolves inside the bundle: the ISA-95 hierarchy the rule names, its stations
 *  (hierarchy paths that do not nest), its members (each a mapping of a mapping set whose equipment is a station or a tool
 *  under one, named by the metric Muninn publishes and the semantic id of the leaf it maps), one Boolean activity member per
 *  equipment, an occupancy binding profile carried by an evidence-artifact, the plc-stamped identity members, and the
 *  temporal order. Member references of activity and identity entries are mappingIds of the rule's own members[]. Refusal
 *  codes are the spec's attribution.* table; the first failure stops the rule. No forseti code is read. */
final class AttributionRules {
 static final String KIND="attribution-rule";
 interface Reader {byte[] read(String path) throws Exception;}
 /** One mapping of the bundle: its set, its equipment's hierarchy path, the semantic leaf it maps, whether its memberPath is
  *  one member step, whether the leaf names of its semantic definition are distinct, and its OPC UA node identifier (null
  *  unless the source is an opcua-node). */
 record Member(String setKey,String equipmentPath,JsonNode leaf,boolean oneStep,boolean distinctNames,String identifier) {}
 static void validate(Collection<JsonNode> docs,Reader files) throws Exception {
  for(JsonNode r:docs){
   if(!text(r,"kind").equals(KIND))continue;
   JsonNode hierarchy=find(docs,EquipmentHierarchy.KIND,r.path("equipmentRef"));
   require(hierarchy!=null,"attribution.hierarchy-missing");
   Map<String,String> paths=paths(hierarchy);Set<String> known=new HashSet<>(paths.values());
   List<String> stations=new ArrayList<>();for(JsonNode s:r.path("stations"))stations.add(s.asText());
   for(String s:stations)require(known.contains(s),"attribution.station-unresolved");
   for(String a:stations)for(String b:stations)require(!b.startsWith(a+":"),"attribution.station-nested");
   Map<String,Member> bundle=members(docs,paths),rule=new LinkedHashMap<>();Set<String> slots=new HashSet<>();
   require(r.path("members").size()>0,"attribution.member-unresolved");
   for(JsonNode m:r.path("members")){
    String id=text(m,"mappingId"),metric=text(m,"metric");Member x=bundle.get(id);
    require(x!=null&&x.setKey().equals(key(m.path("mappingSetRef")))&&x.oneStep()&&x.distinctNames()
     &&text(x.leaf(),"name").equals(metric)&&text(x.leaf(),"semanticId").equals(text(m,"semanticId"))
     &&(x.identifier()==null||x.identifier().endsWith("."+metric))
     &&rule.putIfAbsent(id,x)==null&&slots.add(x.equipmentPath()+"\n"+metric),"attribution.member-unresolved");
    require(within(stations,x.equipmentPath()),"attribution.member-equipment");
   }
   Set<String> active=new HashSet<>();
   for(JsonNode a:r.path("activity")){
    String path=text(a,"equipmentPath");Member x=rule.get(text(a,"memberRef"));
    require(x!=null&&x.equipmentPath().equals(path)&&within(stations,path)&&text(x.leaf(),"valueType").equals("Boolean")&&active.add(path),"attribution.activity-member");
   }
   JsonNode evidence=find(docs,"evidence-artifact",r.path("occupancyBindingRef"));
   require(evidence!=null&&text(evidence,"schemaVersion").equals("1.1.0"),"attribution.binding-unresolved");
   require(text(evidence,"id").startsWith(OccupancyBindingProfile.ID_PREFIX)&&text(evidence.path("file"),"mediaType").equals(OccupancyBindingProfile.MEDIA_TYPE),"attribution.binding-profile");
   OccupancyBindingProfile.parse(files.read(text(evidence.path("file"),"path")),"attribution.binding-profile");
   // plc-stamped identity: Task 6
   JsonNode t=r.path("temporal");
   require(t.path("outOfOrdernessMs").asLong()<=t.path("allowedLatenessMs").asLong()&&t.path("allowedLatenessMs").asLong()<=t.path("horizonMs").asLong(),"attribution.temporal-order");
  }
 }
 /** A path is a station of the rule or a descendant of one (a tool). Ids carry no ':', so the prefix test is exact. */
 static boolean within(List<String> stations,String path){
  for(String s:stations)if(path.equals(s)||path.startsWith(s+":"))return true;
  return false;
 }
 static String key(JsonNode ref){return text(ref,"id")+"@"+text(ref,"version");}
 /** Every mapping of the bundle by mappingId (unique across sets: mapping.duplicate-id). A mapping whose target, semantic
  *  definition, equipment or member path does not resolve is left out and is then attribution.member-unresolved here;
  *  MappingBundle.mappings() reports its own code later only when no rule check threw first. */
 static Map<String,Member> members(Collection<JsonNode> docs,Map<String,String> paths){
  Map<String,Member> out=new HashMap<>();Map<String,Boolean> distinct=new HashMap<>();
  for(JsonNode set:docs){
   if(!text(set,"kind").equals("mapping-set"))continue;
   JsonNode target=find(docs,"target-instance",set.path("targetInstanceRef"));if(target==null)continue;
   JsonNode semantic=find(docs,"semantic-definition",target.path("semanticDefinitionRef"));if(semantic==null)continue;
   String path=paths.get(text(set,"equipmentInstanceId"));if(path==null)continue;
   boolean names=distinct.computeIfAbsent(key(semantic),k->distinctNames(semantic));
   for(JsonNode m:set.path("mappings")){
    JsonNode leaf;try{leaf=LogicalStructure.resolve(semantic,m.path("memberPath"));}catch(IllegalArgumentException e){continue;}
    JsonNode v=m.path("valueRef"),source=text(v,"kind").equals("source")?find(docs,"source-definition",v.path("sourceRef")):null;
    String identifier=source!=null&&text(source.path("access"),"kind").equals("opcua-node")?text(source.path("access"),"identifier"):null;
    out.put(text(m,"mappingId"),new Member(key(set),path,leaf,m.path("memberPath").size()==1,names,identifier));
   }
  }
  return out;
 }
 /** Spec: within each semantic definition a rule uses, no two leaf members share a name (a station and a tool may each have a
  *  member of the same name, because Sparkplug metric names are scoped to one device). */
 static boolean distinctNames(JsonNode semantic){
  Set<String> names=new HashSet<>();
  try{for(LogicalStructure.Leaf l:LogicalStructure.layout(semantic).leaves().values())if(!names.add(text(l.member(),"name")))return false;}
  catch(IllegalArgumentException e){return false;}
  return true;
 }
 static JsonNode find(Collection<JsonNode> docs,String kind,JsonNode ref){
  for(JsonNode d:docs)if(text(d,"kind").equals(kind)&&text(d,"id").equals(text(ref,"id"))&&text(d,"version").equals(text(ref,"version")))return d;
  return null;
 }
 /** Each node's hierarchy path: root first, joined with ':', the string Muninn publishes as the Sparkplug device id and the
  *  occupancy readPoint carries (the rule of CommandBindings.path). EquipmentHierarchy has already refused cycles and missing
  *  parents. */
 static Map<String,String> paths(JsonNode hierarchy){
  Map<String,JsonNode> by=new HashMap<>();for(JsonNode n:hierarchy.path("nodes"))by.put(text(n,"equipmentInstanceId"),n);
  Map<String,String> out=new HashMap<>();
  for(String id:by.keySet()){
   Deque<String> p=new ArrayDeque<>();
   for(JsonNode n=by.get(id);n!=null;n=n.path("parentEquipmentInstanceId").isNull()?null:by.get(text(n,"parentEquipmentInstanceId")))p.addFirst(text(n,"equipmentInstanceId"));
   out.put(id,String.join(":",p));
  }
  return out;
 }
}
