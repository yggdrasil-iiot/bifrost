package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Independent 2.25/2.26 command-binding validator: the published link between one governed member's read binding and one OPC UA
 *  Method of the same equipment. Every reference resolves inside the bundle, the read binding and the mapping set it reads
 *  belong to the equipment the link names, its device is that equipment's hierarchy path, the Method takes exactly one Double input with a UCUM unit, and no two links share a
 *  device and methodNodeId. From 2.26.0 the link also names the OPC UA server it may call: each listed certificate is a
 *  server-certificate evidence artifact in the bundle whose DER yields the listed SHA-1 thumbprint and, as its one
 *  subjectAltName URI, the link's applicationUri. */
final class CommandBindings {
 static final String KIND="command-binding";
 interface Reader {byte[] read(String path) throws Exception;}
 static void validate(Collection<JsonNode> docs,Reader files) throws Exception {
  Set<String> keys=new HashSet<>();Map<String,Set<String>> ucum=new HashMap<>();
  for(JsonNode c:docs){
   if(!text(c,"kind").equals(KIND))continue;
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
   // the mapping set's equipment too: the precondition reads that mapping, so another equipment's set would gate this Method
   require(b.equipmentInstanceId().equals(text(eq,"equipmentInstanceId"))&&text(set,"equipmentInstanceId").equals(b.equipmentInstanceId())
    &&b.device().equals(path(nodes,text(eq,"equipmentInstanceId"))),"command-binding.device-path");
   JsonNode in=c.path("method").path("inputs");
   require(in.size()==1&&!text(in.get(0),"name").isEmpty()&&text(in.get(0),"type").equals("Double")&&ucum.computeIfAbsent(text(c,"schemaVersion"),CommandBindings::ucum).contains(text(in.get(0),"unit")),"command-binding.inputs");
   if(text(c,"schemaVersion").equals("2.26.0"))endpoint(docs,c.path("endpointRef"),files);
   require(keys.add(b.device()+"\n"+text(c.path("method"),"methodNodeId")),"command-binding.duplicate");
  }
 }
 /** Every listed certificate resolves to a server-certificate artifact whose DER yields the listed thumbprint and the
  *  link's applicationUri; no certificate is listed twice. */
 private static void endpoint(Collection<JsonNode> docs,JsonNode ref,Reader files) throws Exception {
  Set<String> seen=new HashSet<>();
  for(JsonNode cert:ref.path("certificates")){
   JsonNode art=find(docs,"evidence-artifact",cert.path("certificateRef"));
   require(art!=null&&text(art,"schemaVersion").equals("1.1.0")&&text(art,"id").startsWith(ServerCertificates.ID_PREFIX)
    &&text(art.path("file"),"mediaType").equals(ServerCertificates.MEDIA_TYPE),"command-binding.endpoint");
   ServerCertificates.Parsed parsed;
   try{parsed=ServerCertificates.parse(files.read(text(art.path("file"),"path")));}
   catch(IllegalArgumentException e){throw new IllegalArgumentException("command-binding.endpoint");}
   require(parsed.thumbprintSha1().equals(text(cert,"thumbprintSha1"))&&parsed.applicationUri().equals(text(ref,"applicationUri"))
    &&seen.add(parsed.thumbprintSha1()),"command-binding.endpoint");
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
 /** The UCUM codes the link's contract version knows: the known-unit enum of that version's common schema. */
 private static Set<String> ucum(String version) {
  try(var in=CommandBindings.class.getResourceAsStream("/mapping-contracts/"+version+"/common.schema.json")){
   require(in!=null,"command-binding.inputs");
   Set<String> out=new HashSet<>();JSON.readTree(in).at("/$defs/unit/oneOf/0/properties/code/enum").forEach(x->out.add(x.asText()));
   require(!out.isEmpty(),"command-binding.inputs");return out;
  }catch(IllegalArgumentException e){throw e;}catch(Exception e){throw new IllegalArgumentException("command-binding.inputs");}
 }
}
