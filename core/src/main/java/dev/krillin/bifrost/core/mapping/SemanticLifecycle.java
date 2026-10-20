package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.util.*;
import java.time.OffsetDateTime;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** Independent bounded URI lifecycle receiver. Immutable meaning signatures remain mandatory. */
final class SemanticLifecycle {
 static Map<String,JsonNode> signatures(Collection<JsonNode> docs){
  Map<String,JsonNode> out=new TreeMap<>();
  for(JsonNode d:docs)if(text(d,"kind").equals("semantic-definition"))for(JsonNode n:LogicalStructure.layout(d).definitions()){
   String uri=text(n,"semanticId");JsonNode sig=LogicalStructure.signature(n);require(!out.containsKey(uri)||out.get(uri).equals(sig),"lifecycle.signature-conflict");out.put(uri,sig);
  }return out;
 }
 static Map<String,ObjectNode> replay(Collection<JsonNode> events,Map<String,JsonNode> known) throws Exception {
  Map<String,JsonNode> unique=new TreeMap<>();Map<String,List<JsonNode>> grouped=new TreeMap<>();
  for(JsonNode e:events){schema(e,"semantic-lifecycle");require(!text(e,"authoredAt").endsWith("-00:00"),"lifecycle.timestamp");OffsetDateTime.parse(text(e,"authoredAt"));String k=text(e,"id")+"@"+text(e,"version");require(!unique.containsKey(k)||unique.get(k).equals(e),"lifecycle.event-conflict");unique.put(k,e);}
  require(unique.size()<=1024,"lifecycle.limit");for(JsonNode e:unique.values())grouped.computeIfAbsent(text(e,"semanticId"),k->new ArrayList<>()).add(e);
  Map<String,ObjectNode> states=new TreeMap<>();
  for(var group:grouped.entrySet()){
   String uri=group.getKey();require(known.containsKey(uri),"lifecycle.uri-missing");List<JsonNode> history=group.getValue();history.sort(Comparator.comparingInt(e->e.path("revision").asInt()));String state="active";JsonNode previous=null,replacement=JSON.nullNode();int i=0;
   for(JsonNode e:history){
    require(e.path("revision").asInt()==++i,"lifecycle.revision-conflict");JsonNode ref=JSON.nullNode();
    if(previous!=null)ref=object().put("id",text(previous,"id")).put("version",text(previous,"version")).put("sha256",sha(bytes(previous)));
    require(e.path("previousEvent").equals(ref),"lifecycle.previous-conflict");require(text(e,"signatureSha256").equals(sha(bytes(known.get(uri)))),"lifecycle.signature-drift");
    require(previous==null||!OffsetDateTime.parse(text(e,"authoredAt")).toInstant().isBefore(OffsetDateTime.parse(text(previous,"authoredAt")).toInstant()),"lifecycle.time-order");
    require(!state.equals("retired"),"lifecycle.retired-terminal");String action=text(e,"action");
    if(action.equals("deprecate")){require(state.equals("active"),"lifecycle.transition");state="deprecated";}
    else if(action.equals("retire")){require(state.equals("deprecated"),"lifecycle.transition");state="retired";}
    if(action.equals("revise")||action.equals("retire"))require(e.path("replacementSemanticId").equals(replacement),"lifecycle.replacement-immutable");else replacement=e.path("replacementSemanticId");
    require(replacement.isNull()||!replacement.asText().equals(uri)&&known.containsKey(replacement.asText()),"lifecycle.replacement-missing");previous=e;
   }
   ObjectNode s=object().put("semanticId",uri).put("state",state).put("revision",i);s.set("replacementSemanticId",replacement);s.set("history",JSON.valueToTree(history));states.put(uri,s);
  }
  for(var group:states.entrySet()){
   Set<String> seen=new HashSet<>();seen.add(group.getKey());JsonNode next=group.getValue().path("replacementSemanticId");
   while(!next.isNull()){
    String uri=next.asText();require(seen.add(uri),"lifecycle.replacement-cycle");ObjectNode s=states.get(uri);if(s==null)break;require(!text(s,"state").equals("retired"),"lifecycle.replacement-retired");next=s.path("replacementSemanticId");
   }
  }return states;
 }
 static ArrayNode impacts(Collection<JsonNode> docs){
  Map<String,JsonNode> index=new HashMap<>();for(JsonNode d:docs)index.put(text(d,"kind")+":"+text(d,"id")+"@"+text(d,"version"),d);ArrayNode out=JSON.createArrayNode();
  for(JsonNode d:docs){String kind=text(d,"kind");if(!Set.of("mapping-set","write-definition").contains(kind))continue;
   JsonNode ref=d.path("targetInstanceRef"),target=index.get("target-instance:"+text(ref,"id")+"@"+text(ref,"version"));if(target==null)continue;
   ref=target.path("semanticDefinitionRef");JsonNode sem=index.get("semantic-definition:"+text(ref,"id")+"@"+text(ref,"version"));if(sem==null)continue;
   Iterable<JsonNode> bindings=kind.equals("mapping-set")?d.path("mappings"):List.of(d);
   for(JsonNode b:bindings){JsonNode nodes=sem.path("members");for(JsonNode step:b.path("memberPath")){
    if(!text(step,"kind").equals("member"))continue;JsonNode found=null;for(JsonNode n:nodes)if(text(n,"memberId").equals(text(step,"memberId")))found=n;if(found==null)break;
    ObjectNode impact=object().put("semanticId",text(found,"semanticId")).put("kind",kind).put("id",text(d,"id")).put("version",text(d,"version")).put("bindingId",b.has("mappingId")?text(b,"mappingId"):text(d,"id")).put("targetInstanceId",text(target,"id")).put("equipmentInstanceId",text(d,"equipmentInstanceId"));impact.set("memberPath",b.path("memberPath"));out.add(impact);nodes=found.path("members");
   }}
  }return out;
 }
 static Map<String,ObjectNode> validate(Collection<JsonNode> docs,Collection<JsonNode> history,Map<String,JsonNode> known) throws Exception {
  Map<String,JsonNode> sigs=new TreeMap<>(known);for(var e:signatures(docs).entrySet()){require(!sigs.containsKey(e.getKey())||sigs.get(e.getKey()).equals(e.getValue()),"lifecycle.signature-drift");sigs.put(e.getKey(),e.getValue());}
  List<JsonNode> events=new ArrayList<>(history);for(JsonNode d:docs)if(text(d,"kind").equals("semantic-lifecycle"))events.add(d);var states=replay(events,sigs);
  for(JsonNode impact:impacts(docs)){JsonNode state=states.get(text(impact,"semanticId"));require(state==null||!text(state,"state").equals("retired"),"lifecycle.retired-binding:"+text(impact,"id")+"/"+text(impact,"bindingId"));}
  return states;
 }
}
