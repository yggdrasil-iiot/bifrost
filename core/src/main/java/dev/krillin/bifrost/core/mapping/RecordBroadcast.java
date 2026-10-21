package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Independent 2.22 finite broadcast recipe validation; no virtual values or provider execution. */
final class RecordBroadcast {
 static void basic(JsonNode r,JsonNode t,Map<String,JsonNode> slots,Set<String> bound) throws Exception {
  require(text(r.path("output"),"mode").equals("array"),"broadcast.array-required");Map<String,JsonNode> sources=new HashMap<>();
  for(JsonNode s:r.path("commonSources")){schema(s,"source-definition");require(sources.put(RecordMappings.pair(s),s)==null,"broadcast.source-duplicate");}
  Set<String> used=new HashSet<>();
  for(JsonNode b:r.path("commonBindings")){
   String sid=text(b,"slotId"),key=RecordMappings.pair(b.path("sourceRef"));require(bound.add(sid)&&slots.containsKey(sid),"record.slot-bindings");JsonNode s=sources.get(key);require(s!=null&&MappingTemplates.pin(s).equals(b.path("sourceRef")),"broadcast.source-pin");used.add(key);
   require((!s.has("viewOf")||s.path("viewOf").isNull())&&(!s.has("fixedArray")||s.path("fixedArray").isNull())&&(!s.has("recordField")||s.path("recordField").isNull()),"broadcast.direct-scalar-required");require(text(s,"status").equals("ready")&&text(s,"equipmentInstanceId").equals(text(r,"equipmentInstanceId"))&&(!s.has("accessMode")||text(s,"accessMode").equals("read")),"broadcast.source-context");require(MappingTemplates.signature(s,sources).equals(slots.get(sid).path("signature")),"broadcast.slot-signature");
  }
  require(used.equals(sources.keySet()),"broadcast.source-closure");for(JsonNode b:t.path("mapping").path("mappings"))require(!b.has("temporalPolicy"),"broadcast.frame-policy-required");
 }
 static void sourcePins(JsonNode r,Collection<JsonNode> docs){Map<String,JsonNode> sources=new HashMap<>();for(JsonNode d:docs)if(text(d,"kind").equals("source-definition"))sources.put(RecordMappings.pair(d),d);for(JsonNode s:r.path("commonSources"))require(s.equals(sources.get(RecordMappings.pair(s))),"broadcast.source-pin-mismatch");}
 static void history(Collection<JsonNode> docs,Collection<JsonNode> prior){
  Map<String,JsonNode> pinned=new HashMap<>();List<JsonNode> all=new ArrayList<>(prior);all.addAll(docs);
  for(JsonNode r:all)if(text(r,"kind").equals("record-mapping"))for(JsonNode s:r.path("commonSources")){String k=RecordMappings.pair(s);require(!pinned.containsKey(k)||pinned.get(k).equals(s),"broadcast.source-history-conflict");pinned.put(k,s);}
  for(JsonNode d:all)if(text(d,"kind").equals("source-definition")&&pinned.containsKey(RecordMappings.pair(d)))require(pinned.get(RecordMappings.pair(d)).equals(d),"broadcast.source-history-conflict");
 }
}
