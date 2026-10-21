package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Independent pinned record-field source validator; no SQL/runtime input access. */
final class RecordFields {
 static boolean isField(JsonNode s){return text(s,"schemaVersion").equals("2.21.0")||s.has("recordField");}
 static void validate(Collection<JsonNode> docs) throws Exception {
  Map<String,JsonNode> records=new HashMap<>();for(JsonNode d:docs)if(text(d,"kind").equals("record-mapping"))records.put(RecordMappings.pair(d),d);
  for(JsonNode s:docs){if(!text(s,"kind").equals("source-definition")||!isField(s))continue;schema(s,"source-definition");require(text(s,"schemaVersion").equals("2.21.0"),"record-field.schema");JsonNode b=s.path("recordField"),ref=b.path("recordMappingRef"),r=records.get(RecordMappings.pair(ref));require(r!=null,"record-field.record-missing");require(ref.equals(RecordMappings.pin(r)),"record-field.record-pin");require(text(r.path("output"),"mode").equals("object")&&r.path("output").path("maxRows").asInt()==1,"record-field.object-required");require(text(s,"equipmentInstanceId").equals(text(r,"equipmentInstanceId")),"record-field.equipment");JsonNode f=RecordMappings.fields(r).get(text(b,"fieldId"));require(f!=null,"record-field.field-missing");require(s.path("rawRepresentation").equals(object().put("mode","typed").put("valueType",text(f,"valueType")))&&s.path("unit").equals(f.path("unit"))&&text(s,"inputStage").equals(text(f,"inputStage")),"record-field.signature");ObjectNode a=object().put("kind","external-value").put("providerRef",text(r.path("resultSchema"),"providerRef")).put("valueKey",text(r.path("resultSchema"),"valueKey")+"."+text(f,"fieldId")).put("expressionLanguage","none").putNull("expression");require(s.path("access").equals(a),"record-field.provider");boolean reject=text(b,"nullPolicy").equals("reject");require(reject?b.path("defaultValue").isNull():f.path("nullable").asBoolean()&&!b.path("defaultValue").isNull(),"record-field.null-policy");if(!reject)RecordMappings.defaultValue(f,b.path("defaultValue"));
  }
 }
 static void history(Collection<JsonNode> docs,Collection<JsonNode> prior){
  Map<String,JsonNode> pinned=new HashMap<>();for(JsonNode s:prior)if(text(s,"kind").equals("source-definition")&&isField(s)){String k=RecordMappings.pair(s);require(!pinned.containsKey(k)||pinned.get(k).equals(s),"record-field.history-conflict");pinned.put(k,s);}
  for(JsonNode s:docs)if(text(s,"kind").equals("source-definition")&&pinned.containsKey(RecordMappings.pair(s)))require(pinned.get(RecordMappings.pair(s)).equals(s),"record-field.history-conflict");
 }
}
