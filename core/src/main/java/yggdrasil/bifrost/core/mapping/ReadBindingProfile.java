package yggdrasil.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import static yggdrasil.bifrost.core.mapping.MappingJson.*;
/** Bifrost's own reader of a Vor read binding, profile 0.1.0: the data file an evidence-artifact (schemaVersion 1.1.0)
 *  carries, naming where Muninn publishes one governed member. Read from the published bytes alone, no Vor code. An
 *  unsupported profileVersion or projection, a missing or extra field, or a field of the wrong type is refused with the
 *  caller's code. */
public record ReadBindingProfile(String streamId,String mappingSetId,String mappingSetVersion,String mappingId,String equipmentInstanceId,
                                 String semanticId,String group,String edge,String device,String metric,
                                 String templateRef,String templateVersion,String templateSha256) {
 public static final String VERSION="0.1.0";
 private static final Set<String> FIELDS=Set.of("profileVersion","streamId","mappingSetRef","mappingId","equipmentInstanceId","semanticId",
  "group","edge","device","metric","governedDefinitionRef","projection");
 public static ReadBindingProfile parse(byte[] bytes,String code){
  JsonNode b;
  try{b=JSON.readTree(bytes);}catch(Exception e){throw new IllegalArgumentException(code);}
  require(b!=null&&b.isObject(),code);
  Set<String> names=new HashSet<>();b.fieldNames().forEachRemaining(names::add);
  require(names.equals(FIELDS)&&text(b,"profileVersion").equals(VERSION)&&text(b,"projection").equals("identity"),code);
  for(String k:List.of("streamId","mappingId","equipmentInstanceId","semanticId","group","edge","device","metric"))require(nonEmpty(b,k),code);
  JsonNode set=b.path("mappingSetRef"),def=b.path("governedDefinitionRef");
  require(set.isObject()&&set.size()==2&&nonEmpty(set,"id")&&nonEmpty(set,"version"),code);
  require(def.isObject()&&def.size()==3&&nonEmpty(def,"templateRef")&&nonEmpty(def,"version")&&text(def,"sha256").matches("[0-9a-f]{64}"),code);
  return new ReadBindingProfile(text(b,"streamId"),text(set,"id"),text(set,"version"),text(b,"mappingId"),text(b,"equipmentInstanceId"),
   text(b,"semanticId"),text(b,"group"),text(b,"edge"),text(b,"device"),text(b,"metric"),text(def,"templateRef"),text(def,"version"),text(def,"sha256"));
 }
 private static boolean nonEmpty(JsonNode n,String k){return n.path(k).isTextual()&&!n.path(k).asText().isEmpty();}
}
