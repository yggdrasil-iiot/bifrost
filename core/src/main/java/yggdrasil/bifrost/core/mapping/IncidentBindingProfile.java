package yggdrasil.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import static yggdrasil.bifrost.core.mapping.MappingJson.*;
import static yggdrasil.bifrost.core.mapping.OccupancyBindingProfile.*;
/** Bifrost's own reader of a forseti incident binding, profile 0.1.0: the data file an evidence-artifact (schemaVersion 1.1.0)
 *  carries, naming how an impact rule accepts quality incidents. Read from the published bytes alone, no forseti code. An
 *  unsupported version, a missing or extra field or an empty value is refused with the caller's code (impact.binding-profile).
 *  kinds[] is a non-empty list of distinct names; whether the incident schema supports each kind is the job's check. */
public record IncidentBindingProfile(String topic,String schemaId,String schemaSha256,List<String> kinds,String equipmentRefBasis) {
 public static final String VERSION="0.1.0",SCHEMA_ID="urn:forseti:schema:incident:1.0.0",ID_PREFIX="incident-binding-",
  MEDIA_TYPE="application/vnd.forseti.incident-binding+json";
 private static final Set<String> FIELDS=Set.of("profileVersion","topic","format","kinds","equipmentRefBasis");
 public static IncidentBindingProfile parse(byte[] bytes,String code){
  JsonNode b;
  try{b=JSON.readTree(bytes);}catch(Exception e){throw new IllegalArgumentException(code);}
  require(b!=null&&b.isObject()&&names(b).equals(FIELDS),code);
  require(text(b,"profileVersion").equals(VERSION)&&nonEmpty(b,"topic")&&text(b,"equipmentRefBasis").equals("isa95-path"),code);
  JsonNode f=b.path("format");
  require(names(f).equals(Set.of("schemaId","schemaSha256"))&&text(f,"schemaId").equals(SCHEMA_ID)&&f.path("schemaSha256").isTextual()&&text(f,"schemaSha256").matches("[0-9a-f]{64}"),code);
  return new IncidentBindingProfile(text(b,"topic"),text(f,"schemaId"),text(f,"schemaSha256"),strings(b.path("kinds"),code),text(b,"equipmentRefBasis"));
 }
}
