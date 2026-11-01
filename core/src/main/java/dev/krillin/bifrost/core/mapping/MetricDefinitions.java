package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import java.util.regex.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Independent 2.24 metric-definition validator: one Apache Ossie metric over one record-mapping result in the same bundle.
 *  The SQL is not executed or parsed here; only identifiers outside string literals are read to see that every input is used. */
final class MetricDefinitions {
 static final String KIND="metric-definition";
 private static final Pattern LITERAL=Pattern.compile("'(?:[^']|'')*'"),IDENTIFIER=Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");
 static Set<String> identifiers(String sql){
  Set<String> out=new HashSet<>();Matcher m=IDENTIFIER.matcher(LITERAL.matcher(sql).replaceAll("''"));
  while(m.find())out.add(m.group().toLowerCase(Locale.ROOT));return out;
 }
 static void validate(Collection<JsonNode> docs){
  Map<String,JsonNode> records=new HashMap<>();Set<String> names=new HashSet<>();
  for(JsonNode d:docs)if(text(d,"kind").equals("record-mapping"))records.put(text(d,"id")+"@"+text(d,"version"),d);
  for(JsonNode m:docs){
   if(!text(m,"kind").equals(KIND))continue;
   JsonNode ref=m.path("dataset").path("recordMappingRef"),r=records.get(text(ref,"id")+"@"+text(ref,"version"));
   require(r!=null,"metric.dataset-missing");
   Map<String,JsonNode> fields=new HashMap<>();for(JsonNode f:r.path("resultSchema").path("fields"))fields.put(text(f,"fieldId"),f);
   Set<String> inputs=new LinkedHashSet<>(),group=new LinkedHashSet<>();
   for(JsonNode i:m.path("inputs"))inputs.add(i.asText());
   for(JsonNode g:m.path("grain").path("groupBy"))group.add(g.asText());
   require(fields.keySet().containsAll(inputs),"metric.input-missing");
   require(inputs.containsAll(group),"metric.grain-input");
   for(String g:group)require(text(fields.get(g),"valueType").equals("String")&&!fields.get(g).path("nullable").asBoolean(),"metric.grain-key");
   Set<String> read=identifiers(text(m.path("ossie").path("metric").path("expression"),"sql"));
   for(String i:inputs)require(read.contains(i)||group.contains(i),"metric.input-unreferenced");
   require(text(m.path("result").path("unit"),"status").equals("known"),"metric.unit-unconfirmed");
   require(names.add(text(m.path("ossie").path("metric"),"name")),"metric.duplicate-name");
  }
 }
}
