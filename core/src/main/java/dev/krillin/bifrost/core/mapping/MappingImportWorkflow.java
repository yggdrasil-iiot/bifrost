package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** Independent review/three-way data-contract verifier. No Týr code or parser execution. */
final class MappingImportWorkflow {
 static final Set<String> IMMUTABLE=Set.of("kind","id","version","equipmentInstanceId","status","evidenceRefs");
 static JsonNode canonical(JsonNode n){
  ArrayNode a=JSON.createArrayNode();
  if(n.isNull())return a.add("null");
  if(n.isBoolean())return a.add("boolean").add(n.asBoolean());
  if(n.isNumber()){BigDecimal d=new BigDecimal(n.asText());return a.add("number").add(d.signum()==0?"0":d.stripTrailingZeros().toPlainString());}
  if(n.isTextual())return a.add("string").add(n.asText());
  ArrayNode values=JSON.createArrayNode();
  if(n.isArray()){for(JsonNode v:n)values.add(canonical(v));return a.add("array").add(values);}
  require(n.isObject(),"workflow.json");
  List<String> keys=new ArrayList<>();n.fieldNames().forEachRemaining(keys::add);keys.sort((x,y)->Arrays.compare(x.codePoints().toArray(),y.codePoints().toArray()));
  for(String k:keys)values.add(JSON.createArrayNode().add(k).add(canonical(n.get(k))));
  return a.add("object").add(values);
 }
 static String digest(JsonNode n)throws Exception{return sha(JSON.writeValueAsString(canonical(n)).getBytes(java.nio.charset.StandardCharsets.UTF_8));}
 static JsonNode latest(JsonNode b,JsonNode o){JsonNode found=null;for(JsonNode q:b.path("reviews"))if(text(q,"observationId").equals(text(o,"id")))found=q;return found;}
 static JsonNode interpreted(JsonNode b,JsonNode o){JsonNode q=latest(b,o);return q==null?o.path("draft"):q.path("source");}
 static boolean pending(JsonNode b,JsonNode o){return latest(b,o)==null&&(!o.path("issues").isEmpty()||o.path("draft").isNull());}
 static String recordKey(JsonNode b,JsonNode o){JsonNode q=latest(b,o);return q!=null&&text(q,"decision").equals("resolve-source")?text(q,"recordKey"):text(o.path("raw"),"id");}
 static ArrayNode refs(JsonNode b,JsonNode o){ArrayNode a=JSON.createArrayNode();for(JsonNode l:o.path("derivation")){ObjectNode e=object();e.put("artifactId","import-"+text(b,"id"));e.set("locator",l);a.add(e);}return a;}
 static ObjectNode project(JsonNode d,String label){ObjectNode a=object();d.fields().forEachRemaining(e->{if(!IMMUTABLE.contains(e.getKey()))a.set(e.getKey(),e.getValue());});a.put("label",label);return a;}
 static JsonNode wrap(JsonNode d,String key){ObjectNode a=object();a.put("present",d.has(key));if(d.has(key))a.set("value",d.get(key));return a;}
 static ArrayNode diff(JsonNode base,JsonNode ours,JsonNode incoming){
  Set<String> keys=new TreeSet<>();for(JsonNode d:List.of(base,ours,incoming))d.fieldNames().forEachRemaining(keys::add);
  ArrayNode fs=JSON.createArrayNode();
  for(String k:keys){JsonNode a=wrap(base,k),b=wrap(ours,k),c=wrap(incoming,k);ObjectNode f=object();f.put("field",k);f.set("base",a);f.set("ours",b);f.set("incoming",c);f.put("conflict",!b.equals(a)&&!c.equals(a)&&!b.equals(c));f.put("suggested",c.equals(a)?"ours":"incoming");fs.add(f);}return fs;
 }
 static void metadata(JsonNode q){require(!text(q,"reviewer").isBlank()&&!text(q,"reason").isBlank(),"review.metadata");String at=text(q,"reviewedAt");require(at.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})")&&!at.endsWith("-00:00"),"review.timestamp");OffsetDateTime.parse(at);}
 static String label(JsonNode o,JsonNode d){return o.path("raw").path("label").isTextual()&&!text(o.path("raw"),"label").isEmpty()?text(o.path("raw"),"label"):text(d,"id");}
 static ArrayNode entries(JsonNode old,JsonNode rows){
  if(!old.path("adoptions").isEmpty())return (ArrayNode)old.path("adoptions").deepCopy();
  ArrayNode a=JSON.createArrayNode();
  for(JsonNode row:rows)if(text(row.path("importRef"),"batchId").equals(text(old,"id"))){
   JsonNode o=find(old.path("observations"),"id",text(row.path("importRef"),"observationId")),d=interpreted(old,o);
   require(!d.isNull(),"merge.base-unresolved");ObjectNode e=object();e.put("observationId",text(o,"id"));e.put("recordKey",recordKey(old,o));e.put("sourceId",text(row.path("definition"),"id"));e.set("imported",project(d,label(o,d)));a.add(e);
  }return a;
 }
 static JsonNode find(JsonNode values,String key,String id){for(JsonNode n:values)if(text(n,key).equals(id))return n;throw new IllegalArgumentException("import.reference-missing");}
 static ObjectNode plan(JsonNode old,JsonNode b,JsonNode rec)throws Exception{
  require(!text(old,"id").equals(text(b,"id"))&&text(old,"format").equals(text(b,"format"))&&text(old,"equipmentInstanceId").equals(text(b,"equipmentInstanceId")),"merge.context");
  require(!b.has("fileIssue"),"merge.new-batch-not-pristine");
  ArrayNode entries=entries(old,rec.path("ours"));require(!entries.isEmpty(),"merge.no-adopted-base");
  Map<String,JsonNode> byKey=new LinkedHashMap<>(),rows=new HashMap<>();
  for(JsonNode e:entries)require(byKey.putIfAbsent(text(e,"recordKey"),e)==null,"merge.ambiguous-base");
  for(JsonNode row:rec.path("ours")){schema(row.path("definition"),"source-definition");require(rows.putIfAbsent(text(row.path("definition"),"id"),row)==null,"merge.duplicate-source");}
  Set<String> seen=new HashSet<>();ArrayNode actions=JSON.createArrayNode();
  for(JsonNode o:b.path("observations")){
   String k=recordKey(b,o);if(k.isEmpty())k=text(o,"id");require(seen.add(k),"merge.ambiguous-key");JsonNode e=byKey.get(k),d=interpreted(b,o);
   JsonNode inc=d.isNull()?NullNode.instance:project(d,label(o,d)),ours=NullNode.instance,base=NullNode.instance;
   if(e!=null){
    JsonNode row=rows.get(text(e,"sourceId"));require(row!=null,"merge.base-source-missing");
    ours=project(row.path("definition"),text(row,"label"));base=e.path("imported");
    if(!e.path("observationId").isNull())require(text(row.path("importRef"),"batchId").equals(text(old,"id"))&&text(row.path("importRef"),"observationId").equals(text(e,"observationId")),"merge.base-not-current");
    if(!inc.isNull()&&text(inc,"label").equals(text(d,"id")))((ObjectNode)inc).put("label",text(e,"sourceId"));
   }
   ArrayNode fs=base.isNull()||inc.isNull()?JSON.createArrayNode():diff(base,ours,inc);
   boolean conflict=false;for(JsonNode f:fs)conflict|=f.path("conflict").asBoolean();
   JsonNode review=latest(b,o);String cls=review!=null&&text(review,"decision").equals("exclude-non-source")?"excluded":pending(b,o)?"unresolved":e==null?"new":conflict?"conflict":base.equals(ours)&&ours.equals(inc)?"unchanged":ours.equals(base)?"incoming-only":inc.equals(base)?"local-only":ours.equals(inc)?"both-same":"mergeable";
   ObjectNode action=object();action.put("key",k);action.put("observationId",text(o,"id"));action.put("recordKey",k);action.put("sourceId",e!=null?text(e,"sourceId"):d.isNull()?"imp-"+text(b,"id")+"-"+k:text(d,"id"));action.put("classification",cls);action.set("base",base);action.set("ours",ours);action.set("incoming",inc);action.set("fields",fs);actions.add(action);
  }
  for(var en:byKey.entrySet())if(!seen.contains(en.getKey())){
   JsonNode e=en.getValue(),row=rows.get(text(e,"sourceId"));require(row!=null,"merge.base-source-missing");
   ObjectNode a=object();a.put("key",en.getKey());a.putNull("observationId");a.put("recordKey",en.getKey());a.put("sourceId",text(e,"sourceId"));a.put("classification","removed");a.set("base",e.path("imported"));a.set("ours",project(row.path("definition"),text(row,"label")));a.putNull("incoming");a.set("fields",JSON.createArrayNode());actions.add(a);
  }
  ObjectNode p=object();ObjectNode ref=object();ref.put("id",text(old,"id"));ref.put("version",text(old,"version"));p.set("previousBatchRef",ref);p.put("previousBatchSha256",digest(old));p.set("workspaceSha256",rec.path("workspaceSha256"));p.set("ours",rec.path("ours"));p.set("actions",actions);p.put("planSha256",digest(p));return p;
 }
 static ObjectNode results(JsonNode p,JsonNode choices){
  Set<String> wanted=new HashSet<>();for(JsonNode a:p.path("actions"))wanted.add(text(a,"key"));
  Set<String> supplied=new HashSet<>();choices.fieldNames().forEachRemaining(supplied::add);require(wanted.equals(supplied),"merge.choices-incomplete");
  ObjectNode results=object();
  for(JsonNode a:p.path("actions")){
   String k=text(a,"key"),cls=text(a,"classification");JsonNode q=choices.path(k);String mode=text(q,"mode");
   if(cls.equals("removed")){require(mode.equals("retain")&&q.path("fields").isEmpty(),"merge.removal-policy");results.set(k,a.path("ours"));continue;}
   if(mode.equals("retain")){require(!Set.of("new","excluded","unresolved").contains(cls)&&!a.path("ours").isNull()&&q.path("fields").isEmpty(),"merge.retain-policy");results.set(k,a.path("ours"));continue;}
   if(mode.equals("skip")){require(Set.of("new","excluded").contains(cls)&&q.path("fields").isEmpty(),"merge.skip-policy");results.putNull(k);continue;}
   require(mode.equals("apply")&&!Set.of("unresolved","excluded").contains(cls),"merge.unresolved");
   Set<String> conflict=new HashSet<>(),actual=new HashSet<>();for(JsonNode f:a.path("fields"))if(f.path("conflict").asBoolean())conflict.add(text(f,"field"));q.path("fields").fieldNames().forEachRemaining(actual::add);require(conflict.equals(actual),"merge.conflicts-unresolved");
   ObjectNode value=object();
   if(cls.equals("new"))value=(ObjectNode)a.path("incoming").deepCopy();
   else for(JsonNode f:a.path("fields")){
    String field=text(f,"field"),choice=q.path("fields").has(field)?text(q.path("fields"),field):text(f,"suggested");require(Set.of("ours","incoming").contains(choice),"merge.field-choice");JsonNode picked=f.path(choice);if(picked.path("present").asBoolean())value.set(field,picked.path("value"));
   }
   results.set(k,value);
  }return results;
 }
 static boolean validate(JsonNode b,Map<String,JsonNode> docs)throws Exception{
  if(!text(b,"schemaVersion").equals("2.14.0")){
   if(b.has("fileIssue"))return false;for(JsonNode o:b.path("observations"))if(pending(b,o))return false;return true;
  }
  Map<String,JsonNode> latest=new HashMap<>();
  for(JsonNode q:b.path("reviews")){
   metadata(q);JsonNode o=find(b.path("observations"),"id",text(q,"observationId"));require(text(q,"observationSha256").equals(digest(o)),"review.observation-stale");
   JsonNode prev=latest.get(text(o,"id"));require(prev==null?q.path("previousReviewSha256").isNull():text(q,"previousReviewSha256").equals(digest(prev)),"review.decision-chain");
   if(text(q,"decision").equals("resolve-source")){
    JsonNode d=q.path("source");schema(d,"source-definition");
    require(text(d,"status").equals("draft")&&text(d,"version").equals("1.0.0"),"review.draft-required");
    require(text(d,"id").equals("imp-"+text(b,"id")+"-"+text(q,"recordKey")),"review.source-id");
    require(text(d,"equipmentInstanceId").equals(text(b,"equipmentInstanceId"))&&d.path("evidenceRefs").equals(refs(b,o)),"review.source-evidence");
    require(!text(d.path("unit"),"status").equals("unknown"),"review.incomplete-source");
    require((!d.has("sourceKind")||text(d,"sourceKind").equals("plc"))&&(!d.has("accessMode")||text(d,"accessMode").equals("read"))&&(!d.has("viewOf")||d.path("viewOf").isNull()),"review.plc-read-only");
    boolean connection=false;for(JsonNode c:b.path("contextConnections"))connection|=text(c,"id").equals(text(d,"connectionProfileRef"))&&text(c,"accessProfileRef").equals(text(d,"accessProfileRef"))&&text(c,"equipmentInstanceId").equals(text(d,"equipmentInstanceId"));require(connection,"review.connection");
   }else require(text(q,"decision").equals("exclude-non-source")&&q.path("source").isNull()&&q.path("recordKey").isNull(),"review.exclusion");
   latest.put(text(o,"id"),q);
  }
  Set<String> keys=new HashSet<>(),sourceIds=new HashSet<>(),obIds=new HashSet<>();
  for(JsonNode o:b.path("observations")){
   JsonNode q=latest(b,o);if(q!=null&&text(q,"decision").equals("exclude-non-source"))continue;
   if(!pending(b,o))require(!recordKey(b,o).isEmpty()&&keys.add(recordKey(b,o)),"review.duplicate-key");
  }
  JsonNode rec=b.path("reconciliation");
  for(JsonNode a:b.path("adoptions")){
   require(sourceIds.add(text(a,"sourceId")),"merge.duplicate-adoption");
   if(a.path("observationId").isNull()){require(!rec.isNull(),"merge.retained-without-plan");continue;}
   require(obIds.add(text(a,"observationId")),"merge.duplicate-adoption");
   JsonNode o=find(b.path("observations"),"id",text(a,"observationId")),d=interpreted(b,o);require(!d.isNull(),"import.unresolved-adoption");
   if(rec.isNull())require(text(a,"sourceId").equals(text(d,"id"))&&text(a,"recordKey").equals(recordKey(b,o))&&a.path("imported").equals(project(d,label(o,d))),"merge.adoption-mismatch");
  }
  if(!rec.isNull()){
   metadata(rec);JsonNode old=docs.get("import-batch:"+text(rec.path("previousBatchRef"),"id")+"@"+text(rec.path("previousBatchRef"),"version"));require(old!=null,"merge.previous-missing");
   ObjectNode p=plan(old,b,rec);p.fields().forEachRemaining(e->require(e.getValue().equals(rec.path(e.getKey())),"merge.plan-mismatch"));
   ObjectNode result=results(p,rec.path("choices"));require(result.equals(rec.path("results")),"merge.result-mismatch");
   ArrayNode expected=JSON.createArrayNode();
   for(JsonNode a:p.path("actions"))if(text(a,"classification").equals("removed")||!result.path(text(a,"key")).isNull()){
    ObjectNode e=object();e.set("observationId",a.path("observationId"));e.set("recordKey",a.path("recordKey"));e.set("sourceId",a.path("sourceId"));e.set("imported",text(a,"classification").equals("removed")?a.path("base"):a.path("incoming"));expected.add(e);
   }
   require(expected.equals(b.path("adoptions")),"merge.adoption-mismatch");
  }
  if(b.has("fileIssue"))return false;for(JsonNode o:b.path("observations"))if(pending(b,o))return false;return true;
 }
}
