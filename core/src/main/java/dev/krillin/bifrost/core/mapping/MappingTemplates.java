package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.util.*;
import java.time.OffsetDateTime;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** Independent recipe compiler/receiver. Consumes wire records only; never invokes Tyr. */
final class MappingTemplates {
 static final Set<String> KINDS=Set.of("mapping-template","template-application");
 static String key(JsonNode d){return text(d,"kind")+":"+text(d,"id")+"@"+text(d,"version");}
 static String pair(JsonNode r){return text(r,"id")+"@"+text(r,"version");}
 static ObjectNode pin(JsonNode d) throws Exception{return object().put("id",text(d,"id")).put("version",text(d,"version")).put("sha256",sha(bytes(d)));}
 static Set<String> sourceClosure(Collection<JsonNode> refs,Map<String,JsonNode> sources){
  Set<String> found=new HashSet<>();List<JsonNode> pending=new ArrayList<>(refs);while(!pending.isEmpty()){JsonNode r=pending.remove(pending.size()-1);String k=pair(r);require(sources.containsKey(k),"template.view-parent-missing");if(!found.add(k))continue;require(found.size()<=128,"template.source-snapshot-limit");JsonNode parent=sources.get(k).path("viewOf");if(!parent.isMissingNode()&&!parent.isNull())pending.add(parent);}return found;
 }
 static ObjectNode signature(JsonNode s,Map<String,JsonNode> sources){
  String type=text(s.path("rawRepresentation"),"valueType");if(s.hasNonNull("fixedArray"))type="FixedArray";
  else {Set<String> seen=new HashSet<>();JsonNode current=s;boolean bit=false;while(true){require(seen.add(pair(current))&&seen.size()<=17,"template.view-cycle");bit|=text(current.path("view"),"kind").equals("bit");JsonNode parent=current.path("viewOf");if(parent.isMissingNode()||parent.isNull())break;current=sources.get(pair(parent));require(current!=null,"template.view-parent-missing");}type=bit||current.path("access").hasNonNull("bitOffset")?"Boolean":text(current.path("rawRepresentation").path("codec"),"kind").equals("bcd16")?"Int32":text(current.path("rawRepresentation"),"valueType");}
  ObjectNode o=object();o.set("rawRepresentation",object().put("valueType",type));for(String k:List.of("unit","inputStage","fixedArray"))o.set(k,s.has(k)?s.get(k):JSON.nullNode());return o;
 }
 interface Visitor{boolean visit(ObjectNode p,String k,JsonNode v) throws Exception;}
 static void walk(JsonNode n,Visitor visitor) throws Exception {
  if(n.isObject()){List<String> names=new ArrayList<>();n.fieldNames().forEachRemaining(names::add);for(String k:names){JsonNode v=n.get(k);if(!visitor.visit((ObjectNode)n,k,v))walk(v,visitor);}}
  else if(n.isArray())for(JsonNode x:n)walk(x,visitor);
 }
 static void time(JsonNode d){String s=text(d,"authoredAt");require(!s.endsWith("-00:00"),"template.timestamp");OffsetDateTime.parse(s);}
 static void template(JsonNode t) throws Exception {
  schema(t,"mapping-template");time(t);for(String p:text(t,"version").split("\\."))try{Integer.parseInt(p);}catch(NumberFormatException e){throw new IllegalArgumentException("template.version");}
  Set<String> slots=new HashSet<>(),refs=new HashSet<>(),graphs=new HashSet<>();for(JsonNode s:t.path("slots"))require(slots.add(text(s,"slotId"))&&refs.add(pair(s.path("sourceRef"))),"template.slot-duplicate");
  int count=0;for(JsonNode g:t.path("graphs")){require(graphs.add(pair(g)),"template.graph-limit");count+=g.path("nodes").size();}require(count<=1024,"template.graph-limit");
  GraphDependencies.order(list(t.path("graphs")));LogicalStructure.layout(t.path("model"));
  require(t.path("target").path("semanticDefinitionRef").equals(object().put("id",text(t.path("model"),"id")).put("version",text(t.path("model"),"version"))),"template.model-ref");
  require(t.path("mapping").path("targetInstanceRef").equals(object().put("id",text(t.path("target"),"id")).put("version",text(t.path("target"),"version"))),"template.target-ref");
  Visitor check=(parent,k,v)->{if(k.equals("sourceRef")){require(refs.contains(pair(v)),"template.slot-reference");return true;}if(k.equals("graphRef")){require(graphs.contains(pair(v)),"template.graph-reference");return true;}return false;};
  for(JsonNode g:t.path("graphs"))walk(g,check);walk(t.path("mapping"),check);
  List<JsonNode> prototypes=new ArrayList<>(list(t.path("graphs")));prototypes.add(t.path("model"));prototypes.add(t.path("target"));prototypes.add(t.path("mapping"));
  ArrayNode ev=JSON.createArrayNode();ObjectNode e=object().put("artifactId","template-prototype");e.set("locator",object().put("kind","text-line").put("line",1));ev.add(e);
  for(JsonNode d:prototypes){JsonNode c=d.deepCopy();walk(c,(p,k,v)->{if(k.equals("evidenceRefs")){p.set(k,ev);return true;}return false;});schema(c,text(c,"kind"));}
 }
 static List<JsonNode> list(JsonNode array){List<JsonNode> out=new ArrayList<>();array.forEach(out::add);return out;}
 static ArrayNode compile(JsonNode t,JsonNode a) throws Exception {
  template(t);schema(a,"template-application");time(a);require(a.path("templateRef").equals(pin(t)),"template.pin-mismatch");
  String id=text(a,"applicationId");int revision=a.path("revision").asInt();require(text(a,"id").equals("application-"+id+"-r"+revision)&&text(a,"version").equals("1.0.0"),"template.application-identity");
  Map<String,JsonNode> bindings=new HashMap<>(),sources=new HashMap<>(),substitutions=new HashMap<>();Set<String> slotIds=new HashSet<>(),sourceIds=new HashSet<>();
  for(JsonNode b:a.path("bindings")){require(bindings.put(text(b,"slotId"),b.path("sourceRef"))==null,"template.bindings");sourceIds.add(pair(b.path("sourceRef")));}
  for(JsonNode s:a.path("sourceSnapshots")){schema(s,"source-definition");require(sources.put(pair(s),s)==null,"template.source-snapshots");}
  require(sources.keySet().equals(sourceClosure(bindings.values(),sources)),"template.source-snapshots");Map<String,JsonNode> evidence=new TreeMap<>();
  for(JsonNode slot:t.path("slots")){
   String sid=text(slot,"slotId");slotIds.add(sid);JsonNode ref=bindings.get(sid);require(ref!=null,"template.bindings");JsonNode s=sources.get(pair(ref));
   require(s!=null&&text(s,"kind").equals("source-definition")&&text(s,"status").equals("ready")&&text(s,"equipmentInstanceId").equals(text(a,"equipmentInstanceId")),"template.source-context");
   require(signature(s,sources).equals(slot.path("signature")),"template.slot-incompatible:"+sid);substitutions.put(pair(slot.path("sourceRef")),ref);
   for(JsonNode e:s.path("evidenceRefs"))evidence.put(sha(bytes(e)),e);
  }
  require(bindings.keySet().equals(slotIds),"template.bindings");for(JsonNode source:sources.values()){require(text(source,"status").equals("ready")&&text(source,"equipmentInstanceId").equals(text(a,"equipmentInstanceId")),"template.source-context");for(JsonNode e:source.path("evidenceRefs"))evidence.put(sha(bytes(e)),e);}require(!evidence.isEmpty(),"template.evidence-required");ArrayNode ev=JSON.createArrayNode();evidence.values().forEach(ev::add);
  String prefix="reuse-"+id,generation=prefix+"-r"+revision,version="1.0."+(revision-1);ObjectNode model=t.path("model").deepCopy();model.put("id",generation+"-model").put("version",version);
  ObjectNode target=t.path("target").deepCopy();target.put("id",prefix+"-target").put("version",version).put("equipmentInstanceId",text(a,"equipmentInstanceId")).put("label",text(a,"targetLabel"));target.set("semanticDefinitionRef",object().put("id",text(model,"id")).put("version",version));
  List<JsonNode> graphs=new ArrayList<>();for(JsonNode g:t.path("graphs"))graphs.add(g.deepCopy());graphs.sort(Comparator.comparing((JsonNode g)->text(g,"id")).thenComparing(g->text(g,"version")));Map<String,JsonNode> gr=new HashMap<>();int i=0;for(JsonNode g:graphs)gr.put(pair(g),object().put("id",generation+"-g"+(i++)).put("version",version));
  ObjectNode mapping=t.path("mapping").deepCopy();mapping.put("id",prefix+"-mapping").put("version",version).put("equipmentInstanceId",text(a,"equipmentInstanceId"));mapping.set("targetInstanceRef",object().put("id",text(target,"id")).put("version",version));
  for(JsonNode b:mapping.path("mappings"))((ObjectNode)b).put("mappingId",prefix+"-b"+sha(bytes(b.path("memberPath"))).substring(0,12));
  for(JsonNode g:graphs){JsonNode r=gr.get(pair(g));((ObjectNode)g).put("id",text(r,"id")).put("version",version).put("equipmentInstanceId",text(a,"equipmentInstanceId"));}
  ArrayNode generated=JSON.createArrayNode().add(model).add(target);graphs.forEach(generated::add);generated.add(mapping);
  for(JsonNode d:generated)walk(d,(p,k,v)->{if(k.equals("sourceRef")){JsonNode r=substitutions.get(pair(v));require(r!=null,"template.slot-reference");p.set(k,r.deepCopy());return true;}if(k.equals("graphRef")){JsonNode r=gr.get(pair(v));require(r!=null,"template.graph-reference");p.set(k,r.deepCopy());return true;}if(k.equals("evidenceRefs")){p.set(k,ev.deepCopy());return true;}return false;});
  return generated;
 }
 static int compareVersion(JsonNode a,JsonNode b){String[] x=text(a,"version").split("\\."),y=text(b,"version").split("\\.");for(int i=0;i<3;i++){int c=Integer.compare(Integer.parseInt(x[i]),Integer.parseInt(y[i]));if(c!=0)return c;}return 0;}
 record History(Map<String,List<JsonNode>> templates,Map<String,List<JsonNode>> apps){}
 static History histories(Collection<JsonNode> documents) throws Exception {
  Map<String,JsonNode> unique=new TreeMap<>();for(JsonNode d:documents)if(KINDS.contains(text(d,"kind"))){schema(d,text(d,"kind"));String key=key(d);require(!unique.containsKey(key)||unique.get(key).equals(d),"template.history-conflict");unique.put(key,d);}
  require(unique.size()<=768,"template.history-limit");Map<String,List<JsonNode>> ts=new TreeMap<>(),apps=new TreeMap<>();
  for(JsonNode d:unique.values()){boolean t=text(d,"kind").equals("mapping-template");(t?ts:apps).computeIfAbsent(text(d,t?"id":"applicationId"),k->new ArrayList<>()).add(d);}
  Map<String,JsonNode> by=new HashMap<>();for(List<JsonNode> versions:ts.values()){
   require(versions.size()<=64,"template.version-limit");versions.sort(MappingTemplates::compareVersion);JsonNode previous=null;
   for(JsonNode t:versions){template(t);require(t.path("previousTemplateRef").equals(previous==null?JSON.nullNode():pin(previous)),"template.version-chain");previous=t;by.put(pair(t),t);}
  }
  for(List<JsonNode> versions:apps.values()){
   versions.sort(Comparator.comparingInt(a->a.path("revision").asInt()));JsonNode previous=null;int i=0;
   for(JsonNode a:versions){require(a.path("revision").asInt()==++i&&a.path("previousApplicationRef").equals(previous==null?JSON.nullNode():pin(previous)),"template.application-chain");require(previous==null||text(a,"equipmentInstanceId").equals(text(previous,"equipmentInstanceId")),"template.application-equipment");JsonNode t=by.get(pair(a.path("templateRef")));require(t!=null,"template.missing-version");require(a.path("generated").equals(compile(t,a)),"template.materialization-drift");previous=a;}
  }return new History(ts,apps);
 }
 static void validate(Collection<JsonNode> documents,Collection<JsonNode> prior) throws Exception {
  List<JsonNode> all=new ArrayList<>(prior);all.addAll(documents);History history=histories(all);Map<String,JsonNode> by=new HashMap<>();Map<String,List<JsonNode>> current=new HashMap<>();Map<String,String> managed=new HashMap<>();
  for(JsonNode d:documents){by.put(key(d),d);if(text(d,"kind").equals("template-application"))current.computeIfAbsent(text(d,"applicationId"),k->new ArrayList<>()).add(d);}
  for(var group:history.apps().entrySet())for(JsonNode a:group.getValue())for(JsonNode g:a.path("generated"))managed.put(text(g,"kind")+":"+text(g,"id"),group.getKey());
  for(JsonNode d:documents){String owner=managed.get(text(d,"kind")+":"+text(d,"id"));if(owner==null||KINDS.contains(text(d,"kind")))continue;require(current.containsKey(owner),"template.provenance-required");boolean found=false;for(JsonNode a:history.apps().get(owner))for(JsonNode g:a.path("generated"))if(key(g).equals(key(d))){require(g.equals(d),"template.materialization-drift");found=true;}require(found,"template.materialization-drift");}
  for(var group:current.entrySet()){
   JsonNode a=group.getValue().stream().max(Comparator.comparingInt(x->x.path("revision").asInt())).orElseThrow();List<JsonNode> chain=history.apps().get(group.getKey());require(a.path("revision").asInt()==chain.get(chain.size()-1).path("revision").asInt(),"template.application-stale");
   for(JsonNode old:chain){boolean included=old.equals(a);for(JsonNode g:old.path("generated"))included|=by.containsKey(key(g));if(included)for(JsonNode s:old.path("sourceSnapshots"))require(s.equals(by.get(key(s))),"template.source-pin-mismatch");}
   for(JsonNode g:a.path("generated"))require(g.equals(by.get(key(g))),"template.materialization-drift");
  }
 }
}
