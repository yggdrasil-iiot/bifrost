package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** Independent receiver tests over published wire fixtures, not producer implementation. */
class MappingCrossGraphTest {
 @TempDir Path tmp;Path bundle;
 @BeforeEach void setup() throws Exception {
  bundle=tmp.resolve("bundle");Path root=Path.of(getClass().getResource("/mapping-fixtures/cross-graph").toURI());
  try(var walk=Files.walk(root)){for(Path p:walk.toList()){Path q=bundle.resolve(root.relativize(p));if(Files.isDirectory(p))Files.createDirectories(q);else Files.copy(p,q);}}
 }
 void manifest(ObjectNode proposal) throws Exception {Files.write(bundle.resolve("proposal.json"),bytes(proposal));ObjectNode submission=(ObjectNode)read(bundle.resolve("submission.json"));submission.put("proposalSha256",sha(bundle.resolve("proposal.json")));Files.write(bundle.resolve("submission.json"),bytes(submission));}
 void patch(String id,Consumer<ObjectNode> change) throws Exception {
  ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));boolean found=false;
  for(JsonNode entry:proposal.path("files"))if(text(entry,"kind").equals("value-graph")&&text(entry,"id").equals(id)){
   Path file=bundle.resolve(text(entry,"path"));ObjectNode doc=(ObjectNode)read(file);change.accept(doc);Files.write(file,bytes(doc));((ObjectNode)entry).put("sha256",sha(file));found=true;
  }
  assertTrue(found);manifest(proposal);
 }
 static ObjectNode external(String graph,String node){ObjectNode e=object().put("kind","graph").put("nodeId",node);e.set("graphRef",object().put("id",graph).put("version","1.0.0"));return e;}
 static ObjectNode first(ObjectNode g){return (ObjectNode)g.path("nodes").get(0);}
 static ObjectNode inputs(ObjectNode g){return (ObjectNode)first(g).path("inputs");}
 @Test void validFourProfilesAndTransitiveClosure(){var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());assertEquals(12,c.documents().values().stream().filter(d->text(d,"kind").equals("value-graph")).count());}
 @Test void declarationOrderDoesNotAffectAcceptance() throws Exception {
  ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));List<JsonNode> entries=new ArrayList<>();p.path("files").forEach(entries::add);Collections.reverse(entries);p.set("files",JSON.valueToTree(entries));manifest(p);assertTrue(new MappingBundle().validate(bundle).accepted());
 }
 @ParameterizedTest @ValueSource(strings={"self","two","three","missing-graph","missing-version","missing-node","equipment","type","unit","evidence","array","legacy","local-cycle"})
 void refuseForgedDefinitionsEvenWithRehashedManifest(String scenario) throws Exception {
  String expected=switch(scenario){
   case "self","two","three"->"graph.dependency-cycle";case "missing-graph","missing-version"->"reference.missing";case "missing-node"->"graph.node-missing";case "equipment"->"value.equipment";case "type"->"graph.output-type";case "unit"->"graph.output-unit";case "evidence"->"graph.evidence-incomplete";case "array"->"graph.reference-scalar-required";case "legacy"->"mapping.schema";default->"graph.cycle";};
  switch(scenario){
   case "self"->patch("consumer-ab",g->inputs(g).set("left",external("consumer-ab","sum")));
   case "two","three"->patch("shared-ab",g->{g.put("schemaVersion","2.17.0");inputs(g).set("left",external(scenario.equals("two")?"consumer-ab":"final-ab",scenario.equals("two")?"sum":"result"));});
   case "missing-graph"->patch("consumer-ab",g->inputs(g).set("left",external("absent","delta")));
   case "missing-version"->patch("consumer-ab",g->{ObjectNode e=external("shared-ab","delta");((ObjectNode)e.path("graphRef")).put("version","1.0.1");inputs(g).set("left",e);});
   case "missing-node"->patch("consumer-ab",g->inputs(g).set("left",external("shared-ab","absent")));
   case "equipment"->patch("consumer-ab",g->inputs(g).set("left",external("shared-ua","delta")));
   case "type"->patch("final-ab",g->first(g).put("valueType","UInt16"));
   case "unit"->patch("final-ab",g->((ObjectNode)first(g).path("unit")).put("code","bar"));
   case "evidence"->patch("final-ab",g->{ArrayNode refs=JSON.createArrayNode();refs.add(first(g).path("evidenceRefs").get(0));first(g).set("evidenceRefs",refs);});
   case "array"->patch("shared-ab",g->{first(g).put("op","identity").put("valueType","FixedArray");ObjectNode e=object().put("kind","source");e.set("sourceRef",object().put("id","structure-ab-actual").put("version","1.0.0"));ObjectNode in=object();in.set("value",e);first(g).set("inputs",in);});
   case "legacy"->patch("consumer-ab",g->g.put("schemaVersion","2.15.0"));
   case "local-cycle"->patch("shared-ab",g->inputs(g).set("left",object().put("kind","node").put("nodeId","delta")));
  }
  var c=new MappingBundle().validate(bundle);assertFalse(c.accepted());assertTrue(c.report().path("findings").toString().contains(expected),c.report().toString());
 }
 static ObjectNode minimal(String id,String parent,int nodes){
  ObjectNode g=object().put("kind","value-graph").put("schemaVersion","2.17.0").put("id",id).put("version","1.0.0").put("equipmentInstanceId","line");ArrayNode all=g.putArray("nodes");
  for(int i=0;i<nodes;i++){ObjectNode n=object().put("nodeId","n"+i).put("valueType","Decimal"),in=n.putObject("inputs");
   if(i>0)in.set("value",object().put("kind","node").put("nodeId","n"+(i-1)));
   else if(parent!=null)in.set("value",external(parent,"n"+(nodes-1)));
   else {ObjectNode e=object().put("kind","source");e.set("sourceRef",object().put("id","source").put("version","1.0.0"));in.set("value",e);}all.add(n);
  }return g;
 }
 @Test void dependencyDepthBound(){List<JsonNode> gs=new ArrayList<>();for(int i=0;i<33;i++)gs.add(minimal("d"+i,i==0?null:"d"+(i-1),1));assertEquals("graph.dependency-depth",assertThrows(IllegalArgumentException.class,()->GraphDependencies.order(gs)).getMessage());}
 @Test void totalNodePathBound(){List<JsonNode> gs=new ArrayList<>();for(int i=0;i<3;i++)gs.add(minimal("p"+i,i==0?null:"p"+(i-1),64));assertEquals("graph.path-depth",assertThrows(IllegalArgumentException.class,()->GraphDependencies.order(gs)).getMessage());}
 @Test void totalNodeCountBound(){List<JsonNode> gs=new ArrayList<>();for(int i=0;i<130;i++)gs.add(minimal("s"+i,i==0?null:"s"+(i-1),64));assertEquals("graph.dependency-size",assertThrows(IllegalArgumentException.class,()->GraphDependencies.order(gs)).getMessage());}
}
