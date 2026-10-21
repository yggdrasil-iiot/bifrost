package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real wire package + real registered Ed25519 keys + real files; no Python or Týr code. */
class MappingBroadcastTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-17T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");copy(Path.of(getClass().getResource("/mapping-fixtures/broadcast").toURI()),bundle);
        ObjectNode sub=(ObjectNode)read(bundle.resolve("submission.json"));sub.put("proposedBy","proposer");Files.write(bundle.resolve("submission.json"),bytes(sub));
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        String keys=JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n";
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),keys);
        policy();service=new MappingRegistry(registry,CLOCK,()->{});
    }
    void policy() throws Exception {
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"broadcast-line\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"broadcast-line\"}]}");
    }
    static void copy(Path source,Path dest) throws Exception {
        try(var walk=Files.walk(source)){for(Path p:walk.toList()){Path q=dest.resolve(source.relativize(p));if(Files.isDirectory(p))Files.createDirectories(q);else Files.copy(p,q);}}
    }
    void rewrite(Path p,JsonNode doc) throws Exception {Files.write(p,bytes(doc));}
    void patch(String kind,String id,Consumer<ObjectNode> mutation) throws Exception {
        ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:proposal.path("files"))if(text(e,"kind").equals(kind)&&text(e,"id").equals(id)){
            Path file=bundle.resolve(text(e,"path"));ObjectNode d=(ObjectNode)read(file);mutation.accept(d);rewrite(file,d);((ObjectNode)e).put("sha256",sha(file));
        }
        rewrite(bundle.resolve("proposal.json"),proposal);ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);
    }
    void approve() throws Exception {service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);}
    JsonNode publish() throws Exception {return service.publish(bundle,"release","1.0.0","approval-1");}
    void catalogStream(String stream) throws Exception {
        ObjectNode submission=(ObjectNode)read(bundle.resolve("submission.json"));submission.put("streamId",stream);rewrite(bundle.resolve("submission.json"),submission);
        Path file=registry.resolve("identity/activation-policy.json");ObjectNode p=(ObjectNode)read(file);ArrayNode rules=(ArrayNode)p.path("rules");
        for(String action:List.of("publish","approve"))rules.add(object().put("id",action+"-"+stream).put("principal",action.equals("publish")?"proposer":"approver")
            .put("action",action).put("target","mapping-publication").put("kind","mapping-release").put("ref",stream));rewrite(file,p);
    }
    void catalogRole(JsonNode node,String uri,String role){if(text(node,"semanticId").equals(uri))((ObjectNode)node).put("role",role);for(JsonNode child:node.path("members"))catalogRole(child,uri,role);}




    JsonNode recipe(Collection<JsonNode> docs){return docs.stream().filter(d->text(d,"kind").equals("record-mapping")&&text(d,"schemaVersion").equals("2.22.0")).findFirst().orElseThrow();}
    @Test void acceptsPinnedBroadcastClosure() throws Exception {var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());JsonNode r=recipe(c.documents().values());assertEquals(4,r.path("commonSources").size());assertEquals("reject-all",text(r,"rowErrorPolicy"));}
    @Test void signedApprovalAndImmutableRelease() throws Exception {approve();assertEquals("mapping-release",text(publish(),"kind"));}
    @Test void independentCanonicalProjectionMatchesPython() throws Exception {var c=new MappingBundle().validate(bundle);JsonNode r=recipe(c.documents().values());JsonNode t=c.documents().values().stream().filter(d->text(d,"kind").equals("mapping-template")&&RecordMappings.pair(d).equals(RecordMappings.pair(r.path("templateRef")))).findFirst().orElseThrow();JsonNode expected=read(Path.of(getClass().getResource("/mapping-fixtures/broadcast-static.json").toURI()));assertEquals(expected,RecordMappings.compile(r,t));}
    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings={"pin","equipment","unit","type","slot","missing","write","mode","policy","rowpolicy","max","sourcepin"})
    void rejectsRehashedRecipeTampering(String which) throws Exception {patch("record-mapping","broadcast-pumps",r->{ObjectNode source=(ObjectNode)r.path("commonSources").get(0);switch(which){
      case "pin"->((ObjectNode)r.path("commonBindings").get(0).path("sourceRef")).put("sha256","0".repeat(64));
      case "equipment"->source.put("equipmentInstanceId","other-equipment");
      case "unit"->source.set("unit",object().put("status","known").put("code","bar"));
      case "type"->((ObjectNode)source.path("rawRepresentation")).put("valueType","Int32");
      case "slot"->((ObjectNode)r.path("commonBindings").get(0)).put("slotId",text(r.path("bindings").get(0),"slotId"));
      case "missing"->((ArrayNode)r.path("commonSources")).remove(0);
      case "write"->source.put("accessMode","write");
      case "mode"->((ObjectNode)r.path("output")).put("mode","object");
      case "policy"->((ObjectNode)r.path("commonPolicy")).put("mode","live-poll");
      case "rowpolicy"->r.put("rowErrorPolicy","ignore");
      case "max"->((ObjectNode)r.path("output")).put("maxRows",65);
      case "sourcepin"->{((ObjectNode)source.path("access")).put("addressIndex",2000);try{((ObjectNode)r.path("commonBindings").get(0)).set("sourceRef",RecordMappings.pin(source));}catch(Exception e){throw new RuntimeException(e);}}
    }});assertFalse(new MappingBundle().validate(bundle).accepted());}
    @Test void olderEnvelopeCannotConcealBroadcast() throws Exception {ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.put("schemaVersion","2.20.0");rewrite(bundle.resolve("proposal.json"),p);ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);assertFalse(new MappingBundle().validate(bundle).accepted());}
    @Test void publishedCommonPinCannotBeRewrittenByLegacySource() throws Exception {var c=new MappingBundle().validate(bundle);JsonNode r=recipe(c.documents().values());ObjectNode source=r.path("commonSources").get(0).deepCopy();source.put("rawAddressText","D9999");assertTrue(assertThrows(Exception.class,()->RecordBroadcast.history(List.of(source),List.of(r))).getMessage().contains("broadcast.source-history-conflict"));}
    @Test void registryRejectsLocallyValidLegacyCommonRewrite() throws Exception {
      approve();publish();var checked=new MappingBundle().validate(bundle);JsonNode r=recipe(checked.documents().values());String sourceId=text(r.path("commonSources").get(0),"id");JsonNode projection=read(Path.of(getClass().getResource("/mapping-fixtures/broadcast-static.json").toURI()));Path legacy=tmp.resolve("legacy");Files.createDirectories(legacy);List<JsonNode> definitions=new ArrayList<>();for(JsonNode d:checked.documents().values())if(text(d,"kind").equals("evidence-artifact"))definitions.add(d);for(JsonNode d:projection.path("sourceSnapshots"))definitions.add(d.deepCopy());for(JsonNode d:projection.path("generated"))definitions.add(d.deepCopy());ObjectNode proposal=object().put("kind","mapping-proposal").put("schemaVersion","2.7.0").put("id","legacy-broadcast").put("version","1.0.0").putNull("baseRelease");ArrayNode files=JSON.createArrayNode();int i=0;
      for(JsonNode d:definitions){if(text(d,"kind").equals("source-definition")&&text(d,"id").equals(sourceId))((ObjectNode)d).put("rawAddressText","changed declaration");String file="definition-"+(i++)+".json";rewrite(legacy.resolve(file),d);files.add(object().put("path",file).put("kind",text(d,"kind")).put("id",text(d,"id")).put("version",text(d,"version")).put("sha256",sha(legacy.resolve(file))));if(text(d,"kind").equals("evidence-artifact")){Path dst=legacy.resolve(text(d.path("file"),"path"));Files.createDirectories(dst.getParent());Files.copy(bundle.resolve(text(d.path("file"),"path")),dst);}}
      proposal.set("files",files);rewrite(legacy.resolve("proposal.json"),proposal);ObjectNode sub=(ObjectNode)read(bundle.resolve("submission.json"));sub.put("streamId","legacy-line").put("proposalSha256",sha(legacy.resolve("proposal.json")));rewrite(legacy.resolve("submission.json"),sub);catalogStream("legacy-line");assertTrue(new MappingBundle().validate(legacy).accepted());assertTrue(assertThrows(Exception.class,()->service.approve(legacy,"approval-legacy","proposer",proposerKey,"approver",approverKey)).getMessage().contains("broadcast.source-history-conflict"));
    }
}
