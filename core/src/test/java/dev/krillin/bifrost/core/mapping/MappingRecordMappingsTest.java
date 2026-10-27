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

/** Real wire package + real registered Ed25519 keys + real files; no Python or Tyr code. */
class MappingRecordMappingsTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-17T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");copy(Path.of(getClass().getResource("/mapping-fixtures/record-mappings").toURI()),bundle);
        ObjectNode sub=(ObjectNode)read(bundle.resolve("submission.json"));sub.put("proposedBy","proposer");Files.write(bundle.resolve("submission.json"),bytes(sub));
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        String keys=JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n";
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),keys);
        policy();service=new MappingRegistry(registry,CLOCK,()->{});
    }
    void policy() throws Exception {
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"record-line\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"record-line\"}]}");
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



    @Test void acceptsRecordOnlyBundleAndIndependentProjection() throws Exception {
      var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());
      var docs=c.documents().values();assertEquals(2,docs.stream().filter(d->text(d,"kind").equals("record-mapping")).count());
      assertFalse(docs.stream().anyMatch(d->text(d,"kind").equals("virtual-result-set")));
      var compiled=RecordMappings.governance(docs);assertEquals(2,compiled.stream().filter(d->text(d,"kind").equals("mapping-set")).count());
    }

    @Test void crossLanguageProjectionOracle() throws Exception {
      var docs=new MappingBundle().validate(bundle).documents().values();JsonNode expected=read(Path.of(getClass().getResource("/record-static-projections.json").toURI()));int i=0;
      for(JsonNode r:docs)if(text(r,"kind").equals("record-mapping")){JsonNode t=docs.stream().filter(d->text(d,"kind").equals("mapping-template")&&text(d,"id").equals(text(r.path("templateRef"),"id"))).findFirst().orElseThrow();JsonNode want=null;for(JsonNode a:expected)if(text(a,"equipmentInstanceId").equals(text(r,"equipmentInstanceId")))want=a;assertNotNull(want);assertEquals(want,RecordMappings.compile(r,t));i++;}assertEquals(2,i);
    }
    @Test void retiredRecordMeaningIsBlockedAndImpactsVisible() throws Exception {
      var docs=new ArrayList<>(new MappingBundle().validate(bundle).documents().values());docs.addAll(RecordMappings.governance(docs));String uri="urn:tyr:concept:record.pressure";var impacts=SemanticLifecycle.impacts(docs);assertEquals(2,java.util.stream.StreamSupport.stream(impacts.spliterator(),false).filter(d->text(d,"semanticId").equals(uri)).count());
      ObjectNode first=(ObjectNode)read(Path.of(getClass().getResource("/mapping-fixtures/semantic-lifecycle/lifecycle/0.json").toURI()));first.put("id","record-deprecated").put("semanticId",uri).put("action","deprecate").put("signatureSha256",sha(bytes(SemanticLifecycle.signatures(docs).get(uri))));ObjectNode second=first.deepCopy();second.put("id","record-retired").put("revision",2).put("action","retire");second.set("previousEvent",object().put("id",text(first,"id")).put("version",text(first,"version")).put("sha256",sha(bytes(first))));docs.add(first);docs.add(second);String error=assertThrows(Exception.class,()->SemanticLifecycle.validate(docs,List.of(),Map.of())).getMessage();assertTrue(error.contains("retired-binding:record-"),error);
    }
    @Test void realSignedApprovalAndPublication() throws Exception {approve();assertEquals("mapping-release",text(publish(),"kind"));}
    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings={"unit","key","default","slot","many","template","model","query","evidence"})
    void rejectsRehashedInvalidDefinitions(String which) throws Exception {
      patch("record-mapping","pressure-records",d->{switch(which){
        case "unit" -> ((ObjectNode)d.path("resultSchema").path("fields").get(1).path("unit")).put("code","bar");
        case "key" -> ((ArrayNode)d.path("resultSchema").path("keyFields")).add("pressure");
        case "default" -> ((ObjectNode)d.path("bindings").get(1)).put("defaultValue","NaN");
        case "slot" -> ((ObjectNode)d.path("bindings").get(0)).put("slotId","missing");
        case "many" -> ((ObjectNode)d.path("output")).put("manyPolicy","reject");
        case "template" -> ((ObjectNode)d.path("templateRef")).put("sha256","0".repeat(64));
        case "model" -> ((ObjectNode)d.path("semanticDefinitionRef")).put("id","missing");
        case "query" -> ((ObjectNode)d.path("resultSchema").path("query")).put("language","none");
        case "evidence" -> ((ArrayNode)d.path("evidenceRefs")).removeAll();
      }});var c=new MappingBundle().validate(bundle);assertFalse(c.accepted(),c.report().toString());
    }
    @Test void globalHistoryRejectsLocallyValidFork() throws Exception {
      approve();publish();catalogStream("other-line");patch("record-mapping","pressure-records",d->d.put("reason","forked reason"));
      var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());
      Exception e=assertThrows(Exception.class,()->service.approve(bundle,"fork","proposer",proposerKey,"approver",approverKey));assertTrue(e.getMessage().contains("record.history-conflict"),e.getMessage());
    }
    @Test void corruptFileFailsIntegrity() throws Exception {Files.writeString(bundle.resolve("records/0.json"),"{}");assertFalse(new MappingBundle().validate(bundle).accepted());}
}
