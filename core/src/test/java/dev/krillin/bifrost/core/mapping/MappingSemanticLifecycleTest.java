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
class MappingSemanticLifecycleTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-17T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");copy(Path.of(getClass().getResource("/mapping-fixtures/semantic-lifecycle").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        String keys=JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n";
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),keys);
        policy();service=new MappingRegistry(registry,CLOCK,()->{});
    }
    void policy() throws Exception {
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"mixed-line\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"mixed-line\"}]}");
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

    JsonNode event(int n) throws Exception {for(JsonNode e:read(bundle.resolve("proposal.json")).path("files"))if(text(e,"kind").equals("semantic-lifecycle")){JsonNode d=read(bundle.resolve(text(e,"path")));if(d.path("revision").asInt()==n)return d;}throw new IllegalStateException();}
    void addDoc(JsonNode d) throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.put("schemaVersion","2.18.0");String path="extra/"+text(d,"id")+".json";Files.createDirectories(bundle.resolve("extra"));rewrite(bundle.resolve(path),d);
        ((ArrayNode)p.path("files")).add(object().put("path",path).put("kind",text(d,"kind")).put("id",text(d,"id")).put("version",text(d,"version")).put("sha256",sha(bundle.resolve(path))));rewrite(bundle.resolve("proposal.json"),p);ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);
    }
    void retirement() throws Exception {
        ObjectNode prev=(ObjectNode)event(2),e=prev.deepCopy();e.put("id","lifecycle-fixture-3").put("revision",3).put("action","retire").put("authoredAt","2026-10-18T00:00:03Z");e.set("previousEvent",object().put("id",text(prev,"id")).put("version",text(prev,"version")).put("sha256",sha(bytes(prev))));addDoc(e);
    }
    void remapRetired() throws Exception {
        String uri=text(event(1),"semanticId");ObjectNode archive=null;
        for(JsonNode e:read(bundle.resolve("proposal.json")).path("files"))if(text(e,"kind").equals("semantic-definition")){archive=((ObjectNode)read(bundle.resolve(text(e,"path")))).deepCopy();break;}
        assertNotNull(archive);archive.put("id","archived-meaning");addDoc(archive);
        patch("semantic-definition","mixed-tank-model",d->{for(JsonNode n:d.path("members"))if(text(n,"semanticId").equals(uri))((ObjectNode)n).put("semanticId","urn:tyr:concept:replacement-pressure");});
    }
    @Test void acceptsLegacyAndNewFixture() throws Exception {assertTrue(new MappingBundle().validate(bundle).accepted());Path old=tmp.resolve("old");copy(Path.of(getClass().getResource("/mapping-fixtures/valid").toURI()),old);assertTrue(new MappingBundle().validate(old).accepted());}
    @Test void signedRevisionPublicationAndHistoryImpact() throws Exception {
        approve();publish();JsonNode c=service.lifecycle();assertEquals(2,c.path("events").size());assertTrue(c.path("entries").toString().contains("deprecated"));assertTrue(c.path("impacts").size()>0);assertTrue(c.path("impacts").get(0).path("currentHead").asBoolean());ObjectNode unhashed=c.deepCopy();String hash=text(unhashed,"catalogSha256");unhashed.remove("catalogSha256");assertEquals(hash,sha(bytes(unhashed)));
    }
    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings={"signature","previous","gap","transition","time","replacement","terminal","fork","unknown-offset"})
    void rejectsRehashedInvalidEvent(String scenario) throws Exception {
        String expected=switch(scenario){case "signature"->"signature-drift";case "previous"->"previous-conflict";case "gap","fork"->"revision-conflict";case "transition"->"transition";case "time"->"time-order";case "replacement"->"replacement-missing";case "terminal"->"retired-terminal";default->"mapping.schema";};
        switch(scenario){
         case "signature"->patch("semantic-lifecycle","lifecycle-fixture-2",d->d.put("signatureSha256","0".repeat(64)));
         case "previous"->patch("semantic-lifecycle","lifecycle-fixture-2",d->((ObjectNode)d.path("previousEvent")).put("sha256","0".repeat(64)));
         case "gap"->patch("semantic-lifecycle","lifecycle-fixture-2",d->d.put("revision",3));
         case "transition"->patch("semantic-lifecycle","lifecycle-fixture-2",d->d.put("action","retire"));
         case "time"->patch("semantic-lifecycle","lifecycle-fixture-2",d->d.put("authoredAt","2026-10-17T00:00:00Z"));
         case "replacement"->patch("semantic-lifecycle","lifecycle-fixture-2",d->d.put("replacementSemanticId","urn:absent"));
         case "unknown-offset"->patch("semantic-lifecycle","lifecycle-fixture-2",d->d.put("authoredAt","2026-10-18T00:00:02-00:00"));
         case "fork"->{ObjectNode d=event(1).deepCopy();d.put("id","fork");addDoc(d);}
         case "terminal"->{retirement();ObjectNode prev=event(3).deepCopy(),d=prev.deepCopy();d.put("id","reactivate").put("revision",4).put("action","revise");d.set("previousEvent",object().put("id",text(prev,"id")).put("version",text(prev,"version")).put("sha256",sha(bytes(prev))));addDoc(d);}
        }
        var c=new MappingBundle().validate(bundle);assertFalse(c.accepted());assertTrue(c.report().path("findings").toString().contains(expected),c.report().toString());
    }
    @Test void refusesRetiredReadAndWriteBindings(){assertDoesNotThrow(()->retirement());var c=new MappingBundle().validate(bundle);assertFalse(c.accepted());assertTrue(c.report().toString().contains("retired-binding"));}
    @Test void remappedRetirementCanPublishAndHistoryRemains() throws Exception {retirement();remapRetired();var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());approve();publish();JsonNode report=service.lifecycle();assertTrue(report.toString().contains("retired"));assertEquals(3,report.path("events").size());Files.delete(registry.resolve("mappings/heads/mixed-line.json"));assertEquals(3,service.lifecycle().path("events").size());}
    @Test void rechecksPreviouslyApprovedLegacyBundleAtPublication() throws Exception {
        Path original=bundle;Path other=tmp.resolve("other");copy(bundle,other);bundle=other;catalogStream("other-line");service.approve(bundle,"other-approval","proposer",proposerKey,"approver",approverKey);
        bundle=original;retirement();remapRetired();approve();publish();bundle=other;
        Exception e=assertThrows(Exception.class,()->service.publish(bundle,"other-release","1.0.0","other-approval"));assertTrue(e.getMessage().contains("retired-binding"),e.getMessage());assertFalse(Files.exists(registry.resolve("mappings/releases/other-release/1.0.0")));
    }
    @Test void crossStreamForkRefusedOnApproval() throws Exception {
        approve();publish();catalogStream("other-line");patch("semantic-lifecycle","lifecycle-fixture-2",d->d.put("reason","forked reason"));assertTrue(new MappingBundle().validate(bundle).accepted());Exception e=assertThrows(Exception.class,()->service.approve(bundle,"fork-approval","proposer",proposerKey,"approver",approverKey));assertTrue(e.getMessage().contains("event-conflict"));
    }
    @Test void corruptedHistoricalFileFailsClosed() throws Exception {approve();publish();Files.writeString(registry.resolve("mappings/releases/release/1.0.0/payload/lifecycle/0.json"),"{}");assertThrows(Exception.class,()->service.lifecycle());}

    void governanceOnly() throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));ArrayNode kept=JSON.createArrayNode();
        for(JsonNode e:p.path("files")){if(Set.of("semantic-definition","semantic-lifecycle","evidence-artifact").contains(text(e,"kind")))kept.add(e);else Files.delete(bundle.resolve(text(e,"path")));}
        p.set("files",kept);rewrite(bundle.resolve("proposal.json"),p);ObjectNode sub=(ObjectNode)read(bundle.resolve("submission.json"));sub.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),sub);
    }
    @Test void lifecycleOnlyRetirementApprovedAndPublished() throws Exception {retirement();governanceOnly();var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());approve();publish();assertEquals(3,service.lifecycle().path("events").size());}
    @Test void readWriteAndAncestorImpactsRemainSeparate() throws Exception {
        var docs=new MappingBundle().validate(bundle).documents().values();var impacts=SemanticLifecycle.impacts(docs);assertTrue(java.util.stream.StreamSupport.stream(impacts.spliterator(),false).anyMatch(i->text(i,"kind").equals("write-definition")));
        JsonNode write=docs.stream().filter(d->text(d,"kind").equals("write-definition")).findFirst().orElseThrow();String uri=null;for(JsonNode i:impacts)if(text(i,"kind").equals("write-definition")&&text(i,"id").equals(text(write,"id")))uri=text(i,"semanticId");assertNotNull(uri);
        ObjectNode first=event(1).deepCopy();first.put("id","write-deprecated").put("semanticId",uri).put("action","deprecate").put("signatureSha256",sha(bytes(SemanticLifecycle.signatures(docs).get(uri))));ObjectNode second=first.deepCopy();second.put("id","write-retired").put("revision",2).put("action","retire");second.set("previousEvent",object().put("id",text(first,"id")).put("version",text(first,"version")).put("sha256",sha(bytes(first))));
        List<JsonNode> selected=new ArrayList<>();for(JsonNode d:docs)if(!Set.of("semantic-lifecycle","mapping-set").contains(text(d,"kind")))selected.add(d);selected.add(first);selected.add(second);String error=assertThrows(Exception.class,()->SemanticLifecycle.validate(selected,List.of(),Map.of())).getMessage();assertTrue(error.contains("retired-binding:"+text(write,"id")),error);
    }
}
