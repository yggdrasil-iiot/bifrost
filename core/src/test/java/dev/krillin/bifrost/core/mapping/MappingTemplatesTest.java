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
class MappingTemplatesTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-17T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");copy(Path.of(getClass().getResource("/mapping-fixtures/mapping-templates").toURI()),bundle);
        ObjectNode sub=(ObjectNode)read(bundle.resolve("submission.json"));sub.put("proposedBy","proposer");Files.write(bundle.resolve("submission.json"),bytes(sub));
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        String keys=JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n";
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),keys);
        policy();service=new MappingRegistry(registry,CLOCK,()->{});
    }
    void policy() throws Exception {
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"template-fixture\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"template-fixture\"}]}");
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


    @Test void independentlyCompilesFourProfilesAndPinnedUpdate() throws Exception {var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());assertEquals(2,c.documents().values().stream().filter(d->text(d,"kind").equals("mapping-template")).count());assertEquals(5,c.documents().values().stream().filter(d->text(d,"kind").equals("template-application")).count());}
    @Test void signedApprovalAndPublication() throws Exception {approve();assertEquals("mapping-release",text(publish(),"kind"));}
    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings={"generated","source","template","application","slot","missing"})
    void rejectsRehashedTampering(String which) throws Exception {
      switch(which){
       case "generated"->patch("mapping-set","reuse-pump-ab-mapping",d->((ObjectNode)d.path("mappings").get(0).path("transform").get(0)).put("rounding","exact"));
       case "source"->patch("source-definition","structure-ab-actual",d->d.put("rawAddressText","altered address"));
       case "template"->patch("mapping-template","pressure-kit",d->d.put("reason","altered history"));
       case "application"->patch("template-application","application-pump-ab-r1",d->d.put("targetLabel","drifted label"));
       case "slot"->patch("template-application","application-pump-ab-r1",d->((ObjectNode)d.path("bindings").get(0)).put("slotId","input-99"));
       case "missing"->patch("template-application","application-pump-ab-r1",d->((ArrayNode)d.path("sourceSnapshots")).removeAll());
      }
      var c=new MappingBundle().validate(bundle);assertFalse(c.accepted(),c.report().toString());assertTrue(c.report().toString().contains(which.equals("missing")?"mapping.schema":"template."),c.report().toString());
    }
    @Test void globalHistoryRefusesFork() throws Exception {
      var docs=new ArrayList<>(new MappingBundle().validate(bundle).documents().values());var prior=new ArrayList<JsonNode>();for(JsonNode d:docs)if(MappingTemplates.KINDS.contains(text(d,"kind")))prior.add(d.deepCopy());
      for(JsonNode d:docs)if(text(d,"kind").equals("mapping-template")){((ObjectNode)d).put("reason","fork");break;}
      assertTrue(assertThrows(Exception.class,()->MappingTemplates.validate(docs,prior)).getMessage().contains("history-conflict"));
    }
    @Test void registryRejectsOmittedProvenanceEvenForLegacyProposal() throws Exception {
      approve();publish();catalogStream("other-line");ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));ArrayNode kept=JSON.createArrayNode();
      for(JsonNode e:p.path("files"))if(!MappingTemplates.KINDS.contains(text(e,"kind")))kept.add(e);else Files.delete(bundle.resolve(text(e,"path")));
      p.set("files",kept);p.put("schemaVersion","2.0.0");rewrite(bundle.resolve("proposal.json"),p);ObjectNode sub=(ObjectNode)read(bundle.resolve("submission.json"));sub.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),sub);
      var legacy=new MappingBundle().validate(bundle);assertTrue(legacy.accepted(),legacy.report().toString());Exception e=assertThrows(Exception.class,()->service.approve(bundle,"omitted-approval","proposer",proposerKey,"approver",approverKey));assertTrue(e.getMessage().contains("provenance-required"),e.getMessage());
    }

    void viewsBundle() throws Exception {bundle=tmp.resolve("view-bundle");copy(Path.of(getClass().getResource("/mapping-fixtures/mapping-template-views").toURI()),bundle);}
    @Test void acceptsBitAliasTemplateWithImplicitParents() throws Exception {viewsBundle();var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());JsonNode a=c.documents().values().stream().filter(d->text(d,"kind").equals("template-application")).findFirst().orElseThrow();assertEquals(1,a.path("bindings").size());assertEquals(3,a.path("sourceSnapshots").size());}
    @Test void rejectsChangedParentNotDirectlyBoundToSlot() throws Exception {viewsBundle();patch("source-definition","a07-melsec-word",d->d.put("rawAddressText","changed parent"));var c=new MappingBundle().validate(bundle);assertFalse(c.accepted());assertTrue(c.report().toString().contains("source-pin-mismatch"),c.report().toString());}
    @Test void signatureUsesInterpretedCodecAndNativeBitType() throws Exception {ObjectNode s=(ObjectNode)JSON.readTree("{\"id\":\"source\",\"version\":\"1.0.0\",\"rawRepresentation\":{\"valueType\":\"UInt16\",\"codec\":{\"kind\":\"bcd16\"}},\"access\":{},\"unit\":{\"status\":\"not-applicable\"},\"inputStage\":\"raw\"}");assertEquals("Int32",text(MappingTemplates.signature(s,Map.of()).path("rawRepresentation"),"valueType"));((ObjectNode)s.path("access")).put("bitOffset",3);assertEquals("Boolean",text(MappingTemplates.signature(s,Map.of()).path("rawRepresentation"),"valueType"));}
}
