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
class MappingMixedObjectsTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-17T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");copy(Path.of(getClass().getResource("/mapping-fixtures/mixed-objects").toURI()),bundle);
        ObjectNode sub=(ObjectNode)read(bundle.resolve("submission.json"));sub.put("proposedBy","proposer");Files.write(bundle.resolve("submission.json"),bytes(sub));
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        String keys=JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n";
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),keys);
        policy();service=new MappingRegistry(registry,CLOCK,()->{});
    }
    void policy() throws Exception {
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"combined-line\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"combined-line\"}]}");
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




    JsonNode field(Collection<JsonNode> docs){return docs.stream().filter(d->text(d,"kind").equals("source-definition")&&d.has("recordField")).findFirst().orElseThrow();}
    @Test void acceptsFourSourceKindsAndPinnedTemplate() throws Exception {var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());JsonNode s=field(c.documents().values());assertEquals("target",text(s.path("recordField"),"fieldId"));assertTrue(c.documents().values().stream().anyMatch(d->text(d,"kind").equals("template-application")));assertFalse(c.documents().values().stream().anyMatch(d->text(d,"kind").equals("virtual-result-set")));}
    @Test void signedApprovalAndImmutableRelease() throws Exception {approve();assertEquals("mapping-release",text(publish(),"kind"));}
    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings={"pin","field","unit","type","stage","equipment","provider","default","write","sql"})
    void rejectsRehashedSourceTampering(String which) throws Exception {
      String id=text(field(new MappingBundle().validate(bundle).documents().values()),"id");patch("source-definition",id,d->{switch(which){
       case "pin"->((ObjectNode)d.path("recordField").path("recordMappingRef")).put("sha256","0".repeat(64));
       case "field"->((ObjectNode)d.path("recordField")).put("fieldId","missing");
       case "unit"->((ObjectNode)d.path("unit")).put("code","Pa");
       case "type"->((ObjectNode)d.path("rawRepresentation")).put("valueType","Double");
       case "stage"->d.put("inputStage","already-engineered");
       case "equipment"->d.put("equipmentInstanceId","record-line-a");
       case "provider"->((ObjectNode)d.path("access")).put("providerRef","different-provider");
       case "default"->((ObjectNode)d.path("recordField")).put("nullPolicy","default").put("defaultValue","0");
       case "write"->d.put("accessMode","write");
       case "sql"->((ObjectNode)d.path("access")).put("expressionLanguage","sql").put("expression","SELECT something");
      }});assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void rejectsArrayEvenWithCorrectPin() throws Exception {
      var docs=new ArrayList<>(new MappingBundle().validate(bundle).documents().values());ObjectNode s=(ObjectNode)field(docs);ObjectNode r=(ObjectNode)docs.stream().filter(d->text(d,"kind").equals("record-mapping")).findFirst().orElseThrow();((ObjectNode)r.path("output")).put("mode","array").put("zeroPolicy","empty").put("manyPolicy","all").put("maxRows",16);((ObjectNode)s.path("recordField")).set("recordMappingRef",RecordMappings.pin(r));assertTrue(assertThrows(Exception.class,()->RecordFields.validate(docs)).getMessage().contains("object-required"));
    }
    @Test void sourceCannotBeDowngradedInGlobalHistory() throws Exception {
      JsonNode old=field(new MappingBundle().validate(bundle).documents().values());ObjectNode changed=old.deepCopy();changed.remove("recordField");changed.put("schemaVersion","2.7.0");assertTrue(assertThrows(Exception.class,()->RecordFields.history(List.of(changed),List.of(old))).getMessage().contains("history-conflict"));
    }

    @Test void registryRejectsLocallyValidSourceDowngrade() throws Exception {
      approve();publish();catalogStream("another-line");String id=text(field(new MappingBundle().validate(bundle).documents().values()),"id");patch("source-definition",id,d->{d.remove("recordField");d.put("schemaVersion","2.7.0");});
      ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));ArrayNode kept=JSON.createArrayNode();for(JsonNode e:p.path("files")){if(Set.of("mapping-template","template-application","record-mapping").contains(text(e,"kind")))Files.delete(bundle.resolve(text(e,"path")));else kept.add(e);}p.set("files",kept);p.put("schemaVersion","2.7.0");rewrite(bundle.resolve("proposal.json"),p);ObjectNode sub=(ObjectNode)read(bundle.resolve("submission.json"));sub.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),sub);var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());Exception e=assertThrows(Exception.class,()->service.approve(bundle,"downgrade","proposer",proposerKey,"approver",approverKey));assertTrue(e.getMessage().contains("record-field.history-conflict"),e.getMessage());
    }
    @Test void oldEnvelopeFailsClosed() throws Exception {
      ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.put("schemaVersion","2.20.0");rewrite(bundle.resolve("proposal.json"),p);ObjectNode sub=(ObjectNode)read(bundle.resolve("submission.json"));sub.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),sub);assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void missingRecordReferenceFailsClosed() throws Exception {
      var docs=new ArrayList<>(new MappingBundle().validate(bundle).documents().values());docs.removeIf(d->text(d,"kind").equals("record-mapping"));assertTrue(assertThrows(Exception.class,()->RecordFields.validate(docs)).getMessage().contains("record-missing"));
    }
}
