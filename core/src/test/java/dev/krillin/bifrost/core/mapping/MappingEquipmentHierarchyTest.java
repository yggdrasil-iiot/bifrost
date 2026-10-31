package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** 2.23 equipment hierarchy: Tyr's wire bundle, Bifrost's own checks, real keys. Governed metadata only. */
class MappingEquipmentHierarchyTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-31T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/equipment-hierarchy").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n");
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"hierarchy-line\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"hierarchy-line\"}]}");
        service=new MappingRegistry(registry,CLOCK,()->{});
    }
    void rewrite(Path p,JsonNode doc) throws Exception {Files.write(p,bytes(doc));}
    void reseal() throws Exception {ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);}
    void hierarchy(Consumer<ObjectNode> mutation) throws Exception {
        ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:proposal.path("files"))if(text(e,"kind").equals("equipment-hierarchy")){
            Path file=bundle.resolve(text(e,"path"));ObjectNode d=(ObjectNode)read(file);mutation.accept(d);rewrite(file,d);((ObjectNode)e).put("sha256",sha(file));
        }
        rewrite(bundle.resolve("proposal.json"),proposal);reseal();
    }
    ObjectNode node(ObjectNode h,int i){return (ObjectNode)h.path("nodes").get(i);}
    List<String> codes(){return new MappingBundle().validate(bundle).report().path("findings").findValuesAsText("ruleCode");}
    void refused(String code,Consumer<ObjectNode> mutation) throws Exception {hierarchy(mutation);assertTrue(codes().contains(code),codes().toString());}

    @Test void acceptsTyrBundle() throws Exception {var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());assertEquals("2.23.0",text(c.proposal(),"schemaVersion"));}
    @Test void releaseAndAttestationCarryTheHierarchy() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        assertEquals("mapping-release",text(service.publish(bundle,"release","1.0.0","approval-1"),"kind"));
        Path dir=registry.resolve("mappings/releases/release/1.0.0");JsonNode release=read(dir.resolve("release.json"));
        JsonNode statement=service.verifyAttestation("release","1.0.0",sha(dir.resolve("release.json")));
        String hierarchy=null;for(JsonNode f:release.path("files"))if(text(f,"path").endsWith("hierarchy/0.json"))hierarchy=text(f,"sha256");
        assertNotNull(hierarchy,release.toString());
        boolean signed=false;for(JsonNode s:statement.path("subject"))signed|=text(s.path("digest"),"sha256").equals(hierarchy);
        assertTrue(signed,statement.path("subject").toString());
    }
    @Test void parentMissing() throws Exception {refused("hierarchy.parent-missing",h->node(h,1).put("parentEquipmentInstanceId","record-line-z"));}
    @Test void selfParent() throws Exception {refused("hierarchy.cycle",h->node(h,0).put("parentEquipmentInstanceId","synthetic-site"));}
    @Test void cycle() throws Exception {refused("hierarchy.cycle",h->node(h,0).put("parentEquipmentInstanceId","record-line-a"));}
    @Test void duplicateNode() throws Exception {refused("hierarchy.duplicate-node",h->((ArrayNode)h.path("nodes")).add(node(h,1).deepCopy()));}
    @Test void nodeOutsideSubmissionContext() throws Exception {refused("hierarchy.context-equipment",h->((ArrayNode)h.path("nodes")).add(node(h,1).deepCopy().put("equipmentInstanceId","record-line-z")));}
    @Test void unresolvedInstance() throws Exception {refused("hierarchy.unresolved-instance",h->((ArrayNode)h.path("nodes")).remove(2));}
    @Test void nodeEvidenceResolves() throws Exception {refused("evidence.locator",h->((ObjectNode)node(h,2).path("evidenceRefs").get(0)).put("artifactId","manual-missing"));}
    @Test void otherLevelNeedsItsName() throws Exception {refused("mapping.schema:2.23.0/equipment-hierarchy",h->node(h,0).put("equipmentLevel","OTHER_14"));}
    @Test void publishedTokenSpellingOnly() throws Exception {
        hierarchy(h->node(h,1).put("equipmentLevel","PRODUCTIONUINT_7"));assertEquals(List.of(),codes());
        refused("mapping.schema:2.23.0/equipment-hierarchy",h->node(h,1).put("equipmentLevel","PRODUCTIONUNIT_7"));
    }
    @Test void depthLimit() {
        java.util.function.IntFunction<List<JsonNode>> chain=n->{ArrayNode nodes=JSON.createArrayNode();for(int i=0;i<n;i++){ObjectNode x=nodes.addObject().put("equipmentInstanceId","n"+i);if(i==0)x.putNull("parentEquipmentInstanceId");else x.put("parentEquipmentInstanceId","n"+(i-1));}
            ObjectNode h=object().put("kind","equipment-hierarchy");h.set("nodes",nodes);return List.of(h);};
        Set<String> all=new HashSet<>();for(int i=0;i<=EquipmentHierarchy.MAX_DEPTH;i++)all.add("n"+i);
        EquipmentHierarchy.validate(chain.apply(EquipmentHierarchy.MAX_DEPTH),all);
        assertEquals("hierarchy.depth",assertThrows(IllegalArgumentException.class,()->EquipmentHierarchy.validate(chain.apply(EquipmentHierarchy.MAX_DEPTH+1),all)).getMessage());
    }
    @Test void olderEnvelopeRefused() throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.put("schemaVersion","2.22.0");rewrite(bundle.resolve("proposal.json"),p);reseal();
        assertEquals(List.of("mapping.schema:2.22.0/mapping-proposal"),codes());
    }
}
