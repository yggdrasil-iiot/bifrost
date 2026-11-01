package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** The synthetic release Vor's governed read path starts from: Line1/Mixer1.Temp in Cel, with a temporal policy,
 *  its place in an ISA-95 hierarchy, and Vor's read binding carried as an uncited evidence artifact. These tests
 *  keep the fixture publishable and its binding consistent with the documents and the governed definition the
 *  gates feed Muninn ({@code scripts/fixtures/activation/udt-Line1-Mixer.json}); judging the binding at read time
 *  is Vor's job, not Bifrost's. */
class VorReadReleaseTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-11-01T00:00:00Z"),ZoneOffset.UTC);
    static final Path UDT=Path.of("../scripts/fixtures/activation/udt-Line1-Mixer.json");

    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/vor-read").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n");
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line1\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line1\"}]}");
        service=new MappingRegistry(registry,CLOCK,()->{});
    }

    Path publish() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);service.publish(bundle,"vor-read","1.0.0","approval-1");
        return registry.resolve("mappings/releases/vor-read/1.0.0");
    }
    static JsonNode payloadDoc(Path dir,String kind,String id) throws Exception {
        for(JsonNode f:read(dir.resolve("payload/proposal.json")).path("files"))if(text(f,"kind").equals(kind)&&text(f,"id").equals(id))return read(dir.resolve("payload/"+text(f,"path")));
        throw new AssertionError("no "+kind+" "+id+" in the release");
    }
    static JsonNode one(Path dir,String kind) throws Exception {
        List<JsonNode> found=new ArrayList<>();for(JsonNode f:read(dir.resolve("payload/proposal.json")).path("files"))if(text(f,"kind").equals(kind))found.add(read(dir.resolve("payload/"+text(f,"path"))));
        assertEquals(1,found.size(),kind);return found.get(0);
    }
    static JsonNode binding(Path dir) throws Exception {return read(dir.resolve("payload/"+text(payloadDoc(dir,"evidence-artifact","vor-binding-mixer1-temp").path("file"),"path")));}

    @Test void accepted() throws Exception {var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());}

    @Test void publishedOnStreamLine1() throws Exception {
        publish();JsonNode head=read(registry.resolve("mappings/heads/line1.json"));
        assertEquals("vor-read",text(head,"id"));assertEquals("1.0.0",text(head,"version"));
    }

    @Test void bindingListedAndSigned() throws Exception {
        Path dir=publish();String path="payload/data/vor-read-binding.json",digest=sha(dir.resolve(path));
        String listed=null;for(JsonNode f:read(dir.resolve("release.json")).path("files"))if(text(f,"path").equals(path))listed=text(f,"sha256");
        assertEquals(digest,listed,"release.json files[]");
        boolean signed=false;for(JsonNode s:service.verifyAttestation("vor-read","1.0.0",sha(dir.resolve("release.json"))).path("subject"))signed|=text(s.path("digest"),"sha256").equals(digest);
        assertTrue(signed,"statement subjects");
    }

    /** Every link the binding names resolves to a document in the same release and agrees with it. */
    @Test void bindingMatchesTheReleasedDocuments() throws Exception {
        Path dir=publish();JsonNode b=binding(dir);
        assertEquals("identity",text(b,"projection"));
        assertEquals(text(read(dir.resolve("payload/submission.json")),"streamId"),text(b,"streamId"));
        JsonNode set=payloadDoc(dir,"mapping-set",text(b.path("mappingSetRef"),"id"));
        assertEquals(text(b.path("mappingSetRef"),"version"),text(set,"version"));
        assertEquals(text(b,"equipmentInstanceId"),text(set,"equipmentInstanceId"));
        JsonNode m=null;for(JsonNode x:set.path("mappings"))if(text(x,"mappingId").equals(text(b,"mappingId")))m=x;
        assertNotNull(m,"mappingId");
        assertTrue(m.path("temporalPolicy").isObject(),"the governed field carries a temporal policy");
        assertEquals("Cel",text(m.path("outputUnit"),"code"));
        JsonNode source=payloadDoc(dir,"source-definition",text(m.path("valueRef").path("sourceRef"),"id"));
        assertEquals("urn:bifrost:opcua:sim",text(source.path("access"),"namespaceUri"));
        assertEquals("Line1/Mixer1."+text(b,"metric"),text(source.path("access"),"identifier"),"Muninn names the metric by the member's browse name");
        JsonNode target=payloadDoc(dir,"target-instance",text(set.path("targetInstanceRef"),"id"));
        JsonNode model=payloadDoc(dir,"semantic-definition",text(target.path("semanticDefinitionRef"),"id"));
        String memberId=text(m.path("memberPath").get(0),"memberId");JsonNode member=null;
        for(JsonNode x:model.path("members"))if(text(x,"memberId").equals(memberId))member=x;
        assertNotNull(member,"memberPath");
        assertEquals(text(b,"semanticId"),text(member,"semanticId"));
        assertEquals(text(b,"metric"),text(member,"name"));
        assertEquals("Cel",text(member.path("unit"),"code"));
    }

    /** {@code device} is the ISA-95 path Muninn derives from this release's hierarchy: root to instance, joined by ':'. */
    @Test void deviceIsTheHierarchyPath() throws Exception {
        Path dir=publish();JsonNode b=binding(dir);Map<String,String> parent=new HashMap<>();
        for(JsonNode n:one(dir,"equipment-hierarchy").path("nodes"))parent.put(text(n,"equipmentInstanceId"),n.path("parentEquipmentInstanceId").isNull()?null:text(n,"parentEquipmentInstanceId"));
        Deque<String> path=new ArrayDeque<>();for(String id=text(b,"equipmentInstanceId");id!=null;id=parent.get(id))path.addFirst(id);
        assertEquals(String.join(":",path),text(b,"device"));
    }

    /** The binding pins the exact bytes of the governed definition the gates publish for Muninn, and means the same member. */
    @Test void bindingPinsTheGovernedDefinition() throws Exception {
        JsonNode b=binding(publish()),ref=b.path("governedDefinitionRef"),udt=read(UDT);
        assertEquals(sha(UDT),text(ref,"sha256"));
        assertEquals(text(udt,"templateRef"),text(ref,"templateRef"));assertEquals(text(udt,"version"),text(ref,"version"));
        String semanticId=null;for(JsonNode x:udt.path("members"))if(text(x,"name").equals(text(b,"metric")))semanticId=text(x,"semanticId");
        assertEquals(text(b,"semanticId"),semanticId);
    }
}
