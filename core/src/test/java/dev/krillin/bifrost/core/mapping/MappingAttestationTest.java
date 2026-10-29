package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** The approval attestation is a sibling: fixed keys and a fixed clock pin the bytes of everything else. */
class MappingAttestationTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-17T00:00:00Z"),ZoneOffset.UTC);
    static Path resource(String name) throws Exception {return Path.of(MappingAttestationTest.class.getResource("/mapping-attestation/"+name).toURI());}
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingPublicationTest.copy(Path.of(getClass().getResource("/mapping-fixtures/valid").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        proposerKey=resource("proposer.key");approverKey=resource("approver.key");
        String keys=JSON.writeValueAsString(new AuthorizedKey("proposer",Files.readString(resource("proposer.pub"))))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Files.readString(resource("approver.pub"))))+"\n";
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),keys);
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"mixed-line\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"mixed-line\"}]}");
        service=new MappingRegistry(registry,CLOCK,()->{});
    }
    Path mappings(String rel){return registry.resolve("mappings").resolve(rel);}

    // Taken from main before the attestation existed (d03d426): approve + publish with these keys and clock.
    static final String RECEIPT_SHA="183360b0787e01985ac3670268bdb5a284c19180180fc5a04e28983e3239b96a",
        RELEASE_SHA="c6596c77a9aa37bc41350e558ee8028665848e680d61614297343bf1d23631f2",
        HEAD_SHA="532f67a8310e4414d6977f68a461d2e3375a1528bbb3855f630907297e18a123";
    @Test void receiptReleaseAndHeadBytesAreUnchanged() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        service.publish(bundle,"release","1.0.0","approval-1");
        String receipt=sha(mappings("approvals/approval-1.json")),release=sha(mappings("releases/release/1.0.0/release.json")),head=sha(mappings("heads/mixed-line.json"));
        assertEquals(RECEIPT_SHA,receipt);assertEquals(RELEASE_SHA,release);assertEquals(HEAD_SHA,head);
    }

    JsonNode publishVerified() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        service.publish(bundle,"release","1.0.0","approval-1");
        return service.verifyAttestation("release","1.0.0",RELEASE_SHA);
    }
    Path envelope(){return mappings("attestations/approval-1.dsse.json");}
    /** Re-signs a statement with the fixture keys, as an attacker holding both keys could; the content must still match. */
    void resign(java.util.function.Consumer<ObjectNode> change) throws Exception {resign(change,"proposer","approver");}
    void resign(java.util.function.Consumer<ObjectNode> change,String... signers) throws Exception {
        ObjectNode statement=(ObjectNode)JSON.readTree(Base64.getDecoder().decode(text(read(envelope()),"payload")));change.accept(statement);
        byte[] body=bytes(statement);List<Dsse.Signature> sigs=new ArrayList<>();
        for(String p:signers)sigs.add(new Dsse.Signature(p,Ed25519Keys.sign(Dsse.pae(Dsse.IN_TOTO,body),Ed25519Keys.privateKey(Files.readString(resource(p+".key")).strip()))));
        Files.write(envelope(),bytes(Dsse.envelope(Dsse.IN_TOTO,body,sigs)));
    }
    String refusal(){return assertThrows(Exception.class,()->service.verifyAttestation("release","1.0.0",RELEASE_SHA)).getMessage();}

    @Test void theStatementNamesTheReleasedFilesAndTheReceipt() throws Exception {
        JsonNode statement=publishVerified();JsonNode release=read(mappings("releases/release/1.0.0/release.json"));
        assertEquals("https://in-toto.io/Statement/v1",text(statement,"_type"));
        assertEquals(release.path("approval").path("payload"),statement.path("predicate"));
        assertEquals(release.path("files").size(),statement.path("subject").size());
        for(int i=0;i<release.path("files").size();i++){
            JsonNode f=release.path("files").get(i),s=statement.path("subject").get(i);
            assertEquals(text(f,"path"),text(s,"name"));assertEquals(text(f,"sha256"),text(s.path("digest"),"sha256"));
            // The subject digest is the raw bytes of the published file, nothing Bifrost-specific.
            assertEquals(sha(mappings("releases/release/1.0.0/"+text(f,"path"))),text(s.path("digest"),"sha256"));
        }
        JsonNode env=read(envelope());assertEquals("application/vnd.in-toto+json",text(env,"payloadType"));assertEquals(2,env.path("signatures").size());
        assertEquals(1,service.catalog().path("releases").size());assertTrue(service.status("mixed-line").path("approvals").size()==1);
    }

    @Test void whatVerifyAttestationRefuses() throws Exception {
        publishVerified();byte[] good=Files.readAllBytes(envelope());
        ObjectNode forged=(ObjectNode)read(envelope());forged.put("payload",Base64.getEncoder().encodeToString("{}".getBytes()));Files.write(envelope(),bytes(forged));
        assertEquals("mapping.attestation-signature:identity.dsse.signature",refusal());
        Files.write(envelope(),good);resign(s->((ObjectNode)s.path("predicate")).put("approvedBy","someone-else"));
        assertEquals("mapping.attestation-statement",refusal());
        Files.write(envelope(),good);resign(s->((ArrayNode)s.path("subject")).remove(0));
        assertEquals("mapping.attestation-subject",refusal());
        Files.write(envelope(),good);resign(s->((ObjectNode)s.path("subject").get(0).path("digest")).put("sha256","0".repeat(64)));
        assertEquals("mapping.attestation-subject",refusal());
        Files.write(envelope(),good);resign(s->s.put("predicateType","https://slsa.dev/provenance/v1"));
        assertEquals("mapping.attestation-statement",refusal());
        Files.write(envelope(),good);resign(s->{},"proposer");
        assertEquals("mapping.attestation-signature:identity.dsse.signature",refusal());
        Files.write(envelope(),good);resign(s->{},"approver");
        assertEquals("mapping.attestation-signature:identity.dsse.signature",refusal());
        Files.delete(envelope());assertEquals("mapping.attestation-missing",refusal());
        Files.write(envelope(),good);assertNotNull(service.verifyAttestation("release","1.0.0",RELEASE_SHA));
    }

    @Test void aCrashBeforeTheReceiptLeavesAnEnvelopeTheRetryReplaces() throws Exception {
        service.faults(p->{if(p.equals("attestation-written"))throw new IllegalStateException("fault");});
        assertThrows(Exception.class,()->service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey));
        assertTrue(Files.exists(envelope()));assertFalse(Files.exists(mappings("approvals/approval-1.json")));
        Files.write(envelope(),"orphan".getBytes());service.faults(p->{});
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        byte[] kept=Files.readAllBytes(envelope());
        assertEquals("mapping.approval-id-conflict",assertThrows(Exception.class,()->service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey)).getMessage());
        assertArrayEquals(kept,Files.readAllBytes(envelope()),"a refused approval rewrote the attestation of the existing one");
        service.publish(bundle,"release","1.0.0","approval-1");
        assertNotNull(service.verifyAttestation("release","1.0.0",RELEASE_SHA));
    }

    @Test void gcCountsAttestationsAmongItsRoots() throws Exception {
        publishVerified();String before=text(service.gc(3600,null),"rootsSha256");
        Files.write(envelope(),Files.readAllBytes(envelope()),StandardOpenOption.APPEND);
        assertNotEquals(before,text(service.gc(3600,null),"rootsSha256"));
    }
}
