package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import dev.krillin.bifrost.core.activation.FileAnchorStore;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.stream.StreamSupport;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** Head freshness under the TUF rules: a version that only goes up, kept by a witness outside mappings/, and an expiry. */
class MappingHeadAttestationTest {
    static final class MovableClock extends Clock {
        Instant now=Instant.parse("2026-10-17T00:00:00Z");
        @Override public ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public Clock withZone(ZoneId zone){return this;}
        @Override public Instant instant(){return now;}
    }
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MovableClock clock=new MovableClock();
    MappingRegistry service;
    static Path resource(String name) throws Exception {return MappingAttestationTest.resource(name);}
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingPublicationTest.copy(Path.of(getClass().getResource("/mapping-fixtures/valid").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        proposerKey=resource("proposer.key");approverKey=resource("approver.key");
        String keys=JSON.writeValueAsString(new AuthorizedKey("proposer",Files.readString(resource("proposer.pub"))))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Files.readString(resource("approver.pub"))))+"\n";
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),keys);
        policy(true);
        service=new MappingRegistry(registry,clock,()->{});
    }
    void policy(boolean approverMayApprove) throws Exception {
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"mixed-line\"}"
            +(approverMayApprove?",{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"mixed-line\"}":"")+"]}");
    }
    Path mappings(String rel){return registry.resolve("mappings").resolve(rel);}
    Path envelope(){return mappings("head-attestations/mixed-line.dsse.json");}
    MappingRegistry.HeadSigners signers(){return signers(Duration.ofDays(90));}
    MappingRegistry.HeadSigners signers(Duration life){return new MappingRegistry.HeadSigners("proposer",proposerKey,"approver",approverKey,life);}
    void rewrite(Path p,JsonNode doc) throws Exception {Files.write(p,bytes(doc));}
    JsonNode publish(String approval,String ver) throws Exception {
        service.approve(bundle,approval,"proposer",proposerKey,"approver",approverKey);return service.publish(bundle,"release",ver,approval,signers());
    }
    /** The next submission names the current head as its base, as Tyr does. */
    void next(String id) throws Exception {
        JsonNode h=service.status("mixed-line").get("head");ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("id",id);s.set("baseRelease",h);
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.set("baseRelease",h);rewrite(bundle.resolve("proposal.json"),p);s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);
    }
    String refusal(org.junit.jupiter.api.function.Executable e){return assertThrows(Exception.class,e).getMessage();}
    String verifyRefusal(){return refusal(()->service.verifyHead("mixed-line"));}
    static void copyTree(Path from,Path to) throws Exception {
        if(Files.exists(to))try(var walk=Files.walk(to)){for(Path p:walk.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}
        MappingPublicationTest.copy(from,to);
    }
    /** Re-signs the head statement with the fixture keys, as someone holding both keys could. */
    void resign(java.util.function.Consumer<ObjectNode> change,String... signers) throws Exception {
        ObjectNode statement=(ObjectNode)JSON.readTree(Base64.getDecoder().decode(text(read(envelope()),"payload")));change.accept(statement);
        byte[] body=bytes(statement);List<Dsse.Signature> sigs=new ArrayList<>();
        for(String p:signers)sigs.add(new Dsse.Signature(p,Ed25519Keys.sign(Dsse.pae(Dsse.IN_TOTO,body),Ed25519Keys.privateKey(Files.readString(resource(p+".key")).strip()))));
        Files.write(envelope(),bytes(Dsse.envelope(Dsse.IN_TOTO,body,sigs)));
    }
    ObjectNode predicate(ObjectNode statement){return (ObjectNode)statement.path("predicate");}

    @Test void signingTheHeadLeavesEveryProtectedFileByteForByte() throws Exception {
        clock.now=Instant.parse("2026-10-17T00:00:00Z");publish("approval-1","1.0.0");
        assertEquals(MappingAttestationTest.RECEIPT_SHA,sha(mappings("approvals/approval-1.json")));
        assertEquals(MappingAttestationTest.RELEASE_SHA,sha(mappings("releases/release/1.0.0/release.json")));
        assertEquals(MappingAttestationTest.HEAD_SHA,sha(mappings("heads/mixed-line.json")));
        assertNotNull(service.verifyAttestation("release","1.0.0",MappingAttestationTest.RELEASE_SHA));
    }

    @Test void publishSignsVersionOneThenTwoAndTheWitnessFollows() throws Exception {
        publish("approval-1","1.0.0");JsonNode v1=service.verifyHead("mixed-line");
        assertEquals(1,v1.path("headVersion").asInt());assertEquals("publish",text(v1,"cause"));assertEquals("2027-01-15T00:00:00Z",text(v1,"expires"));
        JsonNode statement=JSON.readTree(Base64.getDecoder().decode(text(read(envelope()),"payload")));
        assertEquals("https://github.com/yggdrasil-iiot/bifrost/attestation/mapping-head/v1",text(statement,"predicateType"));
        assertEquals(sha(mappings("heads/mixed-line.json")),text(statement.path("subject").get(0).path("digest"),"sha256"));
        assertEquals("releases/release/1.0.0/release.json",text(statement.path("subject").get(1),"name"));
        assertTrue(statement.path("predicate").path("previous").isNull());
        next("second");clock.now=clock.now.plus(Duration.ofDays(1));publish("approval-2","2.0.0");
        JsonNode v2=service.verifyHead("mixed-line");assertEquals(2,v2.path("headVersion").asInt());
        JsonNode p2=JSON.readTree(Base64.getDecoder().decode(text(read(envelope()),"payload"))).path("predicate");
        assertEquals(1,p2.path("previous").path("headVersion").asInt());assertEquals("1.0.0",text(p2.path("previous").path("release"),"version"));
        List<String> witness=Files.readAllLines(registry.resolve("anchor/mapping-head-mixed-line.anchor.jsonl"));assertEquals(2,witness.size());
        assertTrue(witness.get(1).contains(sha(mappings("heads/mixed-line.json"))));
        assertEquals(2,service.catalog().path("releases").size());
    }

    @Test void restoringAnOlderHeadAndItsAttestationIsARollback() throws Exception {
        publish("approval-1","1.0.0");Path saved=tmp.resolve("saved");copyTree(mappings("heads"),saved.resolve("heads"));copyTree(mappings("head-attestations"),saved.resolve("head-attestations"));
        next("second");publish("approval-2","2.0.0");
        copyTree(saved.resolve("heads"),mappings("heads"));copyTree(saved.resolve("head-attestations"),mappings("head-attestations"));
        assertEquals("mapping.head-rollback",verifyRefusal());
        assertEquals("mapping.head-rollback",refusal(()->service.signHead("mixed-line",signers())));
        next("third");service.approve(bundle,"approval-3","proposer",proposerKey,"approver",approverKey);
        assertEquals("mapping.head-rollback",refusal(()->service.publish(bundle,"release","3.0.0","approval-3",signers())));
        assertFalse(Files.exists(mappings("releases/release/3.0.0")));assertFalse(Files.exists(mappings("transactions"))&&Files.list(mappings("transactions")).findAny().isPresent());
    }

    @Test void removingTheAttestationWhileTheWitnessRemainsIsARollback() throws Exception {
        publish("approval-1","1.0.0");Files.delete(envelope());
        assertEquals("mapping.head-rollback",verifyRefusal());
        // An unsigned publication cannot take over a stream that once had a signed head.
        Files.delete(mappings("heads/mixed-line.json"));
        service.approve(bundle,"approval-1b","proposer",proposerKey,"approver",approverKey);
        assertEquals("mapping.head-signers-required",refusal(()->service.publish(bundle,"release","9.0.0","approval-1b")));
    }

    @Test void aWitnessOffTheBoxCatchesARestoredCopyOfTheWholeRegistry() throws Exception {
        Path offBox=tmp.resolve("off-box");service=new MappingRegistry(registry,clock,()->{},new FileAnchorStore(offBox));
        publish("approval-1","1.0.0");Path saved=tmp.resolve("saved");copyTree(registry,saved);
        next("second");publish("approval-2","2.0.0");
        copyTree(saved,registry);
        assertEquals("1.0.0",text(read(mappings("heads/mixed-line.json")),"version"));
        assertEquals("mapping.head-rollback",verifyRefusal());
    }

    @Test void whatVerifyHeadRefuses() throws Exception {
        publish("approval-1","1.0.0");byte[] good=Files.readAllBytes(envelope());
        resign(s->{},"proposer");assertEquals("mapping.head-attestation-signature:identity.dsse.signature",verifyRefusal());
        Files.write(envelope(),good);resign(s->predicate(s).put("approvedBy","proposer"),"proposer","approver");assertEquals("mapping.head-attestation-statement",verifyRefusal());
        Files.write(envelope(),good);resign(s->s.put("predicateType","https://slsa.dev/provenance/v1"),"proposer","approver");assertEquals("mapping.head-attestation-statement",verifyRefusal());
        Files.write(envelope(),good);resign(s->predicate(s).put("streamId","other-line"),"proposer","approver");assertEquals("mapping.head-attestation-statement",verifyRefusal());
        Files.write(envelope(),good);resign(s->predicate(s).put("cause","recover"),"proposer","approver");assertEquals("mapping.head-attestation-statement",verifyRefusal());
        Files.write(envelope(),good);resign(s->predicate(s).put("approvalId","approval-9"),"proposer","approver");assertEquals("mapping.head-attestation-statement",verifyRefusal());
        Files.write(envelope(),good);resign(s->predicate(s).put("expires","2026-10-16T00:00:00Z"),"proposer","approver");assertEquals("mapping.head-attestation-statement",verifyRefusal());
        Files.write(envelope(),good);resign(s->predicate(s).put("extra",1),"proposer","approver");assertEquals("mapping.head-attestation-statement",verifyRefusal());
        Files.write(envelope(),good);resign(s->((ObjectNode)s.path("subject").get(0).path("digest")).put("sha256","0".repeat(64)),"proposer","approver");assertEquals("mapping.head-attestation-subject",verifyRefusal());
        Files.write(envelope(),good);resign(s->((ObjectNode)predicate(s).path("release")).put("version","9.9.9"),"proposer","approver");assertEquals("mapping.head-attestation-subject",verifyRefusal());
        Files.write(envelope(),good);resign(s->predicate(s).set("previous",object().put("headVersion",0).set("release",predicate(s).path("release"))),"proposer","approver");assertEquals("mapping.head-attestation-statement",verifyRefusal());
        Files.write(envelope(),good);resign(s->predicate(s).put("headVersion",3).set("previous",object().put("headVersion",2).set("release",predicate(s).path("release"))),"proposer","approver");assertEquals("mapping.head-anchor-behind",verifyRefusal());
        Files.write(envelope(),good);Path witness=registry.resolve("anchor/mapping-head-mixed-line.anchor.jsonl");String line=Files.readString(witness);
        Files.writeString(witness,line.replace(sha(mappings("heads/mixed-line.json")),"0".repeat(64)));assertEquals("mapping.head-anchor-tail-mismatch",verifyRefusal());
        Files.writeString(witness,line);
        Files.write(envelope(),good);policy(false);assertEquals("mapping.approve-denied",verifyRefusal());
        policy(true);Files.delete(registry.resolve("anchor/mapping-head-mixed-line.anchor.jsonl"));assertEquals("mapping.head-anchor-missing",verifyRefusal());
    }

    @Test void anExpiredHeadIsRefusedUntilRenewed() throws Exception {
        publish("approval-1","1.0.0");clock.now=Instant.parse("2027-01-14T23:59:59Z");service.verifyHead("mixed-line");
        clock.now=Instant.parse("2027-01-15T00:00:00Z");assertEquals("mapping.head-expired",verifyRefusal());
        JsonNode renewed=service.signHead("mixed-line",signers(Duration.ofDays(30)));
        assertEquals(2,renewed.path("headVersion").asInt());assertEquals("renew",text(renewed,"cause"));assertEquals("2027-02-14T00:00:00Z",text(renewed,"expires"));
        assertEquals(2,service.verifyHead("mixed-line").path("headVersion").asInt());
        assertEquals(MappingAttestationTest.HEAD_SHA,sha(mappings("heads/mixed-line.json")));
    }

    @Test void aVerifierClockFarBehindTheSignerRefuses() throws Exception {
        publish("approval-1","1.0.0");
        clock.now=Instant.parse("2026-10-16T00:00:00Z");service.verifyHead("mixed-line");
        clock.now=Instant.parse("2026-10-15T23:59:59Z");assertEquals("mapping.head-clock-behind",verifyRefusal());
    }

    @Test void signingNeedsTwoAuthorizedPrincipalsAndABoundedLifetime() throws Exception {
        publish("approval-1","1.0.0");
        assertEquals("mapping.approval.self",refusal(()->service.signHead("mixed-line",new MappingRegistry.HeadSigners("proposer",proposerKey,"proposer",proposerKey,Duration.ofDays(90)))));
        assertEquals("mapping.head-expiry-bounds",refusal(()->service.signHead("mixed-line",signers(Duration.ofHours(23)))));
        assertEquals("mapping.head-expiry-bounds",refusal(()->service.signHead("mixed-line",signers(Duration.ofDays(367)))));
        assertTrue(refusal(()->service.signHead("mixed-line",new MappingRegistry.HeadSigners("proposer",approverKey,"approver",approverKey,Duration.ofDays(90)))).startsWith("mapping.identity-refused:"));
        policy(false);assertEquals("mapping.approve-denied",refusal(()->service.signHead("mixed-line",signers())));
        policy(true);assertEquals(1,service.verifyHead("mixed-line").path("headVersion").asInt());
    }

    @Test void aLegacyHeadIsReportedThenAttestedAsVersionOne() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);service.publish(bundle,"release","1.0.0","approval-1");
        assertEquals("mapping.head-attestation-missing",verifyRefusal());
        assertEquals(1,service.catalog().path("releases").size());service.status("mixed-line");
        JsonNode migrated=service.signHead("mixed-line",signers());assertEquals(1,migrated.path("headVersion").asInt());assertEquals("migrate",text(migrated,"cause"));
        next("second");service.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey);
        assertEquals("mapping.head-signers-required",refusal(()->service.publish(bundle,"release","2.0.0","approval-2")));
        service.publish(bundle,"release","2.0.0","approval-2",signers());assertEquals(2,service.verifyHead("mixed-line").path("headVersion").asInt());
    }

    @Test void aLegacyStreamAlsoMigratesWithItsNextSignedPublication() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);service.publish(bundle,"release","1.0.0","approval-1");
        next("second");publish("approval-2","2.0.0");
        JsonNode v=service.verifyHead("mixed-line");assertEquals(1,v.path("headVersion").asInt());assertEquals("publish",text(v,"cause"));
    }

    @Test void recoveryPlacesTheSignedAttestationAfterEachInterruption() throws Exception {
        for(String point:List.of("intent-written","release-moved","head-moved","head-attestation-moved","head-anchored")){
            bundle=tmp.resolve("bundle-"+point);MappingPublicationTest.copy(Path.of(getClass().getResource("/mapping-fixtures/valid").toURI()),bundle);
            registry=tmp.resolve("registry-"+point);MappingPublicationTest.copy(tmp.resolve("registry/identity"),registry.resolve("identity"));service=new MappingRegistry(registry,clock,()->{});
            service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
            service.faults(p->{if(p.equals(point))throw new IllegalStateException("fault");});
            assertThrows(Exception.class,()->service.publish(bundle,"release","1.0.0","approval-1",signers()),point);
            service.faults(p->{});assertEquals("mapping.recovery-required",verifyRefusal(),point);
            JsonNode actions=service.recover().path("actions");assertEquals("placed",text(actions.get(0),"headAttestation"),point);
            assertEquals(1,service.verifyHead("mixed-line").path("headVersion").asInt(),point);
            assertEquals(MappingAttestationTest.HEAD_SHA,sha(mappings("heads/mixed-line.json")),point);
        }
    }

    @Test void aStopBeforeTheIntentLeavesTheStreamUntouched() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        service.faults(p->{if(p.equals("head-attestation-staged"))throw new IllegalStateException("fault");});
        assertThrows(Exception.class,()->service.publish(bundle,"release","1.0.0","approval-1",signers()));service.faults(p->{});
        assertFalse(Files.exists(envelope()));assertFalse(Files.exists(mappings("heads/mixed-line.json")));
        service.publish(bundle,"release","1.0.0","approval-1",signers());assertEquals(1,service.verifyHead("mixed-line").path("headVersion").asInt());
    }

    @Test void aSignHeadStoppedBeforeItsWitnessIsFinishedByTheNextOne() throws Exception {
        publish("approval-1","1.0.0");
        service.faults(p->{if(p.equals("head-attestation-moved"))throw new IllegalStateException("fault");});
        assertThrows(Exception.class,()->service.signHead("mixed-line",signers()));service.faults(p->{});
        assertEquals("mapping.head-anchor-behind",verifyRefusal());
        assertEquals(3,service.signHead("mixed-line",signers()).path("headVersion").asInt());
        assertEquals(3,service.verifyHead("mixed-line").path("headVersion").asInt());
    }

    @Test void aVersionOneJournalStillRecoversUnsigned() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        service.faults(p->{if(p.equals("release-moved"))throw new IllegalStateException("fault");});
        assertThrows(Exception.class,()->service.publish(bundle,"release","1.0.0","approval-1"));service.faults(p->{});
        assertEquals("unsigned",text(service.recover().path("actions").get(0),"headAttestation"));
        assertEquals("mapping.head-attestation-missing",verifyRefusal());
    }

    @Test void aJournalNamingAForeignAttestationIsRefused() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        service.faults(p->{if(p.equals("release-moved"))throw new IllegalStateException("fault");});
        assertThrows(Exception.class,()->service.publish(bundle,"release","1.0.0","approval-1",signers()));service.faults(p->{});
        Path journal;try(var files=Files.list(mappings("transactions"))){journal=files.findFirst().orElseThrow();}
        ObjectNode j=(ObjectNode)read(journal);j.put("headAttestation","../heads/mixed-line.json");Files.write(journal,bytes(j));
        assertEquals("mapping.journal-path",refusal(()->service.recover()));
    }

    @Test void gcCountsHeadAttestationsAmongItsRoots() throws Exception {
        publish("approval-1","1.0.0");String before=text(service.gc(3600,null),"rootsSha256");
        Files.write(envelope(),Files.readAllBytes(envelope()),StandardOpenOption.APPEND);
        assertNotEquals(before,text(service.gc(3600,null),"rootsSha256"));
        Path stale=mappings("head-attestations/."+UUID.randomUUID()+".pending");Files.writeString(stale,"{}");
        Files.setLastModifiedTime(stale,java.nio.file.attribute.FileTime.from(clock.now.minusSeconds(7200)));
        JsonNode plan=service.gc(3600,null);
        assertTrue(StreamSupport.stream(plan.path("candidates").spliterator(),false).anyMatch(c->text(c,"path").equals("head-attestations/"+stale.getFileName())));
    }
}
