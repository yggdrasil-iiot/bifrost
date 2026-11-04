package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** 2.25 command binding as Tyr packages it: the imported read bindings ride as evidence-artifacts with their bytes
 *  unchanged, Bifrost's own checks accept the bundle, and the release attests every link and profile. */
class MappingTyrCommandBindingTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-11-04T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/command-binding").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n");
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line1\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line1\"}]}");
        service=new MappingRegistry(registry,CLOCK,()->{});
    }
    @Test void acceptsTyrBundle() {
        var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());
        assertEquals("2.25.0",text(c.proposal(),"schemaVersion"));
        assertEquals(2,c.documents().values().stream().filter(d->text(d,"kind").equals("command-binding")).count());
    }
    @Test void releaseAndAttestationCarryEachLinkAndItsReadBinding() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        assertEquals("mapping-release",text(service.publish(bundle,"release","1.0.0","approval-1"),"kind"));
        Path dir=registry.resolve("mappings/releases/release/1.0.0");JsonNode release=read(dir.resolve("release.json"));
        JsonNode statement=service.verifyAttestation("release","1.0.0",sha(dir.resolve("release.json")));
        Set<String> subjects=new HashSet<>();for(JsonNode s:statement.path("subject"))subjects.add(text(s.path("digest"),"sha256"));
        Map<String,String> files=new HashMap<>();for(JsonNode f:release.path("files"))files.put(text(f,"path"),text(f,"sha256"));
        for(String p:List.of("command-bindings/0.json","command-bindings/1.json","evidence/read-binding-0.json","evidence/read-binding-1.json")){
            String h=files.entrySet().stream().filter(e->e.getKey().endsWith(p)).map(Map.Entry::getValue).findFirst().orElse(null);
            assertEquals(sha(bundle.resolve(p)),h,p);assertTrue(subjects.contains(h),p);
        }
        // the profile bytes Vor will hash are the bytes Tyr imported
        String profile=files.entrySet().stream().filter(e->e.getKey().endsWith("data/read-binding-0.json")).map(Map.Entry::getValue).findFirst().orElseThrow();
        assertEquals(text(read(bundle.resolve("evidence/read-binding-0.json")).path("file"),"sha256"),profile);
    }
    @Test void aLinkToAnotherMixersReadBindingIsRefused() throws Exception {
        Path file=bundle.resolve("command-bindings/1.json");ObjectNode c=(ObjectNode)read(file);
        ((ObjectNode)c.path("readBindingRef")).put("id","read-binding-mixer1-temp");Files.write(file,bytes(c));
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:p.path("files"))if(text(e,"path").equals("command-bindings/1.json"))((ObjectNode)e).put("sha256",sha(file));
        Files.write(bundle.resolve("proposal.json"),bytes(p));
        ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));Files.write(bundle.resolve("submission.json"),bytes(s));
        assertEquals(List.of("command-binding.device-path"),new MappingBundle().validate(bundle).report().path("findings").findValuesAsText("ruleCode"));
    }
}
