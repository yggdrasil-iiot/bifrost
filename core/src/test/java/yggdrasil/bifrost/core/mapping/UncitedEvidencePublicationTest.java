package yggdrasil.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import yggdrasil.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import static yggdrasil.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** An evidence-artifact that no document cites is still part of the release: accepted, copied byte for byte,
 *  listed in release.json and signed as a statement subject. Downstream readers (Vor's read binding) carry
 *  their own files this way and verify the content themselves; Bifrost pins only the bytes. */
class UncitedEvidencePublicationTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-31T00:00:00Z"),ZoneOffset.UTC);
    // Deliberately non-canonical: odd key order, CRLF, tab indent, no trailing newline, non-ASCII.
    static final byte[] FILE=("{\r\n\t\"profileVersion\": \"0.1.0\",  \"metric\":\"Temp\",\r\n\t\"device\": \"synthetic-site:record-line-a\", \"note\": \"Vör\"\r\n}")
            .getBytes(StandardCharsets.UTF_8);
    static final String PUBLISHED="payload/data/uncited.json";

    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/equipment-hierarchy").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n");
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"hierarchy-line\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"hierarchy-line\"}]}");
        service=new MappingRegistry(registry,CLOCK,()->{});
    }

    void addUncited(String schemaVersion) throws Exception {
        Files.write(bundle.resolve("data/uncited.json"),FILE);
        ObjectNode art=(ObjectNode)read(bundle.resolve("evidence/1.json"));
        art.put("schemaVersion",schemaVersion).put("id","uncited-file");
        ((ObjectNode)art.path("file")).put("path","data/uncited.json").put("sha256",sha(bundle.resolve("data/uncited.json"))).put("mediaType","application/json");
        Files.write(bundle.resolve("evidence/uncited.json"),bytes(art));
        ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));
        ((ArrayNode)proposal.path("files")).addObject().put("path","evidence/uncited.json").put("kind","evidence-artifact")
                .put("id","uncited-file").put("version","1.0.0").put("sha256",sha(bundle.resolve("evidence/uncited.json")));
        Files.write(bundle.resolve("proposal.json"),bytes(proposal));
        ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));Files.write(bundle.resolve("submission.json"),bytes(s));
    }
    Path publish() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);service.publish(bundle,"release","1.0.0","approval-1");
        return registry.resolve("mappings/releases/release/1.0.0");
    }
    JsonNode statement(Path dir) throws Exception {return service.verifyAttestation("release","1.0.0",sha(dir.resolve("release.json")));}

    @Test void acceptedUnderEvidence100() throws Exception {addUncited("1.0.0");var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());}
    @Test void acceptedUnderEvidence110() throws Exception {addUncited("1.1.0");var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());}
    @Test void publishedByteForByte() throws Exception {addUncited("1.0.0");assertArrayEquals(FILE,Files.readAllBytes(publish().resolve(PUBLISHED)));}
    @Test void listedAndSigned() throws Exception {
        addUncited("1.0.0");Path dir=publish();String digest=sha(dir.resolve(PUBLISHED));
        String listed=null;for(JsonNode f:read(dir.resolve("release.json")).path("files"))if(text(f,"path").equals(PUBLISHED))listed=text(f,"sha256");
        assertEquals(digest,listed,"release.json files[]");
        boolean signed=false;for(JsonNode s:statement(dir).path("subject"))signed|=text(s.path("digest"),"sha256").equals(digest);
        assertTrue(signed,"statement subjects");
    }
    @Test void tamperAfterPublicationIsRefused() throws Exception {
        addUncited("1.0.0");Path dir=publish();byte[] t=FILE.clone();t[t.length-2]^=1;Files.write(dir.resolve(PUBLISHED),t);
        var e=assertThrows(IllegalArgumentException.class,()->statement(dir));assertEquals("mapping.release-file",e.getMessage());
    }
}
