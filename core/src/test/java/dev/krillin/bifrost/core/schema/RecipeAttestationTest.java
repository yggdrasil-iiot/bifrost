package dev.krillin.bifrost.core.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import static org.junit.jupiter.api.Assertions.*;

/** One publisher signs a recipe publication; the manifest stays byte-identical and the subject binds it by digest. */
class RecipeAttestationTest {
    @TempDir Path registry;
    static final ObjectMapper JSON = new ObjectMapper();
    static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-17T00:00:00Z"), ZoneOffset.UTC);
    static final byte[] CONTENT = "endpoint: x\nsetpoints: {}\n".getBytes(StandardCharsets.UTF_8);
    static final String DEF_REF = "0123456789abcdef0123456789abcdef01234567";
    static final long AT = 1_760_659_200_123L;

    static Path resource(String name) throws Exception {
        return Path.of(RecipeAttestationTest.class.getResource("/mapping-attestation/" + name).toURI());
    }
    @BeforeEach void setup() throws Exception {
        Files.createDirectories(registry.resolve("identity"));
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),
            "{\"principal\":\"proposer\",\"publicKey\":\"" + Files.readString(resource("proposer.pub")).strip() + "\"}\n"
          + "{\"principal\":\"approver\",\"publicKey\":\"" + Files.readString(resource("approver.pub")).strip() + "\"}\n");
        grant("proposer");
    }
    void grant(String principal) throws Exception {
        Files.writeString(registry.resolve("identity/activation-policy.json"), "{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":["
            + "{\"id\":\"publish-recipe\",\"principal\":\"" + principal + "\",\"action\":\"publish\",\"target\":\"recipe-publication\",\"kind\":\"recipe-setpoints\",\"ref\":\"line1\"}]}");
    }
    KeyFileSigner signer(String principal, String keyOf) throws Exception {
        return KeyFileSigner.create(principal, resource(keyOf + ".key"), AuthorizedKeys.load(registry), CLOCK);
    }
    RecipeManifest publish(KeyFileSigner signer) throws Exception {
        return new RecipeDefinitionStore(registry).publish("recipe-setpoints", "line1", "1.0.0", CONTENT, DEF_REF,
                RecipeAttestation.sha(CONTENT), "model/recipe-setpoints.yaml", AT, signer);
    }
    Path dir() { return registry.resolve("recipe/line1/1.0.0"); }
    Path envelope() { return dir().resolve("manifest.dsse.json"); }
    String refusal() { return assertThrows(RecipeAttestation.Refused.class, () -> RecipeAttestation.verify(registry, "line1", "1.0.0")).getMessage(); }

    /** Re-signs a changed statement with a fixture key, as a holder of that key could. */
    void resign(Consumer<ObjectNode> change, String keyOf) throws Exception {
        ObjectNode s = (ObjectNode) JSON.readTree(Base64.getDecoder().decode(JSON.readTree(envelope().toFile()).path("payload").asText()));
        change.accept(s);
        byte[] body = JSON.writeValueAsBytes(s);
        String sig = Ed25519Keys.sign(Dsse.pae(Dsse.IN_TOTO, body), Ed25519Keys.privateKey(Files.readString(resource(keyOf + ".key")).strip()));
        Files.write(envelope(), JSON.writeValueAsBytes(Dsse.envelope(Dsse.IN_TOTO, body, List.of(new Dsse.Signature(keyOf, sig)))));
    }
    static ObjectNode params(ObjectNode s) { return (ObjectNode) s.path("predicate").path("buildDefinition").path("externalParameters"); }

    @Test void aSignedPublishWritesAnSlsaStatementBesideAnUnchangedManifest() throws Exception {
        publish(signer("proposer", "proposer"));
        assertEquals(RecipeManifestBytesTest.MANIFEST_SHA, RecipeManifestBytesTest.sha(dir().resolve("manifest.json")));
        JsonNode s = RecipeAttestation.verify(registry, "line1", "1.0.0");
        assertEquals("https://in-toto.io/Statement/v1", s.path("_type").asText());
        assertEquals("https://slsa.dev/provenance/v1", s.path("predicateType").asText());
        Map<String, String> subject = new TreeMap<>();
        for (JsonNode e : s.path("subject")) subject.put(e.path("name").asText(), e.path("digest").path("sha256").asText());
        assertEquals(Map.of("recipe-setpoints.yaml", RecipeAttestation.sha(CONTENT), "manifest.json", RecipeManifestBytesTest.MANIFEST_SHA), subject);
        JsonNode build = s.path("predicate").path("buildDefinition");
        assertEquals("proposer", build.path("externalParameters").path("publishedBy").asText());
        assertEquals(DEF_REF, build.path("resolvedDependencies").get(0).path("digest").path("gitCommit").asText());
        assertEquals("2025-10-17T00:00:00Z", s.path("predicate").path("runDetails").path("metadata").path("finishedOn").asText());
        JsonNode env = JSON.readTree(envelope().toFile());
        assertEquals("application/vnd.in-toto+json", env.path("payloadType").asText());
        assertEquals(1, env.path("signatures").size());
        assertFalse(Files.exists(dir().resolve("manifest.dsse.json.pending")));
    }

    @Test void aSignedPublishIsRefusedBeforeAnythingIsWritten() throws Exception {
        assertEquals("identity.key.principal-mismatch", assertThrows(RecipeAttestation.Refused.class, () -> publish(signer("proposer", "approver"))).getMessage());
        assertEquals("recipe.publish-denied", assertThrows(RecipeAttestation.Refused.class, () -> publish(signer("approver", "approver"))).getMessage());
        assertFalse(Files.exists(dir()), "a refused publish left a version directory latest() would pick");
    }

    @Test void aRetiredKeyPublishesNothingNew() throws Exception {
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"), "{\"principal\":\"proposer\",\"publicKey\":\""
            + Files.readString(resource("proposer.pub")).strip() + "\",\"notAfter\":\"2026-01-01T00:00:00Z\"}\n");
        assertEquals("identity.key.expired", assertThrows(RecipeAttestation.Refused.class, () -> publish(signer("proposer", "proposer"))).getMessage());
        assertFalse(Files.exists(dir()));
    }

    @Test void anExistingVersionIsNeverSignedAfterTheFact() throws Exception {
        publish(null);
        assertEquals("recipe.publish.already-published-unsigned", assertThrows(RecipeAttestation.Refused.class, () -> publish(signer("proposer", "proposer"))).getMessage());
        assertFalse(Files.exists(envelope()));
        assertEquals("recipe.attestation-missing", refusal());
    }

    @Test void aSignedRePublishKeepsAValidEnvelopeAndRefusesABrokenOne() throws Exception {
        publish(signer("proposer", "proposer"));
        byte[] kept = Files.readAllBytes(envelope());
        publish(signer("proposer", "proposer"));
        assertArrayEquals(kept, Files.readAllBytes(envelope()), "a re-publish rewrote the publication attestation");
        resign(s -> params(s).put("sourcePath", "elsewhere.yaml"), "proposer");
        assertEquals("recipe.attestation-predicate", assertThrows(RecipeAttestation.Refused.class, () -> publish(signer("proposer", "proposer"))).getMessage());
    }

    @Test void whatVerifyRefuses() throws Exception {
        publish(signer("proposer", "proposer"));
        byte[] good = Files.readAllBytes(envelope()), manifest = Files.readAllBytes(dir().resolve("manifest.json"));
        ObjectNode forged = (ObjectNode) JSON.readTree(good);
        forged.put("payload", Base64.getEncoder().encodeToString("{}".getBytes()));
        Files.write(envelope(), JSON.writeValueAsBytes(forged));
        assertEquals("recipe.attestation-signature:identity.dsse.signature", refusal());
        Files.write(envelope(), good); resign(s -> {}, "approver");
        assertEquals("recipe.attestation-signature:identity.dsse.signature", refusal(), "the approver's key signed for the proposer");
        Files.write(envelope(), good); resign(s -> params(s).put("publishedBy", "approver"), "approver");
        assertEquals("recipe.publish-denied", refusal(), "a registered key without a PUBLISH grant");
        Files.write(envelope(), good); resign(s -> s.put("predicateType", "https://in-toto.io/attestation/release/v0.1"), "proposer");
        assertEquals("recipe.attestation-statement", refusal());
        Files.write(envelope(), good); resign(s -> s.withArray("subject").remove(1), "proposer");
        assertEquals("recipe.attestation-subject", refusal());
        Files.write(envelope(), good); resign(s -> ((ObjectNode) s.path("predicate").path("buildDefinition").path("resolvedDependencies").get(0).path("digest")).put("gitCommit", "f".repeat(40)), "proposer");
        assertEquals("recipe.attestation-predicate", refusal());
        Files.write(envelope(), good); resign(s -> params(s).put("version", "1.0.1"), "proposer");
        assertEquals("recipe.attestation-predicate", refusal());
        Files.write(envelope(), good); resign(s -> params(s).put("sourcePath", "elsewhere.yaml"), "proposer");
        assertEquals("recipe.attestation-predicate", refusal());
        Files.write(envelope(), good); resign(s -> ((ObjectNode) s.path("predicate").path("runDetails").path("metadata")).put("finishedOn", "2025-10-17T00:00:01Z"), "proposer");
        assertEquals("recipe.attestation-predicate", refusal());
        Files.write(envelope(), good);
        Files.writeString(dir().resolve("manifest.json"), new String(manifest, StandardCharsets.UTF_8).replace("123", "124"));
        assertEquals("recipe.attestation-subject", refusal(), "publishedAt changed in manifest.json");
        Files.write(dir().resolve("manifest.json"), manifest);
        Files.writeString(dir().resolve("recipe-setpoints.yaml"), "endpoint: y\nsetpoints: {}\n");
        assertEquals("recipe.attestation-subject", refusal());
        Files.write(dir().resolve("recipe-setpoints.yaml"), CONTENT);
        grant("someone-else");
        assertEquals("recipe.publish-denied", refusal(), "the grant was withdrawn");
        grant("proposer");
        Files.delete(envelope());
        assertEquals("recipe.attestation-missing", refusal());
        Files.write(envelope(), good);
        assertNotNull(RecipeAttestation.verify(registry, "line1", "1.0.0"));
    }

    @Test void aLineEndingConversionIsStillRefusedButNamed() throws Exception {
        publish(signer("proposer", "proposer"));
        Path yaml = dir().resolve("recipe-setpoints.yaml"), manifest = dir().resolve("manifest.json");
        byte[] manifestBytes = Files.readAllBytes(manifest);
        String crlfYaml = new String(CONTENT, StandardCharsets.UTF_8).replace("\n", "\r\n");
        String crlfManifest = new String(manifestBytes, StandardCharsets.UTF_8).replace("\n", "\r\n");
        Files.writeString(yaml, crlfYaml);
        assertEquals("recipe.attestation-subject:line-endings", refusal(), "git core.autocrlf on the canonical");
        Files.writeString(manifest, crlfManifest);
        assertEquals("recipe.attestation-subject:line-endings", refusal(), "both files converted");
        Files.write(yaml, CONTENT);
        assertEquals("recipe.attestation-subject:line-endings", refusal(), "only the manifest converted");
        Files.writeString(yaml, crlfYaml.replace("endpoint: x", "endpoint: y"));
        assertEquals("recipe.attestation-subject", refusal(), "a converted manifest does not excuse an edited canonical");
        Files.write(yaml, CONTENT); Files.write(manifest, manifestBytes);
        assertNotNull(RecipeAttestation.verify(registry, "line1", "1.0.0"));
    }

    @Test void anEnvelopeLeftWithoutAManifestIsReplacedByTheSignedRetry() throws Exception {
        Files.createDirectories(dir());
        Files.writeString(envelope(), "orphan");
        publish(signer("proposer", "proposer"));
        assertNotNull(RecipeAttestation.verify(registry, "line1", "1.0.0"));
    }

    @Test void anUnsignedPublishOverAnOrphanEnvelopeDoesNotVerify() throws Exception {
        publish(signer("proposer", "proposer"));
        byte[] orphan = Files.readAllBytes(envelope());
        Files.walk(dir()).sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        Files.createDirectories(dir());
        Files.write(envelope(), orphan);
        new RecipeDefinitionStore(registry).publish("recipe-setpoints", "line1", "1.0.0", CONTENT, DEF_REF,
                RecipeAttestation.sha(CONTENT), "model/recipe-setpoints.yaml", AT + 1000, null);
        assertEquals("recipe.attestation-subject", refusal());
    }
}
