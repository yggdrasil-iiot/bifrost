package dev.krillin.bifrost.core.activation;

import dev.krillin.bifrost.core.conformance.MasterSpecStore;
import dev.krillin.bifrost.core.identity.*;
import dev.krillin.bifrost.core.schema.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.time.*;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/** Activation of kind recipe binds a publication: the canonical bytes, the manifest and envelope digests, and the
 *  git commit go into the ledger, and every way the publication can be wrong refuses with its own rule. */
class PublishedActivationTest {
    @TempDir Path reg;
    @TempDir Path keys;
    static final String DEF_REF = "0123456789abcdef0123456789abcdef01234567";
    static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-17T00:00:00Z"), ZoneOffset.UTC);
    ActivationLedger ledger;
    ActivationService svc;
    KeyPair alice, bob;

    static Path resource(String name) throws Exception {
        return Path.of(PublishedActivationTest.class.getResource("/mapping-attestation/" + name).toURI());
    }

    @BeforeEach void setup() throws Exception {
        alice = Ed25519Keys.generate(); bob = Ed25519Keys.generate();
        Files.createDirectories(reg.resolve("identity"));
        Files.writeString(reg.resolve("identity/authorized-keys.jsonl"),
            "{\"principal\":\"proposer\",\"publicKey\":\"" + Files.readString(resource("proposer.pub")).strip() + "\"}\n"
          + "{\"principal\":\"alice\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(alice.getPublic()) + "\"}\n"
          + "{\"principal\":\"bob\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(bob.getPublic()) + "\"}\n");
        policy(true);
        ledger = new ActivationLedger(reg);
        svc = new ActivationService(new RecipeArtifactResolver(reg), ledger, Clock.fixed(Instant.ofEpochMilli(42L), ZoneOffset.UTC));
    }

    void policy(boolean publisherGranted) throws Exception {
        Files.writeString(reg.resolve("identity/activation-policy.json"), "{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":["
            + (publisherGranted ? "{\"id\":\"pub\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"recipe-publication\",\"kind\":\"recipe-setpoints\",\"ref\":\"*\"}," : "")
            + "{\"id\":\"act\",\"principal\":\"alice\",\"action\":\"activate\",\"target\":\"Line1\",\"kind\":\"recipe\",\"ref\":\"*\"},"
            + "{\"id\":\"app\",\"principal\":\"bob\",\"action\":\"approve\",\"target\":\"Line1\",\"kind\":\"recipe\",\"ref\":\"*\"}]}");
    }

    static byte[] spec(String ref, String version) throws Exception {
        return JsonMapperFactory.prettyWriter(JsonMapperFactory.create()).writeValueAsBytes(
                new MasterSpec(ref, version, "Line1", "Line1-Mixer", "1.0.0", List.of(new Setpoint("Rpm", "Double", 1500))));
    }

    RecipeManifest publish(String kind, String ref, String version, byte[] bytes, boolean signed) throws Exception {
        KeyFileSigner signer = signed ? KeyFileSigner.create("proposer", resource("proposer.key"), AuthorizedKeys.load(reg), CLOCK) : null;
        return new RecipeDefinitionStore(reg).publish(kind, ref, version, bytes, DEF_REF, Sha256.hex(bytes),
                "recipes/" + ref + ".json", 1_760_659_200_123L, signer);
    }
    RecipeManifest publish(String version, boolean signed) throws Exception {
        return publish(PublishedRecipe.MANIFEST_KIND, "mix-recipe", version, spec("mix-recipe", version), signed);
    }

    Path dir(String version) { return reg.resolve("recipe/mix-recipe/" + version); }
    ActivationRequest req(String version) { return new ActivationRequest("Line1", "recipe", "mix-recipe", version, "alice", "bob", false); }

    LedgerSigner ledgerSigner() throws Exception {
        Path a = keys.resolve("alice"), b = keys.resolve("bob");
        Files.writeString(a, Ed25519Keys.privateKeyB64(alice.getPrivate()));
        Files.writeString(b, Ed25519Keys.privateKeyB64(bob.getPrivate()));
        return KeyFileLedgerSigner.create("alice", a, "bob", b, AuthorizedKeys.load(reg));
    }

    String refused(ActivationVerdict v) throws Exception {
        assertFalse(v.ok());
        assertTrue(ledger.history("Line1").isEmpty(), "a refusal leaves the ledger untouched");
        return v.violations().get(0).rule();
    }

    @Test void anUnsignedPublicationBindsTheCanonicalAndIsRecorded() throws Exception {
        publish("1.0.0", false);
        ActivationVerdict v = svc.activate(req("1.0.0"));
        assertTrue(v.ok(), v.violations().toString());
        byte[] canonical = Files.readAllBytes(dir("1.0.0").resolve("recipe-setpoints.yaml"));
        assertEquals(Sha256.hex(canonical), v.event().contentSha256());
        assertEquals(new PublicationRef(Sha256.hex(Files.readAllBytes(dir("1.0.0").resolve("manifest.json"))), DEF_REF, null),
                v.event().publication());
        assertEquals(v.event().publication(), ledger.active("Line1", "recipe", "mix-recipe").orElseThrow().publication());
        assertTrue(ledger.verifyChain("Line1").intact());
    }

    @Test void aSignedPublicationRecordsTheEnvelopeDigestAndASignedActivationAcceptsIt() throws Exception {
        publish("1.0.0", true);
        ActivationVerdict v = svc.activate(req("1.0.0"), ledgerSigner(), ActivationPolicyStore.load(reg));
        assertTrue(v.ok(), v.violations().toString());
        assertEquals(Sha256.hex(Files.readAllBytes(dir("1.0.0").resolve("manifest.dsse.json"))), v.event().publication().attestationSha256());
        assertTrue(SignedLedgerVerifier.forRegistry(reg).verify("Line1").intact());
    }

    @Test void aSignedActivationRefusesAnUnsignedPublication() throws Exception {
        publish("1.0.0", false);
        assertEquals("activation.publication.unsigned", refused(svc.activate(req("1.0.0"), ledgerSigner(), ActivationPolicyStore.load(reg))));
    }

    @Test void aSpecFileWithNoPublicationIsRefusedByName() throws Exception {
        Path f = new MasterSpecStore().file(reg, "mix-recipe", "1.0.0");
        Files.createDirectories(f.getParent());
        Files.write(f, spec("mix-recipe", "1.0.0"));
        assertEquals("activation.publication.missing", refused(svc.activate(req("1.0.0"))));
    }

    @Test void nothingAtAllIsStillUnresolved() throws Exception {
        assertEquals("activation.artifact.unresolved", refused(svc.activate(req("9.9.9"))));
    }

    @Test void aHalfWrittenVersionIsRefused() throws Exception {
        publish("1.0.0", false);
        Files.delete(dir("1.0.0").resolve("manifest.json"));
        assertEquals("activation.publication.incomplete", refused(svc.activate(req("1.0.0"))));
    }

    @Test void aManifestThatDoesNotParseIsRefused() throws Exception {
        publish("1.0.0", false);
        Files.writeString(dir("1.0.0").resolve("manifest.json"), "{ not json");
        assertEquals("activation.publication.manifest-invalid", refused(svc.activate(req("1.0.0"))));
    }

    @Test void aManifestNamingAnotherVersionIsRefused() throws Exception {
        publish("1.0.0", false);
        Path m = dir("1.0.0").resolve("manifest.json");
        Files.writeString(m, Files.readString(m).replace("\"version\" : \"1.0.0\"", "\"version\" : \"1.0.1\""));
        assertEquals("activation.publication.manifest-mismatch", refused(svc.activate(req("1.0.0"))));
    }

    @Test void aPublicationOfAnotherKindIsNotARecipe() throws Exception {
        publish("udt", "mix-recipe", "1.0.0", spec("mix-recipe", "1.0.0"), false);
        assertEquals("activation.publication.kind-mismatch", refused(svc.activate(req("1.0.0"))));
    }

    @Test void anEditedCanonicalIsRefused() throws Exception {
        publish("1.0.0", false);
        Path c = dir("1.0.0").resolve("recipe-setpoints.yaml");
        Files.writeString(c, Files.readString(c).replace("1500", "9999"));
        assertEquals("activation.publication.content-mismatch", refused(svc.activate(req("1.0.0"))));
    }

    @Test void aCanonicalConvertedToCrlfIsRefusedAndNamed() throws Exception {
        publish("1.0.0", false);
        Path c = dir("1.0.0").resolve("recipe-setpoints.yaml");
        Files.writeString(c, Files.readString(c).replace("\n", "\r\n"));
        assertEquals("activation.publication.content-mismatch:line-endings", refused(svc.activate(req("1.0.0"))));
    }

    @Test void aPublishedCanonicalThatIsNotAMasterSpecIsUnresolved() throws Exception {
        publish(PublishedRecipe.MANIFEST_KIND, "mix-recipe", "1.0.0", "endpoint: x\n".getBytes(StandardCharsets.UTF_8), false);
        assertEquals("activation.artifact.unresolved", refused(svc.activate(req("1.0.0"))));
    }

    @Test void aMasterSpecNamingAnotherRecipeIsRefused() throws Exception {
        publish(PublishedRecipe.MANIFEST_KIND, "mix-recipe", "1.0.0", spec("other-recipe", "1.0.0"), false);
        assertEquals("activation.publication.spec-identity", refused(svc.activate(req("1.0.0"))));
    }

    @Test void aBrokenEnvelopeRefusesEvenAnUnsignedActivation() throws Exception {
        publish("1.0.0", true);
        policy(false);   // the publisher no longer holds publish
        assertEquals("activation.publication.attestation:recipe.publish-denied", refused(svc.activate(req("1.0.0"))));
    }

    @Test void anEnvelopeThatNoLongerMatchesTheFilesIsRefused() throws Exception {
        publish("1.0.0", true);
        publish("1.0.1", true);
        Files.copy(dir("1.0.1").resolve("manifest.dsse.json"), dir("1.0.0").resolve("manifest.dsse.json"), StandardCopyOption.REPLACE_EXISTING);
        assertTrue(refused(svc.activate(req("1.0.0"))).startsWith("activation.publication.attestation:recipe.attestation-"));
    }
}
