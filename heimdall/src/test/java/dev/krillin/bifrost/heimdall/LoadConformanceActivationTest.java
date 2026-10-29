package dev.krillin.bifrost.heimdall;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.security.KeyPair;
import java.time.Clock;
import java.util.List;
import dev.krillin.bifrost.core.activation.*;
import dev.krillin.bifrost.core.conformance.*;
import dev.krillin.bifrost.core.identity.*;
import dev.krillin.bifrost.core.schema.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class LoadConformanceActivationTest {
    static final String DEF_REF = "0123456789abcdef0123456789abcdef01234567";
    Path reg, confFile, keys;
    @BeforeEach void setup(@TempDir Path dir) throws Exception {
        reg = dir.resolve("registry"); Files.createDirectories(reg);
        keys = dir.resolve("keys"); Files.createDirectories(keys);
        Path udt = reg.resolve("udt").resolve("Line1-Mixer").resolve("1.0.0.json"); Files.createDirectories(udt.getParent());
        JsonMapperFactory.create().writeValue(udt.toFile(),
            new UdtDefinition("Line1-Mixer", SemVer.parse("1.0.0"),
                List.of(new Member("Rpm","Double","corp:rpm", new Range(0,3000))), List.of(), null));
        publish("1.0.0",1500, null);
        publish("1.1.0",1600, null);
        ConformancePolicy cp = new ConformancePolicy("Line1-pol","1.0.0","Line1-Mixer","1.0.0",
            new ConformancePolicy.Dial("recipe","mix-recipe","0.0.0",0.0), List.of(), List.of());
        confFile = dir.resolve("conformance.json");
        JsonMapperFactory.create().writeValue(confFile.toFile(), cp);
    }
    static byte[] spec(String ref, String ver, double rpm) throws Exception {
        return JsonMapperFactory.prettyWriter(JsonMapperFactory.create()).writeValueAsBytes(
            new MasterSpec(ref,ver,"Line1","Line1-Mixer","1.0.0",List.of(new Setpoint("Rpm","Double",rpm))));
    }
    void publish(String ver, double rpm, KeyFileSigner signer) throws Exception {
        byte[] bytes = spec("mix-recipe", ver, rpm);
        new RecipeDefinitionStore(reg).publish("recipe-setpoints", "mix-recipe", ver, bytes, DEF_REF, Sha256.hex(bytes),
            "recipes/mix-recipe.json", 1L, signer);
    }
    /** Registers a publisher key and grants it publish; returns its signer. */
    KeyFileSigner publisher() throws Exception {
        KeyPair p = Ed25519Keys.generate();
        Files.createDirectories(reg.resolve("identity"));
        Files.writeString(reg.resolve("identity/authorized-keys.jsonl"),
            "{\"principal\":\"pat\",\"publicKey\":\"" + Ed25519Keys.publicKeyB64(p.getPublic()) + "\"}\n");
        Files.writeString(reg.resolve("identity/activation-policy.json"), "{\"version\":\"1\",\"default\":\"deny\",\"rules\":["
            + "{\"id\":\"pub\",\"principal\":\"pat\",\"action\":\"publish\",\"target\":\"recipe-publication\",\"kind\":\"recipe-setpoints\",\"ref\":\"*\"}]}");
        Path kf = keys.resolve("pat");
        Files.writeString(kf, Ed25519Keys.privateKeyB64(p.getPrivate()));
        return KeyFileSigner.create("pat", kf, AuthorizedKeys.load(reg), Clock.systemUTC());
    }
    Path dir(String ver) { return reg.resolve("recipe/mix-recipe/" + ver); }
    void activate(String ver) throws Exception {
        var v = new ActivationService(new RecipeArtifactResolver(reg), new ActivationLedger(reg), Clock.systemUTC())
            .activate(new ActivationRequest("Line1","recipe","mix-recipe",ver,"alice","bob",false));
        assertTrue(v.ok(), v.violations().toString());
    }
    /** An entry as written before activation named its publication: spec/ bytes, no publication. */
    void activateLegacy(String ver, double rpm) throws Exception {
        Path f = new MasterSpecStore().file(reg,"mix-recipe",ver); Files.createDirectories(f.getParent());
        Files.write(f, spec("mix-recipe", ver, rpm));
        new ActivationLedger(reg).append(new ActivationEvent("Line1","recipe","mix-recipe",ver,
            Sha256.hex(Files.readAllBytes(f)),"alice","bob",1L,null,"ACTIVATE"));
    }
    NcmdOpcUaBridgeMain.Config cfg() { return cfg(false); }
    NcmdOpcUaBridgeMain.Config cfg(boolean requirePublished) {
        return new NcmdOpcUaBridgeMain.Config("tcp://x","opc.tcp://x","g","e","p",
            reg.toString(), confFile.toString(), reg.toString(), "Line1", false, false, "file", null, false,
            0, 4, null, false, 1024, null, false, 30, requirePublished);
    }
    String failure(NcmdOpcUaBridgeMain.Config c) {
        return assertThrows(Exception.class, () -> NcmdOpcUaBridgeMain.loadConformance(c)).getMessage();
    }

    @Test void bindsLedgerActiveVersionNotDial() throws Exception {
        activate("1.1.0");
        var conf = NcmdOpcUaBridgeMain.loadConformance(cfg());
        assertEquals(1600.0, conf.recipe().setpoints().get(0).value());
    }
    @Test void noActivePointerFailsClosed() {
        assertTrue(failure(cfg()).contains("activation.edge.no-active-pointer"));
    }
    @Test void tamperedBytesFailClosed() throws Exception {
        activate("1.0.0");
        Path f = dir("1.0.0").resolve("recipe-setpoints.yaml");
        Files.writeString(f, Files.readString(f) + " ");
        String m = failure(cfg());
        assertTrue(m.contains("activation.edge.content-mismatch"), m);
        assertFalse(m.contains(":line-endings"), "a trailing space is an edit, not a conversion");
    }
    @Test void aLineEndingConversionStillFailsClosedButIsNamed() throws Exception {
        activate("1.0.0");
        Path f = dir("1.0.0").resolve("recipe-setpoints.yaml");
        Files.writeString(f, Files.readString(f).replace("\n", "\r\n"));   // git core.autocrlf checkout on the edge
        String m = failure(cfg());
        assertTrue(m.contains("activation.edge.content-mismatch:line-endings"), m);
    }
    @Test void aDeletedPublicationFailsClosed() throws Exception {
        activate("1.0.0");
        Files.delete(dir("1.0.0").resolve("recipe-setpoints.yaml"));
        Files.delete(dir("1.0.0").resolve("manifest.json"));
        assertTrue(failure(cfg()).contains("activation.edge.publication-missing"));
    }
    @Test void aHalfDeletedPublicationFailsClosedByName() throws Exception {
        activate("1.0.0");
        Files.delete(dir("1.0.0").resolve("manifest.json"));
        String m = failure(cfg());
        assertTrue(m.contains("activation.edge.publication-invalid:activation.publication.incomplete"), m);
    }
    @Test void aManifestSwappedAfterActivationFailsClosed() throws Exception {
        activate("1.0.0");
        Path m = dir("1.0.0").resolve("manifest.json");
        Files.writeString(m, Files.readString(m).replace(DEF_REF, "f".repeat(40)));   // same content hash, another commit
        assertTrue(failure(cfg()).contains("activation.edge.publication-manifest-mismatch"));
    }
    @Test void anEnvelopeAddedAfterAnUnsignedActivationFailsClosed() throws Exception {
        activate("1.0.0");
        Files.writeString(dir("1.0.0").resolve("manifest.dsse.json"), "{}");
        assertTrue(failure(cfg()).contains("activation.edge.publication-attestation-mismatch"));
    }
    @Test void aSignedPublicationWhosePublisherLostTheGrantFailsClosed() throws Exception {
        KeyFileSigner pat = publisher();
        publish("2.0.0", 1700, pat);
        activate("2.0.0");
        Files.writeString(reg.resolve("identity/activation-policy.json"), "{\"version\":\"1\",\"default\":\"deny\",\"rules\":[]}");
        String m = failure(cfg());
        assertTrue(m.contains("activation.edge.publication-invalid:activation.publication.attestation:recipe.publish-denied"), m);
    }
    @Test void aSignedPublicationBinds() throws Exception {
        publish("2.0.0", 1700, publisher());
        activate("2.0.0");
        assertEquals(1700.0, NcmdOpcUaBridgeMain.loadConformance(cfg()).recipe().setpoints().get(0).value());
    }
    @Test void aSignedActivationEdgeRefusesAnUnsignedPublication() throws Exception {
        activate("1.0.0");
        ActivationEvent active = new ActivationLedger(reg).active("Line1","recipe","mix-recipe").orElseThrow();
        var ex = assertThrows(IllegalStateException.class, () -> NcmdOpcUaBridgeMain.bindPublished(reg, "mix-recipe", active, true));
        assertTrue(ex.getMessage().contains("activation.edge.publication-unsigned"), ex.getMessage());
        assertEquals(1500.0, NcmdOpcUaBridgeMain.bindPublished(reg, "mix-recipe", active, false).setpoints().get(0).value());
    }
    @Test void aLegacyEntryBindsSpecWithAWarningByDefault() throws Exception {
        activateLegacy("0.9.0", 1400);
        assertEquals(1400.0, NcmdOpcUaBridgeMain.loadConformance(cfg()).recipe().setpoints().get(0).value());
    }
    @Test void aLegacyEntryIsRefusedWhenPublicationIsRequired() throws Exception {
        activateLegacy("0.9.0", 1400);
        assertTrue(failure(cfg(true)).contains("activation.edge.publication-missing"));
    }
    @Test void aLegacyEntryStillChecksTheSpecBytes() throws Exception {
        activateLegacy("0.9.0", 1400);
        Path f = new MasterSpecStore().file(reg,"mix-recipe","0.9.0");
        Files.writeString(f, Files.readString(f) + " ");
        assertTrue(failure(cfg()).contains("activation.edge.content-mismatch"));
    }
    @Test void brokenLedgerChainFailsClosed() throws Exception {
        activate("1.0.0");
        // out-of-band tamper: editing approvedBy on entry-0's raw JSONL line breaks its self-hash
        // (approvedBy "bob" occurs once), so verifyChain fails BEFORE the active pointer is read.
        Path f = reg.resolve("activation").resolve("Line1.jsonl");
        List<String> lines = Files.readAllLines(f);
        lines.set(0, lines.get(0).replace("\"bob\"", "\"eve\""));
        Files.write(f, lines);
        assertTrue(failure(cfg()).contains("activation.edge.ledger-chain-broken"));
    }
}
