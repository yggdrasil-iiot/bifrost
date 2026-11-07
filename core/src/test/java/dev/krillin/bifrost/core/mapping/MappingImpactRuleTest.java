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

/** 2.27 impact rule and incident binding profile. */
class MappingImpactRuleTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-11-06T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/attribution-impact").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n");
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line2\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"line2\"}]}");
        service=new MappingRegistry(registry,CLOCK,()->{});
    }
    static byte[] incident(java.util.function.Consumer<ObjectNode> edit) throws Exception {
        ObjectNode b=(ObjectNode)read(Path.of(MappingImpactRuleTest.class.getResource("/mapping-fixtures/attribution-impact/data/incident-binding-line2.json").toURI()));
        edit.accept(b);return bytes(b);
    }
    static void incidentRefused(byte[] profile){
        assertEquals("impact.binding-profile",assertThrows(IllegalArgumentException.class,()->IncidentBindingProfile.parse(profile,"impact.binding-profile")).getMessage());
    }
    static void incidentRefused(java.util.function.Consumer<ObjectNode> edit) throws Exception {incidentRefused(incident(edit));}
    @Test void parsesTheFixtureProfile() throws Exception {
        var p=IncidentBindingProfile.parse(incident(b->{}),"x");
        assertEquals("mfg.incidents",p.topic());assertEquals(List.of("tool-check-failed","gauge-drift"),p.kinds());assertEquals("isa95-path",p.equipmentRefBasis());
    }
    @Test void profileAcceptsASingleKind() throws Exception {assertEquals(List.of("tool-check-failed"),IncidentBindingProfile.parse(incident(b->((ArrayNode)b.path("kinds")).remove(1)),"x").kinds());}
    @Test void profileRefusesAnExtraField() throws Exception {incidentRefused(b->b.put("note","x"));}
    @Test void profileRefusesAMissingField() throws Exception {incidentRefused(b->b.remove("kinds"));}
    @Test void profileRefusesAnotherVersion() throws Exception {incidentRefused(b->b.put("profileVersion","0.2.0"));}
    @Test void profileRefusesAnEmptyTopic() throws Exception {incidentRefused(b->b.put("topic",""));}
    @Test void profileRefusesAnotherSchemaId() throws Exception {incidentRefused(b->((ObjectNode)b.path("format")).put("schemaId","urn:forseti:schema:occupancy:1.0.0"));}
    @Test void profileRefusesAShortSchemaDigest() throws Exception {incidentRefused(b->((ObjectNode)b.path("format")).put("schemaSha256","abc"));}
    @Test void profileRefusesAnUppercaseSchemaDigest() throws Exception {incidentRefused(b->((ObjectNode)b.path("format")).put("schemaSha256","A".repeat(64)));}
    @Test void profileRefusesANumericSchemaDigest() throws Exception {incidentRefused(b->((ObjectNode)b.path("format")).put("schemaSha256",new java.math.BigInteger("1".repeat(64))));}
    @Test void profileRefusesEmptyKinds() throws Exception {incidentRefused(b->((ArrayNode)b.path("kinds")).removeAll());}
    @Test void profileRefusesDuplicateKinds() throws Exception {incidentRefused(b->((ArrayNode)b.path("kinds")).add("gauge-drift"));}
    @Test void profileRefusesAnotherEquipmentRefBasis() throws Exception {incidentRefused(b->b.put("equipmentRefBasis","node-id"));}
    @Test void profileRefusesBytesThatAreNotJson() {incidentRefused("not json".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
    @Test void profileRefusesDuplicateKeys() {incidentRefused("{\"topic\":\"a\",\"topic\":\"b\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
}
