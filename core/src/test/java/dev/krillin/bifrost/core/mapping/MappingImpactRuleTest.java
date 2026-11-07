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
    @Test void acceptsTyrBundle() {var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());}
    void rewrite(Path p,JsonNode doc) throws Exception {Files.write(p,bytes(doc));}
    void reseal() throws Exception {ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);}
    List<String> codes(){return new MappingBundle().validate(bundle).report().path("findings").findValuesAsText("ruleCode");}
    void refused(String code){assertEquals(List.of(code),codes());}
    void accepted(){assertEquals(List.of(),codes());}
    /** Changes one listed file and re-pins it in the proposal and the submission, so only the rule under test fails. */
    void change(String path,Consumer<ObjectNode> mutation) throws Exception {
        Path file=bundle.resolve(path);ObjectNode d=(ObjectNode)read(file);mutation.accept(d);rewrite(file,d);
        ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:proposal.path("files"))if(text(e,"path").equals(path))((ObjectNode)e).put("sha256",sha(file));
        rewrite(bundle.resolve("proposal.json"),proposal);reseal();
    }
    void rule(Consumer<ObjectNode> mutation) throws Exception {change("rules/impact-line2.json",mutation);}
    /** The profile data file is pinned by its evidence-artifact, not by the proposal: re-pin that artifact too. */
    void profileBytes(byte[] b) throws Exception {
        Files.write(bundle.resolve("data/incident-binding-line2.json"),b);
        change("evidence/incident-binding-line2.json",a->((ObjectNode)a.path("file")).put("sha256",sha0("data/incident-binding-line2.json")));
    }
    void profile(Consumer<ObjectNode> mutation) throws Exception {ObjectNode d=(ObjectNode)read(bundle.resolve("data/incident-binding-line2.json"));mutation.accept(d);profileBytes(bytes(d));}
    String sha0(String rel){try{return sha(bundle.resolve(rel));}catch(Exception e){throw new IllegalStateException(e);}}
    static ObjectNode ref(ObjectNode r,String field){return (ObjectNode)r.path(field);}
    @Test void attributionMissing() throws Exception {rule(r->ref(r,"attributionRuleRef").put("version","9.9.9"));refused("impact.attribution-missing");}
    @Test void scopeMustBeInTheHierarchy() throws Exception {rule(r->((ArrayNode)r.path("incidentScope")).add("synthetic-site:line2:station1:nutrunner9"));refused("impact.scope-containment");}
    @Test void scopeMustBeUnderAnAttributionStation() throws Exception {rule(r->((ArrayNode)r.path("incidentScope")).add("synthetic-site:line2"));refused("impact.scope-containment");}
    @Test void aStationItselfIsInScope() throws Exception {rule(r->((ArrayNode)r.path("incidentScope")).add("synthetic-site:line2:station2"));accepted();}
    @Test void duplicateScopePathsAreRefusedByTheSchema() throws Exception {rule(r->((ArrayNode)r.path("incidentScope")).add("synthetic-site:line2:station1:nutrunner1"));refused("mapping.schema:2.27.0/impact-rule");}
    @Test void emptyScopeIsRefusedByTheSchema() throws Exception {rule(r->((ArrayNode)r.path("incidentScope")).removeAll());refused("mapping.schema:2.27.0/impact-rule");}
    @Test void bindingUnresolved() throws Exception {rule(r->ref(r,"incidentBindingRef").put("id","incident-binding-absent"));refused("impact.binding-unresolved");}
    @Test void bindingMustBeAnArtifact110() throws Exception {change("evidence/incident-binding-line2.json",a->a.put("schemaVersion","1.0.0"));refused("impact.binding-unresolved");}
    @Test void bindingArtifactMustCarryTheMediaType() throws Exception {change("evidence/incident-binding-line2.json",a->((ObjectNode)a.path("file")).put("mediaType","application/json"));refused("impact.binding-profile");}
    @Test void bindingArtifactMustCarryThePrefix() throws Exception {
        change("evidence/incident-binding-line2.json",a->a.put("id","binding-line2"));
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));for(JsonNode e:p.path("files"))if(text(e,"id").equals("incident-binding-line2"))((ObjectNode)e).put("id","binding-line2");rewrite(bundle.resolve("proposal.json"),p);reseal();
        rule(r->ref(r,"incidentBindingRef").put("id","binding-line2"));
        refused("impact.binding-profile");
    }
    @Test void bindingProfileWithEmptyKindsIsRefused() throws Exception {profile(b->((ArrayNode)b.path("kinds")).removeAll());refused("impact.binding-profile");}
    @Test void bindingProfileWithAnotherBasisIsRefused() throws Exception {profile(b->b.put("equipmentRefBasis","node-id"));refused("impact.binding-profile");}
    @Test void retentionOrder() throws Exception {rule(r->ref(r,"retention").put("workRecordsMs",3600000));refused("impact.retention-order");}
    @Test void retentionEqualToTheHorizonIsAccepted() throws Exception {rule(r->ref(r,"retention").put("workRecordsMs",86400000));accepted();}
    @Test void retentionAbove90DaysIsRefusedByTheSchema() throws Exception {rule(r->ref(r,"retention").put("workRecordsMs",7776000001L));refused("mapping.schema:2.27.0/impact-rule");}
    @Test void olderEnvelopeRefused() throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.put("schemaVersion","2.26.0");rewrite(bundle.resolve("proposal.json"),p);reseal();
        refused("mapping.schema:2.26.0/mapping-proposal");
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
    /** The fixture's own profile bytes with one key repeated: valid but for the duplicate. The same bytes without it are accepted. */
    @Test void profileRefusesDuplicateKeys() throws Exception {
        byte[] original=Files.readAllBytes(Path.of(MappingImpactRuleTest.class.getResource("/mapping-fixtures/attribution-impact/data/incident-binding-line2.json").toURI()));
        assertEquals("mfg.incidents",IncidentBindingProfile.parse(original,"x").topic());
        String text=new String(original,java.nio.charset.StandardCharsets.UTF_8);int end=text.lastIndexOf('}');
        incidentRefused((text.substring(0,end)+",\"topic\":\"x\""+text.substring(end)).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
