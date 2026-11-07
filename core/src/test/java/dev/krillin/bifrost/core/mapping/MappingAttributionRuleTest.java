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

/** 2.27 attribution rule (occupancy-join): Tyr's wire bundle, Bifrost's own checks, real keys. */
class MappingAttributionRuleTest {
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
    @Test void acceptsTyrBundle() {
        var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());
        assertEquals("2.27.0",text(c.proposal(),"schemaVersion"));
        assertEquals(1,c.documents().values().stream().filter(d->text(d,"kind").equals("attribution-rule")).count());
        assertEquals(1,c.documents().values().stream().filter(d->text(d,"kind").equals("impact-rule")).count());
    }
    void rewrite(Path p,JsonNode doc) throws Exception {Files.write(p,bytes(doc));}
    void reseal() throws Exception {ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);}
    List<String> codes(){return new MappingBundle().validate(bundle).report().path("findings").findValuesAsText("ruleCode");}
    void refused(String code){assertEquals(List.of(code),codes());}
    void accepted(){assertEquals(List.of(),codes());}
    /** A copy of another fixture whose proposal is re-stamped 2.27.0 and resealed; nothing else changes. */
    MappingBundle.Checked upgraded(String fixture) throws Exception {
        Path other=tmp.resolve(fixture);MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/"+fixture).toURI()),other);
        ObjectNode p=(ObjectNode)read(other.resolve("proposal.json"));p.put("schemaVersion","2.27.0");Files.write(other.resolve("proposal.json"),bytes(p));
        ObjectNode s=(ObjectNode)read(other.resolve("submission.json"));s.put("proposalSha256",sha(other.resolve("proposal.json")));Files.write(other.resolve("submission.json"),bytes(s));
        var c=new MappingBundle().validate(other);assertTrue(c.accepted(),c.report().toString());return c;
    }
    static long count(MappingBundle.Checked c,String field,String value){return c.documents().values().stream().filter(d->text(d,field).equals(value)).count();}
    /** A 2.26.0 proposal cannot list the new kinds: its fileEntry kind enum refuses them at the proposal schema, before any envelope check. */
    @Test void a226ProposalCannotCarryTheRules() throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.put("schemaVersion","2.26.0");rewrite(bundle.resolve("proposal.json"),p);reseal();
        refused("mapping.schema:2.26.0/mapping-proposal");
    }
    /** Spec line 711: a 2.27.0 document of any kind needs a 2.27.0 proposal. One plc source of vor-read re-issued at 2.27.0 under its
     *  2.26.0 proposal is refused rule.envelope (the source itself validates: the 2.27.0 plc schema admits it). */
    @Test void a227SourceAloneNeedsA227Proposal() throws Exception {
        Path other=tmp.resolve("vor-read");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/vor-read").toURI()),other);
        Path source=other.resolve("sources/0.json");ObjectNode s=(ObjectNode)read(source);s.put("schemaVersion","2.27.0");Files.write(source,bytes(s));
        ObjectNode p=(ObjectNode)read(other.resolve("proposal.json"));for(JsonNode e:p.path("files"))if(text(e,"path").equals("sources/0.json"))((ObjectNode)e).put("sha256",sha(source));Files.write(other.resolve("proposal.json"),bytes(p));
        ObjectNode sub=(ObjectNode)read(other.resolve("submission.json"));sub.put("proposalSha256",sha(other.resolve("proposal.json")));Files.write(other.resolve("submission.json"),bytes(sub));
        assertEquals(List.of("rule.envelope"),new MappingBundle().validate(other).report().path("findings").findValuesAsText("ruleCode"));
    }
    /** The vor-read bundle (2.26.0 command bindings, server certificate, read bindings) rides unchanged in a 2.27.0 proposal. */
    @Test void a226CommandBindingRidesInA227Proposal() throws Exception {assertEquals(2,count(upgraded("vor-read"),"kind","command-binding"));}
    /** The 2.22 broadcast and 2.21 record-field envelope checks accept a 2.27.0 proposal, as the 2.23-2.26 sections state. */
    @Test void a222BroadcastRidesInA227Proposal() throws Exception {assertTrue(count(upgraded("broadcast"),"schemaVersion","2.22.0")>0);}
    @Test void a221RecordFieldRidesInA227Proposal() throws Exception {assertTrue(count(upgraded("mixed-objects"),"schemaVersion","2.21.0")>0);}
    /** The String value type is a 2.27.0 addition: a 2.7.0 plc source still cannot declare it. */
    @Test void aTypedStringSourceIsStillRefusedAt270() throws Exception {
        change("sources/station1-running.json",s->((ObjectNode)s.path("rawRepresentation")).put("valueType","String"));
        refused("mapping.schema:2.7.0/source-definition");
    }
    /** Changes one listed file and re-pins it in the proposal and the submission, so only the rule under test fails. */
    void change(String path,Consumer<ObjectNode> mutation) throws Exception {
        Path file=bundle.resolve(path);ObjectNode d=(ObjectNode)read(file);mutation.accept(d);rewrite(file,d);
        ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:proposal.path("files"))if(text(e,"path").equals(path))((ObjectNode)e).put("sha256",sha(file));
        rewrite(bundle.resolve("proposal.json"),proposal);reseal();
    }
    static byte[] occupancy(java.util.function.Consumer<ObjectNode> edit) throws Exception {
        ObjectNode b=(ObjectNode)read(Path.of(MappingAttributionRuleTest.class.getResource("/mapping-fixtures/attribution-impact/data/occupancy-binding-line2.json").toURI()));
        edit.accept(b);return bytes(b);
    }
    static void occupancyRefused(byte[] profile){
        assertEquals("attribution.binding-profile",assertThrows(IllegalArgumentException.class,()->OccupancyBindingProfile.parse(profile,"attribution.binding-profile")).getMessage());
    }
    static void occupancyRefused(java.util.function.Consumer<ObjectNode> edit) throws Exception {occupancyRefused(occupancy(edit));}
    @Test void parsesTheFixtureProfile() throws Exception {
        var p=OccupancyBindingProfile.parse(occupancy(b->{}),"x");
        assertEquals("mfg.occupancy",p.topic());assertEquals("[A-Z0-9]{17}",p.identityPattern());assertEquals(List.of("mes-line2"),p.sources());
        assertEquals(List.of("urn:epcglobal:cbv:er:did_not_occur","urn:epcglobal:cbv:er:incorrect_data"),p.correctionReasons());
    }
    @Test void profileAcceptsASingleCorrectionReason() throws Exception {
        var p=OccupancyBindingProfile.parse(occupancy(b->((ArrayNode)b.path("correction").path("reasons")).remove(1)),"x");
        assertEquals(List.of("urn:epcglobal:cbv:er:did_not_occur"),p.correctionReasons());
    }
    @Test void profileRefusesAnExtraField() throws Exception {occupancyRefused(b->b.put("note","x"));}
    @Test void profileRefusesAMissingField() throws Exception {occupancyRefused(b->b.remove("leave"));}
    @Test void profileRefusesAnotherVersion() throws Exception {occupancyRefused(b->b.put("profileVersion","0.2.0"));}
    @Test void profileRefusesAnEmptyTopic() throws Exception {occupancyRefused(b->b.put("topic",""));}
    @Test void profileRefusesATopicOfAnotherType() throws Exception {occupancyRefused(b->b.put("topic",1));}
    @Test void profileRefusesAnotherSchemaId() throws Exception {occupancyRefused(b->((ObjectNode)b.path("format")).put("schemaId","urn:forseti:schema:occupancy:2.0.0"));}
    @Test void profileRefusesAShortSchemaDigest() throws Exception {occupancyRefused(b->((ObjectNode)b.path("format")).put("schemaSha256","abc"));}
    @Test void profileRefusesAnUppercaseSchemaDigest() throws Exception {occupancyRefused(b->((ObjectNode)b.path("format")).put("schemaSha256","A".repeat(64)));}
    @Test void profileRefusesANumericSchemaDigest() throws Exception {occupancyRefused(b->((ObjectNode)b.path("format")).put("schemaSha256",new java.math.BigInteger("1".repeat(64))));}
    @Test void profileRefusesAnotherIdentityScheme() throws Exception {occupancyRefused(b->((ObjectNode)b.path("identity")).put("scheme","vin"));}
    @Test void profileRefusesAnotherCorrectionMode() throws Exception {occupancyRefused(b->((ObjectNode)b.path("correction")).put("errorDeclaration","tombstone"));}
    @Test void profileRefusesAnUnknownCorrectionReason() throws Exception {occupancyRefused(b->((ArrayNode)b.path("correction").path("reasons")).add("urn:epcglobal:cbv:er:other"));}
    @Test void profileRefusesDuplicateCorrectionReasons() throws Exception {occupancyRefused(b->((ArrayNode)b.path("correction").path("reasons")).add("urn:epcglobal:cbv:er:did_not_occur"));}
    @Test void profileRefusesEmptyCorrectionReasons() throws Exception {occupancyRefused(b->((ArrayNode)b.path("correction").path("reasons")).removeAll());}
    @Test void profileRefusesAnotherTimestampBasis() throws Exception {occupancyRefused(b->b.put("timestampBasis","recordTime"));}
    @Test void profileRefusesEmptySources() throws Exception {occupancyRefused(b->((ArrayNode)b.path("sources")).removeAll());}
    @Test void profileRefusesDuplicateSources() throws Exception {occupancyRefused(b->((ArrayNode)b.path("sources")).add("mes-line2"));}
    @Test void profileRefusesSourcesThatAreNotAnArray() throws Exception {occupancyRefused(b->b.put("sources","mes-line2"));}
    @Test void profileRefusesBytesThatAreNotJson() {occupancyRefused("not json".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
    @Test void profileRefusesDuplicateKeys() {occupancyRefused("{\"topic\":\"a\",\"topic\":\"b\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
    // identity.pattern: the syntax common to Java and ECMA-262 only (spec 225-226)
    static void pattern(String p) throws Exception {OccupancyBindingProfile.parse(occupancy(b->((ObjectNode)b.path("identity")).put("pattern",p)),"x");}
    static void patternRefused(String p) throws Exception {occupancyRefused(b->((ObjectNode)b.path("identity")).put("pattern",p));}
    @Test void patternAcceptsTheCommonSyntax() throws Exception {
        for(String p:List.of("[A-Z0-9]{17}","KMH[A-HJ-NPR-Z0-9]{14}","(?:VIN|BODY)-[0-9]+","[^ ]+","a.c","x?y*z+","[0-9]{2,}","[0-9]{2,4}","\\.[a-z]\\-","[A-Z0-9-]+","[a&b]","\\\\x"))pattern(p);
    }
    @Test void patternRefusesAnchors() throws Exception {patternRefused("^[A-Z]{3}$");patternRefused("BODY$");}
    @Test void patternRefusesLookaround() throws Exception {patternRefused("(?=A)[A-Z]{3}");patternRefused("(?<!X)[A-Z]{3}");}
    @Test void patternRefusesBackreferences() throws Exception {patternRefused("(?:A)\\1");}
    @Test void patternRefusesNamedAndCapturingGroups() throws Exception {patternRefused("(?<v>[A-Z]+)");patternRefused("([A-Z]+)");}
    @Test void patternRefusesFlags() throws Exception {patternRefused("(?i)abc");patternRefused("(?i:abc)");}
    @Test void patternRefusesClassShorthandsAndProperties() throws Exception {patternRefused("\\d{17}");patternRefused("\\p{Lu}+");patternRefused("[[:alpha:]]+");patternRefused("\\x41");}
    @Test void patternRefusesLazyAndPossessiveQuantifiers() throws Exception {patternRefused("[A-Z]+?");patternRefused("[A-Z]*+");}
    /** Java reads && inside brackets as class intersection; ECMA-262 reads two literal characters. Not common syntax. */
    @Test void patternRefusesClassIntersection() throws Exception {patternRefused("[a&&b]");patternRefused("[a-z&&def]");}
    @Test void patternRefusesMalformedSyntax() throws Exception {patternRefused("");patternRefused("[A-Z");patternRefused("(?:A");patternRefused("{3}");patternRefused("a{");patternRefused("A{4,2}");}
    static String nested(int n){return "(?:".repeat(n)+"a"+")".repeat(n);}
    @Test void patternAcceptsNestingUpToTheCap() throws Exception {pattern(nested(32));}
    @Test void patternRefusesNestingBeyondTheCap() throws Exception {patternRefused(nested(33));}
    @Test void patternRefusesAbsurdNestingWithoutThrowing() throws Exception {patternRefused(nested(10000));}
    /** Java reads a surrogate pair as one code point, ECMA-262 without the u flag as two code units. Not common syntax. */
    @Test void patternRefusesSupplementaryCharacters() throws Exception {patternRefused("[😀]");patternRefused("a😀");}
}
