package yggdrasil.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import yggdrasil.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import static yggdrasil.bifrost.core.mapping.MappingJson.*;
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
    /** The fixture's own profile bytes with one key repeated: complete and valid but for the duplicate, so only strict duplicate-key
     *  detection can refuse it. The same bytes without the repeat are accepted. */
    @Test void profileRefusesDuplicateKeys() throws Exception {
        byte[] original=Files.readAllBytes(Path.of(MappingAttributionRuleTest.class.getResource("/mapping-fixtures/attribution-impact/data/occupancy-binding-line2.json").toURI()));
        assertEquals("mfg.occupancy",OccupancyBindingProfile.parse(original,"x").topic());
        String text=new String(original,java.nio.charset.StandardCharsets.UTF_8);int end=text.lastIndexOf('}');
        occupancyRefused((text.substring(0,end)+",\"topic\":\"x\""+text.substring(end)).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
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

    void rule(Consumer<ObjectNode> mutation) throws Exception {change("rules/attribution-line2.json",mutation);}
    /** The profile data file is pinned by its evidence-artifact, not by the proposal: re-pin that artifact too. */
    void profileBytes(byte[] b) throws Exception {
        Files.write(bundle.resolve("data/occupancy-binding-line2.json"),b);
        change("evidence/occupancy-binding-line2.json",a->((ObjectNode)a.path("file")).put("sha256",sha0("data/occupancy-binding-line2.json")));
    }
    void profile(Consumer<ObjectNode> mutation) throws Exception {ObjectNode d=(ObjectNode)read(bundle.resolve("data/occupancy-binding-line2.json"));mutation.accept(d);profileBytes(bytes(d));}
    String sha0(String rel){try{return sha(bundle.resolve(rel));}catch(Exception e){throw new IllegalStateException(e);}}
    static ObjectNode member(ObjectNode r,int i){return (ObjectNode)r.path("members").get(i);}
    static ObjectNode activity(ObjectNode r,int i){return (ObjectNode)r.path("activity").get(i);}
    static ObjectNode ref(ObjectNode r,String field){return (ObjectNode)r.path(field);}
    static ObjectNode entry(String setId,String mappingId,String semanticId,String metric){
        ObjectNode e=object();e.set("mappingSetRef",object().put("id",setId).put("version","1.0.0"));return e.put("mappingId",mappingId).put("semanticId",semanticId).put("metric",metric);
    }
    static final String S1="synthetic-site:line2:station1",S2="synthetic-site:line2:station2",N1=S1+":nutrunner1",N2=S1+":nutrunner2";

    // hierarchy and stations
    @Test void hierarchyMissing() throws Exception {rule(r->ref(r,"equipmentRef").put("id","other-plant"));refused("attribution.hierarchy-missing");}
    @Test void anInvalidHierarchyKeepsItsOwnRefusal() throws Exception {
        // station1's parent becomes its own child: EquipmentHierarchy runs first and reports the cycle, not the rule
        change("hierarchy/0.json",h->((ObjectNode)h.path("nodes").get(2)).put("parentEquipmentInstanceId","nutrunner1"));refused("hierarchy.cycle");
    }
    @Test void stationUnresolved() throws Exception {rule(r->((ArrayNode)r.path("stations")).set(1,"synthetic-site:line2:station9"));refused("attribution.station-unresolved");}
    @Test void stationNested() throws Exception {rule(r->((ArrayNode)r.path("stations")).add("synthetic-site:line2"));refused("attribution.station-nested");}
    @Test void aStationThatIsAToolsAncestorIsNested() throws Exception {rule(r->((ArrayNode)r.path("stations")).add(N1));refused("attribution.station-nested");}
    @Test void duplicateStationsAreRefusedByTheSchema() throws Exception {rule(r->((ArrayNode)r.path("stations")).add(S1));refused("mapping.schema:2.27.0/attribution-rule");}
    @Test void emptyStationsAreRefusedByTheSchema() throws Exception {rule(r->((ArrayNode)r.path("stations")).removeAll());refused("mapping.schema:2.27.0/attribution-rule");}
    // members[]: non-empty (spec line 132), resolution, metric, semanticId, the three extra checks, duplicates
    @Test void emptyMembersAreMemberUnresolved() throws Exception {rule(r->((ArrayNode)r.path("members")).removeAll());refused("attribution.member-unresolved");}
    @Test void memberMappingSetUnresolved() throws Exception {rule(r->ref(member(r,0),"mappingSetRef").put("version","9.9.9"));refused("attribution.member-unresolved");}
    @Test void memberMappingIdUnresolved() throws Exception {rule(r->member(r,0).put("mappingId","nutrunner1-speed"));refused("attribution.member-unresolved");}
    @Test void memberMappingIdOfAnotherSet() throws Exception {rule(r->member(r,0).put("mappingId","nutrunner2-torque"));refused("attribution.member-unresolved");}
    @Test void memberMetricMustEqualTheSemanticName() throws Exception {rule(r->member(r,0).put("metric","Torq"));refused("attribution.member-unresolved");}
    @Test void memberSemanticIdMustEqualTheMember() throws Exception {rule(r->member(r,0).put("semanticId","urn:bifrost:sem:Tool/Speed"));refused("attribution.member-unresolved");}
    @Test void memberListedTwice() throws Exception {rule(r->((ArrayNode)r.path("members")).add(member(r,0).deepCopy()));refused("attribution.member-unresolved");}
    @Test void twoMembersForOneEquipmentAndMetric() throws Exception {
        // a second mapping of nutrunner1's Torque: the rule may name only one entry per (equipment path, metric)
        change("mappings/nutrunner1.json",s->((ArrayNode)s.path("mappings")).add(((ObjectNode)s.path("mappings").get(0).deepCopy()).put("mappingId","nutrunner1-torque-copy")));
        rule(r->((ArrayNode)r.path("members")).add(entry("nutrunner1-mapping","nutrunner1-torque-copy","urn:bifrost:sem:Tool/Torque","Torque")));
        refused("attribution.member-unresolved");
    }
    @Test void memberSourceIdentifierMustEndWithTheMetric() throws Exception {
        change("sources/nutrunner1-torque.json",s->((ObjectNode)s.path("access")).put("identifier","Line2/Station1/Nutrunner1.Torq"));refused("attribution.member-unresolved");
    }
    @Test void duplicateLeafNamesInOneDefinitionAreRefused() throws Exception {
        change("semantics/tool.json",s->((ObjectNode)s.path("members").get(1)).put("name","Torque"));refused("attribution.member-unresolved");
    }
    /** Spec: a station and a tool may each have a member of the same name; the fixture's station-model and tool-model both carry Running. */
    @Test void aStationAndAToolMayEachHaveAMemberNamedRunning() throws Exception {
        assertEquals("Running",text(read(bundle.resolve("semantics/station.json")).path("members").get(0),"name"));
        assertEquals("Running",text(read(bundle.resolve("semantics/tool.json")).path("members").get(1),"name"));
        accepted();
    }
    static ObjectNode json(String text){try{return (ObjectNode)JSON.readTree(text);}catch(Exception e){throw new IllegalStateException(e);}}
    static ObjectNode leaf(String id,String name){
        return json("{\"memberId\":\""+id+"\",\"name\":\""+name+"\",\"semanticId\":\"urn:bifrost:sem:Tool/"+name+"\",\"description\":\"x\",\"valueType\":\"Double\",\"unit\":{\"status\":\"known\",\"code\":\"N.m\"},\"role\":\"measurement\",\"range\":null}");
    }
    static ObjectNode container(String id,String name,String type,String extra){
        return json("{\"memberId\":\""+id+"\",\"name\":\""+name+"\",\"semanticId\":\"urn:bifrost:sem:Tool/"+name+"\",\"description\":\"x\",\"valueType\":\""+type+"\","+extra+"\"members\":[]}");
    }
    /** A StructureArray expands to one layout leaf per index, all of one definition node: its name is counted once. */
    @Test void aStructureArrayLeafIsOneDefinitionNotOnePerIndex() throws Exception {
        change("semantics/tool.json",s->{
            ObjectNode a=container("slots","Slots","StructureArray","\"shape\":[2],\"lowerBounds\":[0],");((ArrayNode)a.path("members")).add(leaf("slot","Slot"));
            ((ArrayNode)s.path("members")).add(a);
        });
        // the target instances map every layout leaf: slots[0].slot and slots[1].slot of each tool, copies of its torque mapping
        for(String set:List.of("mappings/nutrunner1.json","mappings/nutrunner2.json"))change(set,m->{
            ArrayNode all=(ArrayNode)m.path("mappings");
            for(int i=0;i<2;i++){
                ObjectNode c=all.get(0).deepCopy();c.put("mappingId",text(all.get(0),"mappingId")+"-slot"+i);ArrayNode path=(ArrayNode)c.path("memberPath");path.removeAll();
                path.add(object().put("kind","member").put("memberId","slots"));
                ObjectNode ix=object().put("kind","index");ix.putArray("indices").add(i);path.add(ix);
                path.add(object().put("kind","member").put("memberId","slot"));all.add(c);
            }
        });
        accepted();
    }
    /** A leaf nested in a Structure still counts against the definition's names. */
    @Test void aNestedLeafSharingANameIsRefused() throws Exception {
        change("semantics/tool.json",s->{
            ObjectNode g=container("group","Group","Structure","");((ArrayNode)g.path("members")).add(leaf("inner","Torque"));
            ((ArrayNode)s.path("members")).add(g);
        });
        refused("attribution.member-unresolved");
    }
    /** The tool model nests torque in a Structure and both nutrunner mappings map it at the two-step path [group, torque]. */
    void nestTorque() throws Exception {
        change("semantics/tool.json",s->{
            ArrayNode members=(ArrayNode)s.path("members");ObjectNode torque=(ObjectNode)members.remove(0);
            ObjectNode g=container("group","Group","Structure","");((ArrayNode)g.path("members")).add(torque);members.insert(0,g);
        });
        for(String set:List.of("mappings/nutrunner1.json","mappings/nutrunner2.json"))change(set,m->{
            ArrayNode path=(ArrayNode)m.path("mappings").get(0).path("memberPath");path.insert(0,object().put("kind","member").put("memberId","group"));
        });
    }
    @Test void aMemberMappedAtAMultiStepPathIsRefused() throws Exception {nestTorque();refused("attribution.member-unresolved");}
    /** Two mapping sets sharing a mappingId (the rule names it): the bundle's own duplicate refusal, not a member refusal. */
    @Test void aMappingIdSharedByTwoSetsIsADuplicate() throws Exception {
        change("mappings/nutrunner2.json",m->((ObjectNode)m.path("mappings").get(0)).put("mappingId","nutrunner1-torque"));
        refused("mapping.duplicate-id");
    }
    @Test void memberEquipmentOutsideTheStations() throws Exception {
        // station2 alone: nutrunner1 under station1 is neither a station nor a descendant of one
        rule(r->{ArrayNode s=(ArrayNode)r.path("stations");s.removeAll();s.add(S2);});refused("attribution.member-equipment");
    }
    // activity[]
    @Test void activityMemberUnresolved() throws Exception {rule(r->activity(r,0).put("memberRef","station1-busy"));refused("attribution.activity-member");}
    @Test void activityMemberMustBeBoolean() throws Exception {rule(r->activity(r,2).put("memberRef","nutrunner1-torque"));refused("attribution.activity-member");}
    @Test void activityMemberMustBelongToItsEquipment() throws Exception {rule(r->activity(r,2).put("memberRef","nutrunner2-running"));refused("attribution.activity-member");}
    @Test void activityEquipmentMustBeTheMembers() throws Exception {rule(r->activity(r,0).put("equipmentPath","synthetic-site:line2"));refused("attribution.activity-member");}
    /** Two activity references to one mappingId (spec line 132): two activity entries for one equipment, activity-member. The
     *  different-members variant is in MappingPlcStampedRuleTest, whose station1 has a second Boolean member. */
    @Test void twoActivityEntriesForOneEquipment() throws Exception {rule(r->((ArrayNode)r.path("activity")).add(activity(r,0).deepCopy()));refused("attribution.activity-member");}
    @Test void anEquipmentWithoutAnActivityEntryIsAccepted() throws Exception {rule(r->((ArrayNode)r.path("activity")).remove(1));accepted();}
    @Test void emptyActivityIsRefusedByTheSchema() throws Exception {rule(r->((ArrayNode)r.path("activity")).removeAll());refused("mapping.schema:2.27.0/attribution-rule");}
    // occupancy binding
    @Test void bindingUnresolved() throws Exception {rule(r->ref(r,"occupancyBindingRef").put("version","9.9.9"));refused("attribution.binding-unresolved");}
    @Test void bindingMustBeAnArtifact110() throws Exception {change("evidence/occupancy-binding-line2.json",a->a.put("schemaVersion","1.0.0"));refused("attribution.binding-unresolved");}
    @Test void bindingArtifactMustCarryTheMediaType() throws Exception {
        change("evidence/occupancy-binding-line2.json",a->((ObjectNode)a.path("file")).put("mediaType","application/json"));refused("attribution.binding-profile");
    }
    @Test void bindingArtifactMustCarryThePrefix() throws Exception {
        // the artifact id must start with occupancy-binding-; rename it everywhere so only the prefix rule fails
        change("evidence/occupancy-binding-line2.json",a->a.put("id","binding-line2"));
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));for(JsonNode e:p.path("files"))if(text(e,"id").equals("occupancy-binding-line2"))((ObjectNode)e).put("id","binding-line2");rewrite(bundle.resolve("proposal.json"),p);reseal();
        rule(r->ref(r,"occupancyBindingRef").put("id","binding-line2"));
        refused("attribution.binding-profile");
    }
    @Test void bindingProfileWithAnExtraFieldIsRefused() throws Exception {profile(b->b.put("note","x"));refused("attribution.binding-profile");}
    @Test void bindingProfileWithAnAnchoredPatternIsRefused() throws Exception {profile(b->((ObjectNode)b.path("identity")).put("pattern","^[A-Z0-9]{17}$"));refused("attribution.binding-profile");}
    @Test void bindingProfileThatIsNotJsonIsRefused() throws Exception {profileBytes("not json".getBytes(java.nio.charset.StandardCharsets.UTF_8));refused("attribution.binding-profile");}
    @Test void bindingScopeIsNotComparedWithTheStations() throws Exception {
        change("evidence/occupancy-binding-line2.json",a->{ArrayNode s=(ArrayNode)a.path("scope");s.removeAll();s.add("station9");});accepted();
    }
    @Test void aProfileChangedWithoutResealIsADigestRefusal() throws Exception {
        Files.write(bundle.resolve("data/occupancy-binding-line2.json"),"{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        refused("bundle.digest:data/occupancy-binding-line2.json");
    }
    // identity under occupancy-join: namespace is optional (spec 135), identity entries are plc-stamped only
    @Test void aNamespaceIsAllowedUnderOccupancyJoin() throws Exception {rule(r->ref(r,"identity").put("namespace","urn:line2:visits"));accepted();}
    @Test void identityEntriesAreSchemaBoundToPlcStamped() throws Exception {
        rule(r->ref(r,"identity").putArray("members").addObject().put("equipmentPath",S1).put("unitMemberRef","station1-running").put("visitMemberRef","station1-running").put("presentMemberRef","station1-running"));
        refused("mapping.schema:2.27.0/attribution-rule");
    }
    @Test void crossCheckOccupancyIsAllowedUnderOccupancyJoin() throws Exception {rule(r->ref(r,"identity").put("crossCheck","occupancy"));accepted();}
    // temporal and coverage
    @Test void temporalOrder() throws Exception {rule(r->ref(r,"temporal").put("allowedLatenessMs",10000));refused("attribution.temporal-order");}
    @Test void temporalHorizonBelowLateness() throws Exception {rule(r->ref(r,"temporal").put("horizonMs",600000));refused("attribution.temporal-order");}
    @Test void temporalEqualBoundsAreAccepted() throws Exception {rule(r->ref(r,"temporal").put("outOfOrdernessMs",86400000).put("allowedLatenessMs",86400000).put("horizonMs",86400000));accepted();}
    @Test void expectedPeriodZeroIsRefusedByTheSchema() throws Exception {rule(r->ref(r,"coverage").put("expectedPeriodMs",0));refused("mapping.schema:2.27.0/attribution-rule");}
    // release
    @Test void releaseAndAttestationCarryBothRulesAndProfiles() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        assertEquals("mapping-release",text(service.publish(bundle,"release","1.0.0","approval-1"),"kind"));
        Path dir=registry.resolve("mappings/releases/release/1.0.0");JsonNode release=read(dir.resolve("release.json"));
        JsonNode statement=service.verifyAttestation("release","1.0.0",sha(dir.resolve("release.json")));
        Set<String> subjects=new HashSet<>();for(JsonNode s:statement.path("subject"))subjects.add(text(s.path("digest"),"sha256"));
        Map<String,String> files=new HashMap<>();for(JsonNode f:release.path("files"))files.put(text(f,"path"),text(f,"sha256"));
        for(String p:List.of("rules/attribution-line2.json","rules/impact-line2.json","evidence/occupancy-binding-line2.json","evidence/incident-binding-line2.json","data/occupancy-binding-line2.json","data/incident-binding-line2.json")){
            String h=files.entrySet().stream().filter(e->e.getKey().endsWith(p)).map(Map.Entry::getValue).findFirst().orElse(null);
            assertEquals(sha(bundle.resolve(p)),h,p);assertTrue(subjects.contains(h),p);
        }
    }
}
