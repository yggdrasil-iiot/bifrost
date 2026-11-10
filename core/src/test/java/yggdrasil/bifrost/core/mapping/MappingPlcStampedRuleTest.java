package yggdrasil.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import static yggdrasil.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** 2.27 attribution rule (plc-stamped): typed OPC UA String members published under contract 2.27.0, and the identity checks. */
class MappingPlcStampedRuleTest {
    @TempDir Path tmp;
    Path bundle;
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/attribution-plc-stamped").toURI()),bundle);
    }
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
    void rule(Consumer<ObjectNode> mutation) throws Exception {change("rules/attribution-line2.json",mutation);}
    static ObjectNode ref(ObjectNode r,String field){return (ObjectNode)r.path(field);}

    static ObjectNode identityEntry(ObjectNode r,int i){return (ObjectNode)r.path("identity").path("members").get(i);}
    static ArrayNode identityEntries(ObjectNode r){return (ArrayNode)r.path("identity").path("members");}
    static final String S1="synthetic-site:line2:station1",S2="synthetic-site:line2:station2",N1=S1+":nutrunner1";

    @Test void acceptsThePlcStampedBundle() {
        var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());
        // the unit and visit members are typed OPC UA String sources, published under contract 2.27.0
        assertEquals(4,c.documents().values().stream().filter(d->text(d,"kind").equals("source-definition")&&text(d,"schemaVersion").equals("2.27.0")&&text(d.path("rawRepresentation"),"valueType").equals("String")).count());
        JsonNode rule=c.documents().values().stream().filter(d->text(d,"kind").equals("attribution-rule")).findFirst().orElseThrow();
        assertEquals("plc-stamped",text(rule.path("identity"),"mode"));assertEquals("occupancy",text(rule.path("identity"),"crossCheck"));
    }
    @Test void crossCheckNoneIsAllowedUnderPlcStamped() throws Exception {rule(r->ref(r,"identity").put("crossCheck","none"));accepted();}
    @Test void identityEquipmentMissing() throws Exception {rule(r->identityEntries(r).remove(1));refused("attribution.identity-equipment");}
    @Test void identityEquipmentDuplicate() throws Exception {rule(r->identityEntries(r).add(identityEntry(r,0).deepCopy()));refused("attribution.identity-equipment");}
    @Test void identityEntryForAnEquipmentWithoutMembersIsRefused() throws Exception {
        // station2 is a station of the rule but has no measurement or activity member: it may not carry an identity entry
        rule(r->identityEntries(r).add(identityEntry(r,0).deepCopy().put("equipmentPath",S2)));refused("attribution.identity-equipment");
    }
    @Test void identityOnlyEquipmentMayNotCarryAnIdentityEntry() throws Exception {
        // nutrunner1 keeps its UnitId, VisitId and VisitPresent members and its identity entry, but loses its torque member and its
        // activity entry: identity members alone do not make an equipment one with measurement or activity members
        rule(r->{ArrayNode m=(ArrayNode)r.path("members");m.remove(2);m.remove(0);((ArrayNode)r.path("activity")).remove(1);});
        refused("attribution.identity-equipment");
    }
    // identity member types and equipment: the mutations point at nutrunner1's Double torque (a measurement member no other
    // reference names), so the type check, not the role check, is what refuses
    @Test void identityUnitMemberMustBeString() throws Exception {rule(r->identityEntry(r,1).put("unitMemberRef","nutrunner1-torque"));refused("attribution.identity-member");}
    @Test void identityVisitMemberMustBeString() throws Exception {rule(r->identityEntry(r,1).put("visitMemberRef","nutrunner1-torque"));refused("attribution.identity-member");}
    @Test void identityPresentMemberMustBeBoolean() throws Exception {rule(r->identityEntry(r,1).put("presentMemberRef","nutrunner1-torque"));refused("attribution.identity-member");}
    @Test void identityMemberUnresolved() throws Exception {rule(r->identityEntry(r,0).put("visitMemberRef","station1-visitid"));refused("attribution.identity-member");}
    @Test void identityMemberMustBelongToTheEntrysEquipment() throws Exception {
        // station1's entry names nutrunner1's UnitId; nutrunner1's own entry is pointed elsewhere first, so no member is named twice
        // and station1's entry (checked first) fails on equipment, not on a shared reference
        rule(r->{identityEntry(r,1).put("unitMemberRef","nutrunner1-torque");identityEntry(r,0).put("unitMemberRef","nutrunner1-unit");});refused("attribution.identity-member");
    }
    // one role per mappingId (spec line 132): the role check runs after coverage and before the type check
    @Test void identityPresentRefNamingTheActivityMemberIsRefused() throws Exception {
        // station1's Running is its activity member and a Boolean of the same equipment: only the role check refuses it
        rule(r->identityEntry(r,0).put("presentMemberRef","station1-running"));refused("attribution.identity-member");
    }
    @Test void identityEntryNamingOneMemberTwiceIsRefused() throws Exception {
        // visit = unit: both are String members of station1, so the type check would accept it; the role check refuses it
        rule(r->identityEntry(r,0).put("visitMemberRef","station1-unit"));refused("attribution.identity-member");
    }
    @Test void identityRefSharedAcrossTwoEntriesIsRefused() throws Exception {
        // nutrunner1's entry names station1's UnitId: the role check refuses the second use; the equipment check would refuse it
        // too (a member belongs to one equipment and two entries have distinct equipment), with the same code
        rule(r->identityEntry(r,1).put("unitMemberRef","station1-unit"));refused("attribution.identity-member");
    }
    /** Two activity entries for one equipment naming different Boolean members (spec line 133). The rule is switched to occupancy-join
     *  first, so that station1's VisitPresent is a plain Boolean member and no identity reference is involved. */
    @Test void twoActivityEntriesWithDifferentMembersForOneEquipment() throws Exception {
        rule(r->{r.set("identity",object().put("mode","occupancy-join").put("crossCheck","none"));((ArrayNode)r.path("activity")).addObject().put("equipmentPath",S1).put("memberRef","station1-present").put("activeWhen",true);});
        refused("attribution.activity-member");
    }
    static void swap(ArrayNode a){JsonNode first=a.remove(0);a.add(first);}
    @Test void identityEntryOrderDoesNotMatter() throws Exception {rule(r->{swap(identityEntries(r));swap((ArrayNode)r.path("activity"));});accepted();}
    @Test void identityRoleCheckIsOrderIndependent() throws Exception {
        rule(r->{swap(identityEntries(r));swap((ArrayNode)r.path("activity"));identityEntry(r,1).put("presentMemberRef","station1-running");});refused("attribution.identity-member");
    }
    @Test void plcStampedNeedsANamespace() throws Exception {rule(r->ref(r,"identity").remove("namespace"));refused("mapping.schema:2.27.0/attribution-rule");}
    @Test void plcStampedNeedsIdentityEntries() throws Exception {rule(r->identityEntries(r).removeAll());refused("mapping.schema:2.27.0/attribution-rule");}
    /** The same String source re-stamped 2.7.0 is refused by that version's schema: the value type is a 2.27.0 addition. */
    @Test void theStringSourceIsRefusedAt270() throws Exception {change("sources/station1-unit.json",s->s.put("schemaVersion","2.7.0"));refused("mapping.schema:2.7.0/source-definition");}
}
