package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** 2.25 command binding: the link from one read binding to one Method of the same equipment, checked at publish. */
class MappingCommandBindingTest {
    @TempDir Path tmp;
    Path bundle;
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/vor-read").toURI()),bundle);
    }
    void rewrite(Path p,JsonNode doc) throws Exception {Files.write(p,bytes(doc));}
    /** Changes one listed file and re-pins it in the proposal and the submission, so only the rule under test fails. */
    void change(String path,Consumer<ObjectNode> mutation) throws Exception {
        Path file=bundle.resolve(path);ObjectNode d=(ObjectNode)read(file);mutation.accept(d);rewrite(file,d);
        ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:proposal.path("files"))if(text(e,"path").equals(path))((ObjectNode)e).put("sha256",sha(file));
        rewrite(bundle.resolve("proposal.json"),proposal);
        ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);
    }
    void link(String mixer,Consumer<ObjectNode> mutation) throws Exception {change("command-bindings/"+mixer+"-set-temperature.json",mutation);}
    List<String> codes(){return new MappingBundle().validate(bundle).report().path("findings").findValuesAsText("ruleCode");}
    void refused(String code) {assertEquals(List.of(code),codes());}
    static ObjectNode input(ObjectNode d){return (ObjectNode)d.path("method").path("inputs").get(0);}

    @Test void acceptsOneLinkPerMixer() {
        var c=new MappingBundle().validate(bundle);
        assertTrue(c.accepted(),c.report().toString());
        assertEquals("2.25.0",text(c.proposal(),"schemaVersion"));
        assertEquals(2,c.documents().values().stream().filter(d->text(d,"kind").equals("command-binding")).count());
    }
    @Test void aSecondLinkForTheSameDeviceAndMethodIsADuplicate() throws Exception {
        link("mixer2",d->{
            ((ObjectNode)d.path("equipmentRef")).put("equipmentInstanceId","mixer1");
            ((ObjectNode)d.path("readBindingRef")).put("id","vor-binding-mixer1-temp");
            ((ObjectNode)d.path("method")).put("objectNodeId","nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1").put("methodNodeId","nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1.SetTemperature");
        });
        refused("command-binding.duplicate");
    }
    @Test void anotherMethodOfTheSameDeviceIsNotADuplicate() throws Exception {
        link("mixer2",d->{
            ((ObjectNode)d.path("equipmentRef")).put("equipmentInstanceId","mixer1");
            ((ObjectNode)d.path("readBindingRef")).put("id","vor-binding-mixer1-temp");
        });
        assertEquals(List.of(),codes());
    }
    @Test void theReadBindingMustReadTheLinkedEquipment() throws Exception {
        link("mixer2",d->((ObjectNode)d.path("readBindingRef")).put("id","vor-binding-mixer1-temp"));
        refused("command-binding.device-path");
    }
    @Test void theReadBindingDeviceMustBeTheHierarchyPath() throws Exception {
        change("data/vor-read-binding-mixer2.json",d->d.put("device","Line1/Mixer2"));
        // the data file is pinned by its evidence-artifact, not by the proposal: re-pin that artifact too
        change("evidence/vor-read-binding-mixer2.json",d->((ObjectNode)d.path("file")).put("sha256",sha0("data/vor-read-binding-mixer2.json")));
        refused("command-binding.device-path");
    }
    String sha0(String rel){try{return sha(bundle.resolve(rel));}catch(Exception e){throw new IllegalStateException(e);}}
    @Test void exactlyOneInput() throws Exception {
        link("mixer1",d->((ArrayNode)d.path("method").path("inputs")).add(input(d).deepCopy().put("name","rampRate")));
        refused("command-binding.inputs");
    }
    @Test void noInput() throws Exception {link("mixer1",d->((ArrayNode)d.path("method").path("inputs")).removeAll());refused("command-binding.inputs");}
    @Test void theInputIsADouble() throws Exception {link("mixer1",d->input(d).put("type","Int32"));refused("command-binding.inputs");}
    @Test void theInputIsNamed() throws Exception {link("mixer1",d->input(d).put("name",""));refused("command-binding.inputs");}
    @Test void theUnitIsAUcumCodeTheContractKnows() throws Exception {link("mixer1",d->input(d).put("unit","degC"));refused("command-binding.inputs");}
    @Test void anUnknownReadBindingIsUnresolved() throws Exception {link("mixer1",d->((ObjectNode)d.path("readBindingRef")).put("version","9.9.9"));refused("command-binding.unresolved");}
    @Test void anUnknownHierarchyIsUnresolved() throws Exception {link("mixer1",d->((ObjectNode)d.path("equipmentRef")).put("id","other-plant"));refused("command-binding.unresolved");}
    @Test void anUnknownEquipmentIsUnresolved() throws Exception {link("mixer1",d->((ObjectNode)d.path("equipmentRef")).put("equipmentInstanceId","mixer9"));refused("command-binding.unresolved");}
    @Test void aReadBindingThatIsNotAProfileIsUnresolved() throws Exception {link("mixer1",d->((ObjectNode)d.path("readBindingRef")).put("id","manual-mixer1-temp"));refused("command-binding.unresolved");}
    @Test void anUnsupportedProfileVersionIsUnresolved() throws Exception {
        change("data/vor-read-binding.json",d->d.put("profileVersion","0.2.0"));
        change("evidence/vor-read-binding.json",d->((ObjectNode)d.path("file")).put("sha256",sha0("data/vor-read-binding.json")));
        refused("command-binding.unresolved");
    }
    @Test void aProposalBefore225CannotCarryALink() throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.put("schemaVersion","2.24.0");rewrite(bundle.resolve("proposal.json"),p);
        ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);
        refused("mapping.schema:2.24.0/mapping-proposal");
    }
}
