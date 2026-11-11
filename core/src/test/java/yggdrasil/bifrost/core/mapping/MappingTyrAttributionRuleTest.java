package yggdrasil.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import yggdrasil.bifrost.core.identity.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static yggdrasil.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** 2.27 attribution and impact rules as Tyr packages them (occupancy-join and plc-stamped): Bifrost's own checks accept
 *  both bundles, and the release attests both rules and both binding profiles with the bytes Tyr wrote. */
class MappingTyrAttributionRuleTest {
    @TempDir Path tmp;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-11-07T00:00:00Z"),ZoneOffset.UTC);

    Path bundle(String fixture) throws Exception {
        Path b=tmp.resolve("bundle");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/"+fixture).toURI()),b);return b;
    }
    /** The publication policy names the bundle's own stream: Tyr writes the plc-stamped bundle for stream line2-plc. */
    MappingRegistry service(Path registry,Path proposerKey,Path approverKey,String stream) throws Exception {
        Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n");
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\""+stream+"\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\""+stream+"\"}]}");
        return new MappingRegistry(registry,CLOCK,()->{});
    }
    static long count(MappingBundle.Checked c,String field,String value){return c.documents().values().stream().filter(d->text(d,field).equals(value)).count();}

    @ParameterizedTest @ValueSource(strings={"tyr-attribution-impact","tyr-attribution-plc-stamped"})
    void acceptsTyrBundle(String fixture) throws Exception {
        var c=new MappingBundle().validate(bundle(fixture));assertTrue(c.accepted(),c.report().toString());
        assertEquals("2.27.0",text(c.proposal(),"schemaVersion"));
        assertEquals(1,count(c,"kind","attribution-rule"));assertEquals(1,count(c,"kind","impact-rule"));
        JsonNode rule=c.documents().values().stream().filter(d->text(d,"kind").equals("attribution-rule")).findFirst().orElseThrow();
        assertEquals(fixture.endsWith("plc-stamped")?"plc-stamped":"occupancy-join",text(rule.path("identity"),"mode"));
    }
    @ParameterizedTest @ValueSource(strings={"tyr-attribution-plc-stamped"})
    void plcStampedBundleCarriesTypedStringSources(String fixture) throws Exception {
        var c=new MappingBundle().validate(bundle(fixture));
        long strings=c.documents().values().stream().filter(d->text(d,"kind").equals("source-definition")&&text(d,"schemaVersion").equals("2.27.0")&&text(d.path("rawRepresentation"),"valueType").equals("String")).count();
        assertEquals(4,strings);
    }
    @ParameterizedTest @ValueSource(strings={"tyr-attribution-impact","tyr-attribution-plc-stamped"})
    void releaseAndAttestationCarryBothRulesAndBothProfiles(String fixture) throws Exception {
        Path bundle=bundle(fixture),registry=tmp.resolve("registry"),pk=tmp.resolve("proposer.key"),ak=tmp.resolve("approver.key");
        MappingRegistry service=service(registry,pk,ak,text(read(bundle.resolve("submission.json")),"streamId"));
        service.approve(bundle,"approval-1","proposer",pk,"approver",ak);
        assertEquals("mapping-release",text(service.publish(bundle,"release","1.0.0","approval-1"),"kind"));
        Path dir=registry.resolve("mappings/releases/release/1.0.0");JsonNode release=read(dir.resolve("release.json"));
        JsonNode statement=service.verifyAttestation("release","1.0.0",sha(dir.resolve("release.json")));
        Set<String> subjects=new HashSet<>();for(JsonNode s:statement.path("subject"))subjects.add(text(s.path("digest"),"sha256"));
        Map<String,String> files=new HashMap<>();for(JsonNode f:release.path("files"))files.put(text(f,"path"),text(f,"sha256"));
        for(String p:List.of("attribution-rules/0.json","impact-rules/0.json","evidence/occupancy-binding-0.json","evidence/incident-binding-0.json")){
            String h=released(files,p);assertEquals(sha(bundle.resolve(p)),h,p);assertTrue(subjects.contains(h),p);
        }
        // the profile bytes forseti will read are the bytes Tyr wrote
        for(String profile:List.of("occupancy-binding-0","incident-binding-0")){
            String h=released(files,"data/"+profile+".json");
            assertEquals(sha(bundle.resolve("data/"+profile+".json")),h,profile);
            assertEquals(text(read(bundle.resolve("evidence/"+profile+".json")).path("file"),"sha256"),h,profile);
        }
    }
    static String released(Map<String,String> files,String suffix){
        return files.entrySet().stream().filter(e->e.getKey().endsWith(suffix)).map(Map.Entry::getValue).findFirst().orElseThrow(()->new AssertionError(suffix));
    }
    @ParameterizedTest @ValueSource(strings={"tyr-attribution-impact","tyr-attribution-plc-stamped"})
    void anImpactRuleNamingAnotherAttributionRuleIsRefused(String fixture) throws Exception {
        Path bundle=bundle(fixture),file=bundle.resolve("impact-rules/0.json");ObjectNode r=(ObjectNode)read(file);
        ((ObjectNode)r.path("attributionRuleRef")).put("id","line3-attribution");Files.write(file,bytes(r));
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:p.path("files"))if(text(e,"path").equals("impact-rules/0.json"))((ObjectNode)e).put("sha256",sha(file));
        Files.write(bundle.resolve("proposal.json"),bytes(p));
        ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));Files.write(bundle.resolve("submission.json"),bytes(s));
        assertEquals(List.of("impact.attribution-missing"),new MappingBundle().validate(bundle).report().path("findings").findValuesAsText("ruleCode"));
    }
}
