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

/** 2.24 metric definition: Tyr's wire bundle, Bifrost's own checks, real keys. The SQL is approved as text, not executed. */
class MappingMetricDefinitionTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-11-01T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");MappingBroadcastTest.copy(Path.of(getClass().getResource("/mapping-fixtures/metric-definition").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n");
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"metric-line\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"metric-line\"}]}");
        service=new MappingRegistry(registry,CLOCK,()->{});
    }
    void rewrite(Path p,JsonNode doc) throws Exception {Files.write(p,bytes(doc));}
    void reseal() throws Exception {ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);}
    void metric(Consumer<ObjectNode> mutation) throws Exception {
        ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:proposal.path("files"))if(text(e,"kind").equals("metric-definition")){
            Path file=bundle.resolve(text(e,"path"));ObjectNode d=(ObjectNode)read(file);mutation.accept(d);rewrite(file,d);((ObjectNode)e).put("sha256",sha(file));
        }
        rewrite(bundle.resolve("proposal.json"),proposal);reseal();
    }
    static ObjectNode ossie(ObjectNode m){return (ObjectNode)m.path("ossie").path("metric");}
    static ArrayNode inputs(ObjectNode m){return (ArrayNode)m.path("inputs");}
    List<String> codes(){return new MappingBundle().validate(bundle).report().path("findings").findValuesAsText("ruleCode");}
    void refused(String code,Consumer<ObjectNode> mutation) throws Exception {metric(mutation);assertEquals(List.of(code),codes());}

    @Test void acceptsTyrBundle() throws Exception {var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toString());assertEquals("2.24.0",text(c.proposal(),"schemaVersion"));}
    @Test void releaseAndAttestationCarryTheMetric() throws Exception {
        service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);
        assertEquals("mapping-release",text(service.publish(bundle,"release","1.0.0","approval-1"),"kind"));
        Path dir=registry.resolve("mappings/releases/release/1.0.0");JsonNode release=read(dir.resolve("release.json"));
        JsonNode statement=service.verifyAttestation("release","1.0.0",sha(dir.resolve("release.json")));
        String metric=null;for(JsonNode f:release.path("files"))if(text(f,"path").endsWith("metrics/0.json"))metric=text(f,"sha256");
        assertNotNull(metric,release.toString());
        assertEquals(sha(bundle.resolve("metrics/0.json")),metric);
        boolean signed=false;for(JsonNode s:statement.path("subject"))signed|=text(s.path("digest"),"sha256").equals(metric);
        assertTrue(signed,statement.path("subject").toString());
    }
    @Test void datasetMissing() throws Exception {refused("metric.dataset-missing",m->((ObjectNode)m.path("dataset").path("recordMappingRef")).put("id","absent-samples"));}
    @Test void inputMissing() throws Exception {refused("metric.input-missing",m->inputs(m).add("downtime"));}
    @Test void inputUnreferenced() throws Exception {refused("metric.input-unreferenced",m->inputs(m).add("pressure"));}
    @Test void inputInsideStringLiteralIsNotRead() throws Exception {
        refused("metric.input-unreferenced",m->{inputs(m).add("pressure");((ObjectNode)ossie(m).path("expression")).put("sql","100.0 * COUNT(*) FILTER (WHERE running) / COUNT(*) || 'pressure'");});
    }
    @Test void grainNotAnInput() throws Exception {refused("metric.grain-input",m->inputs(m).remove(1));}
    @Test void grainKeyMustBeAStringKey() throws Exception {refused("metric.grain-key",m->((ArrayNode)m.path("grain").path("groupBy")).add("running"));}
    @Test void unitUnconfirmed() throws Exception {refused("metric.unit-unconfirmed",m->((ObjectNode)m.path("result")).set("unit",object().put("status","unknown")));}
    @Test void otherDialectsRefused() throws Exception {refused("mapping.schema:2.24.0/metric-definition",m->((ObjectNode)ossie(m).path("expression")).set("dialects",JSON.createArrayNode()));}
    @Test void customExtensionsRefused() throws Exception {refused("mapping.schema:2.24.0/metric-definition",m->ossie(m).set("custom_extensions",JSON.createArrayNode()));}
    @Test void otherSpecVersionRefused() throws Exception {refused("mapping.schema:2.24.0/metric-definition",m->((ObjectNode)m.path("ossie")).put("specVersion","0.1.1"));}
    @Test void duplicateName() throws Exception {
        List<JsonNode> docs=new ArrayList<>();ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:proposal.path("files"))if(Set.of("record-mapping","metric-definition").contains(text(e,"kind")))docs.add(read(bundle.resolve(text(e,"path"))));
        MetricDefinitions.validate(docs);
        docs.add(((ObjectNode)docs.stream().filter(d->text(d,"kind").equals("metric-definition")).findFirst().orElseThrow().deepCopy()).put("id","running-availability-copy"));
        assertEquals("metric.duplicate-name",assertThrows(IllegalArgumentException.class,()->MetricDefinitions.validate(docs)).getMessage());
    }
    @Test void identifiersSkipStringLiterals() {
        assertEquals(Set.of("count","filter","where","running"),MetricDefinitions.identifiers("COUNT(*) FILTER (WHERE running) || 'pressure' || 'it''s bucket'"));
    }
    @Test void olderEnvelopeRefused() throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.put("schemaVersion","2.23.0");rewrite(bundle.resolve("proposal.json"),p);reseal();
        assertEquals(List.of("mapping.schema:2.23.0/mapping-proposal"),codes());
    }
}
