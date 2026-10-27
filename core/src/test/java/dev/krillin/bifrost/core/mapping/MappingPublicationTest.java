package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import dev.krillin.bifrost.core.identity.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real wire package + real registered Ed25519 keys + real files; no Python or Tyr code. */
class MappingPublicationTest {
    @TempDir Path tmp;
    Path bundle,registry,proposerKey,approverKey;
    MappingRegistry service;
    static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-17T00:00:00Z"),ZoneOffset.UTC);
    @BeforeEach void setup() throws Exception {
        bundle=tmp.resolve("bundle");copy(Path.of(getClass().getResource("/mapping-fixtures/valid").toURI()),bundle);
        registry=tmp.resolve("registry");Files.createDirectories(registry.resolve("identity"));
        var a=Ed25519Keys.generate();var b=Ed25519Keys.generate();proposerKey=tmp.resolve("proposer.key");approverKey=tmp.resolve("approver.key");
        Files.writeString(proposerKey,Ed25519Keys.privateKeyB64(a.getPrivate()));Files.writeString(approverKey,Ed25519Keys.privateKeyB64(b.getPrivate()));
        String keys=JSON.writeValueAsString(new AuthorizedKey("proposer",Ed25519Keys.publicKeyB64(a.getPublic())))+"\n"+JSON.writeValueAsString(new AuthorizedKey("approver",Ed25519Keys.publicKeyB64(b.getPublic())))+"\n";
        Files.writeString(registry.resolve("identity/authorized-keys.jsonl"),keys);
        policy();service=new MappingRegistry(registry,CLOCK,()->{});
    }
    void policy() throws Exception {
        Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"1.0.0\",\"default\":\"deny\",\"rules\":[{\"id\":\"publish-map\",\"principal\":\"proposer\",\"action\":\"publish\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"mixed-line\"},{\"id\":\"approve-map\",\"principal\":\"approver\",\"action\":\"approve\",\"target\":\"mapping-publication\",\"kind\":\"mapping-release\",\"ref\":\"mixed-line\"}]}");
    }
    static void copy(Path source,Path dest) throws Exception {
        try(var walk=Files.walk(source)){for(Path p:walk.toList()){Path q=dest.resolve(source.relativize(p));if(Files.isDirectory(p))Files.createDirectories(q);else Files.copy(p,q);}}
    }
    void rewrite(Path p,JsonNode doc) throws Exception {Files.write(p,bytes(doc));}
    void patch(String kind,String id,Consumer<ObjectNode> mutation) throws Exception {
        ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));
        for(JsonNode e:proposal.path("files"))if(text(e,"kind").equals(kind)&&text(e,"id").equals(id)){
            Path file=bundle.resolve(text(e,"path"));ObjectNode d=(ObjectNode)read(file);mutation.accept(d);rewrite(file,d);((ObjectNode)e).put("sha256",sha(file));
        }
        rewrite(bundle.resolve("proposal.json"),proposal);ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);
    }
    void approve() throws Exception {service.approve(bundle,"approval-1","proposer",proposerKey,"approver",approverKey);}
    JsonNode publish() throws Exception {return service.publish(bundle,"release","1.0.0","approval-1");}
    void catalogStream(String stream) throws Exception {
        ObjectNode submission=(ObjectNode)read(bundle.resolve("submission.json"));submission.put("streamId",stream);rewrite(bundle.resolve("submission.json"),submission);
        Path file=registry.resolve("identity/activation-policy.json");ObjectNode p=(ObjectNode)read(file);ArrayNode rules=(ArrayNode)p.path("rules");
        for(String action:List.of("publish","approve"))rules.add(object().put("id",action+"-"+stream).put("principal",action.equals("publish")?"proposer":"approver")
            .put("action",action).put("target","mapping-publication").put("kind","mapping-release").put("ref",stream));rewrite(file,p);
    }
    void catalogRole(JsonNode node,String uri,String role){if(text(node,"semanticId").equals(uri))((ObjectNode)node).put("role",role);for(JsonNode child:node.path("members"))catalogRole(child,uri,role);}
    @Test void catalogEmptyIsStableAndBounded() throws Exception {
        JsonNode a=service.catalog();assertTrue(a.path("compatible").asBoolean());assertEquals(0,a.path("entries").size());assertEquals(a,service.catalog());
        ObjectNode unhashed=a.deepCopy();String hash=text(unhashed,"catalogSha256");unhashed.remove("catalogSha256");assertEquals(hash,sha(bytes(unhashed)));
    }
    @Test void catalogSameMeaningAcrossStreamsAccepted() throws Exception {
        approve();publish();catalogStream("second-line");service.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey);service.publish(bundle,"second-release","1.0.0","approval-2");
        JsonNode c=service.catalog();assertEquals(2,c.path("releases").size());assertEquals(9,c.path("entries").size());assertTrue(c.path("compatible").asBoolean());assertEquals(2,c.path("entries").get(0).path("variants").get(0).path("occurrences").size());
    }
    @Test void catalogCrossStreamRoleConflictRefused() throws Exception {
        approve();publish();catalogStream("second-line");patch("semantic-definition","mixed-tank-model",d->((ObjectNode)d.path("members").get(0)).put("role","setpoint"));
        assertTrue(new MappingBundle().validate(bundle).accepted());Exception e=assertThrows(Exception.class,()->service.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey));assertTrue(e.getMessage().startsWith("mapping.semantic-drift:"));
        assertFalse(Files.exists(registry.resolve("mappings/approvals/approval-2.json")));
    }
    @Test void catalogPresentationChangesAllowed() throws Exception {
        approve();publish();catalogStream("second-line");patch("semantic-definition","mixed-tank-model",d->{((ObjectNode)d.path("members").get(0)).put("name","different label");((ObjectNode)d.path("members").get(0)).put("description","Different description");});
        service.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey);service.publish(bundle,"second-release","1.0.0","approval-2");assertTrue(service.catalog().path("compatible").asBoolean());
    }
    @Test void catalogSameNameDifferentUriIsSeparate() throws Exception {
        approve();publish();catalogStream("second-line");patch("semantic-definition","mixed-tank-model",d->((ObjectNode)d.path("members").get(0)).put("semanticId","urn:tyr:concept:independent-pressure").put("role","setpoint"));
        service.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey);service.publish(bundle,"second-release","1.0.0","approval-2");assertEquals(10,service.catalog().path("entries").size());
    }
    @Test void catalogRechecksApprovalAfterOtherStreamPublishes() throws Exception {
        approve();Path original=bundle;Path other=tmp.resolve("other-stream");copy(bundle,other);bundle=other;catalogStream("second-line");patch("semantic-definition","mixed-tank-model",d->((ObjectNode)d.path("members").get(0)).put("role","setpoint"));
        service.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey);bundle=original;publish();bundle=other;
        Exception e=assertThrows(Exception.class,()->service.publish(bundle,"second-release","1.0.0","approval-2"));assertTrue(e.getMessage().startsWith("mapping.semantic-drift:"));assertFalse(Files.exists(registry.resolve("mappings/releases/second-release/1.0.0")));
    }
    @Test void catalogNestedLeafConflictRefused() throws Exception {
        logicalBundle();approve();publish();catalogStream("second-line");patch("semantic-definition","logical-skid",d->catalogRole(d,"urn:tyr:concept:pressure.actual","setpoint"));
        var check=new MappingBundle().validate(bundle);assertTrue(check.accepted(),check.report().toPrettyString());assertThrows(Exception.class,()->service.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey));
    }
    @Test void catalogUnheadedHistoryStillConstrainsMeaning() throws Exception {
        approve();publish();Files.delete(registry.resolve("mappings/heads/mixed-line.json"));catalogStream("second-line");patch("semantic-definition","mixed-tank-model",d->((ObjectNode)d.path("members").get(0)).put("role","setpoint"));
        assertEquals(1,service.catalog().path("releases").size());assertThrows(Exception.class,()->service.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey));
    }
    @Test void catalogCorruptHistoryCannotBeSkipped() throws Exception {
        approve();publish();Files.writeString(registry.resolve("mappings/releases/release/1.0.0/payload/semantics/0.json"),"{}");assertThrows(Exception.class,()->service.catalog());
        catalogStream("second-line");assertThrows(Exception.class,()->service.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey));
    }
    @Test void catalogHistoricalConflictsReportedAndBlockNewApprovals() throws Exception {
        approve();publish();catalogStream("second-line");patch("semantic-definition","mixed-tank-model",d->((ObjectNode)d.path("members").get(0)).put("role","setpoint"));
        Path detached=tmp.resolve("detached");copy(registry.resolve("identity"),detached.resolve("identity"));MappingRegistry legacy=new MappingRegistry(detached,CLOCK,()->{});
        legacy.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey);legacy.publish(bundle,"second-release","1.0.0","approval-2");
        copy(detached.resolve("mappings/releases/second-release"),registry.resolve("mappings/releases/second-release"));
        JsonNode report=service.catalog();assertFalse(report.path("compatible").asBoolean());assertTrue(StreamSupport.stream(report.path("entries").spliterator(),false).anyMatch(e->!e.path("compatible").asBoolean()));
        Exception e=assertThrows(Exception.class,()->service.approve(bundle,"approval-3","proposer",proposerKey,"approver",approverKey));assertEquals("mapping.semantic-history-conflict",e.getMessage());
    }
    @Test void catalogPendingTransactionRequiresRecovery() throws Exception {
        approve();service.faults(p->{if(p.equals("release-moved"))throw new IllegalStateException("fault");});assertThrows(Exception.class,()->publish());
        Exception e=assertThrows(Exception.class,()->service.catalog());assertEquals("mapping.recovery-required",e.getMessage());service.faults(p->{});service.recover();assertEquals(1,service.catalog().path("releases").size());
    }
    void boundedMathBundle() throws Exception {
        bundle=tmp.resolve("bounded-math");
        copy(Path.of(getClass().getResource("/mapping-fixtures/p3cb").toURI()),bundle);
    }
    @Test void boundedMathApprovesAndPublishes() throws Exception {
        boundedMathBundle();
        var check=new MappingBundle().validate(bundle);assertTrue(check.accepted(),check.report().toPrettyString());
        approve();assertEquals("not-performed",text(publish(),"activation"));
        assertNotNull(service.status("mixed-line").get("head"));
    }
    @Test void boundedMathRejectsReversedRange() throws Exception {
        boundedMathBundle();
        patch("value-graph","pressure-direct",d->((ObjectNode)d.path("nodes").get(1)).put("low","11"));
        var check=new MappingBundle().validate(bundle);assertFalse(check.accepted());
        assertTrue(check.report().toString().contains("graph.clamp-range"));
        assertThrows(Exception.class,()->approve());
    }
    @Test void boundedMathRejectsDimensionedSqrt() throws Exception {
        boundedMathBundle();
        patch("source-definition","pressure-up",d->((ObjectNode)d.path("unit")).put("code","kPa"));
        var check=new MappingBundle().validate(bundle);assertFalse(check.accepted());
        assertTrue(check.report().toString().contains("graph.input-unit"));
    }
    @Test void boundedMathRejectsLegacyVersionAndUnapprovedPrecision() throws Exception {
        boundedMathBundle();
        patch("value-graph","pressure-direct",d->d.put("schemaVersion","2.5.0"));
        assertFalse(new MappingBundle().validate(bundle).accepted());
        patch("value-graph","pressure-direct",d->{d.put("schemaVersion","2.11.0");((ObjectNode)d.path("nodes").get(0)).put("precision",35);});
        assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    void importWorkflowBundle() throws Exception {
        bundle=tmp.resolve("import-workflow");copy(Path.of(getClass().getResource("/mapping-fixtures/p4ab").toURI()),bundle);
    }
    @Test void importWorkflowApproveAndPublish() throws Exception {
        importWorkflowBundle();var result=new MappingBundle().validate(bundle);assertTrue(result.accepted(),result.report().toPrettyString());approve();assertEquals("not-performed",text(publish(),"activation"));
    }
    @Test void importWorkflowExplicitRetainDoesNotRequireConflictChoices() throws Exception {
        importWorkflowBundle();patch("import-batch","review-next",d->{ObjectNode q=(ObjectNode)d.path("reconciliation").path("choices").path("pressure-ua");q.put("mode","retain");q.set("fields",object());});
        var result=new MappingBundle().validate(bundle);assertTrue(result.accepted(),result.report().toPrettyString());approve();
    }
    @Test void importWorkflowLegacy26ClosedImportStillPublishes() throws Exception {
        bundle=tmp.resolve("import-legacy");copy(Path.of(getClass().getResource("/mapping-fixtures/p4ab-legacy").toURI()),bundle);
        var result=new MappingBundle().validate(bundle);assertTrue(result.accepted(),result.report().toPrettyString());approve();assertEquals("not-performed",text(publish(),"activation"));
    }
    @Test void importWorkflowCanonicalDigestIsIndependent() throws Exception {
        JsonNode cases=read(Path.of(getClass().getResource("/mapping-fixtures/p4ab-digest-cases.json").toURI()));
        for(JsonNode c:cases)assertEquals(text(c,"sha256"),MappingImportWorkflow.digest(c.path("value")));
    }
    @Test void importWorkflowObservationDigestRefused() throws Exception {
        importWorkflowBundle();patch("import-batch","review-base",d->((ObjectNode)d.path("reviews").get(0)).put("observationSha256","0".repeat(64)));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("review.observation-stale"));assertThrows(Exception.class,()->approve());
    }
    @Test void importWorkflowReviewChainRefused() throws Exception {
        importWorkflowBundle();patch("import-batch","review-base",d->((ObjectNode)d.path("reviews").get(0)).put("previousReviewSha256","0".repeat(64)));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("review.decision-chain"));
    }
    @Test void importWorkflowReviewReasonRequired() throws Exception {
        importWorkflowBundle();patch("import-batch","review-base",d->((ObjectNode)d.path("reviews").get(0)).put("reason"," "));
        assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void importWorkflowReviewSourceEvidenceRefused() throws Exception {
        importWorkflowBundle();patch("import-batch","review-base",d->((ArrayNode)d.path("reviews").get(0).path("source").path("evidenceRefs")).removeAll());
        assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void importWorkflowPendingOriginalCannotBeWaived() throws Exception {
        importWorkflowBundle();patch("import-batch","review-base",d->((ArrayNode)d.path("reviews")).removeAll());
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("import.unresolved"));
    }
    @Test void importWorkflowMergeResultRefused() throws Exception {
        importWorkflowBundle();patch("import-batch","review-next",d->((ObjectNode)d.path("reconciliation").path("results").path("speed-ab")).put("rawAddressText","Injected"));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("merge.result-mismatch"));
    }
    @Test void importWorkflowPlanDigestRefused() throws Exception {
        importWorkflowBundle();patch("import-batch","review-next",d->((ObjectNode)d.path("reconciliation")).put("planSha256","0".repeat(64)));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("merge.plan-mismatch"));
    }
    @Test void importWorkflowPreviousBatchDigestRefused() throws Exception {
        importWorkflowBundle();patch("import-batch","review-next",d->((ObjectNode)d.path("reconciliation")).put("previousBatchSha256","0".repeat(64)));
        assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void importWorkflowMissingConflictChoiceRefused() throws Exception {
        importWorkflowBundle();patch("import-batch","review-next",d->((ObjectNode)d.path("reconciliation").path("choices").path("pressure-ua")).set("fields",object()));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("merge.conflicts-unresolved"));
    }
    @Test void importWorkflowAdoptionIdentityRefused() throws Exception {
        importWorkflowBundle();patch("import-batch","review-next",d->((ObjectNode)d.path("adoptions").get(0)).put("sourceId","wrong-source"));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("merge.adoption-mismatch"));
    }
    @Test void importWorkflowLegacySchemaRefused() throws Exception {
        importWorkflowBundle();patch("import-batch","review-next",d->d.put("schemaVersion","2.6.0"));
        assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void importWorkflowSourceMustBeReviewedAfterMerge() throws Exception {
        importWorkflowBundle();patch("source-definition","imp-review-base-speed-ab",d->d.put("status","draft"));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("source.not-ready"));
    }
    void graphCandidateBundle() throws Exception {
        bundle=tmp.resolve("graph-candidates");copy(Path.of(getClass().getResource("/mapping-fixtures/p3fb").toURI()),bundle);
    }
    @Test void graphCandidatesApproveAndPublish() throws Exception {
        graphCandidateBundle();var result=new MappingBundle().validate(bundle);
        assertTrue(result.accepted(),result.report().toPrettyString());approve();assertEquals("not-performed",text(publish(),"activation"));
    }
    @Test void graphCandidatesControlStageDoesNotContaminateValueStage() throws Exception {
        graphCandidateBundle();patch("source-definition","selector-index",d->d.put("inputStage","already-engineered"));
        patch("value-graph","bounded-pressure",d->{
            ObjectNode n=(ObjectNode)d.path("nodes").get(0).deepCopy();n.put("nodeId","after-selection");
            ObjectNode input=JSON.createObjectNode();input.put("kind","node");input.put("nodeId","selected");
            ((ObjectNode)n.path("inputs")).set("value",input);n.put("factor","2");((ArrayNode)d.path("nodes")).add(n);
        });
        patch("mapping-set","bounded-pressure-mapping",d->((ObjectNode)d.path("mappings").get(0).path("valueRef")).put("nodeId","after-selection"));
        var result=new MappingBundle().validate(bundle);assertTrue(result.accepted(),result.report().toPrettyString());approve();
    }
    @Test void graphCandidatesLegacyVersionRefused() throws Exception {
        graphCandidateBundle();patch("value-graph","bounded-pressure",d->d.put("schemaVersion","2.5.0"));
        assertFalse(new MappingBundle().validate(bundle).accepted());assertThrows(Exception.class,()->approve());
    }
    @Test void graphCandidatesUnselectedTypeRefused() throws Exception {
        graphCandidateBundle();patch("value-graph","bounded-pressure",d->((ObjectNode)d.path("nodes").get(3)).put("valueType","UInt16"));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("selector.candidate-type"));
    }
    @Test void graphCandidatesUnselectedUnitRefused() throws Exception {
        graphCandidateBundle();patch("value-graph","bounded-pressure",d->((ObjectNode)d.path("nodes").get(3).path("unit")).put("code","bar"));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("selector.candidate-unit"));
    }
    @Test void graphCandidatesCycleRefused() throws Exception {
        graphCandidateBundle();patch("value-graph","bounded-pressure",d->((ObjectNode)d.path("nodes").get(3).path("inputs").path("candidate1")).put("nodeId","selected"));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("graph.cycle"));assertThrows(Exception.class,()->approve());
    }
    @Test void graphCandidatesMissingNodeRefused() throws Exception {
        graphCandidateBundle();patch("value-graph","bounded-pressure",d->((ObjectNode)d.path("nodes").get(3).path("inputs").path("candidate1")).put("nodeId","absent"));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("graph.node-missing"));
    }
    @Test void graphCandidatesDefaultRangeRefused() throws Exception {
        graphCandidateBundle();patch("value-graph","bounded-pressure",d->{ObjectNode n=(ObjectNode)d.path("nodes").get(3);n.put("outOfRange","default-candidate");n.put("defaultCandidate",3);});
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("selector.default-range"));
    }
    @Test void graphCandidatesEvidenceClosureRefused() throws Exception {
        graphCandidateBundle();patch("value-graph","bounded-pressure",d->((ArrayNode)d.path("nodes").get(3).path("evidenceRefs")).removeAll());
        assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    void logicalBundle() throws Exception {
        bundle=tmp.resolve("logical");copy(Path.of(getClass().getResource("/mapping-fixtures/p3eb").toURI()),bundle);
    }
    @Test void logicalStructureArrayApprovesAndPublishes() throws Exception {
        logicalBundle();var result=new MappingBundle().validate(bundle);
        assertTrue(result.accepted(),result.report().toPrettyString());approve();assertEquals("not-performed",text(publish(),"activation"));
    }
    @Test void logicalOutOfRangeRefused() throws Exception {
        logicalBundle();patch("mapping-set","structure-ab-mapping",d->((ArrayNode)d.path("mappings").get(4).path("memberPath").get(1).path("indices")).set(0,JSON.getNodeFactory().numberNode(3)));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("structure.index-range"));
    }
    @Test void logicalDuplicatePathRefused() throws Exception {
        logicalBundle();patch("mapping-set","structure-ab-mapping",d->{ObjectNode b=d.path("mappings").get(4).deepCopy();b.put("mappingId","duplicate");((ArrayNode)d.path("mappings")).add(b);});
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("mapping.duplicate-target"));assertThrows(Exception.class,()->approve());
    }
    @Test void logicalMissingIndexRefused() throws Exception {
        logicalBundle();patch("mapping-set","structure-ab-mapping",d->((ArrayNode)d.path("mappings").get(4).path("memberPath")).remove(1));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("structure.index-required"));
    }
    @Test void logicalMissingLeafRefusesPublication() throws Exception {
        logicalBundle();patch("mapping-set","structure-ab-mapping",d->((ArrayNode)d.path("mappings")).remove(4));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("mapping.incomplete-object"));assertThrows(Exception.class,()->approve());
    }
    @Test void logicalShapeLimitRefused() throws Exception {
        logicalBundle();patch("semantic-definition","logical-skid",d->((ArrayNode)d.path("members").get(1).path("shape")).set(0,JSON.getNodeFactory().numberNode(256)));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("structure.size"));
    }
    @Test void logicalMeaningConflictRefused() throws Exception {
        logicalBundle();patch("semantic-definition","logical-skid",d->((ObjectNode)d.path("members").get(1).path("members").get(0).path("members").get(0).path("unit")).put("code","bar"));
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("semantic.identity-conflict"));
    }
    @Test void logicalLegacyAndFloatingIndicesRefused() throws Exception {
        logicalBundle();patch("mapping-set","structure-ab-mapping",d->d.put("schemaVersion","2.4.0"));assertFalse(new MappingBundle().validate(bundle).accepted());
        patch("mapping-set","structure-ab-mapping",d->{d.put("schemaVersion","2.12.0");((ArrayNode)d.path("mappings").get(4).path("memberPath").get(1).path("indices")).set(0,JSON.getNodeFactory().numberNode(1.0));});
        var result=new MappingBundle().validate(bundle);assertFalse(result.accepted());assertTrue(result.report().toString().contains("structure.index-range"));
    }
    @Test void validWireAndDigestOracle() throws Exception {
        var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toPrettyString());
        assertEquals("02d1b0d482d668650c12a4c741e7ee30099e6f27459387dec1167e612ca26210",text(c.report(),"bundleSha256"));
    }
    @Test void publicationIsNotActivation() throws Exception {
        approve();JsonNode r=publish();assertEquals("not-performed",text(r,"activation"));
        JsonNode status=service.status("mixed-line");assertEquals("release",text(status.path("head"),"id"));assertEquals(r,status.path("release"));
        assertFalse(Files.exists(registry.resolve("activation")));
        assertEquals("proposer",text(r.path("approval").path("payload"),"proposedBy"));
    }
    @Test void approvalOnlyDoesNotPublish() throws Exception {approve();assertTrue(service.status("mixed-line").path("head").isNull());}
    @Test void missingApprovalRefuses() {assertThrows(Exception.class,()->publish());assertFalse(Files.exists(registry.resolve("mappings/heads/mixed-line.json")));}
    @Test void missingPolicyDenies() throws Exception {Files.delete(registry.resolve("identity/activation-policy.json"));assertThrows(Exception.class,()->approve());}
    @Test void selfApprovalDenies() {assertThrows(Exception.class,()->service.approve(bundle,"a","proposer",proposerKey,"proposer",proposerKey));}
    @Test void wrongKeyDenies() {assertThrows(Exception.class,()->service.approve(bundle,"a","proposer",approverKey,"approver",approverKey));}
    @Test void unregisteredPrincipalDenies() {assertThrows(Exception.class,()->service.approve(bundle,"a","nobody",proposerKey,"approver",approverKey));}
    @Test void unsignedOrForgedApprovalDenies() throws Exception {
        approve();Path p=registry.resolve("mappings/approvals/approval-1.json");ObjectNode receipt=(ObjectNode)read(p);receipt.put("approverSignature","forged");rewrite(p,receipt);assertThrows(Exception.class,()->publish());
    }
    @Test void modifiedAfterApprovalDenies() throws Exception {
        approve();patch("source-definition","mixed-plc-pressure",d->((ObjectNode)d.get("access")).put("addressIndex",1001));assertThrows(Exception.class,()->publish());
    }
    @Test void evidenceTamperDenies() throws Exception {
        approve();Path p=bundle.resolve("data/manual-0.txt");Files.writeString(p,"tampered\n");assertThrows(Exception.class,()->publish());
    }
    @Test void failedStagingPreservesPreviousHead() throws Exception {
        approve();publish();byte[] prior=Files.readAllBytes(registry.resolve("mappings/heads/mixed-line.json"));
        nextSubmission("second");approveNext("approval-2");
        MappingRegistry failing=new MappingRegistry(registry,CLOCK,()->{throw new IllegalStateException("injected staging failure");});
        assertThrows(Exception.class,()->failing.publish(bundle,"release","2.0.0","approval-2"));
        assertArrayEquals(prior,Files.readAllBytes(registry.resolve("mappings/heads/mixed-line.json")));assertFalse(Files.exists(registry.resolve("mappings/releases/release/2.0.0")));
        assertEquals("1.0.0",text(service.status("mixed-line").path("head"),"version"));
    }
    void nextSubmission(String id) throws Exception {
        JsonNode h=service.status("mixed-line").get("head");ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("id",id);s.set("baseRelease",h);
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));p.set("baseRelease",h);rewrite(bundle.resolve("proposal.json"),p);s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);
    }
    void approveNext(String id) throws Exception {service.approve(bundle,id,"proposer",proposerKey,"approver",approverKey);}
    @Test void staleBaseApprovalDeniesAfterNewRelease() throws Exception {
        approve();publish();nextSubmission("second");approveNext("approval-2");
        Path pending=tmp.resolve("pending");copy(bundle,pending);
        patch("source-definition","mixed-plc-pressure",d->((ObjectNode)d.get("access")).put("addressIndex",1002));approveNext("approval-3");service.publish(bundle,"release","2.0.0","approval-3");
        assertThrows(Exception.class,()->service.publish(pending,"release","3.0.0","approval-2"));
        assertEquals("2.0.0",text(service.status("mixed-line").path("head"),"version"));
    }
    @Test void releaseBytesTamperDetected() throws Exception {
        approve();publish();Path dir=registry.resolve("mappings/releases/release/1.0.0/payload");
        Files.writeString(dir.resolve("data/manual-0.txt"),"tamper");assertThrows(Exception.class,()->service.status("mixed-line"));
    }
    @Test void releaseManifestTamperDetected() throws Exception {
        approve();publish();Path p=registry.resolve("mappings/releases/release/1.0.0/release.json");ObjectNode r=(ObjectNode)read(p);r.put("proposalSha256","0".repeat(64));rewrite(p,r);assertThrows(Exception.class,()->service.status("mixed-line"));
    }
    @Test void publishPermissionRechecked() throws Exception {
        approve();Files.writeString(registry.resolve("identity/activation-policy.json"),"{\"version\":\"2\",\"default\":\"deny\",\"rules\":[]}");assertThrows(Exception.class,()->publish());
    }
    @Test void retiredKeyCannotPublishNew() throws Exception {
        approve();Path p=registry.resolve("identity/authorized-keys.jsonl");StringBuilder lines=new StringBuilder();
        for(String line:Files.readAllLines(p)){ObjectNode key=(ObjectNode)JSON.readTree(line);key.put("notAfter","2026-10-16T00:00:00Z");lines.append(JSON.writeValueAsString(key)).append("\n");}
        Files.writeString(p,lines.toString());assertThrows(Exception.class,()->publish());
    }
    @Test void changedApprovalPayloadCannotBeResealed() throws Exception {
        approve();Path p=registry.resolve("mappings/approvals/approval-1.json");ObjectNode r=(ObjectNode)read(p);((ObjectNode)r.path("payload")).put("bundleSha256","0".repeat(64));r.put("payloadSha256",sha(bytes(r.get("payload"))));rewrite(p,r);assertThrows(Exception.class,()->publish());
    }
    @Test void sourceOnlyBundleCannotBecomeMappingRelease() throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));ArrayNode retained=JSON.createArrayNode();
        for(JsonNode e:p.path("files"))if(Set.of("source-definition","evidence-artifact").contains(text(e,"kind")))retained.add(e);else Files.delete(bundle.resolve(text(e,"path")));
        p.set("files",retained);rewrite(bundle.resolve("proposal.json"),p);
        ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));s.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),s);
        var c=new MappingBundle().validate(bundle);assertFalse(c.accepted());assertTrue(c.report().path("findings").toString().contains("mapping.required"));
    }
    @Test void sameConceptDifferentMeaningCannotBeApproved() throws Exception {
        approve();publish();nextSubmission("second");
        patch("semantic-definition","mixed-tank-model",d->((ObjectNode)d.path("members").get(0)).put("role","setpoint"));
        assertThrows(Exception.class,()->approveNext("meaning-changed"));
    }
    @Test void alteredChangeAssessmentRefused() throws Exception {
        approve();Path p=registry.resolve("mappings/approvals/approval-1.json");ObjectNode r=(ObjectNode)read(p);((ObjectNode)r.path("changeAssessment")).put("reviewRequired",false);rewrite(p,r);
        assertThrows(Exception.class,()->publish());
    }
    @Test void approvalIncludesReceiverChanges() throws Exception {
        approve();JsonNode r=read(registry.resolve("mappings/approvals/approval-1.json"));assertFalse(r.path("changeAssessment").path("changes").isEmpty());assertEquals(sha(bytes(r.path("changeAssessment"))),text(r.path("payload"),"changeSha256"));
    }
    @Test void pinnedConnectionMismatchRefused() throws Exception {
        ObjectNode s=(ObjectNode)read(bundle.resolve("submission.json"));((ObjectNode)s.path("context").path("connections").get(0)).put("accessProfileRef","s7-300-db-v1");rewrite(bundle.resolve("submission.json"),s);
        assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void headFromAnotherStreamRefused() throws Exception {
        approve();publish();Files.copy(registry.resolve("mappings/heads/mixed-line.json"),registry.resolve("mappings/heads/other-line.json"));
        assertThrows(Exception.class,()->service.status("other-line"));
    }
    @Test void unknownExtraFileRefused() throws Exception {Files.writeString(bundle.resolve("extra.txt"),"extra");assertFalse(new MappingBundle().validate(bundle).accepted());}
    @Test void traversalRefused() throws Exception {
        ObjectNode p=(ObjectNode)read(bundle.resolve("proposal.json"));((ObjectNode)p.path("files").get(0)).put("path","../outside.json");rewrite(bundle.resolve("proposal.json"),p);
        assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void duplicateJSONRefused() throws Exception {Files.writeString(bundle.resolve("proposal.json"),"{\"kind\":1,\"kind\":2}");assertFalse(new MappingBundle().validate(bundle).accepted());}
    @Test void duplicateReleaseRefused() throws Exception {approve();publish();assertThrows(Exception.class,()->publish());}
    @Test void sourceHashNotTrustedFromSender() throws Exception {
        Path p=bundle.resolve("sources/0.json");Files.writeString(p,Files.readString(p)+" ");
        assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void receiverDiffIncludesAddress() throws Exception {
        Path before=tmp.resolve("before");copy(bundle,before);patch("source-definition","mixed-plc-pressure",d->((ObjectNode)d.get("access")).put("addressIndex",1001));
        JsonNode diff=MappingRegistry.diff(before,bundle);assertTrue(diff.path("changes").toString().contains("addressIndex"));
    }
    record Mutation(String name,String kind,String id,Consumer<ObjectNode> action) {public String toString(){return name;}}
    static Stream<Mutation> mutations(){
        return Stream.of(
            new Mutation("draft","source-definition","mixed-plc-pressure",d->d.put("status","draft")),
            new Mutation("profile","source-definition","mixed-plc-pressure",d->d.put("accessProfileRef","ab-logix-symbol-v1")),
            new Mutation("width","source-definition","mixed-plc-pressure",d->((ObjectNode)d.path("access")).put("wordCount",2)),
            new Mutation("unknown-op","value-graph","mixed-pressure-difference",d->((ObjectNode)d.path("nodes").get(0)).put("op","eval")),
            new Mutation("cycle","value-graph","mixed-pressure-difference",d->((ObjectNode)d.path("nodes").get(0).path("inputs")).set("left",object().put("kind","node").put("nodeId","difference"))),
            new Mutation("missing-ref","mapping-set","mixed-tank-mapping",d->((ObjectNode)d.path("targetInstanceRef")).put("id","missing")),
            new Mutation("unit","semantic-definition","mixed-tank-model",d->((ObjectNode)d.path("members").get(0).path("unit")).put("code","bar")),
            new Mutation("type","semantic-definition","mixed-tank-model",d->((ObjectNode)d.path("members").get(0)).put("valueType","String")),
            new Mutation("write-readonly","source-definition","mixed-plc-write",d->d.put("accessMode","read")),
            new Mutation("write-execution","write-definition","mixed-write-plc",d->d.put("execution","enabled")),
            new Mutation("cast","write-definition","mixed-write-plc",d->((ObjectNode)d.path("transform").get(1)).put("to","Double")),
            new Mutation("constant","source-definition","mixed-baseline",d->((ObjectNode)d.path("access")).put("value","NaN")),
            new Mutation("source-unknown-unit","source-definition","mixed-baseline",d->d.set("unit",object().put("status","unknown"))),
            new Mutation("unknown-version","source-definition","mixed-plc-pressure",d->d.put("schemaVersion","99.0.0")),
            new Mutation("equipment","source-definition","mixed-plc-pressure",d->d.put("equipmentInstanceId","other-equipment"))
        );
    }
    @ParameterizedTest(name="{0}") @MethodSource("mutations") void receiverRejectsIndependentMutation(Mutation m) throws Exception {
        patch(m.kind,m.id,m.action);var c=new MappingBundle().validate(bundle);assertFalse(c.accepted(),m.name+" unexpectedly passed");
    }

    void a07Bundle() throws Exception {
        bundle=tmp.resolve("a07");copy(Path.of(getClass().getResource("/mapping-fixtures/a07").toURI()),bundle);
    }
    @Test void explicitViewsApproveAndPublish() throws Exception {
        a07Bundle();assertTrue(new MappingBundle().validate(bundle).accepted());
        approve();JsonNode release=publish();assertEquals("not-performed",text(release,"activation"));
        assertNotNull(service.status("mixed-line").get("head"));
    }
    static Stream<JsonNode> a07Cases() throws Exception {
        JsonNode d=read(Path.of(MappingPublicationTest.class.getResource("/mapping-fixtures/a07-cases.json").toURI()));
        List<JsonNode> cases=new ArrayList<>();d.path("cases").forEach(cases::add);return cases.stream();
    }
    @ParameterizedTest @MethodSource("a07Cases") void explicitViewMutationRefused(JsonNode c) throws Exception {
        a07Bundle();
        patch("source-definition",text(c,"sourceId"),d->{
            String ptr=text(c,"pointer");int slash=ptr.lastIndexOf('/');
            ObjectNode parent=(ObjectNode)d.at(ptr.substring(0,slash));parent.set(ptr.substring(slash+1),c.get("value"));
        });
        var checked=new MappingBundle().validate(bundle);assertFalse(checked.accepted(),c.toString());
        assertTrue(checked.report().path("findings").toString().contains(text(c,"expectedRule")),checked.report().toPrettyString());
    }

    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings={"intent-written","release-moved","head-moved"})
    void recoveryCompletesEachCrashWindow(String point) throws Exception {
        approve();service.faults(p->{if(p.equals(point))throw new IllegalStateException("injected:"+point);});
        assertThrows(IllegalStateException.class,()->publish());MappingRegistry restarted=new MappingRegistry(registry,CLOCK,()->{});
        assertThrows(Exception.class,()->restarted.publish(bundle,"other","1.0.0","approval-1"));
        assertEquals(1,restarted.recover().path("actions").size());assertEquals("release",text(restarted.status("mixed-line").path("head"),"id"));assertEquals(0,restarted.recover().path("actions").size());
    }
    void interrupt(String point) throws Exception {approve();service.faults(p->{if(p.equals(point))throw new IllegalStateException("crash");});assertThrows(Exception.class,()->publish());}
    Path staging() throws Exception {try(var files=Files.list(registry.resolve("mappings"))){return files.filter(p->p.getFileName().toString().startsWith(".staging-")).findFirst().orElseThrow();}}
    @Test void recoveryRejectsTruncatedJournal() throws Exception {
        interrupt("intent-written");try(var files=Files.list(registry.resolve("mappings/transactions"))){Files.writeString(files.findFirst().orElseThrow(),"{");}
        assertThrows(Exception.class,()->service.recover());assertTrue(service.status("mixed-line").path("head").isNull());assertThrows(Exception.class,()->service.gc(3600,null));
    }
    @Test void recoveryRejectsCorruptStagedPayload() throws Exception {
        interrupt("intent-written");Files.writeString(staging().resolve("payload/submission.json"),"{}");assertThrows(Exception.class,()->service.recover());assertTrue(service.status("mixed-line").path("head").isNull());
    }
    @Test void recoveryRejectsHeadConflict() throws Exception {
        interrupt("release-moved");Files.createDirectories(registry.resolve("mappings/heads"));Files.writeString(registry.resolve("mappings/heads/mixed-line.json"),"{}");assertThrows(Exception.class,()->service.recover());assertEquals("{}",Files.readString(registry.resolve("mappings/heads/mixed-line.json")));
    }
    @Test void recoveryRejectsReleaseMetadataTamper() throws Exception {
        interrupt("release-moved");Files.writeString(registry.resolve("mappings/releases/release/1.0.0/release.json"),"{}");assertThrows(Exception.class,()->service.recover());
    }
    @Test void gcQuarantinesOnlyOldRecognizedOrphansAndPreservesHistory() throws Exception {
        approve();publish();Path root=registry.resolve("mappings"),orphan=root.resolve(".staging-orphan");Files.createDirectories(orphan);Files.writeString(orphan.resolve("partial"),"partial");Files.setLastModifiedTime(orphan,java.nio.file.attribute.FileTime.from(CLOCK.instant().minusSeconds(7200)));Files.writeString(root.resolve("unknown.txt"),"keep");
        JsonNode plan=service.gc(3600,null);assertEquals(1,plan.path("candidates").size());assertTrue(Files.exists(orphan));service.gc(3600,text(plan,"planSha256"));assertFalse(Files.exists(orphan));assertTrue(Files.exists(root.resolve("unknown.txt")));assertEquals("release",text(service.status("mixed-line").path("head"),"id"));assertTrue(Files.exists(root.resolve("approvals/approval-1.json")));assertEquals(0,service.gc(3600,null).path("candidates").size());
    }
    @Test void gcRejectsStalePlanAndTooShortGrace() throws Exception {
        Path orphan=registry.resolve("mappings/.staging-old");Files.createDirectories(orphan);Files.writeString(orphan.resolve("file"),"old");Files.setLastModifiedTime(orphan,java.nio.file.attribute.FileTime.from(CLOCK.instant().minusSeconds(7200)));JsonNode plan=service.gc(3600,null);Files.writeString(orphan.resolve("file"),"new");assertThrows(Exception.class,()->service.gc(3600,text(plan,"planSha256")));assertTrue(Files.exists(orphan));assertThrows(Exception.class,()->service.gc(0,null));
    }
    @Test void gcRefusesDamagedHistoricalRelease() throws Exception {approve();publish();Files.writeString(registry.resolve("mappings/releases/release/1.0.0/payload/submission.json"),"{}");assertThrows(Exception.class,()->service.gc(3600,null));}
    @Test void gcPreservesRecentStaging() throws Exception {Path orphan=registry.resolve("mappings/.staging-recent");Files.createDirectories(orphan);Files.setLastModifiedTime(orphan,java.nio.file.attribute.FileTime.from(CLOCK.instant()));assertEquals(0,service.gc(3600,null).path("candidates").size());}

    @ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings={"intent-written","release-moved","head-moved"})
    void recoveryAfterActualJvmDeath(String point) throws Exception {
        approve();String javaBin=Path.of(System.getProperty("java.home"),"bin","java").toString();
        Process process=new ProcessBuilder(javaBin,"-cp",System.getProperty("surefire.test.class.path",System.getProperty("java.class.path")),MappingCrashProbe.class.getName(),registry.toString(),bundle.toString(),"unused","unused",point).redirectErrorStream(true).start();
        assertTrue(process.waitFor(90,java.util.concurrent.TimeUnit.SECONDS));assertEquals(77,process.exitValue(),new String(process.getInputStream().readAllBytes()));
        assertEquals(1,service.recover().path("actions").size());assertEquals("release",text(service.status("mixed-line").path("head"),"id"));assertEquals(0,service.recover().path("actions").size());
    }
    @Test void gcInterruptedQuarantineIsRecoverableByNewPlan() throws Exception {
        Path orphan=registry.resolve("mappings/.staging-old");Files.createDirectories(orphan);Files.writeString(orphan.resolve("file"),"keep");Files.setLastModifiedTime(orphan,java.nio.file.attribute.FileTime.from(CLOCK.instant().minusSeconds(7200)));
        JsonNode plan=service.gc(3600,null);service.faults(p->{if(p.equals("gc-quarantined"))throw new IllegalStateException("crash");});assertThrows(Exception.class,()->service.gc(3600,text(plan,"planSha256")));
        assertEquals(0,new MappingRegistry(registry,CLOCK,()->{}).gc(3600,null).path("candidates").size());try(var files=Files.walk(registry.resolve("mappings/quarantine"))){assertTrue(files.anyMatch(p->p.getFileName().toString().equals("file")));}
    }

    @Test void gcKeepsUnheadedHistoryAndRejectsItsCorruption() throws Exception {
        approve();publish();JsonNode prior=service.status("mixed-line").path("head");
        ObjectNode proposal=(ObjectNode)read(bundle.resolve("proposal.json"));proposal.set("baseRelease",prior);rewrite(bundle.resolve("proposal.json"),proposal);
        ObjectNode submission=(ObjectNode)read(bundle.resolve("submission.json"));submission.set("baseRelease",prior);submission.put("id","second");submission.put("proposalSha256",sha(bundle.resolve("proposal.json")));rewrite(bundle.resolve("submission.json"),submission);
        service.approve(bundle,"approval-2","proposer",proposerKey,"approver",approverKey);service.publish(bundle,"release-2","1.0.0","approval-2");
        assertEquals(0,service.gc(3600,null).path("candidates").size());assertTrue(Files.exists(registry.resolve("mappings/releases/release/1.0.0/release.json")));
        Files.writeString(registry.resolve("mappings/releases/release/1.0.0/payload/submission.json"),"{}");assertThrows(Exception.class,()->service.gc(3600,null));
    }

    void arithmeticBundle() throws Exception {bundle=tmp.resolve("arithmetic");copy(Path.of(getClass().getResource("/mapping-fixtures/p3cc").toURI()),bundle);}
    @Test void arithmeticAllProfilesApprovePublish() throws Exception {
        arithmeticBundle();var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toPrettyString());approve();assertEquals("not-performed",text(publish(),"activation"));
    }
    @Test void arithmeticLegacyVersionRefused() throws Exception {
        arithmeticBundle();patch("value-graph","arithmetic-ab",d->d.put("schemaVersion","2.13.0"));assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void arithmeticWrongPrecisionRefused() throws Exception {
        arithmeticBundle();patch("value-graph","arithmetic-ab",d->((ObjectNode)d.path("nodes").get(2)).put("precision",35));assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void arithmeticWrongRoundingRefused() throws Exception {
        arithmeticBundle();patch("value-graph","arithmetic-ab",d->((ObjectNode)d.path("nodes").get(2)).put("rounding","exact"));assertFalse(new MappingBundle().validate(bundle).accepted());
    }
    @Test void arithmeticDimensionfulProductRefused() throws Exception {
        arithmeticBundle();patch("value-graph","arithmetic-ab",d->((ObjectNode)d.path("nodes").get(1).path("inputs")).set("right",d.path("nodes").get(0).path("inputs").path("right")));var c=new MappingBundle().validate(bundle);assertFalse(c.accepted());assertTrue(c.report().toString().contains("graph.input-unit"));
    }
    @Test void arithmeticOutputUnitRefused() throws Exception {
        arithmeticBundle();patch("value-graph","arithmetic-ab",d->((ObjectNode)d.path("nodes").get(3)).set("unit",object().put("status","known").put("code","kPa")));var c=new MappingBundle().validate(bundle);assertFalse(c.accepted());assertTrue(c.report().toString().contains("graph.output-unit"));
    }
    @org.junit.jupiter.params.ParameterizedTest @org.junit.jupiter.params.provider.ValueSource(strings={"Cel","K"})
    void arithmeticAbsoluteTemperaturesRefused(String temperature) throws Exception {
        arithmeticBundle();patch("source-definition","structure-ab-actual",d->((ObjectNode)d.path("unit")).put("code",temperature));patch("source-definition","structure-ab-target",d->((ObjectNode)d.path("unit")).put("code",temperature));var c=new MappingBundle().validate(bundle);assertFalse(c.accepted());assertTrue(c.report().toString().contains("graph.input-unit"));
    }
    @Test void arithmeticUnknownUnitRefused() throws Exception {
        arithmeticBundle();patch("source-definition","arithmetic-ab-gain",d->d.set("unit",object().put("status","unknown")));var c=new MappingBundle().validate(bundle);assertFalse(c.accepted());assertTrue(c.report().toString().contains("graph.input-unit"));
    }
    @Test void arithmeticCycleRefused() throws Exception {
        arithmeticBundle();patch("value-graph","arithmetic-ab",d->((ObjectNode)d.path("nodes").get(0).path("inputs")).set("left",object().put("kind","node").put("nodeId","quotient")));var c=new MappingBundle().validate(bundle);assertFalse(c.accepted());assertTrue(c.report().toString().contains("graph.cycle"));
    }
    @Test void arithmeticAsBoundedSelectorCandidate() throws Exception {
        arithmeticBundle();patch("value-graph","arithmetic-ab",d->{ObjectNode n=object().put("nodeId","selected").put("op","bounded-selector").put("valueType","Decimal").put("outOfRange","default-candidate").put("defaultCandidate",0);
            n.set("unit",object().put("status","known").put("code","kPa"));n.set("evidenceRefs",d.path("nodes").get(1).path("evidenceRefs"));
            ObjectNode inputs=object();inputs.set("index",d.path("nodes").get(1).path("inputs").path("right"));inputs.set("candidate0",object().put("kind","node").put("nodeId","sum"));inputs.set("candidate1",object().put("kind","node").put("nodeId","quotient"));n.set("inputs",inputs);((ArrayNode)d.path("nodes")).add(n);});
        var c=new MappingBundle().validate(bundle);assertTrue(c.accepted(),c.report().toPrettyString());approve();
    }
}
